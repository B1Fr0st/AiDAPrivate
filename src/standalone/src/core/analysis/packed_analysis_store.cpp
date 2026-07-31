#include "packed_analysis_store.hpp"

#include <algorithm>
#include <limits>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

static_assert(!std::is_copy_constructible_v<aida::analysis::packed_analysis_shard_builder_t> &&
              !std::is_copy_assignable_v<aida::analysis::packed_analysis_shard_builder_t>,
              "packed_analysis_shard_builder_t must stay move-only so concurrent per-tile builds can never alias shared state");

namespace aida::analysis {
namespace {

packed_store_error_t make_error(packed_store_error_code_t code, std::string_view phase,
                                std::uint16_t shard = 0, std::uint64_t subject = 0,
                                std::uint64_t expected = 0,
                                std::uint64_t actual = 0) noexcept
{
    return packed_store_error_t{code, phase, shard, subject, expected, actual};
}

bool valid_domain(packed_entity_domain_t domain) noexcept
{
    switch (domain) {
    case packed_entity_domain_t::instruction:
    case packed_entity_domain_t::operand:
    case packed_entity_domain_t::edge:
    case packed_entity_domain_t::string:
    case packed_entity_domain_t::symbol:
    case packed_entity_domain_t::address_expression:
    case packed_entity_domain_t::basic_block:
    case packed_entity_domain_t::function:
    case packed_entity_domain_t::function_chunk:
    case packed_entity_domain_t::target_fact:
    case packed_entity_domain_t::xref:
    case packed_entity_domain_t::coverage:
        return true;
    default:
        return false;
    }
}

bool valid_address(const address_t& address) noexcept
{
    return static_cast<std::uint8_t>(address.space) <=
            static_cast<std::uint8_t>(address_space_id_t::live_virtual) &&
        static_cast<std::uint8_t>(address.architecture) <=
            static_cast<std::uint8_t>(architecture_id_t::dalvik_bytecode) &&
        static_cast<std::uint8_t>(address.mode) <=
            static_cast<std::uint8_t>(architecture_mode_t::dalvik);
}

bool valid_provenance(fact_provenance_t provenance) noexcept
{
    return static_cast<std::uint8_t>(provenance) <=
        static_cast<std::uint8_t>(fact_provenance_t::decompiler_feedback);
}

bool valid_coverage(coverage_reason_t coverage) noexcept
{
    return static_cast<std::uint8_t>(coverage) <=
        static_cast<std::uint8_t>(coverage_reason_t::pending);
}

bool valid_operand_kind(operand_kind_t kind) noexcept
{
    return static_cast<std::uint8_t>(kind) <= static_cast<std::uint8_t>(operand_kind_t::pointer);
}

bool valid_expression_kind(address_expression_kind_t kind) noexcept
{
    return static_cast<std::uint8_t>(kind) <=
        static_cast<std::uint8_t>(address_expression_kind_t::segment_relative);
}

bool valid_resolution(target_resolution_t resolution) noexcept
{
    return static_cast<std::uint8_t>(resolution) <=
        static_cast<std::uint8_t>(target_resolution_t::unresolved_indirect);
}

bool valid_edge_kind(edge_kind_t kind) noexcept
{
    return static_cast<std::uint8_t>(kind) <= static_cast<std::uint8_t>(edge_kind_t::indirect);
}

bool valid_string_encoding(string_encoding_t encoding) noexcept
{
    return static_cast<std::uint8_t>(encoding) <= static_cast<std::uint8_t>(string_encoding_t::utf16_le);
}

bool valid_symbol_kind(symbol_kind_t kind) noexcept
{
    return static_cast<std::uint8_t>(kind) <= static_cast<std::uint8_t>(symbol_kind_t::metadata);
}

bool valid_xref_kind(xref_kind_t kind) noexcept
{
    return static_cast<std::uint8_t>(kind) <= static_cast<std::uint8_t>(xref_kind_t::relocation);
}

bool valid_target_kind(target_kind_record_t kind) noexcept
{
    return static_cast<std::uint8_t>(kind) <= static_cast<std::uint8_t>(target_kind_record_t::fallthrough);
}

template <typename value_t>
std::uint64_t vector_payload_bytes(const std::vector<value_t>& values) noexcept
{
    return static_cast<std::uint64_t>(values.size()) * sizeof(value_t);
}

template <typename value_t>
std::uint64_t vector_reserved_bytes(const std::vector<value_t>& values) noexcept
{
    return static_cast<std::uint64_t>(values.capacity()) * sizeof(value_t);
}

template <typename value_t>
void add_vector_accounting(const std::vector<value_t>& values, std::uint64_t& payload,
                           std::uint64_t& reserved) noexcept
{
    payload += vector_payload_bytes(values);
    reserved += vector_reserved_bytes(values);
}

struct packed_address_columns_t final {
    std::vector<std::uint64_t> values;
    std::vector<std::uint32_t> metadata;

    void append(const address_t& address)
    {
        const auto packed = packed_address_t::pack(address);
        values.push_back(packed.value);
        metadata.push_back(packed.metadata);
    }

    std::size_t size() const noexcept { return values.size(); }

    std::optional<address_t> at(std::size_t index) const noexcept
    {
        if (index >= values.size() || index >= metadata.size())
            return std::nullopt;
        return packed_address_t{values[index], metadata[index]}.unpack();
    }

    bool valid(std::size_t expected) const noexcept
    {
        if (values.size() != expected || metadata.size() != expected)
            return false;
        for (std::size_t index = 0; index < expected; ++index) {
            const auto address = packed_address_t{values[index], metadata[index]}.unpack();
            if ((metadata[index] & 0xff000000U) != 0 || !valid_address(address))
                return false;
        }
        return true;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(values, payload, reserved);
        add_vector_accounting(metadata, payload, reserved);
    }
};

struct instruction_draft_t final {
    packed_instruction_input_t input;
    packed_string_id_t mnemonic;
};

struct string_draft_t final {
    packed_string_input_t input;
    packed_string_id_t value;
};

struct symbol_draft_t final {
    packed_symbol_input_t input;
    packed_string_id_t name;
};

struct function_draft_t final {
    packed_function_input_t input;
    packed_string_id_t name;
};

struct instruction_row_t final {
    packed_entity_id_t id;
    packed_instruction_input_t input;
    packed_string_id_t mnemonic;
};

struct operand_row_t final {
    packed_entity_id_t id;
    packed_operand_input_t input;
    packed_entity_id_t instruction;
    packed_entity_id_t address_expression;
};

struct edge_row_t final {
    packed_entity_id_t id;
    packed_edge_input_t input;
    packed_entity_id_t source_entity;
    packed_entity_id_t target_entity;
};

struct string_row_t final {
    packed_entity_id_t id;
    packed_string_input_t input;
    packed_string_id_t value;
};

struct symbol_row_t final {
    packed_entity_id_t id;
    packed_symbol_input_t input;
    packed_string_id_t name;
};

struct address_expression_row_t final {
    packed_entity_id_t id;
    packed_address_expression_input_t input;
    packed_entity_id_t instruction;
};

struct basic_block_row_t final {
    packed_entity_id_t id;
    packed_basic_block_input_t input;
};

struct function_row_t final {
    packed_entity_id_t id;
    packed_function_input_t input;
    packed_string_id_t name;
    packed_entity_id_t entry_block;
    packed_entity_id_t symbol;
};

struct function_chunk_row_t final {
    packed_entity_id_t id;
    packed_function_chunk_input_t input;
    packed_entity_id_t function;
};

struct target_fact_row_t final {
    packed_entity_id_t id;
    packed_target_fact_input_t input;
    packed_entity_id_t instruction;
    packed_entity_id_t operand;
    packed_entity_id_t address_expression;
};

struct xref_row_t final {
    packed_entity_id_t id;
    packed_xref_input_t input;
    packed_entity_id_t source_entity;
    packed_entity_id_t target_entity;
};

struct coverage_row_t final {
    packed_entity_id_t id;
    packed_coverage_input_t input;
};

struct instruction_columns_t final {
    std::vector<packed_entity_id_t> ids;
    packed_address_columns_t addresses;
    std::vector<std::uint8_t> lengths;
    std::vector<std::uint16_t> mnemonic_ids;
    std::vector<packed_string_id_t> mnemonics;
    std::vector<std::uint32_t> opcode_ids;
    std::vector<std::uint32_t> flow_flags;
    std::vector<std::uint32_t> first_operands;
    std::vector<std::uint16_t> operand_counts;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;
    std::vector<coverage_reason_t> coverages;
    std::vector<std::uint64_t> stable_source_ids;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        addresses.values.reserve(count);
        addresses.metadata.reserve(count);
        lengths.reserve(count);
        mnemonic_ids.reserve(count);
        mnemonics.reserve(count);
        opcode_ids.reserve(count);
        flow_flags.reserve(count);
        first_operands.reserve(count);
        operand_counts.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
        coverages.reserve(count);
        stable_source_ids.reserve(count);
    }

    void append(const instruction_row_t& row)
    {
        ids.push_back(row.id);
        addresses.append(row.input.address);
        lengths.push_back(row.input.length);
        mnemonic_ids.push_back(row.input.mnemonic_id);
        mnemonics.push_back(row.mnemonic);
        opcode_ids.push_back(row.input.opcode_id);
        flow_flags.push_back(row.input.flow_flags);
        first_operands.push_back(0);
        operand_counts.push_back(0);
        provenances.push_back(row.input.provenance);
        confidences.push_back(row.input.confidence);
        coverages.push_back(row.input.coverage);
        stable_source_ids.push_back(row.input.stable_source_id);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && addresses.valid(count) && lengths.size() == count &&
            mnemonic_ids.size() == count && mnemonics.size() == count && opcode_ids.size() == count &&
            flow_flags.size() == count && first_operands.size() == count &&
            operand_counts.size() == count && provenances.size() == count &&
            confidences.size() == count && coverages.size() == count &&
            stable_source_ids.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        addresses.account(payload, reserved);
        add_vector_accounting(lengths, payload, reserved);
        add_vector_accounting(mnemonic_ids, payload, reserved);
        add_vector_accounting(mnemonics, payload, reserved);
        add_vector_accounting(opcode_ids, payload, reserved);
        add_vector_accounting(flow_flags, payload, reserved);
        add_vector_accounting(first_operands, payload, reserved);
        add_vector_accounting(operand_counts, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
        add_vector_accounting(coverages, payload, reserved);
        add_vector_accounting(stable_source_ids, payload, reserved);
    }
};

struct operand_columns_t final {
    std::vector<packed_entity_id_t> ids;
    std::vector<packed_entity_id_t> instruction_ids;
    std::vector<packed_entity_id_t> address_expression_ids;
    std::vector<std::uint8_t> operand_indices;
    std::vector<std::uint8_t> decoder_operand_ids;
    std::vector<operand_kind_t> kinds;
    std::vector<std::uint8_t> accesses;
    std::vector<std::uint8_t> visibilities;
    std::vector<std::uint8_t> encodings;
    std::vector<std::uint8_t> memory_types;
    std::vector<std::uint8_t> access_widths;
    std::vector<std::uint16_t> bit_widths;
    std::vector<std::uint16_t> access_width_bits;
    std::vector<std::uint16_t> access_counts;
    std::vector<std::uint16_t> element_width_bits;
    std::vector<std::uint16_t> element_counts;
    std::vector<std::uint16_t> address_width_bits;
    std::vector<std::uint16_t> regs;
    std::vector<std::uint16_t> segment_regs;
    std::vector<std::uint16_t> base_regs;
    std::vector<std::uint16_t> index_regs;
    std::vector<std::uint8_t> scales;
    std::vector<std::uint8_t> relatives;
    std::vector<std::uint8_t> signed_values;
    std::vector<std::uint8_t> has_displacements;
    std::vector<std::uint8_t> has_resolved_expression_values;
    std::vector<std::int64_t> displacements;
    std::vector<std::uint64_t> immediates;
    std::vector<std::uint64_t> resolved_expression_values;
    std::vector<std::uint16_t> address_components;
    std::vector<address_expression_kind_t> address_expression_kinds;
    std::vector<target_resolution_t> address_resolutions;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        instruction_ids.reserve(count);
        address_expression_ids.reserve(count);
        operand_indices.reserve(count);
        decoder_operand_ids.reserve(count);
        kinds.reserve(count);
        accesses.reserve(count);
        visibilities.reserve(count);
        encodings.reserve(count);
        memory_types.reserve(count);
        access_widths.reserve(count);
        bit_widths.reserve(count);
        access_width_bits.reserve(count);
        access_counts.reserve(count);
        element_width_bits.reserve(count);
        element_counts.reserve(count);
        address_width_bits.reserve(count);
        regs.reserve(count);
        segment_regs.reserve(count);
        base_regs.reserve(count);
        index_regs.reserve(count);
        scales.reserve(count);
        relatives.reserve(count);
        signed_values.reserve(count);
        has_displacements.reserve(count);
        has_resolved_expression_values.reserve(count);
        displacements.reserve(count);
        immediates.reserve(count);
        resolved_expression_values.reserve(count);
        address_components.reserve(count);
        address_expression_kinds.reserve(count);
        address_resolutions.reserve(count);
    }

    void append(const operand_row_t& row)
    {
        const auto& input = row.input;
        ids.push_back(row.id);
        instruction_ids.push_back(row.instruction);
        address_expression_ids.push_back(row.address_expression);
        operand_indices.push_back(input.operand_index);
        decoder_operand_ids.push_back(input.decoder_operand_id);
        kinds.push_back(input.kind);
        accesses.push_back(input.access);
        visibilities.push_back(input.visibility);
        encodings.push_back(input.encoding);
        memory_types.push_back(input.memory_type);
        access_widths.push_back(input.access_width);
        bit_widths.push_back(input.bit_width);
        access_width_bits.push_back(input.access_width_bits);
        access_counts.push_back(input.access_count);
        element_width_bits.push_back(input.element_width_bits);
        element_counts.push_back(input.element_count);
        address_width_bits.push_back(input.address_width_bits);
        regs.push_back(input.reg);
        segment_regs.push_back(input.segment_reg);
        base_regs.push_back(input.base_reg);
        index_regs.push_back(input.index_reg);
        scales.push_back(input.scale);
        relatives.push_back(input.relative ? 1U : 0U);
        signed_values.push_back(input.signed_value ? 1U : 0U);
        has_displacements.push_back(input.has_displacement ? 1U : 0U);
        has_resolved_expression_values.push_back(input.has_resolved_expression_value ? 1U : 0U);
        displacements.push_back(input.displacement);
        immediates.push_back(input.immediate);
        resolved_expression_values.push_back(input.resolved_expression_value);
        address_components.push_back(input.address_components);
        address_expression_kinds.push_back(input.address_expression_kind);
        address_resolutions.push_back(input.address_resolution);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && instruction_ids.size() == count &&
            address_expression_ids.size() == count && operand_indices.size() == count &&
            decoder_operand_ids.size() == count && kinds.size() == count && accesses.size() == count &&
            visibilities.size() == count && encodings.size() == count && memory_types.size() == count &&
            access_widths.size() == count && bit_widths.size() == count &&
            access_width_bits.size() == count && access_counts.size() == count &&
            element_width_bits.size() == count && element_counts.size() == count &&
            address_width_bits.size() == count && regs.size() == count && segment_regs.size() == count &&
            base_regs.size() == count && index_regs.size() == count && scales.size() == count &&
            relatives.size() == count && signed_values.size() == count &&
            has_displacements.size() == count && has_resolved_expression_values.size() == count &&
            displacements.size() == count && immediates.size() == count &&
            resolved_expression_values.size() == count && address_components.size() == count &&
            address_expression_kinds.size() == count && address_resolutions.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        add_vector_accounting(instruction_ids, payload, reserved);
        add_vector_accounting(address_expression_ids, payload, reserved);
        add_vector_accounting(operand_indices, payload, reserved);
        add_vector_accounting(decoder_operand_ids, payload, reserved);
        add_vector_accounting(kinds, payload, reserved);
        add_vector_accounting(accesses, payload, reserved);
        add_vector_accounting(visibilities, payload, reserved);
        add_vector_accounting(encodings, payload, reserved);
        add_vector_accounting(memory_types, payload, reserved);
        add_vector_accounting(access_widths, payload, reserved);
        add_vector_accounting(bit_widths, payload, reserved);
        add_vector_accounting(access_width_bits, payload, reserved);
        add_vector_accounting(access_counts, payload, reserved);
        add_vector_accounting(element_width_bits, payload, reserved);
        add_vector_accounting(element_counts, payload, reserved);
        add_vector_accounting(address_width_bits, payload, reserved);
        add_vector_accounting(regs, payload, reserved);
        add_vector_accounting(segment_regs, payload, reserved);
        add_vector_accounting(base_regs, payload, reserved);
        add_vector_accounting(index_regs, payload, reserved);
        add_vector_accounting(scales, payload, reserved);
        add_vector_accounting(relatives, payload, reserved);
        add_vector_accounting(signed_values, payload, reserved);
        add_vector_accounting(has_displacements, payload, reserved);
        add_vector_accounting(has_resolved_expression_values, payload, reserved);
        add_vector_accounting(displacements, payload, reserved);
        add_vector_accounting(immediates, payload, reserved);
        add_vector_accounting(resolved_expression_values, payload, reserved);
        add_vector_accounting(address_components, payload, reserved);
        add_vector_accounting(address_expression_kinds, payload, reserved);
        add_vector_accounting(address_resolutions, payload, reserved);
    }
};

struct edge_columns_t final {
    std::vector<packed_entity_id_t> ids;
    std::vector<packed_entity_id_t> source_entities;
    std::vector<packed_entity_id_t> target_entities;
    packed_address_columns_t sources;
    packed_address_columns_t targets;
    std::vector<edge_kind_t> kinds;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        source_entities.reserve(count);
        target_entities.reserve(count);
        sources.values.reserve(count);
        sources.metadata.reserve(count);
        targets.values.reserve(count);
        targets.metadata.reserve(count);
        kinds.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
    }

    void append(const edge_row_t& row)
    {
        ids.push_back(row.id);
        source_entities.push_back(row.source_entity);
        target_entities.push_back(row.target_entity);
        sources.append(row.input.source);
        targets.append(row.input.target);
        kinds.push_back(row.input.kind);
        provenances.push_back(row.input.provenance);
        confidences.push_back(row.input.confidence);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && source_entities.size() == count &&
            target_entities.size() == count && sources.valid(count) && targets.valid(count) &&
            kinds.size() == count && provenances.size() == count && confidences.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        add_vector_accounting(source_entities, payload, reserved);
        add_vector_accounting(target_entities, payload, reserved);
        sources.account(payload, reserved);
        targets.account(payload, reserved);
        add_vector_accounting(kinds, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
    }
};

struct string_columns_t final {
    std::vector<packed_entity_id_t> ids;
    packed_address_columns_t addresses;
    std::vector<std::uint64_t> byte_lengths;
    std::vector<string_encoding_t> encodings;
    std::vector<packed_string_id_t> values;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        addresses.values.reserve(count);
        addresses.metadata.reserve(count);
        byte_lengths.reserve(count);
        encodings.reserve(count);
        values.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
    }

    void append(const string_row_t& row)
    {
        ids.push_back(row.id);
        addresses.append(row.input.address);
        byte_lengths.push_back(row.input.byte_length);
        encodings.push_back(row.input.encoding);
        values.push_back(row.value);
        provenances.push_back(row.input.provenance);
        confidences.push_back(row.input.confidence);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && addresses.valid(count) && byte_lengths.size() == count &&
            encodings.size() == count && values.size() == count && provenances.size() == count &&
            confidences.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        addresses.account(payload, reserved);
        add_vector_accounting(byte_lengths, payload, reserved);
        add_vector_accounting(encodings, payload, reserved);
        add_vector_accounting(values, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
    }
};

struct symbol_columns_t final {
    std::vector<packed_entity_id_t> ids;
    packed_address_columns_t addresses;
    std::vector<packed_string_id_t> names;
    std::vector<symbol_kind_t> kinds;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        addresses.values.reserve(count);
        addresses.metadata.reserve(count);
        names.reserve(count);
        kinds.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
    }

    void append(const symbol_row_t& row)
    {
        ids.push_back(row.id);
        addresses.append(row.input.address);
        names.push_back(row.name);
        kinds.push_back(row.input.kind);
        provenances.push_back(row.input.provenance);
        confidences.push_back(row.input.confidence);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && addresses.valid(count) && names.size() == count &&
            kinds.size() == count && provenances.size() == count && confidences.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        addresses.account(payload, reserved);
        add_vector_accounting(names, payload, reserved);
        add_vector_accounting(kinds, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
    }
};

struct address_expression_columns_t final {
    std::vector<packed_entity_id_t> ids;
    std::vector<packed_entity_id_t> instruction_ids;
    std::vector<std::uint16_t> base_regs;
    std::vector<std::uint16_t> index_regs;
    std::vector<std::uint8_t> scales;
    std::vector<std::int64_t> displacements;
    std::vector<std::uint16_t> segment_regs;
    std::vector<std::uint16_t> address_components;
    std::vector<address_expression_kind_t> kinds;
    std::vector<target_resolution_t> resolutions;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        instruction_ids.reserve(count);
        base_regs.reserve(count);
        index_regs.reserve(count);
        scales.reserve(count);
        displacements.reserve(count);
        segment_regs.reserve(count);
        address_components.reserve(count);
        kinds.reserve(count);
        resolutions.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
    }

    void append(const address_expression_row_t& row)
    {
        const auto& input = row.input;
        ids.push_back(row.id);
        instruction_ids.push_back(row.instruction);
        base_regs.push_back(input.base_reg);
        index_regs.push_back(input.index_reg);
        scales.push_back(input.scale);
        displacements.push_back(input.displacement);
        segment_regs.push_back(input.segment_reg);
        address_components.push_back(input.address_components);
        kinds.push_back(input.kind);
        resolutions.push_back(input.resolution);
        provenances.push_back(input.provenance);
        confidences.push_back(input.confidence);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && instruction_ids.size() == count && base_regs.size() == count &&
            index_regs.size() == count && scales.size() == count && displacements.size() == count &&
            segment_regs.size() == count && address_components.size() == count &&
            kinds.size() == count && resolutions.size() == count && provenances.size() == count &&
            confidences.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        add_vector_accounting(instruction_ids, payload, reserved);
        add_vector_accounting(base_regs, payload, reserved);
        add_vector_accounting(index_regs, payload, reserved);
        add_vector_accounting(scales, payload, reserved);
        add_vector_accounting(displacements, payload, reserved);
        add_vector_accounting(segment_regs, payload, reserved);
        add_vector_accounting(address_components, payload, reserved);
        add_vector_accounting(kinds, payload, reserved);
        add_vector_accounting(resolutions, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
    }
};

struct basic_block_columns_t final {
    std::vector<packed_entity_id_t> ids;
    packed_address_columns_t start_addresses;
    packed_address_columns_t end_addresses;
    std::vector<std::uint32_t> instruction_begins;
    std::vector<std::uint16_t> instruction_counts;
    std::vector<std::uint16_t> predecessor_counts;
    std::vector<std::uint16_t> successor_counts;
    std::vector<std::uint32_t> flags;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        start_addresses.values.reserve(count);
        start_addresses.metadata.reserve(count);
        end_addresses.values.reserve(count);
        end_addresses.metadata.reserve(count);
        instruction_begins.reserve(count);
        instruction_counts.reserve(count);
        predecessor_counts.reserve(count);
        successor_counts.reserve(count);
        flags.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
    }

    void append(const basic_block_row_t& row)
    {
        const auto& input = row.input;
        ids.push_back(row.id);
        start_addresses.append(input.start_address);
        end_addresses.append(input.end_address);
        instruction_begins.push_back(input.instruction_begin);
        instruction_counts.push_back(input.instruction_count);
        predecessor_counts.push_back(input.predecessor_count);
        successor_counts.push_back(input.successor_count);
        flags.push_back(input.flags);
        provenances.push_back(input.provenance);
        confidences.push_back(input.confidence);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && start_addresses.valid(count) && end_addresses.valid(count) &&
            instruction_begins.size() == count && instruction_counts.size() == count &&
            predecessor_counts.size() == count && successor_counts.size() == count &&
            flags.size() == count && provenances.size() == count && confidences.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        start_addresses.account(payload, reserved);
        end_addresses.account(payload, reserved);
        add_vector_accounting(instruction_begins, payload, reserved);
        add_vector_accounting(instruction_counts, payload, reserved);
        add_vector_accounting(predecessor_counts, payload, reserved);
        add_vector_accounting(successor_counts, payload, reserved);
        add_vector_accounting(flags, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
    }
};

struct function_columns_t final {
    std::vector<packed_entity_id_t> ids;
    packed_address_columns_t start_addresses;
    packed_address_columns_t end_addresses;
    std::vector<packed_entity_id_t> entry_block_ids;
    std::vector<packed_entity_id_t> symbol_ids;
    std::vector<packed_string_id_t> names;
    std::vector<std::uint16_t> chunk_counts;
    std::vector<std::uint32_t> flags;
    std::vector<std::uint64_t> return_type_ids;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        start_addresses.values.reserve(count);
        start_addresses.metadata.reserve(count);
        end_addresses.values.reserve(count);
        end_addresses.metadata.reserve(count);
        entry_block_ids.reserve(count);
        symbol_ids.reserve(count);
        names.reserve(count);
        chunk_counts.reserve(count);
        flags.reserve(count);
        return_type_ids.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
    }

    void append(const function_row_t& row)
    {
        const auto& input = row.input;
        ids.push_back(row.id);
        start_addresses.append(input.start_address);
        end_addresses.append(input.end_address);
        entry_block_ids.push_back(row.entry_block);
        symbol_ids.push_back(row.symbol);
        names.push_back(row.name);
        chunk_counts.push_back(input.chunk_count);
        flags.push_back(input.flags);
        return_type_ids.push_back(input.return_type_id);
        provenances.push_back(input.provenance);
        confidences.push_back(input.confidence);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && start_addresses.valid(count) && end_addresses.valid(count) &&
            entry_block_ids.size() == count && symbol_ids.size() == count && names.size() == count &&
            chunk_counts.size() == count && flags.size() == count && return_type_ids.size() == count &&
            provenances.size() == count && confidences.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        start_addresses.account(payload, reserved);
        end_addresses.account(payload, reserved);
        add_vector_accounting(entry_block_ids, payload, reserved);
        add_vector_accounting(symbol_ids, payload, reserved);
        add_vector_accounting(names, payload, reserved);
        add_vector_accounting(chunk_counts, payload, reserved);
        add_vector_accounting(flags, payload, reserved);
        add_vector_accounting(return_type_ids, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
    }
};

struct function_chunk_columns_t final {
    std::vector<packed_entity_id_t> ids;
    std::vector<packed_entity_id_t> function_ids;
    packed_address_columns_t start_addresses;
    packed_address_columns_t end_addresses;
    std::vector<std::uint32_t> block_begins;
    std::vector<std::uint16_t> block_counts;
    std::vector<std::uint8_t> flags;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        function_ids.reserve(count);
        start_addresses.values.reserve(count);
        start_addresses.metadata.reserve(count);
        end_addresses.values.reserve(count);
        end_addresses.metadata.reserve(count);
        block_begins.reserve(count);
        block_counts.reserve(count);
        flags.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
    }

    void append(const function_chunk_row_t& row)
    {
        const auto& input = row.input;
        ids.push_back(row.id);
        function_ids.push_back(row.function);
        start_addresses.append(input.start_address);
        end_addresses.append(input.end_address);
        block_begins.push_back(input.block_begin);
        block_counts.push_back(input.block_count);
        flags.push_back(input.flags);
        provenances.push_back(input.provenance);
        confidences.push_back(input.confidence);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && function_ids.size() == count &&
            start_addresses.valid(count) && end_addresses.valid(count) &&
            block_begins.size() == count && block_counts.size() == count &&
            flags.size() == count && provenances.size() == count && confidences.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        add_vector_accounting(function_ids, payload, reserved);
        start_addresses.account(payload, reserved);
        end_addresses.account(payload, reserved);
        add_vector_accounting(block_begins, payload, reserved);
        add_vector_accounting(block_counts, payload, reserved);
        add_vector_accounting(flags, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
    }
};

struct target_fact_columns_t final {
    std::vector<packed_entity_id_t> ids;
    std::vector<packed_entity_id_t> instruction_ids;
    std::vector<packed_entity_id_t> operand_ids;
    std::vector<packed_entity_id_t> address_expression_ids;
    packed_address_columns_t targets;
    std::vector<target_kind_record_t> kinds;
    std::vector<target_resolution_t> resolutions;
    std::vector<std::uint8_t> operand_indices;
    std::vector<std::uint16_t> access_width_bits;
    std::vector<std::uint16_t> access_counts;
    std::vector<std::uint8_t> directs;
    std::vector<std::uint8_t> is_externals;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        instruction_ids.reserve(count);
        operand_ids.reserve(count);
        address_expression_ids.reserve(count);
        targets.values.reserve(count);
        targets.metadata.reserve(count);
        kinds.reserve(count);
        resolutions.reserve(count);
        operand_indices.reserve(count);
        access_width_bits.reserve(count);
        access_counts.reserve(count);
        directs.reserve(count);
        is_externals.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
    }

    void append(const target_fact_row_t& row)
    {
        const auto& input = row.input;
        ids.push_back(row.id);
        instruction_ids.push_back(row.instruction);
        operand_ids.push_back(row.operand);
        address_expression_ids.push_back(row.address_expression);
        targets.append(input.target);
        kinds.push_back(input.kind);
        resolutions.push_back(input.resolution);
        operand_indices.push_back(input.operand_index);
        access_width_bits.push_back(input.access_width_bits);
        access_counts.push_back(input.access_count);
        directs.push_back(input.direct ? 1U : 0U);
        is_externals.push_back(input.is_external ? 1U : 0U);
        provenances.push_back(input.provenance);
        confidences.push_back(input.confidence);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && instruction_ids.size() == count &&
            operand_ids.size() == count && address_expression_ids.size() == count &&
            targets.valid(count) && kinds.size() == count && resolutions.size() == count &&
            operand_indices.size() == count && access_width_bits.size() == count &&
            access_counts.size() == count && directs.size() == count &&
            is_externals.size() == count && provenances.size() == count &&
            confidences.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        add_vector_accounting(instruction_ids, payload, reserved);
        add_vector_accounting(operand_ids, payload, reserved);
        add_vector_accounting(address_expression_ids, payload, reserved);
        targets.account(payload, reserved);
        add_vector_accounting(kinds, payload, reserved);
        add_vector_accounting(resolutions, payload, reserved);
        add_vector_accounting(operand_indices, payload, reserved);
        add_vector_accounting(access_width_bits, payload, reserved);
        add_vector_accounting(access_counts, payload, reserved);
        add_vector_accounting(directs, payload, reserved);
        add_vector_accounting(is_externals, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
    }
};

struct xref_columns_t final {
    std::vector<packed_entity_id_t> ids;
    std::vector<packed_entity_id_t> source_entities;
    std::vector<packed_entity_id_t> target_entities;
    packed_address_columns_t source_addresses;
    packed_address_columns_t target_addresses;
    std::vector<xref_kind_t> kinds;
    std::vector<std::uint8_t> directs;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        source_entities.reserve(count);
        target_entities.reserve(count);
        source_addresses.values.reserve(count);
        source_addresses.metadata.reserve(count);
        target_addresses.values.reserve(count);
        target_addresses.metadata.reserve(count);
        kinds.reserve(count);
        directs.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
    }

    void append(const xref_row_t& row)
    {
        const auto& input = row.input;
        ids.push_back(row.id);
        source_entities.push_back(row.source_entity);
        target_entities.push_back(row.target_entity);
        source_addresses.append(input.source_address);
        target_addresses.append(input.target_address);
        kinds.push_back(input.kind);
        directs.push_back(input.is_direct ? 1U : 0U);
        provenances.push_back(input.provenance);
        confidences.push_back(input.confidence);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && source_entities.size() == count &&
            target_entities.size() == count && source_addresses.valid(count) &&
            target_addresses.valid(count) && kinds.size() == count && directs.size() == count &&
            provenances.size() == count && confidences.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        add_vector_accounting(source_entities, payload, reserved);
        add_vector_accounting(target_entities, payload, reserved);
        source_addresses.account(payload, reserved);
        target_addresses.account(payload, reserved);
        add_vector_accounting(kinds, payload, reserved);
        add_vector_accounting(directs, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
    }
};

struct coverage_columns_t final {
    std::vector<packed_entity_id_t> ids;
    packed_address_columns_t span_begins;
    packed_address_columns_t span_ends;
    std::vector<coverage_reason_t> reasons;
    std::vector<std::uint32_t> undecodable_counts;
    std::vector<fact_provenance_t> provenances;
    std::vector<std::uint8_t> confidences;

    void reserve(std::size_t count)
    {
        ids.reserve(count);
        span_begins.values.reserve(count);
        span_begins.metadata.reserve(count);
        span_ends.values.reserve(count);
        span_ends.metadata.reserve(count);
        reasons.reserve(count);
        undecodable_counts.reserve(count);
        provenances.reserve(count);
        confidences.reserve(count);
    }

    void append(const coverage_row_t& row)
    {
        const auto& input = row.input;
        ids.push_back(row.id);
        span_begins.append(input.span_begin);
        span_ends.append(input.span_end);
        reasons.push_back(input.reason);
        undecodable_counts.push_back(input.undecodable_count);
        provenances.push_back(input.provenance);
        confidences.push_back(input.confidence);
    }

    bool valid(std::size_t count) const noexcept
    {
        return ids.size() == count && span_begins.valid(count) && span_ends.valid(count) &&
            reasons.size() == count && undecodable_counts.size() == count &&
            provenances.size() == count && confidences.size() == count;
    }

    void account(std::uint64_t& payload, std::uint64_t& reserved) const noexcept
    {
        add_vector_accounting(ids, payload, reserved);
        span_begins.account(payload, reserved);
        span_ends.account(payload, reserved);
        add_vector_accounting(reasons, payload, reserved);
        add_vector_accounting(undecodable_counts, payload, reserved);
        add_vector_accounting(provenances, payload, reserved);
        add_vector_accounting(confidences, payload, reserved);
    }
};

packed_store_result_t<packed_entity_id_t>
resolve_reference(const packed_entity_reference_t& reference, std::uint16_t local_shard,
                  std::string_view phase) noexcept
{
    if (reference.empty())
        return packed_store_result_t<packed_entity_id_t>::success(packed_entity_id_t{});
    if (!valid_domain(reference.domain) || reference.source_id == 0) {
        return packed_store_result_t<packed_entity_id_t>::failure(make_error(
            packed_store_error_code_t::invalid_entity_reference, phase, local_shard,
            reference.source_id));
    }
    const auto resolved = packed_entity_id_t::make(
        reference.domain, reference.use_local_shard ? local_shard : reference.shard,
        reference.source_id);
    if (!resolved)
        return packed_store_result_t<packed_entity_id_t>::failure(resolved.error());
    return packed_store_result_t<packed_entity_id_t>::success(resolved.value());
}

packed_store_result_t<void> validate_instruction_input(const packed_instruction_input_t& input,
                                                       std::uint16_t shard) noexcept
{
    if (!valid_address(input.address) || !valid_provenance(input.provenance) ||
        !valid_coverage(input.coverage)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "instruction", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void> validate_operand_input(const packed_operand_input_t& input,
                                                   std::uint16_t shard) noexcept
{
    if (input.instruction.empty() || input.instruction.domain != packed_entity_domain_t::instruction ||
        (!input.address_expression.empty() &&
         input.address_expression.domain != packed_entity_domain_t::address_expression) ||
        !valid_operand_kind(input.kind) || !valid_expression_kind(input.address_expression_kind) ||
        !valid_resolution(input.address_resolution)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "operand", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void> validate_edge_input(const packed_edge_input_t& input,
                                                std::uint16_t shard) noexcept
{
    if (input.source_entity.empty() ||
        (input.target_entity.has_value() && input.target_entity->empty()) ||
        !valid_address(input.source) || !valid_address(input.target) || !valid_edge_kind(input.kind) ||
        !valid_provenance(input.provenance)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "edge", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void> validate_string_input(const packed_string_input_t& input,
                                                  std::uint16_t shard) noexcept
{
    if (!valid_address(input.address) || !valid_string_encoding(input.encoding) ||
        !valid_provenance(input.provenance)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "string", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void> validate_symbol_input(const packed_symbol_input_t& input,
                                                   std::uint16_t shard) noexcept
{
    if (!valid_address(input.address) || !valid_symbol_kind(input.kind) ||
        !valid_provenance(input.provenance)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "symbol", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
validate_address_expression_input(const packed_address_expression_input_t& input,
                                  std::uint16_t shard) noexcept
{
    if (!valid_expression_kind(input.kind) || !valid_resolution(input.resolution) ||
        !valid_provenance(input.provenance)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "address_expression", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
validate_basic_block_input(const packed_basic_block_input_t& input, std::uint16_t shard) noexcept
{
    if (!valid_address(input.start_address) || !valid_address(input.end_address) ||
        !valid_provenance(input.provenance)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "basic_block", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
validate_function_input(const packed_function_input_t& input, std::uint16_t shard) noexcept
{
    if (!valid_address(input.start_address) || !valid_address(input.end_address) ||
        !valid_provenance(input.provenance)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "function", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
validate_function_chunk_input(const packed_function_chunk_input_t& input,
                              std::uint16_t shard) noexcept
{
    if (input.function.empty() || input.function.domain != packed_entity_domain_t::function ||
        !valid_address(input.start_address) || !valid_address(input.end_address) ||
        !valid_provenance(input.provenance)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "function_chunk", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
validate_target_fact_input(const packed_target_fact_input_t& input,
                           std::uint16_t shard) noexcept
{
    if (!valid_address(input.target) || !valid_target_kind(input.kind) ||
        !valid_resolution(input.resolution) || !valid_provenance(input.provenance)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "target_fact", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
validate_xref_input(const packed_xref_input_t& input, std::uint16_t shard) noexcept
{
    if (!valid_address(input.source_address) || !valid_address(input.target_address) ||
        !valid_xref_kind(input.kind) || !valid_provenance(input.provenance)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "xref", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
validate_coverage_input(const packed_coverage_input_t& input, std::uint16_t shard) noexcept
{
    if (!valid_address(input.span_begin) || !valid_address(input.span_end) ||
        !valid_coverage(input.reason) || !valid_provenance(input.provenance)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_row, "coverage", shard, input.source_id));
    }
    return packed_store_result_t<void>::success();
}

template <typename set_t>
packed_store_result_t<void> validate_primary(const set_t& sources, entity_id_t source_id,
                                             packed_entity_domain_t domain, std::uint16_t shard,
                                             std::string_view phase) noexcept
{
    const auto packed = packed_entity_id_t::make(domain, shard, source_id);
    if (!packed)
        return packed_store_result_t<void>::failure(packed.error());
    if (sources.find(source_id) != sources.end()) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::duplicate_source_id, phase, shard, source_id));
    }
    return packed_store_result_t<void>::success();
}

template <typename set_t>
void insert_primary(set_t& sources, entity_id_t source_id)
{
    sources.insert(source_id);
}

template <typename row_t>
bool id_less(const row_t& left, const row_t& right) noexcept
{
    return left.id < right.id;
}

template <typename row_t>
packed_store_result_t<void> ensure_count(std::size_t count, std::string_view phase) noexcept
{
    if (count > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)())) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::arithmetic_overflow, phase, 0, 0,
            (std::numeric_limits<std::uint32_t>::max)(), count));
    }
    return packed_store_result_t<void>::success();
}

const packed_string_pool_t& empty_string_pool() noexcept
{
    static const packed_string_pool_t empty;
    return empty;
}

}

struct packed_analysis_shard_t::impl_t final {
    std::uint16_t shard = 0;
    packed_string_pool_t strings;
    std::vector<instruction_draft_t> instructions;
    std::vector<packed_operand_input_t> operands;
    std::vector<packed_edge_input_t> edges;
    std::vector<string_draft_t> string_records;
    std::vector<symbol_draft_t> symbols;
    std::vector<packed_address_expression_input_t> address_expressions;
    std::vector<packed_basic_block_input_t> basic_blocks;
    std::vector<function_draft_t> functions;
    std::vector<packed_function_chunk_input_t> function_chunks;
    std::vector<packed_target_fact_input_t> target_facts;
    std::vector<packed_xref_input_t> xrefs;
    std::vector<packed_coverage_input_t> coverage_spans;
};

struct packed_analysis_shard_builder_t::impl_t final {
    explicit impl_t(std::uint16_t value) : shard(value) {}

    std::uint16_t shard = 0;
    bool finalized = false;
    packed_string_pool_builder_t strings;
    std::unordered_set<entity_id_t> instruction_sources;
    std::unordered_set<entity_id_t> operand_sources;
    std::unordered_set<entity_id_t> edge_sources;
    std::unordered_set<entity_id_t> string_sources;
    std::unordered_set<entity_id_t> symbol_sources;
    std::unordered_set<entity_id_t> address_expression_sources;
    std::unordered_set<entity_id_t> basic_block_sources;
    std::unordered_set<entity_id_t> function_sources;
    std::unordered_set<entity_id_t> function_chunk_sources;
    std::unordered_set<entity_id_t> target_fact_sources;
    std::unordered_set<entity_id_t> xref_sources;
    std::unordered_set<entity_id_t> coverage_sources;
    std::vector<instruction_draft_t> instructions;
    std::vector<packed_operand_input_t> operands;
    std::vector<packed_edge_input_t> edges;
    std::vector<string_draft_t> string_records;
    std::vector<symbol_draft_t> symbols;
    std::vector<packed_address_expression_input_t> address_expressions;
    std::vector<packed_basic_block_input_t> basic_blocks;
    std::vector<function_draft_t> functions;
    std::vector<packed_function_chunk_input_t> function_chunks;
    std::vector<packed_target_fact_input_t> target_facts;
    std::vector<packed_xref_input_t> xrefs;
    std::vector<packed_coverage_input_t> coverage_spans;
};

struct packed_analysis_store_t::impl_t final {
    packed_string_pool_t strings;
    instruction_columns_t instructions;
    operand_columns_t operands;
    edge_columns_t edges;
    string_columns_t string_records;
    symbol_columns_t symbols;
    address_expression_columns_t address_expressions;
    basic_block_columns_t basic_blocks;
    function_columns_t functions;
    function_chunk_columns_t function_chunks;
    target_fact_columns_t target_facts;
    xref_columns_t xrefs;
    coverage_columns_t coverage_spans;
};

packed_store_result_t<packed_entity_id_t>
packed_entity_id_t::make(packed_entity_domain_t domain, std::uint16_t shard,
                         std::uint64_t ordinal) noexcept
{
    if (!valid_domain(domain)) {
        return packed_store_result_t<packed_entity_id_t>::failure(make_error(
            packed_store_error_code_t::invalid_entity_domain, "packed_entity_id", shard,
            static_cast<std::uint16_t>(domain)));
    }
    if (ordinal == 0) {
        return packed_store_result_t<packed_entity_id_t>::failure(make_error(
            packed_store_error_code_t::invalid_source_id, "packed_entity_id", shard, ordinal,
            (std::numeric_limits<std::uint32_t>::max)(), ordinal));
    }
    if (ordinal > (std::numeric_limits<std::uint32_t>::max)()) {
        return packed_store_result_t<packed_entity_id_t>::failure(make_error(
            packed_store_error_code_t::arithmetic_overflow, "packed_entity_id", shard, ordinal,
            (std::numeric_limits<std::uint32_t>::max)(), ordinal));
    }
    const auto value = (static_cast<std::uint64_t>(domain) << 48U) |
        (static_cast<std::uint64_t>(shard) << 32U) | ordinal;
    return packed_store_result_t<packed_entity_id_t>::success(packed_entity_id_t(value));
}

packed_address_t packed_address_t::pack(const address_t& address) noexcept
{
    const auto metadata = static_cast<std::uint32_t>(address.space) |
        (static_cast<std::uint32_t>(address.architecture) << 8U) |
        (static_cast<std::uint32_t>(address.mode) << 16U);
    return packed_address_t{address.value, metadata};
}

address_t packed_address_t::unpack() const noexcept
{
    address_t address;
    address.value = value;
    address.space = static_cast<address_space_id_t>(metadata & 0xffU);
    address.architecture = static_cast<architecture_id_t>((metadata >> 8U) & 0xffU);
    address.mode = static_cast<architecture_mode_t>((metadata >> 16U) & 0xffU);
    return address;
}

packed_analysis_shard_t::packed_analysis_shard_t(std::unique_ptr<impl_t> impl) noexcept
    : impl_(std::move(impl))
{
}

packed_analysis_shard_t::packed_analysis_shard_t(packed_analysis_shard_t&&) noexcept = default;
packed_analysis_shard_t& packed_analysis_shard_t::operator=(packed_analysis_shard_t&&) noexcept = default;
packed_analysis_shard_t::~packed_analysis_shard_t() = default;

bool packed_analysis_shard_t::valid() const noexcept
{
    return static_cast<bool>(impl_);
}

std::uint16_t packed_analysis_shard_t::shard_id() const noexcept
{
    return impl_ ? impl_->shard : 0;
}

std::uint32_t packed_analysis_shard_t::local_string_count() const noexcept
{
    return impl_ ? impl_->strings.size() : 0;
}

std::uint32_t packed_analysis_shard_t::instruction_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->instructions.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::operand_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->operands.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::edge_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->edges.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::string_record_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->string_records.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::symbol_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->symbols.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::address_expression_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->address_expressions.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::basic_block_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->basic_blocks.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::function_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->functions.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::function_chunk_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->function_chunks.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::target_fact_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->target_facts.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::xref_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->xrefs.size()) : 0;
}

std::uint32_t packed_analysis_shard_t::coverage_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->coverage_spans.size()) : 0;
}

const packed_string_pool_t& packed_analysis_shard_t::string_pool() const noexcept
{
    return impl_ ? impl_->strings : empty_string_pool();
}

packed_size_accounting_t packed_analysis_shard_t::size_accounting() const noexcept
{
    if (!impl_)
        return {};
    const auto string_size = impl_->strings.size_accounting();
    std::uint64_t instruction_payload = 0;
    std::uint64_t instruction_reserved = 0;
    std::uint64_t operand_payload = 0;
    std::uint64_t operand_reserved = 0;
    std::uint64_t edge_payload = 0;
    std::uint64_t edge_reserved = 0;
    std::uint64_t string_payload = 0;
    std::uint64_t string_reserved = 0;
    std::uint64_t symbol_payload = 0;
    std::uint64_t symbol_reserved = 0;
    std::uint64_t address_expression_payload = 0;
    std::uint64_t address_expression_reserved = 0;
    std::uint64_t basic_block_payload = 0;
    std::uint64_t basic_block_reserved = 0;
    std::uint64_t function_payload = 0;
    std::uint64_t function_reserved = 0;
    std::uint64_t function_chunk_payload = 0;
    std::uint64_t function_chunk_reserved = 0;
    std::uint64_t target_fact_payload = 0;
    std::uint64_t target_fact_reserved = 0;
    std::uint64_t xref_payload = 0;
    std::uint64_t xref_reserved = 0;
    std::uint64_t coverage_payload = 0;
    std::uint64_t coverage_reserved = 0;
    add_vector_accounting(impl_->instructions, instruction_payload, instruction_reserved);
    add_vector_accounting(impl_->operands, operand_payload, operand_reserved);
    add_vector_accounting(impl_->edges, edge_payload, edge_reserved);
    add_vector_accounting(impl_->string_records, string_payload, string_reserved);
    add_vector_accounting(impl_->symbols, symbol_payload, symbol_reserved);
    add_vector_accounting(impl_->address_expressions, address_expression_payload,
                          address_expression_reserved);
    add_vector_accounting(impl_->basic_blocks, basic_block_payload, basic_block_reserved);
    add_vector_accounting(impl_->functions, function_payload, function_reserved);
    add_vector_accounting(impl_->function_chunks, function_chunk_payload,
                          function_chunk_reserved);
    add_vector_accounting(impl_->target_facts, target_fact_payload, target_fact_reserved);
    add_vector_accounting(impl_->xrefs, xref_payload, xref_reserved);
    add_vector_accounting(impl_->coverage_spans, coverage_payload, coverage_reserved);
    const auto payload = string_size.payload_bytes + instruction_payload + operand_payload +
        edge_payload + string_payload + symbol_payload + address_expression_payload +
        basic_block_payload + function_payload + function_chunk_payload + target_fact_payload +
        xref_payload + coverage_payload;
    const auto reserved = string_size.reserved_bytes + instruction_reserved + operand_reserved +
        edge_reserved + string_reserved + symbol_reserved + address_expression_reserved +
        basic_block_reserved + function_reserved + function_chunk_reserved +
        target_fact_reserved + xref_reserved + coverage_reserved;
    return packed_size_accounting_t{string_size.payload_bytes, instruction_payload,
                                    operand_payload, edge_payload, string_payload, symbol_payload,
                                    address_expression_payload, basic_block_payload,
                                    function_payload, function_chunk_payload, target_fact_payload,
                                    xref_payload, coverage_payload, payload, reserved};
}

packed_store_result_t<void> packed_analysis_shard_t::validate() const
{
    if (!impl_) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_shard, "shard"));
    }
    const auto& data = *impl_;
    const auto valid_pool = data.strings.validate();
    if (!valid_pool) {
        auto error = valid_pool.error();
        error.shard = data.shard;
        return packed_store_result_t<void>::failure(error);
    }
    for (std::size_t index = 0; index < data.strings.size(); ++index) {
        const auto id = packed_string_id_t::from_value(static_cast<std::uint32_t>(index + 1U));
        if (!data.strings.lookup(id)) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_string_pool, "shard", data.shard,
                id.value()));
        }
    }
    const auto translate_string = [&](packed_string_id_t local,
                                      bool required) -> packed_store_result_t<void> {
        if (!local.valid()) {
            if (required) {
                return packed_store_result_t<void>::failure(make_error(
                    packed_store_error_code_t::invalid_string_id, "shard", data.shard,
                    local.value()));
            }
            return packed_store_result_t<void>::success();
        }
        if (!data.strings.lookup(local)) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_string_id, "shard", data.shard,
                local.value()));
        }
        return packed_store_result_t<void>::success();
    };

    const auto valid_instruction_count =
        ensure_count<instruction_row_t>(data.instructions.size(), "instruction");
    if (!valid_instruction_count)
        return valid_instruction_count;
    const auto valid_operand_count =
        ensure_count<operand_row_t>(data.operands.size(), "operand");
    if (!valid_operand_count)
        return valid_operand_count;
    const auto valid_edge_count = ensure_count<edge_row_t>(data.edges.size(), "edge");
    if (!valid_edge_count)
        return valid_edge_count;
    const auto valid_string_count =
        ensure_count<string_row_t>(data.string_records.size(), "string");
    if (!valid_string_count)
        return valid_string_count;
    const auto valid_symbol_count = ensure_count<symbol_row_t>(data.symbols.size(), "symbol");
    if (!valid_symbol_count)
        return valid_symbol_count;
    const auto valid_address_expression_count = ensure_count<address_expression_row_t>(
        data.address_expressions.size(), "address_expression");
    if (!valid_address_expression_count)
        return valid_address_expression_count;
    const auto valid_basic_block_count =
        ensure_count<basic_block_row_t>(data.basic_blocks.size(), "basic_block");
    if (!valid_basic_block_count)
        return valid_basic_block_count;
    const auto valid_function_count =
        ensure_count<function_row_t>(data.functions.size(), "function");
    if (!valid_function_count)
        return valid_function_count;
    const auto valid_function_chunk_count =
        ensure_count<function_chunk_row_t>(data.function_chunks.size(), "function_chunk");
    if (!valid_function_chunk_count)
        return valid_function_chunk_count;
    const auto valid_target_fact_count =
        ensure_count<target_fact_row_t>(data.target_facts.size(), "target_fact");
    if (!valid_target_fact_count)
        return valid_target_fact_count;
    const auto valid_xref_count = ensure_count<xref_row_t>(data.xrefs.size(), "xref");
    if (!valid_xref_count)
        return valid_xref_count;
    const auto valid_coverage_count =
        ensure_count<coverage_row_t>(data.coverage_spans.size(), "coverage");
    if (!valid_coverage_count)
        return valid_coverage_count;

    std::unordered_set<entity_id_t> instruction_sources;
    instruction_sources.reserve(data.instructions.size());
    for (const auto& draft : data.instructions) {
        const auto valid_input = validate_instruction_input(draft.input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::instruction,
                                                 data.shard, draft.input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!instruction_sources.insert(draft.input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "instruction", data.shard,
                id.value().value()));
        }
        const auto mnemonic = translate_string(draft.mnemonic, false);
        if (!mnemonic)
            return mnemonic;
    }
    std::unordered_set<entity_id_t> operand_sources;
    operand_sources.reserve(data.operands.size());
    for (const auto& input : data.operands) {
        const auto valid_input = validate_operand_input(input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::operand,
                                                 data.shard, input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!operand_sources.insert(input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "operand", data.shard,
                id.value().value()));
        }
        const auto instruction = resolve_reference(input.instruction, data.shard, "operand");
        if (!instruction)
            return packed_store_result_t<void>::failure(instruction.error());
        const auto expression =
            resolve_reference(input.address_expression, data.shard, "operand");
        if (!expression)
            return packed_store_result_t<void>::failure(expression.error());
    }
    std::unordered_set<entity_id_t> edge_sources;
    edge_sources.reserve(data.edges.size());
    for (const auto& input : data.edges) {
        const auto valid_input = validate_edge_input(input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::edge,
                                                 data.shard, input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!edge_sources.insert(input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "edge", data.shard,
                id.value().value()));
        }
        const auto source = resolve_reference(input.source_entity, data.shard, "edge");
        if (!source)
            return packed_store_result_t<void>::failure(source.error());
        if (input.target_entity.has_value()) {
            const auto resolved = resolve_reference(*input.target_entity, data.shard, "edge");
            if (!resolved)
                return packed_store_result_t<void>::failure(resolved.error());
        }
    }
    std::unordered_set<entity_id_t> string_sources;
    string_sources.reserve(data.string_records.size());
    for (const auto& draft : data.string_records) {
        const auto valid_input = validate_string_input(draft.input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::string,
                                                 data.shard, draft.input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!string_sources.insert(draft.input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "string", data.shard,
                id.value().value()));
        }
        const auto value = translate_string(draft.value, true);
        if (!value)
            return value;
    }
    std::unordered_set<entity_id_t> symbol_sources;
    symbol_sources.reserve(data.symbols.size());
    for (const auto& draft : data.symbols) {
        const auto valid_input = validate_symbol_input(draft.input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::symbol,
                                                 data.shard, draft.input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!symbol_sources.insert(draft.input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "symbol", data.shard,
                id.value().value()));
        }
        const auto name = translate_string(draft.name, true);
        if (!name)
            return name;
    }
    std::unordered_set<entity_id_t> address_expression_sources;
    address_expression_sources.reserve(data.address_expressions.size());
    for (const auto& input : data.address_expressions) {
        const auto valid_input = validate_address_expression_input(input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::address_expression,
                                                 data.shard, input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!address_expression_sources.insert(input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "address_expression",
                data.shard, id.value().value()));
        }
        const auto instruction =
            resolve_reference(input.instruction, data.shard, "address_expression");
        if (!instruction)
            return packed_store_result_t<void>::failure(instruction.error());
    }
    std::unordered_set<entity_id_t> basic_block_sources;
    basic_block_sources.reserve(data.basic_blocks.size());
    for (const auto& input : data.basic_blocks) {
        const auto valid_input = validate_basic_block_input(input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::basic_block,
                                                 data.shard, input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!basic_block_sources.insert(input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "basic_block", data.shard,
                id.value().value()));
        }
    }
    std::unordered_set<entity_id_t> function_sources;
    function_sources.reserve(data.functions.size());
    for (const auto& draft : data.functions) {
        const auto valid_input = validate_function_input(draft.input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::function,
                                                 data.shard, draft.input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!function_sources.insert(draft.input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "function", data.shard,
                id.value().value()));
        }
        const auto name = translate_string(draft.name, false);
        if (!name)
            return name;
        const auto entry_block =
            resolve_reference(draft.input.entry_block, data.shard, "function");
        if (!entry_block)
            return packed_store_result_t<void>::failure(entry_block.error());
        const auto symbol = resolve_reference(draft.input.symbol, data.shard, "function");
        if (!symbol)
            return packed_store_result_t<void>::failure(symbol.error());
    }
    std::unordered_set<entity_id_t> function_chunk_sources;
    function_chunk_sources.reserve(data.function_chunks.size());
    for (const auto& input : data.function_chunks) {
        const auto valid_input = validate_function_chunk_input(input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::function_chunk,
                                                 data.shard, input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!function_chunk_sources.insert(input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "function_chunk", data.shard,
                id.value().value()));
        }
        const auto function = resolve_reference(input.function, data.shard, "function_chunk");
        if (!function)
            return packed_store_result_t<void>::failure(function.error());
    }
    std::unordered_set<entity_id_t> target_fact_sources;
    target_fact_sources.reserve(data.target_facts.size());
    for (const auto& input : data.target_facts) {
        const auto valid_input = validate_target_fact_input(input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::target_fact,
                                                 data.shard, input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!target_fact_sources.insert(input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "target_fact", data.shard,
                id.value().value()));
        }
        const auto instruction = resolve_reference(input.instruction, data.shard, "target_fact");
        if (!instruction)
            return packed_store_result_t<void>::failure(instruction.error());
        const auto operand = resolve_reference(input.operand, data.shard, "target_fact");
        if (!operand)
            return packed_store_result_t<void>::failure(operand.error());
        const auto expression =
            resolve_reference(input.address_expression, data.shard, "target_fact");
        if (!expression)
            return packed_store_result_t<void>::failure(expression.error());
    }
    std::unordered_set<entity_id_t> xref_sources;
    xref_sources.reserve(data.xrefs.size());
    for (const auto& input : data.xrefs) {
        const auto valid_input = validate_xref_input(input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::xref,
                                                 data.shard, input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!xref_sources.insert(input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "xref", data.shard,
                id.value().value()));
        }
        const auto source = resolve_reference(input.source_entity, data.shard, "xref");
        if (!source)
            return packed_store_result_t<void>::failure(source.error());
        const auto target = resolve_reference(input.target_entity, data.shard, "xref");
        if (!target)
            return packed_store_result_t<void>::failure(target.error());
    }
    std::unordered_set<entity_id_t> coverage_sources;
    coverage_sources.reserve(data.coverage_spans.size());
    for (const auto& input : data.coverage_spans) {
        const auto valid_input = validate_coverage_input(input, data.shard);
        if (!valid_input)
            return valid_input;
        const auto id = packed_entity_id_t::make(packed_entity_domain_t::coverage,
                                                 data.shard, input.source_id);
        if (!id)
            return packed_store_result_t<void>::failure(id.error());
        if (!coverage_sources.insert(input.source_id).second) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::duplicate_packed_id, "coverage", data.shard,
                id.value().value()));
        }
    }
    return packed_store_result_t<void>::success();
}

void packed_analysis_shard_t::release() noexcept
{
    impl_.reset();
}

namespace {

std::optional<packed_entity_id_t> shard_row_id(packed_entity_domain_t domain,
                                               std::uint16_t shard,
                                               entity_id_t source_id) noexcept
{
    const auto id = packed_entity_id_t::make(domain, shard, source_id);
    if (!id)
        return std::nullopt;
    return id.value();
}

}

std::optional<packed_instruction_view_t>
packed_analysis_shard_t::instruction(std::size_t index) const
{
    if (!impl_ || index >= impl_->instructions.size())
        return std::nullopt;
    const auto& draft = impl_->instructions[index];
    const auto id = shard_row_id(packed_entity_domain_t::instruction, impl_->shard,
                                 draft.input.source_id);
    if (!id)
        return std::nullopt;
    std::string_view mnemonic;
    if (draft.mnemonic.valid()) {
        const auto value = impl_->strings.lookup(draft.mnemonic);
        if (!value)
            return std::nullopt;
        mnemonic = *value;
    }
    return packed_instruction_view_t{*id, draft.input.address, draft.input.length,
                                     draft.input.mnemonic_id, mnemonic, draft.input.opcode_id,
                                     draft.input.flow_flags, 0, 0, draft.input.provenance,
                                     draft.input.confidence, draft.input.coverage,
                                     draft.input.stable_source_id};
}

std::optional<packed_operand_view_t> packed_analysis_shard_t::operand(std::size_t index) const
{
    if (!impl_ || index >= impl_->operands.size())
        return std::nullopt;
    const auto& input = impl_->operands[index];
    const auto id = shard_row_id(packed_entity_domain_t::operand, impl_->shard, input.source_id);
    const auto instruction = resolve_reference(input.instruction, impl_->shard, "operand");
    const auto expression = resolve_reference(input.address_expression, impl_->shard, "operand");
    if (!id || !instruction || !expression)
        return std::nullopt;
    return packed_operand_view_t{*id, instruction.value(), expression.value(),
                                 input.operand_index, input.decoder_operand_id, input.kind,
                                 input.access, input.visibility, input.encoding,
                                 input.memory_type, input.access_width, input.bit_width,
                                 input.access_width_bits, input.access_count,
                                 input.element_width_bits, input.element_count,
                                 input.address_width_bits, input.reg, input.segment_reg,
                                 input.base_reg, input.index_reg, input.scale, input.relative,
                                 input.signed_value, input.has_displacement,
                                 input.has_resolved_expression_value, input.displacement,
                                 input.immediate, input.resolved_expression_value,
                                 input.address_components, input.address_expression_kind,
                                 input.address_resolution};
}

std::optional<packed_edge_view_t> packed_analysis_shard_t::edge(std::size_t index) const
{
    if (!impl_ || index >= impl_->edges.size())
        return std::nullopt;
    const auto& input = impl_->edges[index];
    const auto id = shard_row_id(packed_entity_domain_t::edge, impl_->shard, input.source_id);
    const auto source = resolve_reference(input.source_entity, impl_->shard, "edge");
    if (!id || !source)
        return std::nullopt;
    std::optional<packed_entity_id_t> target_entity;
    if (input.target_entity.has_value()) {
        const auto resolved = resolve_reference(*input.target_entity, impl_->shard, "edge");
        if (!resolved)
            return std::nullopt;
        target_entity = resolved.value();
    }
    return packed_edge_view_t{*id, source.value(), target_entity, input.source, input.target,
                              input.kind, input.provenance, input.confidence};
}

std::optional<packed_string_view_t> packed_analysis_shard_t::string(std::size_t index) const
{
    if (!impl_ || index >= impl_->string_records.size())
        return std::nullopt;
    const auto& draft = impl_->string_records[index];
    const auto id = shard_row_id(packed_entity_domain_t::string, impl_->shard,
                                 draft.input.source_id);
    if (!id)
        return std::nullopt;
    const auto value = impl_->strings.lookup(draft.value);
    if (!value)
        return std::nullopt;
    return packed_string_view_t{*id, draft.input.address, draft.input.byte_length,
                                draft.input.encoding, *value, draft.input.provenance,
                                draft.input.confidence};
}

std::optional<packed_symbol_view_t> packed_analysis_shard_t::symbol(std::size_t index) const
{
    if (!impl_ || index >= impl_->symbols.size())
        return std::nullopt;
    const auto& draft = impl_->symbols[index];
    const auto id = shard_row_id(packed_entity_domain_t::symbol, impl_->shard,
                                 draft.input.source_id);
    if (!id)
        return std::nullopt;
    const auto name = impl_->strings.lookup(draft.name);
    if (!name)
        return std::nullopt;
    return packed_symbol_view_t{*id, draft.input.address, *name, draft.input.kind,
                                draft.input.provenance, draft.input.confidence};
}

std::optional<packed_address_expression_view_t>
packed_analysis_shard_t::address_expression(std::size_t index) const
{
    if (!impl_ || index >= impl_->address_expressions.size())
        return std::nullopt;
    const auto& input = impl_->address_expressions[index];
    const auto id = shard_row_id(packed_entity_domain_t::address_expression, impl_->shard,
                                 input.source_id);
    const auto instruction =
        resolve_reference(input.instruction, impl_->shard, "address_expression");
    if (!id || !instruction)
        return std::nullopt;
    return packed_address_expression_view_t{*id, instruction.value(), input.base_reg,
                                            input.index_reg, input.scale, input.displacement,
                                            input.segment_reg, input.address_components,
                                            input.kind, input.resolution, input.provenance,
                                            input.confidence};
}

std::optional<packed_basic_block_view_t>
packed_analysis_shard_t::basic_block(std::size_t index) const
{
    if (!impl_ || index >= impl_->basic_blocks.size())
        return std::nullopt;
    const auto& input = impl_->basic_blocks[index];
    const auto id = shard_row_id(packed_entity_domain_t::basic_block, impl_->shard,
                                 input.source_id);
    if (!id)
        return std::nullopt;
    return packed_basic_block_view_t{*id, input.start_address, input.end_address,
                                     input.instruction_begin, input.instruction_count,
                                     input.predecessor_count, input.successor_count, input.flags,
                                     input.provenance, input.confidence};
}

std::optional<packed_function_view_t> packed_analysis_shard_t::function(std::size_t index) const
{
    if (!impl_ || index >= impl_->functions.size())
        return std::nullopt;
    const auto& draft = impl_->functions[index];
    const auto id = shard_row_id(packed_entity_domain_t::function, impl_->shard,
                                 draft.input.source_id);
    const auto entry_block =
        resolve_reference(draft.input.entry_block, impl_->shard, "function");
    const auto symbol = resolve_reference(draft.input.symbol, impl_->shard, "function");
    if (!id || !entry_block || !symbol)
        return std::nullopt;
    std::string_view name;
    if (draft.name.valid()) {
        const auto value = impl_->strings.lookup(draft.name);
        if (!value)
            return std::nullopt;
        name = *value;
    }
    return packed_function_view_t{*id, draft.input.start_address, draft.input.end_address,
                                  entry_block.value(), symbol.value(), name,
                                  draft.input.chunk_count, draft.input.flags,
                                  draft.input.return_type_id, draft.input.provenance,
                                  draft.input.confidence};
}

std::optional<packed_function_chunk_view_t>
packed_analysis_shard_t::function_chunk(std::size_t index) const
{
    if (!impl_ || index >= impl_->function_chunks.size())
        return std::nullopt;
    const auto& input = impl_->function_chunks[index];
    const auto id = shard_row_id(packed_entity_domain_t::function_chunk, impl_->shard,
                                 input.source_id);
    const auto function = resolve_reference(input.function, impl_->shard, "function_chunk");
    if (!id || !function)
        return std::nullopt;
    return packed_function_chunk_view_t{*id, function.value(), input.start_address,
                                        input.end_address, input.block_begin, input.block_count,
                                        input.flags, input.provenance, input.confidence};
}

std::optional<packed_target_fact_view_t>
packed_analysis_shard_t::target_fact(std::size_t index) const
{
    if (!impl_ || index >= impl_->target_facts.size())
        return std::nullopt;
    const auto& input = impl_->target_facts[index];
    const auto id = shard_row_id(packed_entity_domain_t::target_fact, impl_->shard,
                                 input.source_id);
    const auto instruction = resolve_reference(input.instruction, impl_->shard, "target_fact");
    const auto operand = resolve_reference(input.operand, impl_->shard, "target_fact");
    const auto expression =
        resolve_reference(input.address_expression, impl_->shard, "target_fact");
    if (!id || !instruction || !operand || !expression)
        return std::nullopt;
    return packed_target_fact_view_t{*id, instruction.value(), operand.value(),
                                     expression.value(), input.target, input.kind,
                                     input.resolution, input.operand_index,
                                     input.access_width_bits, input.access_count, input.direct,
                                     input.is_external, input.provenance, input.confidence};
}

std::optional<packed_xref_view_t> packed_analysis_shard_t::xref(std::size_t index) const
{
    if (!impl_ || index >= impl_->xrefs.size())
        return std::nullopt;
    const auto& input = impl_->xrefs[index];
    const auto id = shard_row_id(packed_entity_domain_t::xref, impl_->shard, input.source_id);
    const auto source = resolve_reference(input.source_entity, impl_->shard, "xref");
    const auto target = resolve_reference(input.target_entity, impl_->shard, "xref");
    if (!id || !source || !target)
        return std::nullopt;
    return packed_xref_view_t{*id, source.value(), target.value(), input.source_address,
                              input.target_address, input.kind, input.is_direct,
                              input.provenance, input.confidence};
}

std::optional<packed_coverage_view_t> packed_analysis_shard_t::coverage(std::size_t index) const
{
    if (!impl_ || index >= impl_->coverage_spans.size())
        return std::nullopt;
    const auto& input = impl_->coverage_spans[index];
    const auto id = shard_row_id(packed_entity_domain_t::coverage, impl_->shard,
                                 input.source_id);
    if (!id)
        return std::nullopt;
    return packed_coverage_view_t{*id, input.span_begin, input.span_end, input.reason,
                                  input.undecodable_count, input.provenance, input.confidence};
}

packed_analysis_shard_compatibility_view_t
packed_analysis_shard_t::compatibility_view() const noexcept
{
    return packed_analysis_shard_compatibility_view_t(this);
}


packed_analysis_shard_builder_t::packed_analysis_shard_builder_t(std::uint16_t shard)
    : impl_(std::make_unique<impl_t>(shard))
{
}

packed_analysis_shard_builder_t::packed_analysis_shard_builder_t(
    packed_analysis_shard_builder_t&&) noexcept = default;
packed_analysis_shard_builder_t& packed_analysis_shard_builder_t::operator=(
    packed_analysis_shard_builder_t&&) noexcept = default;
packed_analysis_shard_builder_t::~packed_analysis_shard_builder_t() = default;

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_instruction(const packed_instruction_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "instruction", shard_id()));
    }
    const auto valid_input = validate_instruction_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->instruction_sources, input.source_id,
                                                packed_entity_domain_t::instruction, impl_->shard,
                                                "instruction");
    if (!valid_primary)
        return valid_primary;
    const auto mnemonic = impl_->strings.intern(input.mnemonic);
    if (!mnemonic)
        return packed_store_result_t<void>::failure(mnemonic.error());
    auto stored = input;
    stored.mnemonic = {};
    impl_->instructions.push_back(instruction_draft_t{stored, mnemonic.value()});
    insert_primary(impl_->instruction_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_operand(const packed_operand_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "operand", shard_id()));
    }
    const auto valid_input = validate_operand_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->operand_sources, input.source_id,
                                                packed_entity_domain_t::operand, impl_->shard,
                                                "operand");
    if (!valid_primary)
        return valid_primary;
    impl_->operands.push_back(input);
    insert_primary(impl_->operand_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_edge(const packed_edge_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "edge", shard_id()));
    }
    const auto valid_input = validate_edge_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->edge_sources, input.source_id,
                                                packed_entity_domain_t::edge, impl_->shard, "edge");
    if (!valid_primary)
        return valid_primary;
    impl_->edges.push_back(input);
    insert_primary(impl_->edge_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_string(const packed_string_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "string", shard_id()));
    }
    const auto valid_input = validate_string_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->string_sources, input.source_id,
                                                packed_entity_domain_t::string, impl_->shard,
                                                "string");
    if (!valid_primary)
        return valid_primary;
    const auto value = impl_->strings.intern(input.value);
    if (!value)
        return packed_store_result_t<void>::failure(value.error());
    auto stored = input;
    stored.value = {};
    impl_->string_records.push_back(string_draft_t{stored, value.value()});
    insert_primary(impl_->string_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_symbol(const packed_symbol_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "symbol", shard_id()));
    }
    const auto valid_input = validate_symbol_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->symbol_sources, input.source_id,
                                                packed_entity_domain_t::symbol, impl_->shard,
                                                "symbol");
    if (!valid_primary)
        return valid_primary;
    const auto name = impl_->strings.intern(input.name);
    if (!name)
        return packed_store_result_t<void>::failure(name.error());
    auto stored = input;
    stored.name = {};
    impl_->symbols.push_back(symbol_draft_t{stored, name.value()});
    insert_primary(impl_->symbol_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_address_expression(const packed_address_expression_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "address_expression", shard_id()));
    }
    const auto valid_input = validate_address_expression_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->address_expression_sources, input.source_id,
                                                 packed_entity_domain_t::address_expression,
                                                 impl_->shard, "address_expression");
    if (!valid_primary)
        return valid_primary;
    impl_->address_expressions.push_back(input);
    insert_primary(impl_->address_expression_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_basic_block(const packed_basic_block_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "basic_block", shard_id()));
    }
    const auto valid_input = validate_basic_block_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->basic_block_sources, input.source_id,
                                                 packed_entity_domain_t::basic_block,
                                                 impl_->shard, "basic_block");
    if (!valid_primary)
        return valid_primary;
    impl_->basic_blocks.push_back(input);
    insert_primary(impl_->basic_block_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_function(const packed_function_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "function", shard_id()));
    }
    const auto valid_input = validate_function_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->function_sources, input.source_id,
                                                 packed_entity_domain_t::function, impl_->shard,
                                                 "function");
    if (!valid_primary)
        return valid_primary;
    const auto name = impl_->strings.intern(input.name);
    if (!name)
        return packed_store_result_t<void>::failure(name.error());
    auto stored = input;
    stored.name = {};
    impl_->functions.push_back(function_draft_t{stored, name.value()});
    insert_primary(impl_->function_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_function_chunk(const packed_function_chunk_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "function_chunk", shard_id()));
    }
    const auto valid_input = validate_function_chunk_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->function_chunk_sources, input.source_id,
                                                 packed_entity_domain_t::function_chunk,
                                                 impl_->shard, "function_chunk");
    if (!valid_primary)
        return valid_primary;
    impl_->function_chunks.push_back(input);
    insert_primary(impl_->function_chunk_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_target_fact(const packed_target_fact_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "target_fact", shard_id()));
    }
    const auto valid_input = validate_target_fact_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->target_fact_sources, input.source_id,
                                                 packed_entity_domain_t::target_fact,
                                                 impl_->shard, "target_fact");
    if (!valid_primary)
        return valid_primary;
    impl_->target_facts.push_back(input);
    insert_primary(impl_->target_fact_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_xref(const packed_xref_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "xref", shard_id()));
    }
    const auto valid_input = validate_xref_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->xref_sources, input.source_id,
                                                 packed_entity_domain_t::xref, impl_->shard,
                                                 "xref");
    if (!valid_primary)
        return valid_primary;
    impl_->xrefs.push_back(input);
    insert_primary(impl_->xref_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<void>
packed_analysis_shard_builder_t::add_coverage(const packed_coverage_input_t& input)
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "coverage", shard_id()));
    }
    const auto valid_input = validate_coverage_input(input, impl_->shard);
    if (!valid_input)
        return valid_input;
    const auto valid_primary = validate_primary(impl_->coverage_sources, input.source_id,
                                                 packed_entity_domain_t::coverage,
                                                 impl_->shard, "coverage");
    if (!valid_primary)
        return valid_primary;
    impl_->coverage_spans.push_back(input);
    insert_primary(impl_->coverage_sources, input.source_id);
    return packed_store_result_t<void>::success();
}

packed_store_result_t<packed_analysis_shard_t> packed_analysis_shard_builder_t::finalize() &&
{
    if (!impl_ || impl_->finalized) {
        return packed_store_result_t<packed_analysis_shard_t>::failure(make_error(
            packed_store_error_code_t::builder_finalized, "shard", shard_id()));
    }
    const auto strings = impl_->strings.freeze();
    if (!strings)
        return packed_store_result_t<packed_analysis_shard_t>::failure(strings.error());
    auto shard_impl = std::make_unique<packed_analysis_shard_t::impl_t>();
    shard_impl->shard = impl_->shard;
    shard_impl->strings = strings.value();
    shard_impl->instructions = std::move(impl_->instructions);
    shard_impl->operands = std::move(impl_->operands);
    shard_impl->edges = std::move(impl_->edges);
    shard_impl->string_records = std::move(impl_->string_records);
    shard_impl->symbols = std::move(impl_->symbols);
    shard_impl->address_expressions = std::move(impl_->address_expressions);
    shard_impl->basic_blocks = std::move(impl_->basic_blocks);
    shard_impl->functions = std::move(impl_->functions);
    shard_impl->function_chunks = std::move(impl_->function_chunks);
    shard_impl->target_facts = std::move(impl_->target_facts);
    shard_impl->xrefs = std::move(impl_->xrefs);
    shard_impl->coverage_spans = std::move(impl_->coverage_spans);
    impl_->finalized = true;
    return packed_store_result_t<packed_analysis_shard_t>::success(
        packed_analysis_shard_t(std::move(shard_impl)));
}

void packed_analysis_shard_builder_t::reserve_strings(std::size_t string_estimate)
{
    if (impl_ && !impl_->finalized)
        impl_->strings.reserve(string_estimate);
}

std::uint16_t packed_analysis_shard_builder_t::shard_id() const noexcept
{
    return impl_ ? impl_->shard : 0;
}

bool packed_analysis_shard_builder_t::finalized() const noexcept
{
    return !impl_ || impl_->finalized;
}

packed_analysis_store_t::packed_analysis_store_t(std::unique_ptr<impl_t> impl) noexcept
    : impl_(std::move(impl))
{
}

packed_analysis_store_t::packed_analysis_store_t(packed_analysis_store_t&&) noexcept = default;
packed_analysis_store_t& packed_analysis_store_t::operator=(packed_analysis_store_t&&) noexcept = default;
packed_analysis_store_t::~packed_analysis_store_t() = default;

packed_store_result_t<packed_analysis_store_t>
packed_analysis_store_t::merge(std::vector<packed_analysis_shard_t> shards)
{
    std::unordered_set<std::uint16_t> shard_ids;
    std::vector<std::string> global_strings;
    for (const auto& shard : shards) {
        if (!shard.impl_) {
            return packed_store_result_t<packed_analysis_store_t>::failure(make_error(
                packed_store_error_code_t::invalid_shard, "merge"));
        }
        if (!shard_ids.insert(shard.impl_->shard).second) {
            return packed_store_result_t<packed_analysis_store_t>::failure(make_error(
                packed_store_error_code_t::duplicate_final_mirror, "merge", shard.impl_->shard));
        }
        const auto valid_pool = shard.impl_->strings.validate();
        if (!valid_pool) {
            auto error = valid_pool.error();
            error.shard = shard.impl_->shard;
            return packed_store_result_t<packed_analysis_store_t>::failure(error);
        }
        for (std::size_t index = 0; index < shard.impl_->strings.size(); ++index) {
            const auto id = packed_string_id_t::from_value(static_cast<std::uint32_t>(index + 1U));
            const auto value = shard.impl_->strings.lookup(id);
            if (!value) {
                return packed_store_result_t<packed_analysis_store_t>::failure(make_error(
                    packed_store_error_code_t::invalid_string_pool, "merge", shard.impl_->shard,
                    id.value()));
            }
            global_strings.emplace_back(*value);
        }
    }

    const auto pool = packed_string_pool_t::build_deterministic(std::move(global_strings));
    if (!pool)
        return packed_store_result_t<packed_analysis_store_t>::failure(pool.error());
    std::unordered_map<std::string, packed_string_id_t> global_index;
    global_index.reserve(pool.value().size());
    for (std::size_t index = 0; index < pool.value().size(); ++index) {
        const auto id = packed_string_id_t::from_value(static_cast<std::uint32_t>(index + 1U));
        const auto value = pool.value().lookup(id);
        if (!value) {
            return packed_store_result_t<packed_analysis_store_t>::failure(make_error(
                packed_store_error_code_t::invalid_string_pool, "merge", 0, id.value()));
        }
        global_index.emplace(std::string(*value), id);
    }

    auto translate_string = [&](const packed_analysis_shard_t::impl_t& shard,
                                packed_string_id_t local) -> packed_store_result_t<packed_string_id_t> {
        if (!local.valid())
            return packed_store_result_t<packed_string_id_t>::success(packed_string_id_t{});
        const auto value = shard.strings.lookup(local);
        if (!value) {
            return packed_store_result_t<packed_string_id_t>::failure(make_error(
                packed_store_error_code_t::invalid_string_id, "merge", shard.shard, local.value()));
        }
        const auto found = global_index.find(std::string(*value));
        if (found == global_index.end()) {
            return packed_store_result_t<packed_string_id_t>::failure(make_error(
                packed_store_error_code_t::invalid_string_id, "merge", shard.shard, local.value()));
        }
        return packed_store_result_t<packed_string_id_t>::success(found->second);
    };

    std::vector<instruction_row_t> instructions;
    std::vector<operand_row_t> operands;
    std::vector<edge_row_t> edges;
    std::vector<string_row_t> string_records;
    std::vector<symbol_row_t> symbols;
    std::vector<address_expression_row_t> address_expressions;
    std::vector<basic_block_row_t> basic_blocks;
    std::vector<function_row_t> functions;
    std::vector<function_chunk_row_t> function_chunks;
    std::vector<target_fact_row_t> target_facts;
    std::vector<xref_row_t> xrefs;
    std::vector<coverage_row_t> coverage_spans;
    for (const auto& shard : shards) {
        const auto& data = *shard.impl_;
        for (const auto& draft : data.instructions) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::instruction, data.shard,
                                                      draft.input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            const auto mnemonic = translate_string(data, draft.mnemonic);
            if (!mnemonic)
                return packed_store_result_t<packed_analysis_store_t>::failure(mnemonic.error());
            instructions.push_back(instruction_row_t{id.value(), draft.input, mnemonic.value()});
        }
        for (const auto& input : data.operands) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::operand, data.shard,
                                                      input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            const auto instruction = resolve_reference(input.instruction, data.shard, "operand");
            if (!instruction)
                return packed_store_result_t<packed_analysis_store_t>::failure(instruction.error());
            const auto expression = resolve_reference(input.address_expression, data.shard, "operand");
            if (!expression)
                return packed_store_result_t<packed_analysis_store_t>::failure(expression.error());
            operands.push_back(operand_row_t{id.value(), input, instruction.value(), expression.value()});
        }
        for (const auto& input : data.edges) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::edge, data.shard,
                                                      input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            const auto source = resolve_reference(input.source_entity, data.shard, "edge");
            if (!source)
                return packed_store_result_t<packed_analysis_store_t>::failure(source.error());
            packed_entity_id_t target;
            if (input.target_entity.has_value()) {
                const auto resolved = resolve_reference(*input.target_entity, data.shard, "edge");
                if (!resolved)
                    return packed_store_result_t<packed_analysis_store_t>::failure(resolved.error());
                target = resolved.value();
            }
            edges.push_back(edge_row_t{id.value(), input, source.value(), target});
        }
        for (const auto& draft : data.string_records) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::string, data.shard,
                                                      draft.input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            const auto value = translate_string(data, draft.value);
            if (!value)
                return packed_store_result_t<packed_analysis_store_t>::failure(value.error());
            string_records.push_back(string_row_t{id.value(), draft.input, value.value()});
        }
        for (const auto& draft : data.symbols) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::symbol, data.shard,
                                                      draft.input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            const auto name = translate_string(data, draft.name);
            if (!name)
                return packed_store_result_t<packed_analysis_store_t>::failure(name.error());
            symbols.push_back(symbol_row_t{id.value(), draft.input, name.value()});
        }
        for (const auto& input : data.address_expressions) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::address_expression,
                                                       data.shard, input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            const auto instruction = resolve_reference(input.instruction, data.shard,
                                                        "address_expression");
            if (!instruction)
                return packed_store_result_t<packed_analysis_store_t>::failure(instruction.error());
            address_expressions.push_back(
                address_expression_row_t{id.value(), input, instruction.value()});
        }
        for (const auto& input : data.basic_blocks) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::basic_block,
                                                       data.shard, input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            basic_blocks.push_back(basic_block_row_t{id.value(), input});
        }
        for (const auto& draft : data.functions) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::function,
                                                       data.shard, draft.input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            const auto name = translate_string(data, draft.name);
            if (!name)
                return packed_store_result_t<packed_analysis_store_t>::failure(name.error());
            const auto entry_block = resolve_reference(draft.input.entry_block, data.shard,
                                                        "function");
            if (!entry_block)
                return packed_store_result_t<packed_analysis_store_t>::failure(entry_block.error());
            const auto symbol = resolve_reference(draft.input.symbol, data.shard, "function");
            if (!symbol)
                return packed_store_result_t<packed_analysis_store_t>::failure(symbol.error());
            functions.push_back(function_row_t{id.value(), draft.input, name.value(),
                                                entry_block.value(), symbol.value()});
        }
        for (const auto& input : data.function_chunks) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::function_chunk,
                                                       data.shard, input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            const auto function = resolve_reference(input.function, data.shard, "function_chunk");
            if (!function)
                return packed_store_result_t<packed_analysis_store_t>::failure(function.error());
            function_chunks.push_back(function_chunk_row_t{id.value(), input, function.value()});
        }
        for (const auto& input : data.target_facts) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::target_fact,
                                                       data.shard, input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            const auto instruction = resolve_reference(input.instruction, data.shard,
                                                        "target_fact");
            if (!instruction)
                return packed_store_result_t<packed_analysis_store_t>::failure(instruction.error());
            const auto operand = resolve_reference(input.operand, data.shard, "target_fact");
            if (!operand)
                return packed_store_result_t<packed_analysis_store_t>::failure(operand.error());
            const auto expression = resolve_reference(input.address_expression, data.shard,
                                                        "target_fact");
            if (!expression)
                return packed_store_result_t<packed_analysis_store_t>::failure(expression.error());
            target_facts.push_back(target_fact_row_t{id.value(), input, instruction.value(),
                                                       operand.value(), expression.value()});
        }
        for (const auto& input : data.xrefs) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::xref, data.shard,
                                                       input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            const auto source = resolve_reference(input.source_entity, data.shard, "xref");
            if (!source)
                return packed_store_result_t<packed_analysis_store_t>::failure(source.error());
            const auto target = resolve_reference(input.target_entity, data.shard, "xref");
            if (!target)
                return packed_store_result_t<packed_analysis_store_t>::failure(target.error());
            xrefs.push_back(xref_row_t{id.value(), input, source.value(), target.value()});
        }
        for (const auto& input : data.coverage_spans) {
            const auto id = packed_entity_id_t::make(packed_entity_domain_t::coverage,
                                                       data.shard, input.source_id);
            if (!id)
                return packed_store_result_t<packed_analysis_store_t>::failure(id.error());
            coverage_spans.push_back(coverage_row_t{id.value(), input});
        }
    }

    const auto valid_instruction_count = ensure_count<instruction_row_t>(instructions.size(), "instruction");
    const auto valid_operand_count = ensure_count<operand_row_t>(operands.size(), "operand");
    const auto valid_edge_count = ensure_count<edge_row_t>(edges.size(), "edge");
    const auto valid_string_count = ensure_count<string_row_t>(string_records.size(), "string");
    const auto valid_symbol_count = ensure_count<symbol_row_t>(symbols.size(), "symbol");
    const auto valid_address_expression_count = ensure_count<address_expression_row_t>(
        address_expressions.size(), "address_expression");
    const auto valid_basic_block_count = ensure_count<basic_block_row_t>(
        basic_blocks.size(), "basic_block");
    const auto valid_function_count = ensure_count<function_row_t>(functions.size(), "function");
    const auto valid_function_chunk_count = ensure_count<function_chunk_row_t>(
        function_chunks.size(), "function_chunk");
    const auto valid_target_fact_count = ensure_count<target_fact_row_t>(
        target_facts.size(), "target_fact");
    const auto valid_xref_count = ensure_count<xref_row_t>(xrefs.size(), "xref");
    const auto valid_coverage_count = ensure_count<coverage_row_t>(
        coverage_spans.size(), "coverage");
    if (!valid_instruction_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(valid_instruction_count.error());
    if (!valid_operand_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(valid_operand_count.error());
    if (!valid_edge_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(valid_edge_count.error());
    if (!valid_string_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(valid_string_count.error());
    if (!valid_symbol_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(valid_symbol_count.error());
    if (!valid_address_expression_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(
            valid_address_expression_count.error());
    if (!valid_basic_block_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(
            valid_basic_block_count.error());
    if (!valid_function_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(valid_function_count.error());
    if (!valid_function_chunk_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(
            valid_function_chunk_count.error());
    if (!valid_target_fact_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(
            valid_target_fact_count.error());
    if (!valid_xref_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(valid_xref_count.error());
    if (!valid_coverage_count)
        return packed_store_result_t<packed_analysis_store_t>::failure(
            valid_coverage_count.error());

    std::sort(instructions.begin(), instructions.end(), id_less<instruction_row_t>);
    std::sort(operands.begin(), operands.end(), [](const operand_row_t& left, const operand_row_t& right) {
        if (left.instruction != right.instruction)
            return left.instruction < right.instruction;
        return left.id < right.id;
    });
    std::sort(edges.begin(), edges.end(), id_less<edge_row_t>);
    std::sort(string_records.begin(), string_records.end(), id_less<string_row_t>);
    std::sort(symbols.begin(), symbols.end(), id_less<symbol_row_t>);
    std::sort(address_expressions.begin(), address_expressions.end(),
              id_less<address_expression_row_t>);
    std::sort(basic_blocks.begin(), basic_blocks.end(), id_less<basic_block_row_t>);
    std::sort(functions.begin(), functions.end(), id_less<function_row_t>);
    std::sort(function_chunks.begin(), function_chunks.end(), id_less<function_chunk_row_t>);
    std::sort(target_facts.begin(), target_facts.end(), id_less<target_fact_row_t>);
    std::sort(xrefs.begin(), xrefs.end(), id_less<xref_row_t>);
    std::sort(coverage_spans.begin(), coverage_spans.end(), id_less<coverage_row_t>);

    auto store_impl = std::make_unique<impl_t>();
    store_impl->strings = pool.value();
    store_impl->instructions.reserve(instructions.size());
    store_impl->operands.reserve(operands.size());
    store_impl->edges.reserve(edges.size());
    store_impl->string_records.reserve(string_records.size());
    store_impl->symbols.reserve(symbols.size());
    store_impl->address_expressions.reserve(address_expressions.size());
    store_impl->basic_blocks.reserve(basic_blocks.size());
    store_impl->functions.reserve(functions.size());
    store_impl->function_chunks.reserve(function_chunks.size());
    store_impl->target_facts.reserve(target_facts.size());
    store_impl->xrefs.reserve(xrefs.size());
    store_impl->coverage_spans.reserve(coverage_spans.size());
    for (const auto& row : instructions)
        store_impl->instructions.append(row);
    for (const auto& row : operands)
        store_impl->operands.append(row);
    for (const auto& row : edges)
        store_impl->edges.append(row);
    for (const auto& row : string_records)
        store_impl->string_records.append(row);
    for (const auto& row : symbols)
        store_impl->symbols.append(row);
    for (const auto& row : address_expressions)
        store_impl->address_expressions.append(row);
    for (const auto& row : basic_blocks)
        store_impl->basic_blocks.append(row);
    for (const auto& row : functions)
        store_impl->functions.append(row);
    for (const auto& row : function_chunks)
        store_impl->function_chunks.append(row);
    for (const auto& row : target_facts)
        store_impl->target_facts.append(row);
    for (const auto& row : xrefs)
        store_impl->xrefs.append(row);
    for (const auto& row : coverage_spans)
        store_impl->coverage_spans.append(row);

    std::size_t operand_index = 0;
    for (std::size_t instruction_index = 0;
         instruction_index < store_impl->instructions.ids.size(); ++instruction_index) {
        const auto instruction_id = store_impl->instructions.ids[instruction_index];
        const std::size_t first = operand_index;
        while (operand_index < store_impl->operands.ids.size() &&
               store_impl->operands.instruction_ids[operand_index] == instruction_id) {
            ++operand_index;
        }
        const std::size_t count = operand_index - first;
        if (count > static_cast<std::size_t>((std::numeric_limits<std::uint16_t>::max)())) {
            return packed_store_result_t<packed_analysis_store_t>::failure(make_error(
                packed_store_error_code_t::arithmetic_overflow, "instruction_operands", 0,
                instruction_id.value(), (std::numeric_limits<std::uint16_t>::max)(), count));
        }
        store_impl->instructions.first_operands[instruction_index] = static_cast<std::uint32_t>(first);
        store_impl->instructions.operand_counts[instruction_index] = static_cast<std::uint16_t>(count);
    }
    if (operand_index != store_impl->operands.ids.size()) {
        return packed_store_result_t<packed_analysis_store_t>::failure(make_error(
            packed_store_error_code_t::dangling_reference, "operand", 0,
            store_impl->operands.instruction_ids[operand_index].value()));
    }

    packed_analysis_store_t store(std::move(store_impl));
    const auto valid_store = store.validate();
    if (!valid_store)
        return packed_store_result_t<packed_analysis_store_t>::failure(valid_store.error());
    return packed_store_result_t<packed_analysis_store_t>::success(std::move(store));
}

bool packed_analysis_store_t::valid() const
{
    return static_cast<bool>(validate());
}

std::uint32_t packed_analysis_store_t::instruction_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->instructions.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::operand_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->operands.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::edge_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->edges.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::string_record_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->string_records.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::symbol_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->symbols.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::address_expression_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->address_expressions.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::basic_block_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->basic_blocks.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::function_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->functions.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::function_chunk_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->function_chunks.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::target_fact_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->target_facts.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::xref_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->xrefs.ids.size()) : 0;
}

std::uint32_t packed_analysis_store_t::coverage_count() const noexcept
{
    return impl_ ? static_cast<std::uint32_t>(impl_->coverage_spans.ids.size()) : 0;
}

const packed_string_pool_t& packed_analysis_store_t::string_pool() const noexcept
{
    return impl_ ? impl_->strings : empty_string_pool();
}

packed_size_accounting_t packed_analysis_store_t::size_accounting() const noexcept
{
    if (!impl_)
        return {};
    const auto string_size = impl_->strings.size_accounting();
    std::uint64_t instruction_payload = 0;
    std::uint64_t instruction_reserved = 0;
    std::uint64_t operand_payload = 0;
    std::uint64_t operand_reserved = 0;
    std::uint64_t edge_payload = 0;
    std::uint64_t edge_reserved = 0;
    std::uint64_t string_payload = 0;
    std::uint64_t string_reserved = 0;
    std::uint64_t symbol_payload = 0;
    std::uint64_t symbol_reserved = 0;
    std::uint64_t address_expression_payload = 0;
    std::uint64_t address_expression_reserved = 0;
    std::uint64_t basic_block_payload = 0;
    std::uint64_t basic_block_reserved = 0;
    std::uint64_t function_payload = 0;
    std::uint64_t function_reserved = 0;
    std::uint64_t function_chunk_payload = 0;
    std::uint64_t function_chunk_reserved = 0;
    std::uint64_t target_fact_payload = 0;
    std::uint64_t target_fact_reserved = 0;
    std::uint64_t xref_payload = 0;
    std::uint64_t xref_reserved = 0;
    std::uint64_t coverage_payload = 0;
    std::uint64_t coverage_reserved = 0;
    impl_->instructions.account(instruction_payload, instruction_reserved);
    impl_->operands.account(operand_payload, operand_reserved);
    impl_->edges.account(edge_payload, edge_reserved);
    impl_->string_records.account(string_payload, string_reserved);
    impl_->symbols.account(symbol_payload, symbol_reserved);
    impl_->address_expressions.account(address_expression_payload, address_expression_reserved);
    impl_->basic_blocks.account(basic_block_payload, basic_block_reserved);
    impl_->functions.account(function_payload, function_reserved);
    impl_->function_chunks.account(function_chunk_payload, function_chunk_reserved);
    impl_->target_facts.account(target_fact_payload, target_fact_reserved);
    impl_->xrefs.account(xref_payload, xref_reserved);
    impl_->coverage_spans.account(coverage_payload, coverage_reserved);
    const auto payload = string_size.payload_bytes + instruction_payload + operand_payload + edge_payload +
        string_payload + symbol_payload + address_expression_payload + basic_block_payload +
        function_payload + function_chunk_payload + target_fact_payload + xref_payload +
        coverage_payload;
    const auto reserved = string_size.reserved_bytes + instruction_reserved + operand_reserved + edge_reserved +
        string_reserved + symbol_reserved + address_expression_reserved + basic_block_reserved +
        function_reserved + function_chunk_reserved + target_fact_reserved + xref_reserved +
        coverage_reserved;
    return packed_size_accounting_t{string_size.payload_bytes, instruction_payload, operand_payload,
                                    edge_payload, string_payload, symbol_payload,
                                    address_expression_payload, basic_block_payload,
                                    function_payload, function_chunk_payload,
                                    target_fact_payload, xref_payload, coverage_payload,
                                    payload, reserved};
}

packed_store_result_t<void> packed_analysis_store_t::validate() const
{
    if (!impl_) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::integrity_mismatch, "store"));
    }
    const auto valid_pool = impl_->strings.validate();
    if (!valid_pool)
        return valid_pool;
    const auto instruction_count = impl_->instructions.ids.size();
    const auto operand_count = impl_->operands.ids.size();
    const auto edge_count = impl_->edges.ids.size();
    const auto string_count = impl_->string_records.ids.size();
    const auto symbol_count = impl_->symbols.ids.size();
    const auto address_expression_count = impl_->address_expressions.ids.size();
    const auto basic_block_count = impl_->basic_blocks.ids.size();
    const auto function_count = impl_->functions.ids.size();
    const auto function_chunk_count = impl_->function_chunks.ids.size();
    const auto target_fact_count = impl_->target_facts.ids.size();
    const auto xref_count = impl_->xrefs.ids.size();
    const auto coverage_count = impl_->coverage_spans.ids.size();
    if (!impl_->instructions.valid(instruction_count) || !impl_->operands.valid(operand_count) ||
        !impl_->edges.valid(edge_count) || !impl_->string_records.valid(string_count) ||
        !impl_->symbols.valid(symbol_count) ||
        !impl_->address_expressions.valid(address_expression_count) ||
        !impl_->basic_blocks.valid(basic_block_count) ||
        !impl_->functions.valid(function_count) ||
        !impl_->function_chunks.valid(function_chunk_count) ||
        !impl_->target_facts.valid(target_fact_count) ||
        !impl_->xrefs.valid(xref_count) ||
        !impl_->coverage_spans.valid(coverage_count)) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::integrity_mismatch, "columns"));
    }

    std::unordered_set<std::uint64_t> instruction_ids;
    std::unordered_set<std::uint64_t> operand_ids;
    std::unordered_set<std::uint64_t> edge_ids;
    std::unordered_set<std::uint64_t> string_ids;
    std::unordered_set<std::uint64_t> symbol_ids;
    std::unordered_set<std::uint64_t> address_expression_ids;
    std::unordered_set<std::uint64_t> basic_block_ids;
    std::unordered_set<std::uint64_t> function_ids;
    std::unordered_set<std::uint64_t> function_chunk_ids;
    std::unordered_set<std::uint64_t> target_fact_ids;
    std::unordered_set<std::uint64_t> xref_ids;
    std::unordered_set<std::uint64_t> coverage_ids;
    auto validate_ids = [](const std::vector<packed_entity_id_t>& ids,
                           packed_entity_domain_t domain, std::string_view phase,
                           bool require_monotonic,
                           std::unordered_set<std::uint64_t>& known_ids)
        -> packed_store_result_t<void> {
        known_ids.reserve(ids.size());
        packed_entity_id_t previous;
        for (const auto& id : ids) {
            if (!id.valid() || id.parts().domain != domain || id.parts().ordinal == 0) {
                return packed_store_result_t<void>::failure(make_error(
                    packed_store_error_code_t::invalid_row, phase, id.parts().shard, id.value()));
            }
            if (!known_ids.insert(id.value()).second) {
                return packed_store_result_t<void>::failure(make_error(
                    packed_store_error_code_t::duplicate_packed_id,
                    phase, id.parts().shard, id.value()));
            }
            if (require_monotonic && previous.valid() && !(previous < id)) {
                return packed_store_result_t<void>::failure(make_error(
                    packed_store_error_code_t::integrity_mismatch, phase, id.parts().shard,
                    id.value()));
            }
            previous = id;
        }
        return packed_store_result_t<void>::success();
    };

    const auto valid_instruction_ids = validate_ids(impl_->instructions.ids,
                                                    packed_entity_domain_t::instruction,
                                                    "instruction", true, instruction_ids);
    const auto valid_operand_ids = validate_ids(impl_->operands.ids, packed_entity_domain_t::operand,
                                                "operand", false, operand_ids);
    const auto valid_edge_ids = validate_ids(impl_->edges.ids, packed_entity_domain_t::edge, "edge",
                                             true, edge_ids);
    const auto valid_string_ids = validate_ids(impl_->string_records.ids, packed_entity_domain_t::string,
                                               "string", true, string_ids);
    const auto valid_symbol_ids = validate_ids(impl_->symbols.ids, packed_entity_domain_t::symbol,
                                                "symbol", true, symbol_ids);
    const auto valid_address_expression_ids = validate_ids(
        impl_->address_expressions.ids, packed_entity_domain_t::address_expression,
        "address_expression", true, address_expression_ids);
    const auto valid_basic_block_ids = validate_ids(impl_->basic_blocks.ids,
                                                     packed_entity_domain_t::basic_block,
                                                     "basic_block", true, basic_block_ids);
    const auto valid_function_ids = validate_ids(impl_->functions.ids,
                                                  packed_entity_domain_t::function, "function",
                                                  true, function_ids);
    const auto valid_function_chunk_ids = validate_ids(impl_->function_chunks.ids,
                                                        packed_entity_domain_t::function_chunk,
                                                        "function_chunk", true,
                                                        function_chunk_ids);
    const auto valid_target_fact_ids = validate_ids(impl_->target_facts.ids,
                                                     packed_entity_domain_t::target_fact,
                                                     "target_fact", true, target_fact_ids);
    const auto valid_xref_ids = validate_ids(impl_->xrefs.ids, packed_entity_domain_t::xref,
                                              "xref", true, xref_ids);
    const auto valid_coverage_ids = validate_ids(impl_->coverage_spans.ids,
                                                  packed_entity_domain_t::coverage, "coverage",
                                                  true, coverage_ids);
    if (!valid_instruction_ids)
        return valid_instruction_ids;
    if (!valid_operand_ids)
        return valid_operand_ids;
    if (!valid_edge_ids)
        return valid_edge_ids;
    if (!valid_string_ids)
        return valid_string_ids;
    if (!valid_symbol_ids)
        return valid_symbol_ids;
    if (!valid_address_expression_ids)
        return valid_address_expression_ids;
    if (!valid_basic_block_ids)
        return valid_basic_block_ids;
    if (!valid_function_ids)
        return valid_function_ids;
    if (!valid_function_chunk_ids)
        return valid_function_chunk_ids;
    if (!valid_target_fact_ids)
        return valid_target_fact_ids;
    if (!valid_xref_ids)
        return valid_xref_ids;
    if (!valid_coverage_ids)
        return valid_coverage_ids;

    auto validate_reference = [&](packed_entity_id_t id, bool required,
                                  std::string_view phase) -> packed_store_result_t<void> {
        if (!id.valid()) {
            if (!required)
                return packed_store_result_t<void>::success();
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_entity_reference, phase));
        }
        const auto domain = id.parts().domain;
        bool exists = false;
        switch (domain) {
        case packed_entity_domain_t::instruction:
            exists = instruction_ids.find(id.value()) != instruction_ids.end();
            break;
        case packed_entity_domain_t::operand:
            exists = operand_ids.find(id.value()) != operand_ids.end();
            break;
        case packed_entity_domain_t::edge:
            exists = edge_ids.find(id.value()) != edge_ids.end();
            break;
        case packed_entity_domain_t::string:
            exists = string_ids.find(id.value()) != string_ids.end();
            break;
        case packed_entity_domain_t::symbol:
            exists = symbol_ids.find(id.value()) != symbol_ids.end();
            break;
        case packed_entity_domain_t::address_expression:
            exists = address_expression_ids.find(id.value()) != address_expression_ids.end();
            break;
        case packed_entity_domain_t::basic_block:
            exists = basic_block_ids.find(id.value()) != basic_block_ids.end();
            break;
        case packed_entity_domain_t::function:
            exists = function_ids.find(id.value()) != function_ids.end();
            break;
        case packed_entity_domain_t::function_chunk:
            exists = function_chunk_ids.find(id.value()) != function_chunk_ids.end();
            break;
        case packed_entity_domain_t::target_fact:
            exists = target_fact_ids.find(id.value()) != target_fact_ids.end();
            break;
        case packed_entity_domain_t::xref:
            exists = xref_ids.find(id.value()) != xref_ids.end();
            break;
        case packed_entity_domain_t::coverage:
            exists = coverage_ids.find(id.value()) != coverage_ids.end();
            break;
        default:
            break;
        }
        if (!exists) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::dangling_reference, phase, id.parts().shard, id.value()));
        }
        return packed_store_result_t<void>::success();
    };

    std::size_t expected_operand = 0;
    for (std::size_t index = 0; index < instruction_count; ++index) {
        if (!valid_provenance(impl_->instructions.provenances[index]) ||
            !valid_coverage(impl_->instructions.coverages[index])) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "instruction",
                impl_->instructions.ids[index].parts().shard,
                impl_->instructions.ids[index].value()));
        }
        const auto mnemonic = impl_->instructions.mnemonics[index];
        if (mnemonic.valid() && !impl_->strings.lookup(mnemonic)) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_string_id, "instruction",
                impl_->instructions.ids[index].parts().shard, mnemonic.value()));
        }
        const std::size_t first = impl_->instructions.first_operands[index];
        const std::size_t count = impl_->instructions.operand_counts[index];
        if (first != expected_operand || first > operand_count || count > operand_count - first) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::integrity_mismatch, "instruction_operands",
                impl_->instructions.ids[index].parts().shard,
                impl_->instructions.ids[index].value(), operand_count, first + count));
        }
        for (std::size_t operand = first; operand < first + count; ++operand) {
            if (impl_->operands.instruction_ids[operand] != impl_->instructions.ids[index]) {
                return packed_store_result_t<void>::failure(make_error(
                    packed_store_error_code_t::integrity_mismatch, "instruction_operands",
                    impl_->instructions.ids[index].parts().shard,
                    impl_->instructions.ids[index].value()));
            }
        }
        expected_operand = first + count;
    }
    if (expected_operand != operand_count) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::integrity_mismatch, "instruction_operands", 0, 0,
            operand_count, expected_operand));
    }
    for (std::size_t index = 0; index < operand_count; ++index) {
        const auto& columns = impl_->operands;
        if (!valid_operand_kind(columns.kinds[index]) ||
            !valid_expression_kind(columns.address_expression_kinds[index]) ||
            !valid_resolution(columns.address_resolutions[index]) || columns.relatives[index] > 1U ||
            columns.signed_values[index] > 1U || columns.has_displacements[index] > 1U ||
            columns.has_resolved_expression_values[index] > 1U ||
            columns.instruction_ids[index].parts().domain != packed_entity_domain_t::instruction) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "operand", columns.ids[index].parts().shard,
                columns.ids[index].value()));
        }
        const auto instruction = validate_reference(columns.instruction_ids[index], true, "operand");
        if (!instruction)
            return instruction;
        const auto expression = validate_reference(columns.address_expression_ids[index], false, "operand");
        if (!expression)
            return expression;
    }
    for (std::size_t index = 0; index < edge_count; ++index) {
        const auto& columns = impl_->edges;
        if (!valid_edge_kind(columns.kinds[index]) || !valid_provenance(columns.provenances[index])) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "edge", columns.ids[index].parts().shard,
                columns.ids[index].value()));
        }
        const auto source = validate_reference(columns.source_entities[index], true, "edge");
        if (!source)
            return source;
        const auto target = validate_reference(columns.target_entities[index], false, "edge");
        if (!target)
            return target;
    }
    for (std::size_t index = 0; index < string_count; ++index) {
        const auto& columns = impl_->string_records;
        if (!valid_string_encoding(columns.encodings[index]) || !valid_provenance(columns.provenances[index]) ||
            !columns.values[index].valid() || !impl_->strings.lookup(columns.values[index])) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "string", columns.ids[index].parts().shard,
                columns.ids[index].value()));
        }
    }
    for (std::size_t index = 0; index < symbol_count; ++index) {
        const auto& columns = impl_->symbols;
        if (!valid_symbol_kind(columns.kinds[index]) || !valid_provenance(columns.provenances[index]) ||
            !columns.names[index].valid() || !impl_->strings.lookup(columns.names[index])) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "symbol", columns.ids[index].parts().shard,
                columns.ids[index].value()));
        }
    }
    for (std::size_t index = 0; index < address_expression_count; ++index) {
        const auto& columns = impl_->address_expressions;
        if (!valid_expression_kind(columns.kinds[index]) ||
            !valid_resolution(columns.resolutions[index]) ||
            !valid_provenance(columns.provenances[index])) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "address_expression",
                columns.ids[index].parts().shard, columns.ids[index].value()));
        }
        const auto instruction = validate_reference(columns.instruction_ids[index], false,
                                                      "address_expression");
        if (!instruction)
            return instruction;
    }
    for (std::size_t index = 0; index < basic_block_count; ++index) {
        const auto& columns = impl_->basic_blocks;
        if (!valid_provenance(columns.provenances[index])) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "basic_block",
                columns.ids[index].parts().shard, columns.ids[index].value()));
        }
    }
    for (std::size_t index = 0; index < function_count; ++index) {
        const auto& columns = impl_->functions;
        if (!valid_provenance(columns.provenances[index]) ||
            (columns.names[index].valid() && !impl_->strings.lookup(columns.names[index]))) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "function",
                columns.ids[index].parts().shard, columns.ids[index].value()));
        }
        const auto entry_block = validate_reference(columns.entry_block_ids[index], false,
                                                      "function");
        if (!entry_block)
            return entry_block;
        const auto symbol = validate_reference(columns.symbol_ids[index], false, "function");
        if (!symbol)
            return symbol;
    }
    for (std::size_t index = 0; index < function_chunk_count; ++index) {
        const auto& columns = impl_->function_chunks;
        if (!valid_provenance(columns.provenances[index]) ||
            columns.function_ids[index].parts().domain != packed_entity_domain_t::function) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "function_chunk",
                columns.ids[index].parts().shard, columns.ids[index].value()));
        }
        const auto function = validate_reference(columns.function_ids[index], true,
                                                   "function_chunk");
        if (!function)
            return function;
    }
    for (std::size_t index = 0; index < target_fact_count; ++index) {
        const auto& columns = impl_->target_facts;
        if (!valid_target_kind(columns.kinds[index]) ||
            !valid_resolution(columns.resolutions[index]) ||
            !valid_provenance(columns.provenances[index]) || columns.directs[index] > 1U ||
            columns.is_externals[index] > 1U) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "target_fact",
                columns.ids[index].parts().shard, columns.ids[index].value()));
        }
        const auto instruction = validate_reference(columns.instruction_ids[index], false,
                                                      "target_fact");
        if (!instruction)
            return instruction;
        const auto operand = validate_reference(columns.operand_ids[index], false, "target_fact");
        if (!operand)
            return operand;
        const auto expression = validate_reference(columns.address_expression_ids[index], false,
                                                     "target_fact");
        if (!expression)
            return expression;
    }
    for (std::size_t index = 0; index < xref_count; ++index) {
        const auto& columns = impl_->xrefs;
        if (!valid_xref_kind(columns.kinds[index]) || !valid_provenance(columns.provenances[index]) ||
            columns.directs[index] > 1U) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "xref",
                columns.ids[index].parts().shard, columns.ids[index].value()));
        }
        const auto source = validate_reference(columns.source_entities[index], false, "xref");
        if (!source)
            return source;
        const auto target = validate_reference(columns.target_entities[index], false, "xref");
        if (!target)
            return target;
    }
    for (std::size_t index = 0; index < coverage_count; ++index) {
        const auto& columns = impl_->coverage_spans;
        if (!valid_coverage(columns.reasons[index]) ||
            !valid_provenance(columns.provenances[index])) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_row, "coverage",
                columns.ids[index].parts().shard, columns.ids[index].value()));
        }
    }
    return packed_store_result_t<void>::success();
}

std::optional<packed_instruction_view_t>
packed_analysis_store_t::instruction(std::size_t index) const
{
    if (!impl_ || index >= impl_->instructions.ids.size())
        return std::nullopt;
    const auto address = impl_->instructions.addresses.at(index);
    if (!address)
        return std::nullopt;
    std::string_view mnemonic;
    const auto mnemonic_id = impl_->instructions.mnemonics[index];
    if (mnemonic_id.valid()) {
        const auto value = impl_->strings.lookup(mnemonic_id);
        if (!value)
            return std::nullopt;
        mnemonic = *value;
    }
    return packed_instruction_view_t{impl_->instructions.ids[index], *address,
                                     impl_->instructions.lengths[index],
                                     impl_->instructions.mnemonic_ids[index], mnemonic,
                                     impl_->instructions.opcode_ids[index],
                                     impl_->instructions.flow_flags[index],
                                     impl_->instructions.first_operands[index],
                                     impl_->instructions.operand_counts[index],
                                     impl_->instructions.provenances[index],
                                     impl_->instructions.confidences[index],
                                     impl_->instructions.coverages[index],
                                     impl_->instructions.stable_source_ids[index]};
}

std::optional<packed_operand_view_t> packed_analysis_store_t::operand(std::size_t index) const
{
    if (!impl_ || index >= impl_->operands.ids.size())
        return std::nullopt;
    const auto& columns = impl_->operands;
    return packed_operand_view_t{
        columns.ids[index], columns.instruction_ids[index], columns.address_expression_ids[index],
        columns.operand_indices[index], columns.decoder_operand_ids[index], columns.kinds[index],
        columns.accesses[index], columns.visibilities[index], columns.encodings[index],
        columns.memory_types[index], columns.access_widths[index], columns.bit_widths[index],
        columns.access_width_bits[index], columns.access_counts[index], columns.element_width_bits[index],
        columns.element_counts[index], columns.address_width_bits[index], columns.regs[index],
        columns.segment_regs[index], columns.base_regs[index], columns.index_regs[index], columns.scales[index],
        columns.relatives[index] != 0, columns.signed_values[index] != 0,
        columns.has_displacements[index] != 0, columns.has_resolved_expression_values[index] != 0,
        columns.displacements[index], columns.immediates[index], columns.resolved_expression_values[index],
        columns.address_components[index], columns.address_expression_kinds[index],
        columns.address_resolutions[index]};
}

std::optional<packed_edge_view_t> packed_analysis_store_t::edge(std::size_t index) const
{
    if (!impl_ || index >= impl_->edges.ids.size())
        return std::nullopt;
    const auto source = impl_->edges.sources.at(index);
    const auto target = impl_->edges.targets.at(index);
    if (!source || !target)
        return std::nullopt;
    std::optional<packed_entity_id_t> target_entity;
    if (impl_->edges.target_entities[index].valid())
        target_entity = impl_->edges.target_entities[index];
    return packed_edge_view_t{impl_->edges.ids[index], impl_->edges.source_entities[index], target_entity,
                              *source, *target, impl_->edges.kinds[index],
                              impl_->edges.provenances[index], impl_->edges.confidences[index]};
}

std::optional<packed_string_view_t> packed_analysis_store_t::string(std::size_t index) const
{
    if (!impl_ || index >= impl_->string_records.ids.size())
        return std::nullopt;
    const auto address = impl_->string_records.addresses.at(index);
    const auto value = impl_->strings.lookup(impl_->string_records.values[index]);
    if (!address || !value)
        return std::nullopt;
    return packed_string_view_t{impl_->string_records.ids[index], *address,
                                impl_->string_records.byte_lengths[index],
                                impl_->string_records.encodings[index], *value,
                                impl_->string_records.provenances[index],
                                impl_->string_records.confidences[index]};
}

std::optional<packed_symbol_view_t> packed_analysis_store_t::symbol(std::size_t index) const
{
    if (!impl_ || index >= impl_->symbols.ids.size())
        return std::nullopt;
    const auto address = impl_->symbols.addresses.at(index);
    const auto name = impl_->strings.lookup(impl_->symbols.names[index]);
    if (!address || !name)
        return std::nullopt;
    return packed_symbol_view_t{impl_->symbols.ids[index], *address, *name,
                                impl_->symbols.kinds[index], impl_->symbols.provenances[index],
                                impl_->symbols.confidences[index]};
}

std::optional<packed_address_expression_view_t>
packed_analysis_store_t::address_expression(std::size_t index) const
{
    if (!impl_ || index >= impl_->address_expressions.ids.size())
        return std::nullopt;
    const auto& columns = impl_->address_expressions;
    return packed_address_expression_view_t{
        columns.ids[index], columns.instruction_ids[index], columns.base_regs[index],
        columns.index_regs[index], columns.scales[index], columns.displacements[index],
        columns.segment_regs[index], columns.address_components[index], columns.kinds[index],
        columns.resolutions[index], columns.provenances[index], columns.confidences[index]};
}

std::optional<packed_basic_block_view_t>
packed_analysis_store_t::basic_block(std::size_t index) const
{
    if (!impl_ || index >= impl_->basic_blocks.ids.size())
        return std::nullopt;
    const auto start = impl_->basic_blocks.start_addresses.at(index);
    const auto end = impl_->basic_blocks.end_addresses.at(index);
    if (!start || !end)
        return std::nullopt;
    const auto& columns = impl_->basic_blocks;
    return packed_basic_block_view_t{
        columns.ids[index], *start, *end, columns.instruction_begins[index],
        columns.instruction_counts[index], columns.predecessor_counts[index],
        columns.successor_counts[index], columns.flags[index], columns.provenances[index],
        columns.confidences[index]};
}

std::optional<packed_function_view_t>
packed_analysis_store_t::function(std::size_t index) const
{
    if (!impl_ || index >= impl_->functions.ids.size())
        return std::nullopt;
    const auto start = impl_->functions.start_addresses.at(index);
    const auto end = impl_->functions.end_addresses.at(index);
    if (!start || !end)
        return std::nullopt;
    std::string_view name;
    const auto name_id = impl_->functions.names[index];
    if (name_id.valid()) {
        const auto value = impl_->strings.lookup(name_id);
        if (!value)
            return std::nullopt;
        name = *value;
    }
    const auto& columns = impl_->functions;
    return packed_function_view_t{
        columns.ids[index], *start, *end, columns.entry_block_ids[index],
        columns.symbol_ids[index], name, columns.chunk_counts[index], columns.flags[index],
        columns.return_type_ids[index], columns.provenances[index], columns.confidences[index]};
}

std::optional<packed_function_chunk_view_t>
packed_analysis_store_t::function_chunk(std::size_t index) const
{
    if (!impl_ || index >= impl_->function_chunks.ids.size())
        return std::nullopt;
    const auto start = impl_->function_chunks.start_addresses.at(index);
    const auto end = impl_->function_chunks.end_addresses.at(index);
    if (!start || !end)
        return std::nullopt;
    const auto& columns = impl_->function_chunks;
    return packed_function_chunk_view_t{
        columns.ids[index], columns.function_ids[index], *start, *end,
        columns.block_begins[index], columns.block_counts[index], columns.flags[index],
        columns.provenances[index], columns.confidences[index]};
}

std::optional<packed_target_fact_view_t>
packed_analysis_store_t::target_fact(std::size_t index) const
{
    if (!impl_ || index >= impl_->target_facts.ids.size())
        return std::nullopt;
    const auto target = impl_->target_facts.targets.at(index);
    if (!target)
        return std::nullopt;
    const auto& columns = impl_->target_facts;
    return packed_target_fact_view_t{
        columns.ids[index], columns.instruction_ids[index], columns.operand_ids[index],
        columns.address_expression_ids[index], *target, columns.kinds[index],
        columns.resolutions[index], columns.operand_indices[index],
        columns.access_width_bits[index], columns.access_counts[index],
        columns.directs[index] != 0, columns.is_externals[index] != 0,
        columns.provenances[index], columns.confidences[index]};
}

std::optional<packed_xref_view_t>
packed_analysis_store_t::xref(std::size_t index) const
{
    if (!impl_ || index >= impl_->xrefs.ids.size())
        return std::nullopt;
    const auto source = impl_->xrefs.source_addresses.at(index);
    const auto target = impl_->xrefs.target_addresses.at(index);
    if (!source || !target)
        return std::nullopt;
    const auto& columns = impl_->xrefs;
    return packed_xref_view_t{
        columns.ids[index], columns.source_entities[index], columns.target_entities[index],
        *source, *target, columns.kinds[index], columns.directs[index] != 0,
        columns.provenances[index], columns.confidences[index]};
}

std::optional<packed_coverage_view_t>
packed_analysis_store_t::coverage(std::size_t index) const
{
    if (!impl_ || index >= impl_->coverage_spans.ids.size())
        return std::nullopt;
    const auto begin = impl_->coverage_spans.span_begins.at(index);
    const auto end = impl_->coverage_spans.span_ends.at(index);
    if (!begin || !end)
        return std::nullopt;
    const auto& columns = impl_->coverage_spans;
    return packed_coverage_view_t{
        columns.ids[index], *begin, *end, columns.reasons[index],
        columns.undecodable_counts[index], columns.provenances[index],
        columns.confidences[index]};
}

packed_analysis_compatibility_view_t packed_analysis_store_t::compatibility_view() const noexcept
{
    return packed_analysis_compatibility_view_t(this);
}

packed_analysis_compatibility_view_t::packed_analysis_compatibility_view_t(
    const packed_analysis_store_t* store) noexcept
    : store_(store)
{
}

std::optional<instruction_record_t>
packed_analysis_compatibility_view_t::instruction(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->instruction(index);
    if (!view)
        return std::nullopt;
    instruction_record_t result;
    result.id = view->id.value();
    result.address = view->address;
    result.length = view->length;
    result.mnemonic_id = view->mnemonic_id;
    result.opcode_id = view->opcode_id;
    result.flow_flags = static_cast<std::uint16_t>(view->flow_flags);
    result.operand_fact_begin = view->first_operand;
    result.operand_fact_count = view->operand_count;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    result.coverage = view->coverage;
    result.stable_source_id = view->stable_source_id;
    return result;
}

std::optional<operand_fact_t>
packed_analysis_compatibility_view_t::operand(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->operand(index);
    if (!view)
        return std::nullopt;
    operand_fact_t result;
    result.id = view->id.value();
    result.instruction_id = view->instruction_id.value();
    result.address_expression_id = view->address_expression_id.value();
    result.operand_index = view->operand_index;
    result.decoder_operand_id = view->decoder_operand_id;
    result.kind = view->kind;
    result.access = view->access;
    result.visibility = view->visibility;
    result.encoding = view->encoding;
    result.memory_type = view->memory_type;
    result.access_width = view->access_width;
    result.bit_width = view->bit_width;
    result.access_width_bits = view->access_width_bits;
    result.access_count = view->access_count;
    result.element_width_bits = view->element_width_bits;
    result.element_count = view->element_count;
    result.address_width_bits = view->address_width_bits;
    result.reg = view->reg;
    result.segment_reg = view->segment_reg;
    result.base_reg = view->base_reg;
    result.index_reg = view->index_reg;
    result.scale = view->scale;
    result.relative = view->relative;
    result.signed_value = view->signed_value;
    result.has_displacement = view->has_displacement;
    result.has_resolved_expression_value = view->has_resolved_expression_value;
    result.displacement = view->displacement;
    result.immediate = view->immediate;
    result.resolved_expression_value = view->resolved_expression_value;
    result.address_components = view->address_components;
    result.address_expression = view->address_expression_kind;
    result.address_resolution = view->address_resolution;
    return result;
}

std::optional<edge_record_t> packed_analysis_compatibility_view_t::edge(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->edge(index);
    if (!view)
        return std::nullopt;
    edge_record_t result;
    result.id = view->id.value();
    result.source_entity = view->source_entity.value();
    if (view->target_entity.has_value())
        result.target_entity = view->target_entity->value();
    result.source = view->source;
    result.target = view->target;
    result.kind = view->kind;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<string_record_t> packed_analysis_compatibility_view_t::string(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->string(index);
    if (!view)
        return std::nullopt;
    string_record_t result;
    result.id = view->id.value();
    result.address = view->address;
    result.byte_length = view->byte_length;
    result.encoding = view->encoding;
    result.value.assign(view->value.data(), view->value.size());
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<symbol_record_t> packed_analysis_compatibility_view_t::symbol(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->symbol(index);
    if (!view)
        return std::nullopt;
    symbol_record_t result;
    result.id = view->id.value();
    result.address = view->address;
    result.name.assign(view->name.data(), view->name.size());
    result.kind = view->kind;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<basic_block_record_t>
packed_analysis_compatibility_view_t::basic_block(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->basic_block(index);
    if (!view)
        return std::nullopt;
    basic_block_record_t result;
    result.id = view->id.value();
    result.start = view->start_address;
    result.end = view->end_address;
    result.first_instruction = view->instruction_begin;
    result.instruction_count = view->instruction_count;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<function_record_t>
packed_analysis_compatibility_view_t::function(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->function(index);
    if (!view)
        return std::nullopt;
    function_record_t result;
    result.id = view->id.value();
    result.start = view->start_address;
    result.end = view->end_address;
    result.chunk_count = view->chunk_count;
    if (view->symbol_id.valid())
        result.symbol_id = view->symbol_id.value();
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<function_chunk_record_t>
packed_analysis_compatibility_view_t::function_chunk(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->function_chunk(index);
    if (!view)
        return std::nullopt;
    function_chunk_record_t result;
    result.id = view->id.value();
    result.function_id = view->function_id.value();
    result.start = view->start_address;
    result.end = view->end_address;
    result.first_block = view->block_begin;
    result.block_count = view->block_count;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<target_fact_t>
packed_analysis_compatibility_view_t::target_fact(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->target_fact(index);
    if (!view)
        return std::nullopt;
    target_fact_t result;
    result.instruction_id = view->instruction_id.value();
    result.operand_fact_id = view->operand_id.value();
    result.address_expression_id = view->address_expression_id.value();
    result.target = view->target;
    result.kind = view->kind;
    result.resolution = view->resolution;
    result.operand_index = view->operand_index;
    result.access_width_bits = view->access_width_bits;
    result.access_count = static_cast<std::uint8_t>(view->access_count);
    result.direct = view->direct;
    result.is_external = view->is_external;
    return result;
}

std::optional<xref_record_t>
packed_analysis_compatibility_view_t::xref(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->xref(index);
    if (!view)
        return std::nullopt;
    xref_record_t result;
    result.id = view->id.value();
    result.source = view->source_address;
    result.target = view->target_address;
    result.kind = view->kind;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<coverage_span_t>
packed_analysis_compatibility_view_t::coverage(std::size_t index) const
{
    if (!store_)
        return std::nullopt;
    const auto view = store_->coverage(index);
    if (!view)
        return std::nullopt;
    coverage_span_t result;
    result.start = view->span_begin;
    result.size = view->span_end.value >= view->span_begin.value
        ? view->span_end.value - view->span_begin.value : 0;
    result.reason = view->reason;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    result.detail_code = view->undecodable_count;
    return result;
}

packed_analysis_shard_compatibility_view_t::packed_analysis_shard_compatibility_view_t(
    const packed_analysis_shard_t* shard) noexcept
    : shard_(shard)
{
}

std::optional<instruction_record_t>
packed_analysis_shard_compatibility_view_t::instruction(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->instruction(index);
    if (!view)
        return std::nullopt;
    instruction_record_t result;
    result.id = view->id.value();
    result.address = view->address;
    result.length = view->length;
    result.mnemonic_id = view->mnemonic_id;
    result.opcode_id = view->opcode_id;
    result.flow_flags = static_cast<std::uint16_t>(view->flow_flags);
    result.operand_fact_begin = view->first_operand;
    result.operand_fact_count = view->operand_count;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    result.coverage = view->coverage;
    result.stable_source_id = view->stable_source_id;
    return result;
}

std::optional<operand_fact_t>
packed_analysis_shard_compatibility_view_t::operand(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->operand(index);
    if (!view)
        return std::nullopt;
    operand_fact_t result;
    result.id = view->id.value();
    result.instruction_id = view->instruction_id.value();
    result.address_expression_id = view->address_expression_id.value();
    result.operand_index = view->operand_index;
    result.decoder_operand_id = view->decoder_operand_id;
    result.kind = view->kind;
    result.access = view->access;
    result.visibility = view->visibility;
    result.encoding = view->encoding;
    result.memory_type = view->memory_type;
    result.access_width = view->access_width;
    result.bit_width = view->bit_width;
    result.access_width_bits = view->access_width_bits;
    result.access_count = view->access_count;
    result.element_width_bits = view->element_width_bits;
    result.element_count = view->element_count;
    result.address_width_bits = view->address_width_bits;
    result.reg = view->reg;
    result.segment_reg = view->segment_reg;
    result.base_reg = view->base_reg;
    result.index_reg = view->index_reg;
    result.scale = view->scale;
    result.relative = view->relative;
    result.signed_value = view->signed_value;
    result.has_displacement = view->has_displacement;
    result.has_resolved_expression_value = view->has_resolved_expression_value;
    result.displacement = view->displacement;
    result.immediate = view->immediate;
    result.resolved_expression_value = view->resolved_expression_value;
    result.address_components = view->address_components;
    result.address_expression = view->address_expression_kind;
    result.address_resolution = view->address_resolution;
    return result;
}

std::optional<edge_record_t>
packed_analysis_shard_compatibility_view_t::edge(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->edge(index);
    if (!view)
        return std::nullopt;
    edge_record_t result;
    result.id = view->id.value();
    result.source_entity = view->source_entity.value();
    if (view->target_entity.has_value())
        result.target_entity = view->target_entity->value();
    result.source = view->source;
    result.target = view->target;
    result.kind = view->kind;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<string_record_t>
packed_analysis_shard_compatibility_view_t::string(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->string(index);
    if (!view)
        return std::nullopt;
    string_record_t result;
    result.id = view->id.value();
    result.address = view->address;
    result.byte_length = view->byte_length;
    result.encoding = view->encoding;
    result.value.assign(view->value.data(), view->value.size());
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<symbol_record_t>
packed_analysis_shard_compatibility_view_t::symbol(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->symbol(index);
    if (!view)
        return std::nullopt;
    symbol_record_t result;
    result.id = view->id.value();
    result.address = view->address;
    result.name.assign(view->name.data(), view->name.size());
    result.kind = view->kind;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<basic_block_record_t>
packed_analysis_shard_compatibility_view_t::basic_block(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->basic_block(index);
    if (!view)
        return std::nullopt;
    basic_block_record_t result;
    result.id = view->id.value();
    result.start = view->start_address;
    result.end = view->end_address;
    result.first_instruction = view->instruction_begin;
    result.instruction_count = view->instruction_count;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<function_record_t>
packed_analysis_shard_compatibility_view_t::function(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->function(index);
    if (!view)
        return std::nullopt;
    function_record_t result;
    result.id = view->id.value();
    result.start = view->start_address;
    result.end = view->end_address;
    result.chunk_count = view->chunk_count;
    if (view->symbol_id.valid())
        result.symbol_id = view->symbol_id.value();
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<function_chunk_record_t>
packed_analysis_shard_compatibility_view_t::function_chunk(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->function_chunk(index);
    if (!view)
        return std::nullopt;
    function_chunk_record_t result;
    result.id = view->id.value();
    result.function_id = view->function_id.value();
    result.start = view->start_address;
    result.end = view->end_address;
    result.first_block = view->block_begin;
    result.block_count = view->block_count;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<target_fact_t>
packed_analysis_shard_compatibility_view_t::target_fact(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->target_fact(index);
    if (!view)
        return std::nullopt;
    target_fact_t result;
    result.instruction_id = view->instruction_id.value();
    result.operand_fact_id = view->operand_id.value();
    result.address_expression_id = view->address_expression_id.value();
    result.target = view->target;
    result.kind = view->kind;
    result.resolution = view->resolution;
    result.operand_index = view->operand_index;
    result.access_width_bits = view->access_width_bits;
    result.access_count = static_cast<std::uint8_t>(view->access_count);
    result.direct = view->direct;
    result.is_external = view->is_external;
    return result;
}

std::optional<xref_record_t>
packed_analysis_shard_compatibility_view_t::xref(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->xref(index);
    if (!view)
        return std::nullopt;
    xref_record_t result;
    result.id = view->id.value();
    result.source = view->source_address;
    result.target = view->target_address;
    result.kind = view->kind;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    return result;
}

std::optional<coverage_span_t>
packed_analysis_shard_compatibility_view_t::coverage(std::size_t index) const
{
    if (!shard_)
        return std::nullopt;
    const auto view = shard_->coverage(index);
    if (!view)
        return std::nullopt;
    coverage_span_t result;
    result.start = view->span_begin;
    result.size = view->span_end.value >= view->span_begin.value
        ? view->span_end.value - view->span_begin.value : 0;
    result.reason = view->reason;
    result.provenance = view->provenance;
    result.confidence = view->confidence;
    result.detail_code = view->undecodable_count;
    return result;
}

}
