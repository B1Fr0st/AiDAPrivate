#pragma once

#include "checked_range.hpp"
#include "fact_residency.hpp"
#include "record_span.hpp"
#include "snapshot_tables.hpp"
#include "workspace_types.hpp"

#include "../packed_string_pool.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace aida::analysis {

class byte_provider_t;
class pe_image_t;
class paged_fact_staging_t;
class paged_domain_source_t;

using entity_id_t = std::uint64_t;

inline constexpr std::uint64_t entity_ordinal_mask = 0x00FFFFFFFFFFFFFFULL;
inline constexpr std::uint64_t instruction_entity_tag = 1ULL << 56;
inline constexpr std::uint64_t operand_entity_tag = 2ULL << 56;
inline constexpr std::uint64_t address_expression_entity_tag = 6ULL << 56;
inline constexpr std::uint64_t call_site_entity_tag = 15ULL << 56;
inline constexpr std::uint64_t call_candidate_entity_tag = 16ULL << 56;
inline constexpr std::uint64_t call_edge_entity_tag = 17ULL << 56;
inline constexpr std::uint64_t call_conflict_entity_tag = 18ULL << 56;

inline constexpr std::uint8_t entity_domain(entity_id_t id) noexcept {
    return static_cast<std::uint8_t>(id >> 56U);
}

inline constexpr std::uint64_t entity_ordinal(entity_id_t id) noexcept {
    return id & entity_ordinal_mask;
}

enum class fact_provenance_t : std::uint8_t {
    unknown = 0,
    gap_recovery = 1,
    linear_validation = 2,
    recursive_decode = 3,
    relocation = 4,
    call_target = 5,
    export_entry = 6,
    tls_entry = 7,
    image_entry = 8,
    unwind_metadata = 9,
    debug_symbol = 10,
    user_definition = 11,
    decompiler_feedback = 12
};

inline std::uint8_t provenance_rank(fact_provenance_t provenance) noexcept {
    return static_cast<std::uint8_t>(provenance);
}

enum class coverage_reason_t : std::uint8_t {
    decoded = 0,
    proven_data = 1,
    padding = 2,
    conflict = 3,
    undecodable = 4,
    non_executable = 5,
    excluded_by_metadata = 6,
    pending = 7
};

enum class operand_kind_t : std::uint8_t {
    none = 0,
    reg = 1,
    memory = 2,
    immediate = 3,
    pointer = 4
};

enum class address_expression_kind_t : std::uint8_t {
    none = 0,
    absolute = 1,
    base_displacement = 2,
    base_index_displacement = 3,
    instruction_relative = 4,
    segment_relative = 5
};

enum address_expression_component_flag_t : std::uint16_t {
    address_component_none = 0,
    address_component_segment = 1U << 0,
    address_component_base = 1U << 1,
    address_component_index = 1U << 2,
    address_component_scale = 1U << 3,
    address_component_displacement = 1U << 4,
    address_component_instruction_pointer = 1U << 5
};

enum class target_resolution_t : std::uint8_t {
    image_relative = 0,
    image_virtual = 1,
    external_virtual = 2,
    segment_relative = 3,
    unresolved_indirect = 4
};

enum class target_kind_record_t : std::uint8_t {
    branch = 0,
    call = 1,
    data = 2,
    fallthrough = 3
};

enum instruction_flow_flag_t : std::uint32_t {
    flow_none = 0,
    flow_fallthrough = 1U << 0,
    flow_direct = 1U << 1,
    flow_indirect = 1U << 2,
    flow_call = 1U << 3,
    flow_branch = 1U << 4,
    flow_conditional = 1U << 5,
    flow_return = 1U << 6,
    flow_interrupt = 1U << 7,
    flow_terminal = 1U << 8,
    flow_privileged = 1U << 9
};

struct operand_fact_t {
    entity_id_t id = 0;
    entity_id_t instruction_id = 0;
    entity_id_t address_expression_id = 0;
    std::int64_t displacement = 0;
    std::uint64_t immediate = 0;
    std::uint64_t resolved_expression_value = 0;
    std::uint16_t bit_width = 0;
    std::uint16_t access_width_bits = 0;
    std::uint16_t element_width_bits = 0;
    std::uint16_t reg = 0;
    std::uint16_t segment_reg = 0;
    std::uint16_t base_reg = 0;
    std::uint16_t index_reg = 0;
    std::uint16_t address_components = address_component_none;
    std::uint16_t access_count = 0;
    std::uint16_t element_count = 0;
    std::uint16_t address_width_bits = 0;
    std::uint8_t operand_index = 0;
    std::uint8_t decoder_operand_id = 0;
    operand_kind_t kind = operand_kind_t::none;
    std::uint8_t access = 0;
    std::uint8_t visibility = 0;
    std::uint8_t encoding = 0;
    std::uint8_t memory_type = 0;
    std::uint8_t access_width = 0;
    std::uint8_t scale = 0;
    bool relative = false;
    bool signed_value = false;
    bool has_displacement = false;
    bool has_resolved_expression_value = false;
    address_expression_kind_t address_expression = address_expression_kind_t::none;
    target_resolution_t address_resolution = target_resolution_t::unresolved_indirect;
};

inline constexpr std::uint16_t operand_hot_kind_shift = 0;
inline constexpr std::uint16_t operand_hot_access_shift = 3;
inline constexpr std::uint16_t operand_hot_scale_shift = 7;
inline constexpr std::uint16_t operand_hot_relative_bit = 11;
inline constexpr std::uint16_t operand_hot_signed_bit = 12;
inline constexpr std::uint16_t operand_hot_displacement_bit = 13;
inline constexpr std::uint16_t operand_hot_memory_type_shift = 14;
inline constexpr std::uint8_t operand_cold_has_resolved_bit = 1U;

struct operand_fact_hot_t {
    std::uint64_t value = 0;
    std::uint32_t instruction_ordinal = 0;
    std::uint32_t cold_index = 0;
    std::uint16_t reg = 0;
    std::uint16_t base_reg = 0;
    std::uint16_t index_reg = 0;
    std::uint16_t flags = 0;
    std::uint8_t operand_index = 0;
    std::uint8_t access_width = 0;
    std::uint8_t segment_reg = 0;
    std::uint8_t width_class = 0;
    std::uint8_t memory_type_wide = 0;
    std::uint8_t segment_reg_hi = 0;
    std::uint8_t reserved[2]{};
};

struct operand_fact_cold_t {
    std::uint64_t resolved_expression_value = 0;
    std::uint32_t expression_ordinal = 0;
    std::uint16_t bit_width = 0;
    std::uint16_t access_width_bits = 0;
    std::uint16_t element_width_bits = 0;
    std::uint16_t address_components = 0;
    std::uint16_t access_count = 0;
    std::uint16_t element_count = 0;
    std::uint8_t address_expression = 0;
    std::uint8_t address_resolution = 0;
    std::uint8_t visibility = 0;
    std::uint8_t encoding = 0;
    std::uint8_t decoder_operand_id = 0;
    std::uint8_t address_width_bits = 0;
    std::uint8_t flags = 0;
    std::uint8_t reserved = 0;
};

struct address_expression_record_t {
    std::uint16_t components = 0;
    std::uint16_t base_reg = 0;
    std::uint16_t index_reg = 0;
    std::uint16_t segment_reg = 0;
    std::uint8_t kind = 0;
    std::uint8_t resolution = 0;
    std::uint8_t scale = 0;
    std::uint8_t disp_class = 0;
};

struct operand_fact_store_t {
    snapshot_table_t<operand_fact_hot_t> hot;
    snapshot_table_t<operand_fact_cold_t> cold;

    std::size_t size() const noexcept { return hot.size(); }
    bool empty() const noexcept { return hot.empty(); }
    void clear() noexcept {
        hot.clear();
        cold.clear();
    }
    void append(const operand_fact_t& fact, std::uint32_t instruction_ordinal);
};

inline void reserve_exact(operand_fact_store_t& store, std::size_t hot_count,
                          std::size_t cold_count) {
    reserve_exact(store.hot, hot_count);
    reserve_exact(store.cold, cold_count);
}

inline void resize_uninitialized(operand_fact_store_t& store, std::size_t hot_count,
                                 std::size_t cold_count) {
    resize_uninitialized(store.hot, hot_count);
    resize_uninitialized(store.cold, cold_count);
}

inline std::uint8_t operand_hot_width_class(std::uint16_t bit_width) noexcept {
    if (bit_width == 0 || (bit_width & (bit_width - 1U)) != 0)
        return 0;
    std::uint8_t shift = 0;
    std::uint16_t value = bit_width;
    while (value > 1U) {
        value >>= 1U;
        ++shift;
    }
    return static_cast<std::uint8_t>(shift + 1U);
}

inline std::uint16_t operand_hot_width_bits(std::uint8_t width_class) noexcept {
    return width_class == 0
        ? static_cast<std::uint16_t>(0)
        : static_cast<std::uint16_t>(1U << (width_class - 1U));
}

struct operand_fact_split_t {
    operand_fact_hot_t hot;
    operand_fact_cold_t cold;
    bool has_cold = false;
};

inline operand_fact_split_t operand_fact_split(
    const operand_fact_t& fact, std::uint32_t instruction_ordinal) noexcept {
    operand_fact_split_t parts;
    auto& hot = parts.hot;
    hot.value = fact.has_displacement
        ? static_cast<std::uint64_t>(fact.displacement)
        : fact.immediate;
    hot.instruction_ordinal = instruction_ordinal;
    hot.reg = fact.reg;
    hot.base_reg = fact.base_reg;
    hot.index_reg = fact.index_reg;
    std::uint16_t flags = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(fact.kind) & 0x7U) << operand_hot_kind_shift);
    flags |= static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(fact.access) & 0xFU) << operand_hot_access_shift);
    flags |= static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(fact.scale) & 0xFU) << operand_hot_scale_shift);
    if (fact.relative)
        flags |= static_cast<std::uint16_t>(1U << operand_hot_relative_bit);
    if (fact.signed_value)
        flags |= static_cast<std::uint16_t>(1U << operand_hot_signed_bit);
    if (fact.has_displacement)
        flags |= static_cast<std::uint16_t>(1U << operand_hot_displacement_bit);
    if (fact.memory_type <= 3U) {
        flags |= static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(fact.memory_type) & 0x3U)
            << operand_hot_memory_type_shift);
        hot.memory_type_wide = 0;
    } else {
        hot.memory_type_wide = fact.memory_type;
    }
    hot.flags = flags;
    hot.operand_index = fact.operand_index;
    hot.access_width = fact.access_width;
    hot.segment_reg = static_cast<std::uint8_t>(fact.segment_reg & 0xFFU);
    hot.segment_reg_hi = static_cast<std::uint8_t>(fact.segment_reg >> 8U);
    hot.width_class = operand_hot_width_class(fact.bit_width);
    auto& cold = parts.cold;
    cold.resolved_expression_value = fact.resolved_expression_value;
    cold.bit_width = fact.bit_width;
    cold.access_width_bits = fact.access_width_bits;
    cold.element_width_bits = fact.element_width_bits;
    cold.address_components = fact.address_components;
    cold.access_count = fact.access_count;
    cold.element_count = fact.element_count;
    cold.address_expression = static_cast<std::uint8_t>(fact.address_expression);
    cold.address_resolution = static_cast<std::uint8_t>(fact.address_resolution);
    cold.visibility = fact.visibility;
    cold.encoding = fact.encoding;
    cold.decoder_operand_id = fact.decoder_operand_id;
    cold.address_width_bits = static_cast<std::uint8_t>(fact.address_width_bits & 0xFFU);
    if (entity_domain(fact.address_expression_id) ==
            static_cast<std::uint8_t>(address_expression_entity_tag >> 56U) &&
        entity_ordinal(fact.address_expression_id) != 0) {
        cold.expression_ordinal = static_cast<std::uint32_t>(
            entity_ordinal(fact.address_expression_id));
    }
    if (fact.has_resolved_expression_value)
        cold.flags |= operand_cold_has_resolved_bit;
    const bool needs_cold = fact.has_resolved_expression_value ||
        fact.resolved_expression_value != 0 ||
        fact.address_expression_id != 0 ||
        fact.address_expression != address_expression_kind_t::none ||
        fact.address_resolution != target_resolution_t::unresolved_indirect ||
        hot.width_class == 0 && fact.bit_width != 0 ||
        fact.access_width_bits != 0 || fact.element_width_bits != 0 ||
        fact.address_components != address_component_none ||
        fact.access_count != 0 || fact.element_count != 0 ||
        fact.visibility != 0 || fact.encoding != 0 ||
        fact.decoder_operand_id != 0 || fact.address_width_bits != 0;
    parts.has_cold = needs_cold;
    return parts;
}

inline void operand_fact_store_t::append(
    const operand_fact_t& fact, std::uint32_t instruction_ordinal) {
    auto parts = operand_fact_split(fact, instruction_ordinal);
    if (parts.has_cold) {
        cold.push_back(parts.cold);
        parts.hot.cold_index = static_cast<std::uint32_t>(cold.size());
    }
    hot.push_back(parts.hot);
}

inline operand_fact_t operand_fact_materialize(
    const operand_fact_hot_t& hot, const operand_fact_cold_t* cold,
    entity_id_t id, entity_id_t instruction_id) noexcept {
    operand_fact_t fact;
    fact.id = id;
    fact.instruction_id = instruction_id;
    fact.displacement = 0;
    fact.immediate = 0;
    const bool has_displacement =
        (hot.flags & static_cast<std::uint16_t>(1U << operand_hot_displacement_bit)) != 0;
    if (has_displacement)
        fact.displacement = static_cast<std::int64_t>(hot.value);
    else
        fact.immediate = hot.value;
    fact.bit_width = cold != nullptr
        ? (hot.width_class != 0 ? operand_hot_width_bits(hot.width_class)
                                : cold->bit_width)
        : operand_hot_width_bits(hot.width_class);
    fact.reg = hot.reg;
    fact.base_reg = hot.base_reg;
    fact.index_reg = hot.index_reg;
    fact.segment_reg = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(hot.segment_reg_hi) << 8U) | hot.segment_reg);
    fact.operand_index = hot.operand_index;
    fact.access_width = hot.access_width;
    fact.kind = static_cast<operand_kind_t>(
        (hot.flags >> operand_hot_kind_shift) & 0x7U);
    fact.access = static_cast<std::uint8_t>(
        (hot.flags >> operand_hot_access_shift) & 0xFU);
    fact.scale = static_cast<std::uint8_t>(
        (hot.flags >> operand_hot_scale_shift) & 0xFU);
    fact.relative =
        (hot.flags & static_cast<std::uint16_t>(1U << operand_hot_relative_bit)) != 0;
    fact.signed_value =
        (hot.flags & static_cast<std::uint16_t>(1U << operand_hot_signed_bit)) != 0;
    fact.has_displacement = has_displacement;
    fact.memory_type = hot.memory_type_wide != 0
        ? hot.memory_type_wide
        : static_cast<std::uint8_t>(
              (hot.flags >> operand_hot_memory_type_shift) & 0x3U);
    fact.resolved_expression_value =
        cold != nullptr ? cold->resolved_expression_value : 0;
    fact.access_width_bits = cold != nullptr ? cold->access_width_bits : 0;
    fact.element_width_bits = cold != nullptr ? cold->element_width_bits : 0;
    fact.address_components =
        cold != nullptr ? cold->address_components : address_component_none;
    fact.access_count = cold != nullptr ? cold->access_count : 0;
    fact.element_count = cold != nullptr ? cold->element_count : 0;
    fact.address_expression = cold != nullptr
        ? static_cast<address_expression_kind_t>(cold->address_expression)
        : address_expression_kind_t::none;
    fact.address_resolution = cold != nullptr
        ? static_cast<target_resolution_t>(cold->address_resolution)
        : target_resolution_t::unresolved_indirect;
    fact.visibility = cold != nullptr ? cold->visibility : 0;
    fact.encoding = cold != nullptr ? cold->encoding : 0;
    fact.decoder_operand_id = cold != nullptr ? cold->decoder_operand_id : 0;
    fact.address_width_bits = cold != nullptr ? cold->address_width_bits : 0;
    fact.has_resolved_expression_value = cold != nullptr &&
        (cold->flags & operand_cold_has_resolved_bit) != 0;
    fact.address_expression_id = cold != nullptr && cold->expression_ordinal != 0
        ? address_expression_entity_tag | cold->expression_ordinal
        : 0;
    return fact;
}

struct target_fact_t {
    entity_id_t instruction_id = 0;
    entity_id_t operand_fact_id = 0;
    entity_id_t address_expression_id = 0;
    address_t target;
    std::uint16_t access_width_bits = 0;
    target_kind_record_t kind = target_kind_record_t::branch;
    target_resolution_t resolution = target_resolution_t::image_relative;
    std::uint8_t operand_index = 0xFFU;
    std::uint8_t access_count = 0;
    bool direct = false;
    bool is_external = false;
};

struct instruction_record_t {
    entity_id_t id = 0;
    std::uint64_t stable_source_id = 0;
    address_t address;
    std::uint32_t opcode_id = 0;
    std::uint32_t operand_fact_begin = 0;
    std::uint32_t target_fact_begin = 0;
    std::uint16_t mnemonic_id = 0;
    std::uint16_t flow_flags = flow_none;
    std::uint16_t operand_fact_count = 0;
    std::uint16_t target_fact_count = 0;
    std::uint8_t length = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    coverage_reason_t coverage = coverage_reason_t::decoded;
};

struct basic_block_record_t {
    entity_id_t id = 0;
    entity_id_t function_id = 0;
    address_t start;
    address_t end;
    std::uint32_t first_instruction = 0;
    std::uint32_t instruction_count = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

inline operand_fact_t operand_fact_materialize(
    const operand_fact_store_t& store, std::uint64_t ordinal,
    const snapshot_table_t<instruction_record_t>& instructions) noexcept {
    const auto& hot = store.hot[static_cast<std::size_t>(ordinal)];
    const operand_fact_cold_t* cold = nullptr;
    if (hot.cold_index != 0 &&
        static_cast<std::size_t>(hot.cold_index - 1U) < store.cold.size())
        cold = &store.cold[static_cast<std::size_t>(hot.cold_index - 1U)];
    entity_id_t instruction_id = instruction_entity_tag | (hot.instruction_ordinal + 1ULL);
    if (hot.instruction_ordinal < instructions.size() &&
        instructions[static_cast<std::size_t>(hot.instruction_ordinal)].id != 0)
        instruction_id =
            instructions[static_cast<std::size_t>(hot.instruction_ordinal)].id;
    return operand_fact_materialize(hot, cold,
        operand_entity_tag | (ordinal & entity_ordinal_mask), instruction_id);
}

struct function_chunk_record_t {
    entity_id_t id = 0;
    entity_id_t function_id = 0;
    address_t start;
    address_t end;
    std::uint32_t first_block = 0;
    std::uint32_t block_count = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool cold = false;
    bool shared = false;
};

enum function_chunk_flag_t : std::uint8_t {
    function_chunk_none = 0,
    function_chunk_shared = 1U << 0,
    function_chunk_cold = 1U << 1
};

struct function_block_membership_record_t {
    entity_id_t function_id = 0;
    entity_id_t chunk_id = 0;
    entity_id_t block_id = 0;
    std::uint32_t block_index = 0;
    std::uint32_t ordinal = 0;
    bool shared = false;
};

struct address_range_t {
    std::uint64_t rva_start = 0;
    std::uint64_t rva_end = 0;
    std::uint8_t chunk_kind = 0;
};

struct function_record_t {
    entity_id_t id = 0;
    address_t start;
    address_t end;
    std::optional<entity_id_t> symbol_id;
    std::vector<address_range_t> chunks;
    std::uint32_t first_block = 0;
    std::uint32_t block_count = 0;
    std::uint32_t first_chunk = 0;
    std::uint32_t chunk_count = 0;
    std::uint32_t first_block_membership = 0;
    std::uint32_t block_membership_count = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool thunk = false;
    bool noreturn = false;
};

enum class edge_kind_t : std::uint8_t {
    fallthrough = 0,
    conditional_taken = 1,
    unconditional = 2,
    call = 3,
    tail_call = 4,
    return_edge = 5,
    exception_edge = 6,
    indirect = 7
};

struct edge_record_t {
    entity_id_t id = 0;
    entity_id_t source_entity = 0;
    std::optional<entity_id_t> target_entity;
    address_t source;
    address_t target;
    edge_kind_t kind = edge_kind_t::fallthrough;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

enum class indirect_call_candidate_kind_t : std::uint8_t {
    target_fact = 0,
    relocation,
    import_slot,
    jump_table,
    vtable,
    pointer_scan,
    decompiler
};

struct call_graph_quality_t {
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::uint32_t contributor_count = 0;
    bool conflicted = false;
};

enum class call_graph_resolution_t : std::uint8_t {
    direct = 0,
    tail_call,
    indirect_candidate,
    unresolved
};

enum class call_graph_conflict_kind_t : std::uint8_t {
    candidate_target_disagreement = 0,
    candidate_identity_mismatch,
    candidate_limit,
    unresolved_site,
    orphan_candidate
};

struct call_graph_conflict_t {
    entity_id_t id = 0;
    call_graph_conflict_kind_t kind =
        call_graph_conflict_kind_t::candidate_target_disagreement;
    entity_id_t instruction_id = 0;
    entity_id_t source_function_id = 0;
    std::uint64_t call_site_rva = 0;
    std::uint64_t selected_target_rva = 0;
    std::uint64_t competing_target_rva = 0;
    entity_id_t selected_target_function_id = 0;
    entity_id_t competing_target_function_id = 0;
};

struct recovered_call_candidate_t {
    entity_id_t id = 0;
    entity_id_t call_site_id = 0;
    address_t target;
    std::optional<entity_id_t> target_function_id;
    indirect_call_candidate_kind_t kind =
        indirect_call_candidate_kind_t::target_fact;
    call_graph_quality_t quality;
    std::uint64_t stable_source_id = 0;
    std::uint32_t rank = 0;
    bool external_target = false;
};

struct recovered_call_site_t {
    entity_id_t id = 0;
    entity_id_t source_function_id = 0;
    entity_id_t source_block_id = 0;
    entity_id_t instruction_id = 0;
    address_t address;
    std::uint32_t first_candidate = 0;
    std::uint32_t candidate_count = 0;
    bool indirect = false;
    bool tail_call = false;
    bool unresolved = false;
};

struct call_graph_edge_record_t {
    entity_id_t id = 0;
    entity_id_t call_site_id = 0;
    entity_id_t source_function_id = 0;
    entity_id_t source_block_id = 0;
    std::optional<entity_id_t> target_function_id;
    address_t call_site;
    address_t target;
    call_graph_resolution_t resolution = call_graph_resolution_t::unresolved;
    call_graph_quality_t quality;
    std::uint32_t candidate_rank = 0;
    bool external_target = false;
    bool target_noreturn = false;
};

struct call_graph_node_record_t {
    entity_id_t function_id = 0;
    address_t address;
    std::uint64_t incoming_edges = 0;
    std::uint64_t outgoing_edges = 0;
    std::uint64_t indirect_edges = 0;
    std::uint64_t unresolved_sites = 0;
};

struct call_graph_publication_t {
    std::vector<call_graph_node_record_t> nodes;
    std::vector<recovered_call_site_t> call_sites;
    std::vector<recovered_call_candidate_t> candidates;
    std::vector<call_graph_edge_record_t> edges;
    std::vector<call_graph_conflict_t> conflicts;
    std::uint64_t indirect_site_count = 0;
    std::uint64_t unresolved_site_count = 0;
    bool bounded = false;
};

enum class xref_kind_t : std::uint8_t {
    code = 0,
    call = 1,
    read = 2,
    write = 3,
    address = 4,
    relocation = 5
};

struct xref_record_t {
    entity_id_t id = 0;
    address_t source;
    address_t target;
    xref_kind_t kind = xref_kind_t::code;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

enum class data_candidate_kind_t : std::uint8_t {
    relocation_slot = 0,
    import_address_slot,
    load_config_pointer,
    thread_local_storage,
    referenced_storage,
    in_image_pointer
};

enum class data_pointer_encoding_t : std::uint8_t {
    absolute_virtual = 0,
    image_relative,
    relocation_target,
    signed_relative_to_slot,
    signed_relative_to_next
};

struct data_candidate_record_t {
    entity_id_t id = 0;
    address_t address;
    std::uint64_t size = 0;
    std::optional<address_t> target;
    data_candidate_kind_t kind = data_candidate_kind_t::referenced_storage;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct data_pointer_fact_t {
    entity_id_t id = 0;
    address_t slot;
    address_t target;
    data_candidate_kind_t candidate_kind = data_candidate_kind_t::in_image_pointer;
    data_pointer_encoding_t encoding = data_pointer_encoding_t::absolute_virtual;
    std::uint8_t width_bytes = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct data_candidate_conflict_t {
    entity_id_t id = 0;
    address_t address;
    std::optional<address_t> selected_target;
    std::optional<address_t> rejected_target;
    data_candidate_kind_t kind = data_candidate_kind_t::referenced_storage;
    fact_provenance_t selected_provenance = fact_provenance_t::unknown;
    fact_provenance_t rejected_provenance = fact_provenance_t::unknown;
    std::uint8_t selected_confidence = 0;
    std::uint8_t rejected_confidence = 0;
};

enum class metadata_provenance_t : std::uint8_t {
    unknown = 0,
    decoded = 1,
    relocation = 2,
    loader_symbol = 3,
    import_metadata = 4,
    export_metadata = 5,
    debug_metadata = 6,
    rtti = 7,
    vtable_validation = 8,
    objective_c_metadata = 9,
    swift_metadata = 10,
    managed_metadata = 11
};

inline std::uint8_t metadata_provenance_rank(metadata_provenance_t provenance) noexcept {
    return static_cast<std::uint8_t>(provenance);
}

enum class symbol_type_candidate_kind_t : std::uint8_t {
    function_prototype = 0,
    import_prototype,
    global_object,
    pointer_object,
    rtti_type,
    virtual_table,
    type_information,
    objective_c_class,
    objective_c_protocol,
    objective_c_selector,
    swift_type,
    swift_protocol,
    managed_type,
    managed_method,
    managed_field,
    debug_type,
    metadata_region
};

enum class type_reference_kind_t : std::uint8_t {
    definition = 0,
    metadata_reference,
    inheritance,
    virtual_table_slot,
    protocol_conformance,
    managed_reference
};

struct symbol_type_candidate_record_t {
    entity_id_t id = 0;
    std::optional<address_t> address;
    std::optional<address_t> related_address;
    std::string display_name;
    std::string canonical_type;
    std::string source_key;
    symbol_type_candidate_kind_t kind = symbol_type_candidate_kind_t::global_object;
    metadata_provenance_t provenance = metadata_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool explicitly_unknown = true;
};

struct type_reference_fact_t {
    entity_id_t id = 0;
    std::optional<address_t> source;
    std::optional<address_t> target;
    entity_id_t source_entity = 0;
    entity_id_t target_entity = 0;
    type_reference_kind_t kind = type_reference_kind_t::metadata_reference;
    metadata_provenance_t provenance = metadata_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::string source_key;
};

enum class metadata_conflict_kind_t : std::uint8_t {
    symbol_kind = 0,
    type_kind,
    canonical_type,
    related_address
};

struct metadata_conflict_record_t {
    entity_id_t id = 0;
    std::optional<address_t> address;
    std::string identity;
    std::string selected_value;
    std::string rejected_value;
    metadata_conflict_kind_t kind = metadata_conflict_kind_t::type_kind;
    metadata_provenance_t selected_provenance = metadata_provenance_t::unknown;
    metadata_provenance_t rejected_provenance = metadata_provenance_t::unknown;
    std::uint8_t selected_confidence = 0;
    std::uint8_t rejected_confidence = 0;
};

struct analysis_rich_fact_publication_t {
    std::vector<data_candidate_record_t> data_candidates;
    std::vector<data_pointer_fact_t> data_pointer_facts;
    std::vector<data_candidate_conflict_t> data_conflicts;
    std::vector<symbol_type_candidate_record_t> type_candidates;
    std::vector<type_reference_fact_t> type_references;
    std::vector<metadata_conflict_record_t> metadata_conflicts;
};

struct unwind_code_t {
    std::uint8_t code_offset = 0;
    std::uint8_t unwind_op = 0;
    std::uint8_t op_info = 0;
};

struct unwind_record_t {
    std::uint64_t function_rva = 0;
    std::uint64_t end_rva = 0;
    std::uint64_t unwind_info_rva = 0;
    std::uint8_t version = 0;
    std::uint8_t flags = 0;
    std::uint8_t frame_reg = 0;
    std::vector<unwind_code_t> unwind_codes;
    std::uint64_t handler_rva = 0;
    std::vector<std::uint8_t> handler_data;
    std::uint64_t chained_function_rva = 0;
    std::uint64_t chained_end_rva = 0;
};

struct exception_edge_t {
    std::uint64_t from_rva = 0;
    std::uint64_t to_rva = 0;
    std::uint8_t edge_kind = 0;
    std::uint64_t handler_rva = 0;
    std::uint8_t provenance = 0;
};

enum class string_encoding_t : std::uint8_t {
    ascii = 0,
    utf8 = 1,
    utf16_le = 2
};

struct string_record_t {
    entity_id_t id = 0;
    address_t address;
    std::uint64_t byte_length = 0;
    std::string value;
    string_encoding_t encoding = string_encoding_t::ascii;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

enum class symbol_kind_t : std::uint8_t {
    function = 0,
    data = 1,
    import_symbol = 2,
    export_symbol = 3,
    debug_symbol = 4,
    type_symbol = 5,
    metadata = 6
};

struct symbol_record_t {
    entity_id_t id = 0;
    address_t address;
    std::string name;
    symbol_kind_t kind = symbol_kind_t::data;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct coverage_span_t {
    address_t start;
    std::uint64_t size = 0;
    std::uint32_t detail_code = 0;
    coverage_reason_t reason = coverage_reason_t::pending;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct snapshot_page_source_holder_t {
    snapshot_page_source_holder_t() = default;
    snapshot_page_source_holder_t(const snapshot_page_source_holder_t& other) noexcept {
        std::atomic_store_explicit(
            &source, std::atomic_load_explicit(&other.source, std::memory_order_acquire),
            std::memory_order_release);
    }
    snapshot_page_source_holder_t& operator=(
        const snapshot_page_source_holder_t& other) noexcept {
        std::atomic_store_explicit(
            &source, std::atomic_load_explicit(&other.source, std::memory_order_acquire),
            std::memory_order_release);
        return *this;
    }
    std::shared_ptr<const paged_domain_source_t> source;
};

struct analysis_snapshot_t {
    binary_id_t binary_id;
    sha256_digest_t load_profile_hash;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    bool baseline_complete = false;
    mutable std::shared_ptr<const workspace_image_t> normalized_image;
    std::shared_ptr<const pe_image_t> image;
    snapshot_table_t<instruction_record_t> instructions;
    std::vector<std::uint8_t> delay_slot_counts;
    operand_fact_store_t operand_facts;
    snapshot_table_t<target_fact_t> target_facts;
    snapshot_table_t<basic_block_record_t> blocks;
    snapshot_table_t<function_chunk_record_t> function_chunks;
    snapshot_table_t<function_block_membership_record_t> function_block_memberships;
    std::vector<function_record_t> functions;
    snapshot_table_t<edge_record_t> edges;
    call_graph_publication_t call_graph;
    snapshot_table_t<xref_record_t> xrefs;
    std::vector<string_record_t> strings;
    std::vector<symbol_record_t> symbols;
    analysis_rich_fact_publication_t rich_facts;
    snapshot_table_t<coverage_span_t> coverage;
    snapshot_table_t<address_expression_record_t> address_expressions;
    snapshot_table_t<address_range_t> function_chunk_ranges;
    fact_residency_plan_t residency_plan;
    std::array<std::uint64_t, fact_domain_count> paged_domain_counts{};
    std::shared_ptr<paged_fact_staging_t> paged_staging;
    mutable snapshot_page_source_holder_t persisted_page_source;
    std::shared_ptr<const packed_string_pool_t> string_pool;
    std::uint64_t string_value_bytes = 0;
    std::uint64_t symbol_name_bytes = 0;
    std::uint64_t function_chunk_bytes = 0;
    std::uint64_t type_candidate_text_bytes = 0;
    std::uint64_t type_reference_key_bytes = 0;
    std::uint64_t metadata_conflict_text_bytes = 0;

    record_span_t<const address_range_t> function_chunks_of(
        const function_record_t& function) const noexcept {
        if (!function.chunks.empty())
            return record_span_t<const address_range_t>(
                function.chunks.data(), function.chunks.size());
        if (function.chunk_count == 0)
            return {};
        const std::uint64_t begin = function.first_chunk;
        if (begin >= function_chunk_ranges.size() ||
            function.chunk_count > function_chunk_ranges.size() - begin)
            return {};
        return record_span_t<const address_range_t>(
            function_chunk_ranges.data() + begin, function.chunk_count);
    }
};

static_assert(sizeof(instruction_record_t) == 56,
              "instruction_record_t must remain 56 bytes for compact snapshot residency");
static_assert(offsetof(instruction_record_t, stable_source_id) == 8,
              "instruction_record_t stable_source_id must stay at offset 8");
static_assert(offsetof(instruction_record_t, address) == 16,
              "instruction_record_t address must stay at offset 16");
static_assert(sizeof(operand_fact_t) == 88,
              "operand_fact_t must remain 88 bytes for compact snapshot residency");
static_assert(offsetof(operand_fact_t, displacement) == 24,
              "operand_fact_t displacement must stay at offset 24");
static_assert(sizeof(operand_fact_hot_t) == 32,
              "operand_fact_hot_t must remain 32 bytes for compact snapshot residency");
static_assert(std::is_trivially_copyable<operand_fact_hot_t>::value,
              "operand_fact_hot_t must remain trivially copyable");
static_assert(sizeof(operand_fact_cold_t) == 32,
              "operand_fact_cold_t must remain 32 bytes for compact snapshot residency");
static_assert(std::is_trivially_copyable<operand_fact_cold_t>::value,
              "operand_fact_cold_t must remain trivially copyable");
static_assert(sizeof(address_expression_record_t) == 12,
              "address_expression_record_t must remain 12 bytes");
static_assert(std::is_trivially_copyable<address_expression_record_t>::value,
              "address_expression_record_t must remain trivially copyable");
static_assert(sizeof(address_range_t) == 24,
              "address_range_t must remain 24 bytes");
static_assert(std::is_trivially_copyable<address_range_t>::value,
              "address_range_t must remain trivially copyable");
static_assert(sizeof(target_fact_t) == 48,
              "target_fact_t must remain 48 bytes for compact snapshot residency");
static_assert(offsetof(target_fact_t, target) == 24,
              "target_fact_t target must stay at offset 24");
static_assert(sizeof(basic_block_record_t) == 64,
              "basic_block_record_t must remain 64 bytes");
static_assert(sizeof(function_chunk_record_t) == 64,
              "function_chunk_record_t must remain 64 bytes");
static_assert(sizeof(function_block_membership_record_t) == 40,
              "function_block_membership_record_t must remain 40 bytes");
static_assert(sizeof(function_record_t) == 112,
              "function_record_t must remain 112 bytes");
static_assert(sizeof(edge_record_t) == 72,
              "edge_record_t must remain 72 bytes");
static_assert(sizeof(xref_record_t) == 48,
              "xref_record_t must remain 48 bytes");
static_assert(sizeof(string_record_t) == 72,
              "string_record_t must remain 72 bytes");
static_assert(sizeof(symbol_record_t) == 64,
              "symbol_record_t must remain 64 bytes");
static_assert(sizeof(coverage_span_t) == 32,
              "coverage_span_t must remain 32 bytes");
static_assert(sizeof(data_candidate_record_t) == 64,
              "data_candidate_record_t must remain 64 bytes");
static_assert(sizeof(data_pointer_fact_t) == 48,
              "data_pointer_fact_t must remain 48 bytes");
static_assert(sizeof(data_candidate_conflict_t) == 80,
              "data_candidate_conflict_t must remain 80 bytes");
static_assert(sizeof(symbol_type_candidate_record_t) == 160,
              "symbol_type_candidate_record_t must remain 160 bytes");
static_assert(sizeof(type_reference_fact_t) == 112,
              "type_reference_fact_t must remain 112 bytes");
static_assert(sizeof(metadata_conflict_record_t) == 136,
              "metadata_conflict_record_t must remain 136 bytes");
static_assert(sizeof(recovered_call_candidate_t) == 80,
              "recovered_call_candidate_t must remain 80 bytes");
static_assert(sizeof(recovered_call_site_t) == 64,
              "recovered_call_site_t must remain 64 bytes");
static_assert(sizeof(call_graph_edge_record_t) == 104,
              "call_graph_edge_record_t must remain 104 bytes");
static_assert(sizeof(call_graph_node_record_t) == 56,
              "call_graph_node_record_t must remain 56 bytes");
static_assert(sizeof(call_graph_quality_t) == 12,
              "call_graph_quality_t must remain 12 bytes");
static_assert(sizeof(call_graph_conflict_t) == 72,
              "call_graph_conflict_t must remain 72 bytes");

static_assert(std::is_trivially_copyable<instruction_record_t>::value,
              "instruction_record_t must remain trivially copyable");
static_assert(std::is_trivially_copyable<operand_fact_t>::value,
              "operand_fact_t must remain trivially copyable");
static_assert(std::is_trivially_copyable<target_fact_t>::value,
              "target_fact_t must remain trivially copyable");
static_assert(std::is_trivially_copyable<basic_block_record_t>::value,
              "basic_block_record_t must remain trivially copyable");
static_assert(std::is_trivially_copyable<function_chunk_record_t>::value,
              "function_chunk_record_t must remain trivially copyable");
static_assert(std::is_trivially_copyable<function_block_membership_record_t>::value,
              "function_block_membership_record_t must remain trivially copyable");
static_assert(std::is_trivially_copyable<xref_record_t>::value,
              "xref_record_t must remain trivially copyable");
static_assert(std::is_trivially_copyable<coverage_span_t>::value,
              "coverage_span_t must remain trivially copyable");

static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<instruction_record_t>,
              "instructions must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<operand_fact_t>,
              "operand_facts must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<target_fact_t>,
              "target_facts must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<basic_block_record_t>,
              "blocks must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<function_chunk_record_t>,
              "function_chunks must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<function_block_membership_record_t>,
              "function_block_memberships must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<edge_record_t>,
              "edges must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<xref_record_t>,
              "xrefs must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<coverage_span_t>,
              "coverage must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<operand_fact_hot_t>,
              "operand hot records must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<operand_fact_cold_t>,
              "operand cold records must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<address_expression_record_t>,
              "address expression records must stay noinit-safe when the stage-2 allocator is active");
static_assert(!snapshot_table_noinit_stage_v ||
              snapshot_table_noinit_safe_v<address_range_t>,
              "function chunk ranges must stay noinit-safe when the stage-2 allocator is active");

std::uint64_t paged_fact_staging_resident_bytes(
    const paged_fact_staging_t* staging) noexcept;

inline workspace_result_t<std::uint64_t> snapshot_memory_accounted_bytes(
    const analysis_snapshot_t& snapshot) {
    std::uint64_t total = sizeof(snapshot);
    const auto add = [&total](std::uint64_t count, std::uint64_t size)
        -> workspace_result_t<void> {
        std::uint64_t bytes = 0;
        std::uint64_t updated = 0;
        if (!checked_mul_u64(count, size, bytes) || !checked_add_u64(total, bytes, updated)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "analysis memory accounting overflows", "memory_budget"));
        }
        total = updated;
        return workspace_result_t<void>::success();
    };
    const std::pair<std::uint64_t, std::uint64_t> allocations[] = {
        {snapshot.instructions.capacity(), sizeof(instruction_record_t)},
        {snapshot.delay_slot_counts.capacity(), sizeof(std::uint8_t)},
        {snapshot.operand_facts.hot.capacity(), sizeof(operand_fact_hot_t)},
        {snapshot.operand_facts.cold.capacity(), sizeof(operand_fact_cold_t)},
        {snapshot.target_facts.capacity(), sizeof(target_fact_t)},
        {snapshot.blocks.capacity(), sizeof(basic_block_record_t)},
        {snapshot.function_chunks.capacity(), sizeof(function_chunk_record_t)},
        {snapshot.function_block_memberships.capacity(), sizeof(function_block_membership_record_t)},
        {snapshot.functions.capacity(), sizeof(function_record_t)},
        {snapshot.edges.capacity(), sizeof(edge_record_t)},
        {snapshot.call_graph.nodes.capacity(), sizeof(call_graph_node_record_t)},
        {snapshot.call_graph.call_sites.capacity(), sizeof(recovered_call_site_t)},
        {snapshot.call_graph.candidates.capacity(), sizeof(recovered_call_candidate_t)},
        {snapshot.call_graph.edges.capacity(), sizeof(call_graph_edge_record_t)},
        {snapshot.call_graph.conflicts.capacity(), sizeof(call_graph_conflict_t)},
        {snapshot.xrefs.capacity(), sizeof(xref_record_t)},
        {snapshot.strings.capacity(), sizeof(string_record_t)},
        {snapshot.symbols.capacity(), sizeof(symbol_record_t)},
        {snapshot.rich_facts.data_candidates.capacity(), sizeof(data_candidate_record_t)},
        {snapshot.rich_facts.data_pointer_facts.capacity(), sizeof(data_pointer_fact_t)},
        {snapshot.rich_facts.data_conflicts.capacity(), sizeof(data_candidate_conflict_t)},
        {snapshot.rich_facts.type_candidates.capacity(), sizeof(symbol_type_candidate_record_t)},
        {snapshot.rich_facts.type_references.capacity(), sizeof(type_reference_fact_t)},
        {snapshot.rich_facts.metadata_conflicts.capacity(), sizeof(metadata_conflict_record_t)},
        {snapshot.coverage.capacity(), sizeof(coverage_span_t)},
        {snapshot.address_expressions.capacity(), sizeof(address_expression_record_t)},
        {snapshot.function_chunk_ranges.capacity(), sizeof(address_range_t)}};
    for (const auto& allocation : allocations) {
        auto added = add(allocation.first, allocation.second);
        if (!added)
            return workspace_result_t<std::uint64_t>::failure(added.error());
    }
    const std::uint64_t ledger[] = {
        snapshot.string_value_bytes,
        snapshot.symbol_name_bytes,
        snapshot.function_chunk_bytes,
        snapshot.type_candidate_text_bytes,
        snapshot.type_reference_key_bytes,
        snapshot.metadata_conflict_text_bytes};
    for (const std::uint64_t bytes : ledger) {
        auto added = add(bytes, 1);
        if (!added)
            return workspace_result_t<std::uint64_t>::failure(added.error());
    }
    if (snapshot.string_pool) {
        auto added = add(snapshot.string_pool->size_accounting().reserved_bytes, 1);
        if (!added)
            return workspace_result_t<std::uint64_t>::failure(added.error());
    }
    if (snapshot.paged_staging) {
        auto added = add(
            paged_fact_staging_resident_bytes(snapshot.paged_staging.get()), 1);
        if (!added)
            return workspace_result_t<std::uint64_t>::failure(added.error());
    }
    return workspace_result_t<std::uint64_t>::success(total);
}

workspace_result_t<void> validate_call_graph_publication(
    const analysis_snapshot_t& snapshot,
    const call_graph_publication_t& publication,
    const cancellation_token_t& cancel = {});

workspace_result_t<void> validate_rich_fact_publication(
    const analysis_snapshot_t& snapshot,
    const analysis_rich_fact_publication_t& publication,
    const cancellation_token_t& cancel = {});

workspace_result_t<void> validate_analysis_snapshot(const analysis_snapshot_t& snapshot,
                                                     bool require_complete_coverage,
                                                     const cancellation_token_t& cancel = {});

std::vector<unwind_record_t> parse_x64_unwind_records(const byte_provider_t& provider,
                                                      const pe_image_t& image,
                                                      const cancellation_token_t& cancel);

std::vector<exception_edge_t> build_exception_edges(const std::vector<unwind_record_t>& unwinds);

}
