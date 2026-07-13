#pragma once

#include "workspace_types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

class byte_provider_t;
class pe_image_t;

using entity_id_t = std::uint64_t;

inline constexpr std::uint64_t entity_ordinal_mask = 0x00FFFFFFFFFFFFFFULL;
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
    std::uint8_t operand_index = 0;
    std::uint8_t decoder_operand_id = 0;
    operand_kind_t kind = operand_kind_t::none;
    std::uint8_t access = 0;
    std::uint8_t visibility = 0;
    std::uint8_t encoding = 0;
    std::uint8_t memory_type = 0;
    std::uint8_t access_width = 0;
    std::uint16_t bit_width = 0;
    std::uint16_t access_width_bits = 0;
    std::uint16_t access_count = 0;
    std::uint16_t element_width_bits = 0;
    std::uint16_t element_count = 0;
    std::uint16_t address_width_bits = 0;
    std::uint16_t reg = 0;
    std::uint16_t segment_reg = 0;
    std::uint16_t base_reg = 0;
    std::uint16_t index_reg = 0;
    std::uint8_t scale = 0;
    bool relative = false;
    bool signed_value = false;
    bool has_displacement = false;
    bool has_resolved_expression_value = false;
    std::int64_t displacement = 0;
    std::uint64_t immediate = 0;
    std::uint64_t resolved_expression_value = 0;
    std::uint16_t address_components = address_component_none;
    address_expression_kind_t address_expression = address_expression_kind_t::none;
    target_resolution_t address_resolution = target_resolution_t::unresolved_indirect;
};

struct target_fact_t {
    entity_id_t instruction_id = 0;
    entity_id_t operand_fact_id = 0;
    entity_id_t address_expression_id = 0;
    address_t target;
    target_kind_record_t kind = target_kind_record_t::branch;
    target_resolution_t resolution = target_resolution_t::image_relative;
    std::uint8_t operand_index = 0xFFU;
    std::uint16_t access_width_bits = 0;
    std::uint16_t access_count = 0;
    bool direct = false;
    bool is_external = false;
};

struct instruction_record_t {
    entity_id_t id = 0;
    address_t address;
    std::uint8_t length = 0;
    std::uint16_t mnemonic_id = 0;
    std::uint32_t opcode_id = 0;
    std::uint32_t flow_flags = flow_none;
    std::uint32_t operand_fact_begin = 0;
    std::uint16_t operand_fact_count = 0;
    std::uint32_t target_fact_begin = 0;
    std::uint16_t target_fact_count = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    coverage_reason_t coverage = coverage_reason_t::decoded;
    std::uint64_t stable_source_id = 0;
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
    std::uint32_t first_block = 0;
    std::uint32_t block_count = 0;
    std::uint32_t first_chunk = 0;
    std::uint32_t chunk_count = 0;
    std::uint32_t first_block_membership = 0;
    std::uint32_t block_membership_count = 0;
    std::optional<entity_id_t> symbol_id;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool thunk = false;
    bool noreturn = false;
    std::vector<address_range_t> chunks;
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
    data_candidate_kind_t kind = data_candidate_kind_t::referenced_storage;
    std::optional<address_t> target;
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
    data_candidate_kind_t kind = data_candidate_kind_t::referenced_storage;
    std::optional<address_t> selected_target;
    std::optional<address_t> rejected_target;
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
    symbol_type_candidate_kind_t kind = symbol_type_candidate_kind_t::global_object;
    std::string display_name;
    std::string canonical_type;
    std::string source_key;
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
    metadata_conflict_kind_t kind = metadata_conflict_kind_t::type_kind;
    std::string selected_value;
    std::string rejected_value;
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
    string_encoding_t encoding = string_encoding_t::ascii;
    std::string value;
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
    coverage_reason_t reason = coverage_reason_t::pending;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::uint32_t detail_code = 0;
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
    std::vector<instruction_record_t> instructions;
    std::vector<std::uint8_t> delay_slot_counts;
    std::vector<operand_fact_t> operand_facts;
    std::vector<target_fact_t> target_facts;
    std::vector<basic_block_record_t> blocks;
    std::vector<function_chunk_record_t> function_chunks;
    std::vector<function_block_membership_record_t> function_block_memberships;
    std::vector<function_record_t> functions;
    std::vector<edge_record_t> edges;
    call_graph_publication_t call_graph;
    std::vector<xref_record_t> xrefs;
    std::vector<string_record_t> strings;
    std::vector<symbol_record_t> symbols;
    analysis_rich_fact_publication_t rich_facts;
    std::vector<coverage_span_t> coverage;
};

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
