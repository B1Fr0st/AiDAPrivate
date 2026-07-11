#pragma once

#include "analysis_workspace.hpp"
#include "advanced_cfg.hpp"
#include "calling_convention.hpp"
#include "compact_ir.hpp"
#include "semantic_fusion.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

inline constexpr std::uint64_t type_recovery_max_constraints = 65536;
inline constexpr std::uint64_t type_recovery_max_iterations = 16;
inline constexpr std::uint64_t type_recovery_max_evidence = 65536;
inline constexpr std::uint64_t type_recovery_max_results = 16384;

enum class recovered_type_kind_t : std::uint8_t {
    unknown = 0,
    void_type = 1,
    integer = 2,
    floating_point = 3,
    pointer = 4,
    struct_type = 5,
    array = 6,
    function_type = 7,
    boolean = 8,
    enum_type = 9,
    reference = 10,
    union_type = 11,
    class_type = 12,
    function_pointer = 13,
    objc_object = 14,
    swift_value = 15,
    managed_object = 16,
    opaque_handle = 17
};

enum class type_signedness_t : std::uint8_t {
    unknown = 0,
    signed_value = 1,
    unsigned_value = 2,
    not_applicable = 3
};

enum class type_language_t : std::uint8_t {
    unknown = 0,
    c = 1,
    cpp = 2,
    objective_c = 3,
    swift = 4,
    csharp = 5,
    java = 6,
    kotlin = 7,
    rust = 8,
    go = 9
};

enum class type_subject_kind_t : std::uint8_t {
    unknown = 0,
    local = 1,
    parameter = 2,
    return_value = 3,
    global = 4,
    register_value = 5,
    stack_slot = 6,
    memory_location = 7,
    array_element = 8,
    field = 9,
    function = 10,
    function_pointer = 11,
    virtual_table = 12,
    virtual_slot = 13,
    rtti_type = 14,
    objc_class = 15,
    swift_type = 16,
    managed_type = 17,
    imported_symbol = 18,
    exported_symbol = 19,
    metadata_type = 20
};

enum class type_evidence_provenance_t : std::uint8_t {
    unknown = 0,
    instruction_semantics = 1,
    control_flow = 2,
    interprocedural = 3,
    source_symbol = 4,
    debug_info = 5,
    import_symbol = 6,
    export_symbol = 7,
    decompiler = 8,
    binary_metadata = 9,
    rtti = 10,
    vtable = 11,
    objc_metadata = 12,
    swift_metadata = 13,
    managed_metadata = 14,
    user_definition = 15,
    calling_convention = 16
};

enum class type_evidence_kind_t : std::uint8_t {
    unknown = 0,
    direct_declaration = 1,
    value_width = 2,
    signedness = 3,
    pointer_dereference = 4,
    memory_access = 5,
    array_stride = 6,
    field_offset = 7,
    assignment = 8,
    call_argument = 9,
    call_return = 10,
    function_target = 11,
    source_symbol = 12,
    debug_symbol = 13,
    import_symbol = 14,
    export_symbol = 15,
    decompiler_hint = 16,
    metadata_hint = 17,
    rtti_descriptor = 18,
    vtable_descriptor = 19,
    vtable_slot = 20,
    objc_descriptor = 21,
    swift_descriptor = 22,
    managed_descriptor = 23,
    inheritance = 24,
    user_override = 25,
    calling_convention_argument = 26,
    calling_convention_return = 27,
    calling_convention_function = 28
};

enum class type_constraint_kind_t : std::uint8_t {
    register_width = 0,
    memory_access_width = 1,
    call_argument = 2,
    call_return = 3,
    store_value = 4,
    load_value = 5,
    arithmetic_result = 6,
    comparison_operand = 7,
    field_access = 8,
    pointer_dereference = 9,
    assignment = 10,
    rtti_hint = 11,
    array_element = 12,
    function_target = 13,
    inheritance = 14,
    virtual_dispatch = 15,
    metadata_declaration = 16,
    calling_convention_argument = 17,
    calling_convention_return = 18
};

enum class type_constraint_relation_t : std::uint8_t {
    unknown = 0,
    compatible = 1,
    assignment = 2,
    points_to = 3,
    member_of = 4,
    array_element_of = 5,
    call_argument_to = 6,
    call_return_from = 7,
    inherits_from = 8,
    virtual_slot_of = 9
};

enum class type_resolution_state_t : std::uint8_t {
    unknown = 0,
    resolved = 1,
    conflicted = 2,
    abstained = 3
};

enum class type_abstention_reason_t : std::uint8_t {
    no_evidence = 0,
    insufficient_confidence = 1,
    incompatible_evidence = 2,
    result_limit = 3,
    cancellation = 4,
    deadline = 5
};

enum class type_recovery_status_t : std::uint8_t {
    complete = 0,
    partial = 1,
    no_evidence = 2,
    cancelled = 3,
    deadline_exceeded = 4,
    result_limited = 5
};

struct type_subject_t {
    type_subject_kind_t kind = type_subject_kind_t::unknown;
    address_t address;
    std::uint64_t entity_id = 0;
    std::uint64_t container_id = 0;
    std::uint64_t function_rva = 0;
    std::int64_t stack_offset = 0;
    std::uint32_t ordinal = 0;
    std::uint16_t reg = 0;
    std::string stable_name;
};

struct type_descriptor_t {
    recovered_type_kind_t kind = recovered_type_kind_t::unknown;
    type_signedness_t signedness = type_signedness_t::unknown;
    type_language_t language = type_language_t::unknown;
    std::uint16_t bit_width = 0;
    std::uint16_t element_bit_width = 0;
    std::uint32_t element_count = 0;
    std::uint64_t referenced_type_id = 0;
    std::string declared_name;
    std::string referenced_type_name;
    bool nullable = false;
    bool variadic = false;
    bool noreturn = false;
};

struct type_recovery_evidence_t {
    std::uint64_t evidence_id = 0;
    type_subject_t subject;
    std::optional<type_subject_t> related_subject;
    type_descriptor_t candidate;
    type_evidence_provenance_t provenance = type_evidence_provenance_t::unknown;
    type_evidence_kind_t kind = type_evidence_kind_t::unknown;
    address_t source_address;
    std::uint64_t source_entity_id = 0;
    std::uint8_t confidence = 0;
    std::uint32_t propagation_hops = 0;
    bool hard_constraint = false;
    bool propagated = false;
    std::string detail;
};

struct type_constraint_t {
    type_constraint_kind_t kind = type_constraint_kind_t::register_width;
    type_constraint_relation_t relation = type_constraint_relation_t::unknown;
    type_subject_t source;
    std::optional<type_subject_t> target;
    type_descriptor_t candidate;
    std::uint16_t reg = 0;
    std::int64_t stack_offset = 0;
    std::uint16_t bit_width = 0;
    std::uint64_t instruction_rva = 0;
    recovered_type_kind_t inferred_kind = recovered_type_kind_t::unknown;
    std::uint64_t source_instruction_id = 0;
    std::uint64_t target_entity_id = 0;
    type_evidence_provenance_t provenance = type_evidence_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::uint32_t propagation_hops = 0;
    bool is_signed = false;
    bool is_stack = false;
    bool propagate = false;
};

struct struct_field_t {
    std::uint64_t offset = 0;
    recovered_type_kind_t kind = recovered_type_kind_t::unknown;
    std::uint16_t bit_width = 0;
    std::string name;
    bool is_pointer = false;
    type_resolution_state_t state = type_resolution_state_t::unknown;
    std::uint8_t confidence = 0;
    std::vector<std::uint64_t> evidence_ids;
};

struct recovered_struct_t {
    std::uint64_t rva = 0;
    std::uint64_t estimated_size = 0;
    std::vector<struct_field_t> fields;
    std::vector<std::uint64_t> base_type_ids;
    std::uint64_t type_id = 0;
    recovered_type_kind_t kind = recovered_type_kind_t::struct_type;
    type_language_t language = type_language_t::unknown;
    std::string name;
    std::uint8_t confidence = 0;
    bool has_virtual_table = false;
};

struct rtti_class_info_t {
    std::uint64_t type_descriptor_rva = 0;
    std::uint64_t class_descriptor_rva = 0;
    std::string class_name;
    std::vector<std::uint64_t> base_class_rvas;
    std::uint64_t vtable_rva = 0;
    std::uint64_t collocated_rva = 0;
    type_language_t language = type_language_t::cpp;
    std::uint8_t confidence = 0;
    bool is_polymorphic = false;
};

struct vtable_entry_t {
    std::uint64_t entry_rva = 0;
    std::uint64_t function_rva = 0;
    std::uint64_t slot_index = 0;
    type_resolution_state_t state = type_resolution_state_t::unknown;
    std::uint8_t confidence = 0;
};

struct recovered_vtable_t {
    std::uint64_t vtable_rva = 0;
    std::uint64_t owning_struct_rva = 0;
    std::vector<vtable_entry_t> entries;
    std::uint64_t entry_count = 0;
    std::string name;
    type_language_t language = type_language_t::cpp;
    std::uint8_t confidence = 0;
};

struct prototype_info_t {
    std::vector<recovered_type_kind_t> argument_types;
    recovered_type_kind_t return_type = recovered_type_kind_t::unknown;
    std::vector<std::uint16_t> argument_bit_widths;
    std::uint16_t return_bit_width = 0;
    std::uint64_t call_site_rva = 0;
    std::uint64_t target_function_rva = 0;
    type_language_t language = type_language_t::unknown;
    type_resolution_state_t return_state = type_resolution_state_t::unknown;
    cc_abi_t calling_convention = cc_abi_t::unknown;
    cc_inference_state_t calling_convention_state = cc_inference_state_t::unknown;
    cc_value_state_t arguments_state = cc_value_state_t::unknown;
    cc_value_state_t return_value_state = cc_value_state_t::unknown;
    cc_value_state_t variadic_state = cc_value_state_t::unknown;
    bool is_variadic = false;
    bool is_noreturn = false;
    bool indirect = false;
    std::uint8_t confidence = 0;
};

struct recovered_type_t {
    recovered_type_kind_t kind = recovered_type_kind_t::unknown;
    std::uint16_t bit_width = 0;
    std::uint16_t reg = 0;
    std::int64_t stack_offset = 0;
    bool is_signed = false;
    bool is_stack = false;
    std::uint64_t instruction_rva = 0;
    type_subject_t subject;
    type_descriptor_t descriptor;
    type_resolution_state_t state = type_resolution_state_t::unknown;
    std::vector<std::uint64_t> supporting_evidence_ids;
    std::vector<std::uint64_t> conflicting_evidence_ids;
    std::optional<recovered_struct_t> struct_info;
    std::optional<prototype_info_t> prototype;
    std::uint8_t confidence = 0;
    std::string display_name;
};

struct type_conflict_t {
    type_subject_t subject;
    std::vector<type_descriptor_t> candidates;
    std::vector<std::uint64_t> evidence_ids;
    std::uint8_t winning_confidence = 0;
    bool hard_conflict = false;
};

struct type_abstention_t {
    type_subject_t subject;
    type_abstention_reason_t reason = type_abstention_reason_t::no_evidence;
    std::vector<std::uint64_t> evidence_ids;
};

struct type_recovery_limits_t {
    std::uint64_t max_evidence = type_recovery_max_evidence;
    std::uint64_t max_constraints = type_recovery_max_constraints;
    std::uint64_t max_results = type_recovery_max_results;
    std::uint64_t max_fields_per_aggregate = 512;
    std::uint64_t max_aggregates = 2048;
    std::uint64_t max_vtables = 2048;
    std::uint64_t max_prototypes = 4096;
    std::uint64_t max_interprocedural_functions = 64;
    std::uint32_t max_interprocedural_depth = 2;
    std::uint32_t max_propagation_iterations =
        static_cast<std::uint32_t>(type_recovery_max_iterations);
    std::uint8_t minimum_confidence = 35;
    std::uint8_t conflict_margin = 12;
};

struct type_recovery_cache_key_t {
    binary_id_t binary_id;
    address_t root_address;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    target_kind_t target_kind = target_kind_t::static_file;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    calling_convention_cache_key_t calling_convention_key;
    std::uint64_t calling_convention_fingerprint = 0;
    std::uint64_t options_fingerprint = 0;
};

struct type_recovery_request_t {
    std::uint64_t function_rva = 0;
    address_space_id_t address_space = address_space_id_t::relative_virtual;
    type_recovery_limits_t limits;
    std::vector<type_recovery_evidence_t> injected_evidence;
    const semantic_fusion_result_t* semantic_result = nullptr;
    const cfg_analysis_result_t* cfg_result = nullptr;
    const cc_analysis_result_t* calling_convention_result = nullptr;
    bool include_image_metadata = true;
    bool include_interprocedural = true;
    bool consume_semantic_facts = true;
    bool consume_cfg_facts = true;
    bool consume_calling_convention_facts = true;
};

struct type_recovery_result_t {
    std::vector<recovered_type_t> types;
    std::vector<recovered_struct_t> structs;
    std::vector<rtti_class_info_t> rtti_classes;
    std::vector<recovered_vtable_t> vtables;
    std::vector<prototype_info_t> prototypes;
    std::vector<type_constraint_t> constraints;
    std::vector<type_recovery_evidence_t> evidence;
    std::vector<type_conflict_t> conflicts;
    std::vector<type_abstention_t> abstentions;
    type_recovery_cache_key_t cache_key;
    std::uint64_t function_rva = 0;
    std::uint64_t constraints_collected = 0;
    std::uint64_t evidence_collected = 0;
    std::uint64_t propagation_iterations = 0;
    std::uint64_t interprocedural_functions = 0;
    std::uint64_t iterations = 0;
    std::uint64_t types_recovered = 0;
    std::uint64_t structs_recovered = 0;
    std::uint64_t vtables_recovered = 0;
    type_recovery_status_t status = type_recovery_status_t::no_evidence;
    bool bounded = false;
    bool cancelled = false;
    bool deadline_exceeded = false;
};

bool operator==(const type_recovery_cache_key_t& lhs,
                const type_recovery_cache_key_t& rhs) noexcept;
bool operator!=(const type_recovery_cache_key_t& lhs,
                const type_recovery_cache_key_t& rhs) noexcept;
std::string stable_type_recovery_cache_key_material(const type_recovery_cache_key_t& key);
type_recovery_cache_key_t make_type_recovery_cache_key(
    const analysis_workspace_t& workspace, const type_recovery_request_t& request);

workspace_result_t<type_recovery_result_t>
    recover_types(const analysis_workspace_t& workspace,
                  const type_recovery_request_t& request,
                  const cancellation_token_t& cancel);

workspace_result_t<type_recovery_result_t>
    recover_types(const analysis_workspace_t& workspace,
                  std::uint64_t function_rva,
                  const cancellation_token_t& cancel);

}
