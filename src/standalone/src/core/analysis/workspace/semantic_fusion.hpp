#pragma once

#include "analysis_workspace.hpp"
#include "compact_ir.hpp"
#include "workspace_types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace aida::analysis {

inline constexpr std::uint64_t semantic_fusion_model_revision = 2;
inline constexpr std::uint64_t semantic_fusion_max_instructions = 65536;
inline constexpr std::uint64_t semantic_fusion_max_evidence = 262144;

enum class semantic_location_kind_t : std::uint8_t {
    unknown = 0,
    register_value = 1,
    stack_slot = 2,
    global_address = 3,
    memory_address = 4,
    immediate_value = 5,
    temporary = 6,
    function_return = 7,
    function_argument = 8
};

enum class semantic_value_kind_t : std::uint8_t {
    unknown = 0,
    constant = 1,
    symbolic = 2,
    address = 3,
    null_pointer = 4
};

enum class semantic_expression_kind_t : std::uint8_t {
    unknown = 0,
    identity = 1,
    constant_fold = 2,
    algebraic_identity = 3,
    boolean_fold = 4,
    address_fold = 5,
    cast_elision = 6,
    select_fold = 7
};

enum class control_flow_kind_t : std::uint8_t {
    unknown = 0,
    call = 1,
    tail_call = 2,
    conditional_jump = 3,
    unconditional_jump = 4,
    indirect_jump = 5,
    switch_case = 6,
    switch_default = 7,
    return_path = 8,
    exception_path = 9,
    thunk = 10
};

enum class alias_relation_t : std::uint8_t {
    unknown = 0,
    must_alias = 1,
    may_alias = 2,
    no_alias = 3
};

enum class semantic_type_kind_t : std::uint8_t {
    unknown = 0,
    void_type = 1,
    boolean = 2,
    integer = 3,
    floating_point = 4,
    pointer = 5,
    array = 6,
    structure = 7,
    union_type = 8,
    enumeration = 9,
    function = 10,
    reference = 11,
    managed_reference = 12
};

enum class metadata_kind_t : std::uint8_t {
    unknown = 0,
    symbol = 1,
    relocation = 2,
    import = 3,
    export_symbol = 4,
    unwind = 5,
    debug = 6,
    rtti = 7,
    vtable = 8,
    exception_table = 9,
    section = 10,
    user_annotation = 11
};

enum class semantic_idiom_kind_t : std::uint8_t {
    unknown = 0,
    zeroing = 1,
    sign_extension = 2,
    byte_swap = 3,
    rotate = 4,
    bounds_check = 5,
    stack_cookie = 6,
    virtual_dispatch = 7,
    position_independent_address = 8,
    jump_table = 9,
    exception_prologue = 10,
    coroutine = 11
};

enum class semantic_intrinsic_kind_t : std::uint8_t {
    unknown = 0,
    memory_copy = 1,
    memory_set = 2,
    count_leading_zeroes = 3,
    count_trailing_zeroes = 4,
    population_count = 5,
    byte_swap = 6,
    atomic_compare_exchange = 7,
    atomic_fetch_add = 8,
    trap = 9,
    read_thread_pointer = 10,
    system_call = 11
};

enum class semantic_runtime_kind_t : std::uint8_t {
    unknown = 0,
    c_runtime = 1,
    cpp_runtime = 2,
    objc_runtime = 3,
    jvm_runtime = 4,
    dalvik_runtime = 5,
    clr_runtime = 6,
    go_runtime = 7,
    rust_runtime = 8,
    swift_runtime = 9
};

enum class branch_feasibility_t : std::uint8_t {
    unknown = 0,
    feasible = 1,
    infeasible = 2,
    always_taken = 3,
    never_taken = 4
};

enum class semantic_validation_t : std::uint8_t {
    rejected = 0,
    unvalidated = 1,
    derived = 2,
    validated = 3,
    abstained = 4
};

enum class semantic_resolution_t : std::uint8_t {
    accepted = 0,
    rejected = 1,
    abstained = 2,
    conflict = 3,
    bounded = 4,
    cancelled = 5,
    deadline_exceeded = 6
};

enum class semantic_abstention_reason_t : std::uint8_t {
    insufficient_evidence = 0,
    conflicting_evidence = 1,
    unresolved_indirect_target = 2,
    unknown_branch_condition = 3,
    missing_metadata = 4,
    validation_requirement = 5,
    merge_budget_exhausted = 6,
    cancellation_requested = 7,
    deadline_exceeded = 8,
    target_not_found = 9
};

enum class semantic_fact_kind_t : std::uint8_t {
    value = 0,
    value_range = 1,
    expression_simplification = 2,
    control_flow = 3,
    location_access = 4,
    use_def = 5,
    liveness = 6,
    alias = 7,
    prototype = 8,
    calling_convention = 9,
    type = 10,
    metadata = 11,
    idiom = 12,
    branch_feasibility = 13
};

enum class semantic_subject_kind_t : std::uint8_t {
    unknown = 0,
    function = 1,
    instruction = 2,
    location = 3,
    edge = 4,
    call_target = 5,
    type_target = 6,
    metadata_target = 7
};

enum class semantic_origin_t : std::uint8_t {
    unknown = 0,
    workspace_decode = 1,
    workspace_cfg = 2,
    workspace_metadata = 3,
    decompiler_ir = 4,
    decompiler_type_recovery = 5,
    decompiler_simplifier = 6,
    user_annotation = 7,
    external_validator = 8
};

struct semantic_location_t {
    semantic_location_kind_t kind = semantic_location_kind_t::unknown;
    address_space_id_t address_space = address_space_id_t::relative_virtual;
    std::uint16_t register_id = 0;
    std::int64_t stack_offset = 0;
    std::uint64_t global_address = 0;
    std::uint64_t temporary_id = 0;
    std::uint32_t version = 0;
    std::uint16_t bit_width = 0;
    bool is_signed = false;

    friend bool operator==(const semantic_location_t& lhs,
                           const semantic_location_t& rhs) noexcept;
    friend bool operator<(const semantic_location_t& lhs,
                          const semantic_location_t& rhs) noexcept;
};

struct constant_value_t {
    semantic_value_kind_t kind = semantic_value_kind_t::unknown;
    std::uint64_t value = 0;
    std::uint16_t bit_width = 0;
    bool known = false;
    bool symbolic = false;
    bool is_signed = false;
    std::uint64_t definition_rva = 0;
};

struct value_range_t {
    std::uint64_t min = 0;
    std::uint64_t max = 0;
    std::uint16_t bit_width = 0;
    bool bounded = false;
    bool is_signed = false;
    bool wraps = false;
};

struct simplified_expression_t {
    entity_id_t instruction_id = 0;
    address_t address;
    semantic_expression_kind_t kind = semantic_expression_kind_t::unknown;
    semantic_location_t result;
    std::uint64_t left_value = 0;
    std::uint64_t right_value = 0;
    std::uint64_t result_value = 0;
    bool folded = false;
};

struct control_flow_evidence_t {
    control_flow_kind_t kind = control_flow_kind_t::unknown;
    entity_id_t source_instruction_id = 0;
    entity_id_t target_function_id = 0;
    address_t source;
    address_t target;
    std::uint64_t switch_value = 0;
    std::uint32_t switch_index = 0;
    bool direct = false;
    bool external = false;
    bool noreturn = false;
    bool resolved = false;
};

struct location_access_evidence_t {
    semantic_location_t location;
    entity_id_t instruction_id = 0;
    address_t address;
    std::uint16_t access_width_bits = 0;
    std::uint16_t access_count = 0;
    std::uint8_t access = 0;
    bool volatile_access = false;
};

struct definition_site_t {
    entity_id_t instruction_id = 0;
    address_t address;
    semantic_location_t location;
};

struct use_def_chain_t {
    semantic_location_t location;
    std::vector<definition_site_t> definitions;
    std::vector<entity_id_t> uses;
    bool complete = false;
};

struct use_def_evidence_t {
    semantic_location_t location;
    definition_site_t definition;
    entity_id_t use_instruction_id = 0;
    address_t use_address;
    bool definite = false;
};

struct liveness_range_t {
    semantic_location_t location;
    entity_id_t definition_instruction = 0;
    entity_id_t last_use_instruction = 0;
    address_t definition_address;
    address_t last_use_address;
    bool live_in = false;
    bool live_out = false;
};

struct liveness_evidence_t {
    liveness_range_t range;
    bool exact = false;
};

struct alias_evidence_t {
    semantic_location_t left;
    semantic_location_t right;
    alias_relation_t relation = alias_relation_t::unknown;
    std::uint16_t access_width_bits = 0;
};

struct semantic_type_descriptor_t {
    semantic_type_kind_t kind = semantic_type_kind_t::unknown;
    std::uint16_t bit_width = 0;
    std::uint16_t pointer_depth = 0;
    std::uint32_t type_id = 0;
    bool is_signed = false;
    bool is_const = false;
    std::string display_name;
};

struct prototype_evidence_t {
    address_t function;
    abi_id_t abi = abi_id_t::unknown;
    std::vector<semantic_type_descriptor_t> arguments;
    semantic_type_descriptor_t return_type;
    bool variadic = false;
    bool noreturn = false;
};

struct calling_convention_evidence_t {
    address_t function;
    abi_id_t abi = abi_id_t::unknown;
    std::uint16_t stack_pointer_register = 0;
    std::uint16_t frame_pointer_register = 0;
    std::uint16_t return_register = 0;
    std::uint32_t stack_alignment = 0;
    std::uint32_t shadow_space_size = 0;
    bool uses_frame_pointer = false;
    bool variadic = false;
};

struct type_evidence_t {
    semantic_location_t location;
    semantic_type_descriptor_t type;
    entity_id_t instruction_id = 0;
    address_t address;
};

struct metadata_evidence_t {
    metadata_kind_t kind = metadata_kind_t::unknown;
    address_t address;
    std::uint64_t value = 0;
    std::string name;
    bool authoritative = false;
};

struct idiom_evidence_t {
    semantic_idiom_kind_t idiom = semantic_idiom_kind_t::unknown;
    semantic_intrinsic_kind_t intrinsic = semantic_intrinsic_kind_t::unknown;
    semantic_runtime_kind_t runtime = semantic_runtime_kind_t::unknown;
    entity_id_t instruction_id = 0;
    address_t address;
    std::string name;
};

struct branch_feasibility_evidence_t {
    entity_id_t instruction_id = 0;
    address_t branch;
    address_t target;
    branch_feasibility_t feasibility = branch_feasibility_t::unknown;
    bool condition_known = false;
};

using semantic_fact_payload_t = std::variant<constant_value_t,
                                              value_range_t,
                                              simplified_expression_t,
                                              control_flow_evidence_t,
                                              location_access_evidence_t,
                                              use_def_evidence_t,
                                              liveness_evidence_t,
                                              alias_evidence_t,
                                              prototype_evidence_t,
                                              calling_convention_evidence_t,
                                              type_evidence_t,
                                              metadata_evidence_t,
                                              idiom_evidence_t,
                                              branch_feasibility_evidence_t>;

struct semantic_scope_key_t {
    binary_id_t binary_id;
    sha256_digest_t load_profile_hash;
    address_t function_address;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    address_space_id_t address_space = address_space_id_t::relative_virtual;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;

    friend bool operator==(const semantic_scope_key_t& lhs,
                           const semantic_scope_key_t& rhs) noexcept;
    friend bool operator<(const semantic_scope_key_t& lhs,
                          const semantic_scope_key_t& rhs) noexcept;
};

struct semantic_subject_t {
    semantic_subject_kind_t kind = semantic_subject_kind_t::unknown;
    entity_id_t function_id = 0;
    entity_id_t instruction_id = 0;
    address_t address;
    semantic_location_t location;
    std::uint64_t ordinal = 0;

    friend bool operator==(const semantic_subject_t& lhs,
                           const semantic_subject_t& rhs) noexcept;
    friend bool operator<(const semantic_subject_t& lhs,
                          const semantic_subject_t& rhs) noexcept;
};

struct semantic_provenance_t {
    semantic_origin_t origin = semantic_origin_t::unknown;
    fact_provenance_t source = fact_provenance_t::unknown;
    entity_id_t source_entity_id = 0;
    address_t source_address;
    std::uint64_t stable_source_id = 0;
    std::uint64_t source_generation = 0;
    std::uint64_t source_analysis_revision = 0;
    std::uint64_t source_overlay_revision = 0;
    bool independently_validated = false;
};

struct semantic_evidence_t {
    std::uint64_t evidence_id = 0;
    semantic_fact_kind_t kind = semantic_fact_kind_t::value;
    semantic_subject_t subject;
    semantic_fact_payload_t payload;
    semantic_provenance_t provenance;
    semantic_validation_t validation = semantic_validation_t::unvalidated;
    std::uint8_t confidence = 0;
};

struct semantic_merge_budget_t {
    std::size_t max_workspace_instructions = semantic_fusion_max_instructions;
    std::size_t max_evidence_records = semantic_fusion_max_evidence;
    std::size_t max_evidence_per_subject = 128;
    std::size_t max_fused_facts = 131072;
    std::size_t max_conflicts = 16384;
    std::size_t max_abstentions = 16384;
    std::size_t max_provenance_per_fact = 32;
    std::size_t cancellation_poll_interval = 256;
};

struct semantic_validation_policy_t {
    std::uint8_t minimum_confidence = 96;
    std::size_t minimum_independent_sources = 1;
    semantic_validation_t minimum_validation = semantic_validation_t::derived;
    std::uint16_t conflict_margin = 48;
    bool require_independent_validation = false;
    bool permit_dominant_conflict_resolution = true;
};

struct semantic_cache_key_material_t {
    semantic_scope_key_t scope;
    std::uint64_t model_revision = semantic_fusion_model_revision;
    std::uint64_t policy_fingerprint = 0;
    std::uint64_t budget_fingerprint = 0;
    std::uint64_t evidence_fingerprint = 0;
};

struct semantic_fact_t {
    semantic_fact_kind_t kind = semantic_fact_kind_t::value;
    semantic_subject_t subject;
    semantic_fact_payload_t payload;
    semantic_validation_t validation = semantic_validation_t::unvalidated;
    semantic_resolution_t resolution = semantic_resolution_t::abstained;
    std::uint8_t confidence = 0;
    std::vector<std::uint64_t> contributing_evidence_ids;
    std::vector<semantic_provenance_t> provenance;
};

struct semantic_conflict_t {
    semantic_fact_kind_t kind = semantic_fact_kind_t::value;
    semantic_subject_t subject;
    std::vector<std::uint64_t> selected_evidence_ids;
    std::vector<std::uint64_t> conflicting_evidence_ids;
    semantic_resolution_t resolution = semantic_resolution_t::conflict;
    std::uint16_t selected_strength = 0;
    std::uint16_t conflicting_strength = 0;
};

struct semantic_abstention_t {
    semantic_fact_kind_t kind = semantic_fact_kind_t::value;
    semantic_subject_t subject;
    semantic_abstention_reason_t reason = semantic_abstention_reason_t::insufficient_evidence;
    std::vector<std::uint64_t> evidence_ids;
};

struct semantic_fusion_request_t {
    std::uint64_t function_rva = 0;
    std::optional<address_t> function_address;
    std::vector<semantic_evidence_t> decompiler_evidence;
    semantic_merge_budget_t budget;
    semantic_validation_policy_t validation;
    bool derive_workspace_evidence = true;
    std::size_t worker_count_hint = 0;
};

struct semantic_fusion_result_t {
    semantic_scope_key_t scope;
    semantic_cache_key_material_t cache_key;
    std::vector<semantic_fact_t> facts;
    std::vector<semantic_conflict_t> conflicts;
    std::vector<semantic_abstention_t> abstentions;
    std::uint64_t workspace_evidence_collected = 0;
    std::uint64_t evidence_considered = 0;
    std::uint64_t evidence_dropped = 0;
    std::uint64_t merged_subjects = 0;
    std::uint64_t fused_fact_count = 0;
    bool bounded = false;
    bool cancelled = false;
    bool deadline_exceeded = false;
    bool deterministic = true;
};

bool semantic_location_less(const semantic_location_t& lhs,
                            const semantic_location_t& rhs) noexcept;
bool semantic_subject_less(const semantic_subject_t& lhs,
                           const semantic_subject_t& rhs) noexcept;
bool semantic_evidence_less(const semantic_evidence_t& lhs,
                            const semantic_evidence_t& rhs);
std::uint64_t semantic_evidence_fingerprint(const semantic_evidence_t& evidence);
semantic_cache_key_material_t make_semantic_cache_key_material(
    const semantic_scope_key_t& scope,
    const semantic_merge_budget_t& budget,
    const semantic_validation_policy_t& validation,
    const std::vector<semantic_evidence_t>& evidence);
semantic_scope_key_t make_semantic_scope_key(const analysis_workspace_t& workspace,
                                             const analysis_snapshot_t* snapshot,
                                             std::uint64_t function_rva,
                                             std::optional<address_t> function_address = {});
workspace_result_t<semantic_fusion_result_t> reduce_semantic_evidence(
    const semantic_scope_key_t& scope,
    std::vector<semantic_evidence_t> evidence,
    const semantic_merge_budget_t& budget = {},
    const semantic_validation_policy_t& validation = {},
    const cancellation_token_t& cancel = {});
workspace_result_t<semantic_fusion_result_t> fuse_semantic_evidence(
    const analysis_workspace_t& workspace,
    const semantic_fusion_request_t& request = {},
    const cancellation_token_t& cancel = {});
workspace_result_t<semantic_fusion_result_t> run_semantic_fusion(
    const analysis_workspace_t& workspace,
    std::uint64_t function_rva,
    const cancellation_token_t& cancel = {});

}
