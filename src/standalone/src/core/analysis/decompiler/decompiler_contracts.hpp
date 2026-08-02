#pragma once

#include "../workspace/compact_ir.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace aida::analysis {

constexpr std::uint32_t k_decompiler_contract_schema_version = 2;
constexpr std::uint32_t k_provider_ir_schema_version = 1;
constexpr std::uint32_t k_hir_schema_version = 1;
constexpr std::uint32_t k_type_graph_schema_version = 1;
constexpr std::uint32_t k_typed_pseudocode_ast_schema_version = 2;
constexpr std::uint32_t k_decompiler_document_schema_version = 1;
constexpr std::uint32_t k_decompiler_cache_key_schema_version = 2;
constexpr std::uint32_t k_decompiler_render_evidence_schema_version = 2;
constexpr std::size_t k_decompiler_render_evidence_max_entries = 1U << 20;
constexpr std::size_t k_decompiler_render_evidence_max_text_bytes = 4096;
constexpr std::uint32_t k_decompiler_worker_protocol_version = 3;
constexpr std::size_t k_decompiler_worker_control_frame_max_bytes = 8U * 1024U * 1024U;
constexpr std::size_t k_decompiler_worker_result_frame_max_bytes = 80U * 1024U * 1024U;
constexpr std::size_t k_decompiler_worker_provider_artifacts_max_bytes = 48U * 1024U * 1024U;
constexpr std::size_t k_decompiler_worker_printc_evidence_max_bytes = 8U * 1024U * 1024U;
static_assert(k_decompiler_worker_control_frame_max_bytes <=
    k_decompiler_worker_result_frame_max_bytes);
static_assert(k_decompiler_worker_provider_artifacts_max_bytes +
    k_decompiler_worker_printc_evidence_max_bytes <
    k_decompiler_worker_result_frame_max_bytes);
constexpr std::uint64_t k_decompiler_profile_max_cpu_ms = 60'000;
constexpr std::uint64_t k_decompiler_profile_max_memory_bytes = 4ULL << 30;

enum class decompiler_entity_kind_t : std::uint8_t {
    native_function = 1,
    cli_method = 2,
    jvm_method = 3,
    dalvik_method = 4
};

enum class decompiler_coordinate_layer_t : std::uint8_t {
    provider_ir = 1,
    hir = 2,
    typed_ast = 3,
    document = 4
};

enum class decompiler_provider_id_t : std::uint8_t {
    ghidra_native = 1,
    ilspy_cli = 2,
    jvm_ssa = 3,
    dalvik_ssa = 4
};

enum class decompiler_unknown_reason_t : std::uint8_t {
    unsupported_instruction = 1,
    unsupported_metadata = 2,
    unresolved_reference = 3,
    opaque_control_flow = 4,
    bounded_analysis_limit = 5,
    semantic_timeout = 6,
    incomplete_debug_information = 7,
    conflicting_type_evidence = 8,
    malformed_input = 9,
    provider_abstained = 10
};

enum class decompiler_diagnostic_severity_t : std::uint8_t {
    note = 1,
    warning = 2,
    error = 3
};

enum class decompiler_diagnostic_code_t : std::uint16_t {
    invalid_contract = 1,
    malformed_serialization = 2,
    unsupported_entity = 3,
    unsupported_provider = 4,
    unsupported_architecture = 5,
    provider_failure = 6,
    worker_protocol_failure = 7,
    worker_integrity_failure = 8,
    resource_limit = 9,
    deadline_exceeded = 10,
    cancelled = 11,
    unresolved_type = 12,
    unresolved_symbol = 13,
    malformed_provider_ir = 14,
    malformed_hir = 15,
    malformed_type_graph = 16,
    malformed_ast = 17,
    malformed_document = 18,
    cache_key_rejected = 19,
    source_map_rejected = 20,
    partial_decompilation = 21
};

enum class decompiler_fact_provenance_t : std::uint8_t {
    loader_metadata = 1,
    debug_metadata = 2,
    provider_semantics = 3,
    bytecode_verifier = 4,
    rtti = 5,
    objc_metadata = 6,
    swift_metadata = 7,
    call_signature = 8,
    semantic_proof = 9,
    user_overlay = 10,
    unknown = 11
};

enum class provider_ir_opcode_t : std::uint16_t {
    parameter = 1,
    local = 2,
    constant = 3,
    copy = 4,
    unary = 5,
    binary = 6,
    cast = 7,
    load = 8,
    store = 9,
    field_load = 10,
    field_store = 11,
    array_load = 12,
    array_store = 13,
    call = 14,
    indirect_call = 15,
    phi = 16,
    branch = 17,
    conditional_branch = 18,
    switch_branch = 19,
    return_value = 20,
    throw_value = 21,
    monitor_enter = 22,
    monitor_exit = 23,
    unknown = 24
};

enum class hir_node_kind_t : std::uint16_t {
    parameter = 1,
    local = 2,
    literal = 3,
    reference = 4,
    unary = 5,
    binary = 6,
    cast = 7,
    assignment = 8,
    load = 9,
    store = 10,
    field = 11,
    index = 12,
    call = 13,
    phi = 14,
    branch = 15,
    conditional = 16,
    switch_branch = 17,
    return_value = 18,
    throw_value = 19,
    unknown = 20
};

enum class decompiler_type_kind_t : std::uint8_t {
    unknown = 1,
    void_type = 2,
    boolean = 3,
    signed_integer = 4,
    unsigned_integer = 5,
    floating_point = 6,
    pointer = 7,
    reference = 8,
    array = 9,
    vector = 10,
    structure = 11,
    union_type = 12,
    enumeration = 13,
    function = 14,
    class_type = 15,
    interface_type = 16,
    generic_parameter = 17,
    generic_instance = 18,
    managed_by_reference = 19
};

enum class decompiler_type_edge_kind_t : std::uint8_t {
    member = 1,
    base = 2,
    pointee = 3,
    element = 4,
    return_type = 5,
    parameter = 6,
    alias = 7,
    generic_argument = 8,
    constraint = 9
};

enum class typed_pseudocode_ast_node_kind_t : std::uint16_t {
    function_definition = 1,
    compound_statement = 2,
    declaration = 3,
    expression_statement = 4,
    if_statement = 5,
    else_clause = 6,
    while_statement = 7,
    do_while_statement = 8,
    for_statement = 9,
    switch_statement = 10,
    switch_case = 11,
    break_statement = 12,
    continue_statement = 13,
    return_statement = 14,
    throw_statement = 15,
    try_statement = 16,
    catch_clause = 17,
    finally_clause = 18,
    assignment_expression = 19,
    unary_expression = 20,
    binary_expression = 21,
    cast_expression = 22,
    call_expression = 23,
    member_expression = 24,
    index_expression = 25,
    identifier = 26,
    literal = 27,
    unknown_expression = 28,
    goto_statement = 29,
    label_statement = 30,
    comment_statement = 31
};

enum class decompiler_document_token_kind_t : std::uint8_t {
    keyword = 1,
    identifier = 2,
    type_name = 3,
    literal = 4,
    operator_token = 5,
    punctuation = 6,
    whitespace = 7,
    unknown = 8,
    comment = 9
};

enum class decompiler_profile_id_t : std::uint8_t {
    fast = 1,
    balanced = 2,
    thorough = 3
};

enum class decompiler_semantic_proof_availability_t : std::uint8_t {
    not_requested = 1,
    ready = 2,
    triton_unavailable = 3,
    z3_unavailable = 4,
    z3_not_linked = 5,
    adapter_denied = 6
};

enum class decompiler_cache_stage_t : std::uint8_t {
    provider_ir = 1,
    normalized_hir_ast = 2,
    rendered_document = 3
};

enum class decompiler_worker_message_kind_t : std::uint8_t {
    hello = 1,
    job_request = 2,
    cancel_request = 3,
    document = 4,
    failure = 5,
    heartbeat = 6
};

struct decompiler_address_range_t {
    address_t begin;
    address_t end;
};

struct decompiler_token_range_t {
    std::uint32_t begin = 0;
    std::uint32_t end = 0;
};

struct decompiler_instruction_range_t {
    std::uint64_t first_instruction_id = 0;
    std::uint64_t last_instruction_id = 0;
};

struct decompiler_source_origin_t {
    sha256_digest_t source_artifact_hash;
    std::string source_path;
    std::uint32_t first_line = 0;
    std::uint32_t first_column = 0;
    std::uint32_t last_line = 0;
    std::uint32_t last_column = 0;
};

struct native_decompiler_entity_identity_t {
    entity_id_t function_id = 0;
    address_t entry;
    address_t end;
    sha256_digest_t function_bytes_hash;
    std::string canonical_symbol;
};

struct cli_decompiler_entity_identity_t {
    sha256_digest_t module_hash;
    std::string assembly_identity;
    std::string module_name;
    std::uint32_t metadata_token = 0;
    std::string declaring_type;
    std::string method_name;
    std::string method_signature;
    std::uint32_t generic_arity = 0;
};

struct jvm_decompiler_entity_identity_t {
    sha256_digest_t class_artifact_hash;
    std::string class_internal_name;
    std::string method_name;
    std::string method_descriptor;
    std::uint32_t method_index = 0;
    std::uint32_t code_offset = 0;
};

struct dalvik_decompiler_entity_identity_t {
    sha256_digest_t dex_hash;
    std::uint32_t dex_ordinal = 0;
    std::string class_descriptor;
    std::string method_name;
    std::string prototype;
    std::uint32_t method_id = 0;
    std::uint32_t code_item_offset = 0;
};

using decompiler_entity_identity_t = std::variant<
    native_decompiler_entity_identity_t,
    cli_decompiler_entity_identity_t,
    jvm_decompiler_entity_identity_t,
    dalvik_decompiler_entity_identity_t>;

struct decompiler_entity_key_t {
    std::uint32_t schema_version = k_decompiler_contract_schema_version;
    decompiler_entity_kind_t kind = decompiler_entity_kind_t::native_function;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t mode = architecture_mode_t::unknown;
    endian_t endian = endian_t::little;
    decompiler_entity_identity_t identity;

    bool operator==(const decompiler_entity_key_t& other) const noexcept;
    bool operator!=(const decompiler_entity_key_t& other) const noexcept { return !(*this == other); }
    bool operator<(const decompiler_entity_key_t& other) const noexcept;
};

struct source_coordinate_t {
    decompiler_coordinate_layer_t layer = decompiler_coordinate_layer_t::provider_ir;
    std::uint64_t workspace_generation = 0;
    decompiler_entity_key_t entity;
    std::optional<decompiler_address_range_t> address_range;
    std::optional<decompiler_token_range_t> token_range;
    std::optional<decompiler_instruction_range_t> instruction_range;
    std::optional<decompiler_token_range_t> document_range;
    std::optional<decompiler_source_origin_t> source_origin;
};

struct decompiler_diagnostic_t {
    decompiler_diagnostic_severity_t severity = decompiler_diagnostic_severity_t::error;
    decompiler_diagnostic_code_t code = decompiler_diagnostic_code_t::invalid_contract;
    std::string localization_key;
    std::vector<std::string> localization_arguments;
    std::optional<source_coordinate_t> coordinate;
    std::uint8_t confidence = 0;
    bool retryable = false;
    std::uint32_t ordinal = 0;
};

struct decompiler_unknown_t {
    decompiler_unknown_reason_t reason = decompiler_unknown_reason_t::provider_abstained;
    std::string stable_token;
    source_coordinate_t coordinate;
    std::uint8_t confidence = 0;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
};

struct decompiler_provider_identity_t {
    decompiler_provider_id_t provider = decompiler_provider_id_t::ghidra_native;
    std::string provider_name;
    std::string provider_version;
    sha256_digest_t provider_binary_hash;
    std::string worker_build_id;
    sha256_digest_t worker_build_hash;
};

struct decompiler_language_identity_t {
    std::string language_id;
    std::string language_version;
    std::string compiler_spec_id;
    sha256_digest_t language_spec_hash;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t mode = architecture_mode_t::unknown;
    endian_t endian = endian_t::little;
};

struct provider_ir_value_t {
    std::uint64_t id = 0;
    provider_ir_opcode_t opcode = provider_ir_opcode_t::unknown;
    std::uint64_t type_id = 0;
    std::vector<std::uint64_t> operand_ids;
    std::string stable_immediate;
    std::string stable_symbol;
    source_coordinate_t coordinate;
    std::uint8_t confidence = 0;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
};

struct provider_ir_block_t {
    std::uint64_t id = 0;
    std::vector<std::uint64_t> predecessor_ids;
    std::vector<std::uint64_t> successor_ids;
    std::vector<std::uint64_t> exception_successor_ids;
    std::vector<provider_ir_value_t> values;
    source_coordinate_t coordinate;
};

struct provider_ir_t {
    std::uint32_t schema_version = k_provider_ir_schema_version;
    decompiler_provider_identity_t provider;
    decompiler_language_identity_t language;
    decompiler_entity_key_t entity;
    std::uint64_t entry_block_id = 0;
    std::vector<provider_ir_block_t> blocks;
    std::vector<source_coordinate_t> source_coordinates;
    std::vector<decompiler_unknown_t> unknowns;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct hir_value_t {
    std::uint64_t id = 0;
    hir_node_kind_t kind = hir_node_kind_t::unknown;
    std::uint64_t type_id = 0;
    std::vector<std::uint64_t> operand_ids;
    std::string stable_value;
    source_coordinate_t coordinate;
    std::uint8_t confidence = 0;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
};

struct hir_block_t {
    std::uint64_t id = 0;
    std::vector<std::uint64_t> predecessor_ids;
    std::vector<std::uint64_t> successor_ids;
    std::vector<std::uint64_t> exception_successor_ids;
    std::vector<hir_value_t> values;
    source_coordinate_t coordinate;
};

struct hir_variable_t {
    std::uint64_t id = 0;
    std::string stable_name;
    std::uint64_t type_id = 0;
    source_coordinate_t coordinate;
    std::uint8_t confidence = 0;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
};

struct hir_function_t {
    std::uint32_t schema_version = k_hir_schema_version;
    decompiler_entity_key_t entity;
    sha256_digest_t provider_ir_hash;
    std::uint64_t type_graph_revision = 0;
    std::uint64_t return_type_id = 0;
    std::vector<hir_variable_t> parameters;
    std::vector<hir_variable_t> locals;
    std::vector<hir_block_t> blocks;
    std::vector<source_coordinate_t> source_coordinates;
    std::vector<decompiler_unknown_t> unknowns;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct decompiler_type_node_t {
    std::uint64_t id = 0;
    decompiler_type_kind_t kind = decompiler_type_kind_t::unknown;
    std::string canonical_name;
    std::string display_name;
    std::optional<std::uint64_t> byte_size;
    std::uint32_t alignment = 0;
    bool is_signed = false;
    std::uint8_t confidence = 0;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
    std::vector<source_coordinate_t> coordinates;
};

struct decompiler_type_edge_t {
    std::uint64_t source_type_id = 0;
    std::uint64_t target_type_id = 0;
    decompiler_type_edge_kind_t kind = decompiler_type_edge_kind_t::member;
    std::string stable_name;
    std::optional<std::uint64_t> byte_offset;
    std::uint32_t ordinal = 0;
    std::uint8_t confidence = 0;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
};

struct type_graph_t {
    std::uint32_t schema_version = k_type_graph_schema_version;
    decompiler_entity_key_t entity;
    std::uint64_t revision = 0;
    std::vector<decompiler_type_node_t> nodes;
    std::vector<decompiler_type_edge_t> edges;
    std::vector<decompiler_unknown_t> unknowns;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct typed_pseudocode_ast_node_t {
    std::uint64_t id = 0;
    typed_pseudocode_ast_node_kind_t kind = typed_pseudocode_ast_node_kind_t::unknown_expression;
    std::uint64_t type_id = 0;
    std::vector<std::uint64_t> child_ids;
    std::string stable_text;
    source_coordinate_t coordinate;
    std::uint8_t confidence = 0;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::unknown;
};

struct typed_pseudocode_ast_v2_t {
    std::uint32_t schema_version = k_typed_pseudocode_ast_schema_version;
    decompiler_entity_key_t entity;
    sha256_digest_t hir_hash;
    sha256_digest_t type_graph_hash;
    std::uint64_t root_node_id = 0;
    std::uint64_t body_node_id = 0;
    std::vector<typed_pseudocode_ast_node_t> nodes;
    std::vector<source_coordinate_t> source_coordinates;
    std::vector<decompiler_unknown_t> unknowns;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct decompiler_document_token_t {
    decompiler_document_token_kind_t kind = decompiler_document_token_kind_t::unknown;
    decompiler_token_range_t range;
    std::uint64_t ast_node_id = 0;
};

struct decompiler_document_source_map_t {
    decompiler_token_range_t document_range;
    std::vector<source_coordinate_t> coordinates;
};

struct readability_transform_settings_t {
    bool enable_variable_renaming = true;
    bool enable_expression_simplification = true;
    bool enable_temporary_coalescing = true;
    bool enable_loop_counter_naming = true;
    bool enable_api_call_naming = true;
    bool enable_type_based_naming = true;
    bool enable_string_reference_naming = true;
    bool enable_constant_folding = true;
    bool enable_identity_simplification = true;
    bool enable_cast_simplification = true;
    bool enable_comparison_normalization = true;
    bool enable_compound_assignment_marking = true;
    bool enable_double_negation_simplification = true;
    bool enable_single_use_inlining = true;
    bool enable_copy_propagation = true;
    bool enable_dead_store_elimination = true;
    bool enable_member_name_propagation = true;
    bool enable_min_max_idioms = true;
    bool enable_idiom_recognition = true;
    bool enable_declaration_at_first_use = true;
    bool enable_string_comment_injection = true;
    bool enable_user_comment_injection = true;
    bool enable_string_literal_substitution = true;
    bool enable_cast_idiom_folding = true;
    bool enable_bit_operation_idioms = true;
    bool enable_loop_intrinsic_idioms = true;
    bool enable_magic_division_recognition = true;
    std::size_t max_transform_iterations = 4;
    std::size_t max_expression_depth = 256;
    std::size_t max_comment_bytes = 96;
    std::size_t max_comments_per_function = 256;
    std::size_t max_transform_nodes = 250000;
    std::size_t max_transform_work_units = 4000000;

    bool operator==(const readability_transform_settings_t& other) const noexcept
    {
        return enable_variable_renaming == other.enable_variable_renaming &&
            enable_expression_simplification == other.enable_expression_simplification &&
            enable_temporary_coalescing == other.enable_temporary_coalescing &&
            enable_loop_counter_naming == other.enable_loop_counter_naming &&
            enable_api_call_naming == other.enable_api_call_naming &&
            enable_type_based_naming == other.enable_type_based_naming &&
            enable_string_reference_naming == other.enable_string_reference_naming &&
            enable_constant_folding == other.enable_constant_folding &&
            enable_identity_simplification == other.enable_identity_simplification &&
            enable_cast_simplification == other.enable_cast_simplification &&
            enable_comparison_normalization == other.enable_comparison_normalization &&
            enable_compound_assignment_marking == other.enable_compound_assignment_marking &&
            enable_double_negation_simplification == other.enable_double_negation_simplification &&
            enable_single_use_inlining == other.enable_single_use_inlining &&
            enable_copy_propagation == other.enable_copy_propagation &&
            enable_dead_store_elimination == other.enable_dead_store_elimination &&
            enable_member_name_propagation == other.enable_member_name_propagation &&
            enable_min_max_idioms == other.enable_min_max_idioms &&
            enable_idiom_recognition == other.enable_idiom_recognition &&
            enable_declaration_at_first_use == other.enable_declaration_at_first_use &&
            enable_string_comment_injection == other.enable_string_comment_injection &&
            enable_user_comment_injection == other.enable_user_comment_injection &&
            enable_string_literal_substitution == other.enable_string_literal_substitution &&
            enable_cast_idiom_folding == other.enable_cast_idiom_folding &&
            enable_bit_operation_idioms == other.enable_bit_operation_idioms &&
            enable_loop_intrinsic_idioms == other.enable_loop_intrinsic_idioms &&
            enable_magic_division_recognition == other.enable_magic_division_recognition &&
            max_transform_iterations == other.max_transform_iterations &&
            max_expression_depth == other.max_expression_depth &&
            max_comment_bytes == other.max_comment_bytes &&
            max_comments_per_function == other.max_comments_per_function &&
            max_transform_nodes == other.max_transform_nodes &&
            max_transform_work_units == other.max_transform_work_units;
    }
    bool operator!=(const readability_transform_settings_t& other) const noexcept { return !(*this == other); }
};

struct decompiler_renderer_settings_t {
    std::uint32_t schema_version = 4;
    std::string style_id;
    std::uint32_t indentation_spaces = 4;
    bool emit_type_annotations = true;
    bool emit_provenance_annotations = true;
    bool emit_unknown_tokens = true;
    bool emit_comments = true;
    bool emit_resolved_symbols = true;
    bool emit_enum_case_names = true;
    readability_transform_settings_t readability;
};

struct decompiler_document_t {
    std::uint32_t schema_version = k_decompiler_document_schema_version;
    decompiler_entity_key_t entity;
    typed_pseudocode_ast_v2_t ast;
    sha256_digest_t ast_hash;
    sha256_digest_t type_graph_hash;
    decompiler_profile_id_t profile = decompiler_profile_id_t::balanced;
    decompiler_renderer_settings_t renderer;
    std::string rendered_text;
    std::vector<decompiler_document_token_t> tokens;
    std::vector<decompiler_document_source_map_t> source_maps;
    std::vector<decompiler_unknown_t> unknowns;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct decompiler_profile_budget_t {
    decompiler_profile_id_t profile = decompiler_profile_id_t::balanced;
    std::uint32_t schema_version = 1;
    std::uint64_t max_wall_clock_ms = 0;
    std::uint64_t max_cpu_ms = 0;
    std::uint64_t max_memory_bytes = 0;
    std::uint64_t max_provider_ir_nodes = 0;
    std::uint64_t max_hir_nodes = 0;
    std::uint64_t max_ast_nodes = 0;
    std::uint32_t max_semantic_queries = 0;
    bool semantic_proofs_enabled = false;
};

struct decompiler_chunk_fingerprint_t {
    address_t begin;
    address_t end;
    sha256_digest_t bytes_hash;
};

struct decompiler_dependency_version_t {
    std::string name;
    std::string version;
    sha256_digest_t content_hash;
};

struct decompiler_pipeline_cache_key_t {
    std::uint32_t schema_version = k_decompiler_cache_key_schema_version;
    decompiler_cache_stage_t stage = decompiler_cache_stage_t::provider_ir;
    std::string workspace_id;
    std::uint64_t workspace_generation = 0;
    std::uint64_t analysis_revision = 0;
    decompiler_entity_key_t entity;
    decompiler_provider_identity_t provider;
    std::uint32_t worker_protocol_version = k_decompiler_worker_protocol_version;
    sha256_digest_t worker_protocol_hash;
    decompiler_language_identity_t language;
    sha256_digest_t loader_layout_hash;
    sha256_digest_t function_bytes_hash;
    std::vector<decompiler_chunk_fingerprint_t> chunk_fingerprints;
    std::uint64_t metadata_revision = 0;
    std::uint64_t type_graph_revision = 0;
    std::uint64_t overlay_revision = 0;
    decompiler_profile_budget_t profile;
    std::uint32_t provider_ir_schema_version = k_provider_ir_schema_version;
    std::uint32_t hir_schema_version = k_hir_schema_version;
    std::uint32_t type_graph_schema_version = k_type_graph_schema_version;
    std::uint32_t ast_schema_version = k_typed_pseudocode_ast_schema_version;
    std::uint32_t document_schema_version = k_decompiler_document_schema_version;
    decompiler_renderer_settings_t renderer;
    std::vector<decompiler_dependency_version_t> dependencies;
};

struct decompiler_worker_envelope_t {
    std::uint32_t protocol_version = k_decompiler_worker_protocol_version;
    decompiler_worker_message_kind_t kind = decompiler_worker_message_kind_t::hello;
    sha256_digest_t session_nonce_hash;
    std::uint64_t sequence = 0;
};

struct decompiler_worker_hello_t {
    decompiler_worker_envelope_t envelope;
    decompiler_provider_identity_t provider;
    sha256_digest_t manifest_hash;
};

struct decompiler_worker_job_request_t {
    decompiler_worker_envelope_t envelope;
    std::uint64_t job_id = 0;
    decompiler_pipeline_cache_key_t cache_key;
    decompiler_profile_budget_t profile;
    sha256_digest_t snapshot_hash;
    bool request_printc_evidence = false;
};

struct decompiler_worker_cancel_request_t {
    decompiler_worker_envelope_t envelope;
    std::uint64_t job_id = 0;
    std::string stable_reason;
};

struct decompiler_worker_document_message_t {
    decompiler_worker_envelope_t envelope;
    std::uint64_t job_id = 0;
    std::string provider_artifacts;
    sha256_digest_t provider_artifacts_hash;
    std::optional<std::string> printc_evidence;
    sha256_digest_t printc_evidence_hash;
    decompiler_document_t document;
};

struct decompiler_worker_failure_message_t {
    decompiler_worker_envelope_t envelope;
    std::uint64_t job_id = 0;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct decompiler_worker_heartbeat_t {
    decompiler_worker_envelope_t envelope;
    std::uint64_t active_job_id = 0;
};

using decompiler_worker_message_t = std::variant<
    decompiler_worker_hello_t,
    decompiler_worker_job_request_t,
    decompiler_worker_cancel_request_t,
    decompiler_worker_document_message_t,
    decompiler_worker_failure_message_t,
    decompiler_worker_heartbeat_t>;

struct decompiler_symbol_evidence_t {
    std::string unresolved_text;
    std::string resolved_name;
    std::string module_name;
    std::uint32_t argument_count = 0;
    bool is_import = false;
    bool is_noreturn = false;
    std::uint8_t confidence = 0;
};

struct decompiler_prototype_evidence_t {
    std::string api_name;
    std::string return_type_display;
    std::vector<std::string> argument_names;
    std::vector<std::string> argument_type_displays;
    bool is_variadic = false;
    bool is_noreturn = false;
    std::uint8_t confidence = 0;
};

struct decompiler_string_evidence_t {
    std::string reference_text;
    std::string utf8_content;
    bool is_wide = false;
    std::uint8_t confidence = 0;
    std::uint64_t absolute_address = 0;
    bool truncated = false;
    std::uint32_t original_byte_length = 0;
};

struct decompiler_member_evidence_t {
    std::string object_type_canonical;
    std::uint64_t byte_offset = 0;
    std::string field_name;
    std::string selector_hint;
    std::uint8_t confidence = 0;
};

struct decompiler_vtable_slot_evidence_t {
    std::string vtable_selector;
    std::uint64_t slot_index = 0;
    std::string method_name;
    std::uint8_t confidence = 0;
    std::uint64_t vtable_rva = 0;
};

struct decompiler_user_comment_evidence_t {
    std::string anchor_text;
    std::string comment_text;
    bool before_statement = false;
    std::uint8_t confidence = 0;
    std::uint64_t rva = 0;
    std::uint64_t function_rva = 0;
};

struct decompiler_global_scalar_evidence_t {
    std::uint64_t absolute_address = 0;
    std::uint64_t value = 0;
    std::uint8_t size_log2 = 0;
};

struct decompiler_render_evidence_t {
    std::uint32_t schema_version = k_decompiler_render_evidence_schema_version;
    std::vector<decompiler_symbol_evidence_t> symbols;
    std::vector<decompiler_prototype_evidence_t> prototypes;
    std::vector<decompiler_string_evidence_t> strings;
    std::vector<decompiler_member_evidence_t> members;
    std::vector<decompiler_vtable_slot_evidence_t> vtable_slots;
    std::vector<decompiler_user_comment_evidence_t> user_comments;
    std::vector<decompiler_global_scalar_evidence_t> global_scalars;

    bool empty() const noexcept;
};

enum class decompiler_render_pass_id_t : std::uint8_t {
    readability_transforms = 1,
    member_name_propagation = 2,
    min_max_idiom_rewrite = 3,
    declaration_at_first_use = 4,
    string_comment_injection = 5,
    user_comment_injection = 6,
    idiom_comment_recognition = 7,
    symbol_resolution_rendering = 8,
    enum_case_name_rendering = 9,
    vtable_call_rendering = 10,
    string_literal_substitution = 11,
    cast_idiom_folding = 12,
    bit_operation_idioms = 13,
    loop_intrinsic_idioms = 14,
    magic_division_recognition = 15
};

constexpr std::uint32_t k_decompiler_render_pass_revision_readability_transforms = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_member_name_propagation = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_min_max_idiom_rewrite = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_declaration_at_first_use = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_string_comment_injection = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_user_comment_injection = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_idiom_comment_recognition = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_symbol_resolution_rendering = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_enum_case_name_rendering = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_vtable_call_rendering = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_string_literal_substitution = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_cast_idiom_folding = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_bit_operation_idioms = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_loop_intrinsic_idioms = 1;
constexpr std::uint32_t k_decompiler_render_pass_revision_magic_division_recognition = 1;

struct decompiler_render_pass_registration_t {
    decompiler_render_pass_id_t id = decompiler_render_pass_id_t::readability_transforms;
    std::string stable_label;
    std::uint32_t pass_revision = 1;
    bool enabled = true;
};

struct decompiler_contract_validation_t {
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool valid() const noexcept;
};

template <typename T>
struct decompiler_contract_decode_result_t {
    std::optional<T> value;
    std::string error;

    bool valid() const noexcept { return value.has_value() && error.empty(); }
};

decompiler_contract_validation_t validate_decompiler_entity_key(const decompiler_entity_key_t& value);
decompiler_contract_validation_t validate_source_coordinate(const source_coordinate_t& value);
decompiler_contract_validation_t validate_provider_ir(const provider_ir_t& value);
decompiler_contract_validation_t validate_hir_function(const hir_function_t& value);
decompiler_contract_validation_t validate_type_graph(const type_graph_t& value);
decompiler_contract_validation_t validate_typed_pseudocode_ast(const typed_pseudocode_ast_v2_t& value);
decompiler_contract_validation_t validate_decompiler_document(const decompiler_document_t& value);
decompiler_contract_validation_t validate_decompiler_profile(const decompiler_profile_budget_t& value);
decompiler_contract_validation_t validate_decompiler_pipeline_cache_key(const decompiler_pipeline_cache_key_t& value);
decompiler_contract_validation_t validate_decompiler_worker_message(const decompiler_worker_message_t& value);
decompiler_contract_validation_t validate_decompiler_render_evidence(const decompiler_render_evidence_t& value);

std::vector<decompiler_render_pass_registration_t> decompiler_render_pass_chain(
    const readability_transform_settings_t& readability,
    const decompiler_renderer_settings_t& renderer,
    const decompiler_render_evidence_t* evidence);

sha256_digest_t decompiler_render_pass_chain_hash(
    const std::vector<decompiler_render_pass_registration_t>& passes);

std::string serialize_decompiler_entity_key(const decompiler_entity_key_t& value);
std::string serialize_source_coordinate(const source_coordinate_t& value);
std::string serialize_provider_ir(const provider_ir_t& value);
std::string serialize_hir_function(const hir_function_t& value);
std::string serialize_type_graph(const type_graph_t& value);
std::string serialize_typed_pseudocode_ast(const typed_pseudocode_ast_v2_t& value);
std::string serialize_decompiler_document(const decompiler_document_t& value);
std::string serialize_decompiler_diagnostic(const decompiler_diagnostic_t& value);
std::string serialize_decompiler_pipeline_cache_key(const decompiler_pipeline_cache_key_t& value);
std::string serialize_decompiler_worker_message(const decompiler_worker_message_t& value);
std::string serialize_decompiler_render_evidence(const decompiler_render_evidence_t& value);

decompiler_contract_decode_result_t<decompiler_entity_key_t> deserialize_decompiler_entity_key(const std::string& value);
decompiler_contract_decode_result_t<source_coordinate_t> deserialize_source_coordinate(const std::string& value);
decompiler_contract_decode_result_t<provider_ir_t> deserialize_provider_ir(const std::string& value);
decompiler_contract_decode_result_t<hir_function_t> deserialize_hir_function(const std::string& value);
decompiler_contract_decode_result_t<type_graph_t> deserialize_type_graph(const std::string& value);
decompiler_contract_decode_result_t<typed_pseudocode_ast_v2_t> deserialize_typed_pseudocode_ast(const std::string& value);
decompiler_contract_decode_result_t<decompiler_document_t> deserialize_decompiler_document(const std::string& value);
decompiler_contract_decode_result_t<decompiler_diagnostic_t> deserialize_decompiler_diagnostic(const std::string& value);
decompiler_contract_decode_result_t<decompiler_pipeline_cache_key_t> deserialize_decompiler_pipeline_cache_key(const std::string& value);
decompiler_contract_decode_result_t<decompiler_worker_message_t> deserialize_decompiler_worker_message(const std::string& value);
decompiler_contract_decode_result_t<decompiler_render_evidence_t> deserialize_decompiler_render_evidence(const std::string& value);

sha256_digest_t stable_serialization_hash(const std::string& bytes);
sha256_digest_t stable_serialization_hash(const decompiler_entity_key_t& value);
sha256_digest_t stable_serialization_hash(const source_coordinate_t& value);
sha256_digest_t stable_serialization_hash(const provider_ir_t& value);
sha256_digest_t stable_serialization_hash(const hir_function_t& value);
sha256_digest_t stable_serialization_hash(const type_graph_t& value);
sha256_digest_t stable_serialization_hash(const typed_pseudocode_ast_v2_t& value);
sha256_digest_t stable_serialization_hash(const decompiler_document_t& value);
sha256_digest_t stable_serialization_hash(const decompiler_diagnostic_t& value);
sha256_digest_t stable_serialization_hash(const decompiler_pipeline_cache_key_t& value);
sha256_digest_t stable_serialization_hash(const decompiler_worker_message_t& value);
sha256_digest_t stable_serialization_hash(const decompiler_render_evidence_t& value);

}
