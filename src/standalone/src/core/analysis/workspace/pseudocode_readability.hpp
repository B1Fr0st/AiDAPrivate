#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace aida::analysis {

using pseudocode_node_id_t = std::uint64_t;
using pseudocode_variable_id_t = std::uint64_t;

inline constexpr pseudocode_node_id_t invalid_pseudocode_node_id = 0;
inline constexpr pseudocode_variable_id_t invalid_pseudocode_variable_id = 0;
inline constexpr std::uint64_t unknown_pseudocode_address = std::numeric_limits<std::uint64_t>::max();

enum class pseudocode_type_kind_t : std::uint8_t {
    unknown,
    void_type,
    boolean,
    character,
    signed_integer,
    unsigned_integer,
    floating_point,
    pointer,
    array,
    function,
    aggregate,
    enumeration
};

struct pseudocode_type_t {
    pseudocode_type_kind_t kind = pseudocode_type_kind_t::unknown;
    std::string spelling;
    std::string pointee_spelling;
    std::uint16_t bit_width = 0;
    bool is_signed = false;
    bool is_const = false;
    bool is_volatile = false;
};

enum class pseudocode_provenance_kind_t : std::uint8_t {
    unknown,
    binary,
    decompiler,
    type_recovery,
    dataflow,
    user_overlay,
    imported_metadata,
    synthetic
};

struct pseudocode_provenance_t {
    pseudocode_provenance_kind_t kind = pseudocode_provenance_kind_t::unknown;
    std::string source_id;
    double confidence = 0.0;
};

struct pseudocode_source_span_t {
    std::uint64_t begin_address = unknown_pseudocode_address;
    std::uint64_t end_address = unknown_pseudocode_address;
};

struct pseudocode_annotation_t {
    pseudocode_provenance_t provenance;
    double semantic_confidence = 0.0;
    double type_confidence = 0.0;
    bool user_confirmed = false;
};

enum class pseudocode_variable_role_t : std::uint8_t {
    unknown,
    parameter,
    local,
    temporary,
    return_value,
    global
};

struct pseudocode_live_range_t {
    pseudocode_node_id_t first_node = invalid_pseudocode_node_id;
    pseudocode_node_id_t last_node = invalid_pseudocode_node_id;
    pseudocode_source_span_t source;
};

struct typed_pseudocode_variable_t {
    pseudocode_variable_id_t id = invalid_pseudocode_variable_id;
    std::string source_name;
    std::string suggested_name;
    pseudocode_variable_role_t role = pseudocode_variable_role_t::unknown;
    pseudocode_type_t type;
    pseudocode_node_id_t declaration_scope = invalid_pseudocode_node_id;
    std::vector<pseudocode_node_id_t> definition_nodes;
    std::vector<pseudocode_node_id_t> use_nodes;
    std::vector<pseudocode_live_range_t> live_ranges;
    std::optional<pseudocode_variable_id_t> coalesce_target;
    pseudocode_source_span_t source;
    pseudocode_annotation_t annotation;
    bool requires_declaration = true;
    bool is_volatile = false;
};

enum class pseudocode_literal_kind_t : std::uint8_t {
    integer,
    floating_point,
    character,
    string,
    boolean,
    null_pointer,
    enumeration_value
};

enum class pseudocode_literal_style_hint_t : std::uint8_t {
    unspecified,
    decimal,
    hexadecimal,
    character,
    address
};

struct pseudocode_identifier_expression_t {
    pseudocode_variable_id_t variable = invalid_pseudocode_variable_id;
};

struct pseudocode_literal_expression_t {
    pseudocode_literal_kind_t kind = pseudocode_literal_kind_t::integer;
    std::string original_spelling;
    std::uint64_t unsigned_value = 0;
    std::int64_t signed_value = 0;
    bool is_signed = false;
    pseudocode_literal_style_hint_t style_hint = pseudocode_literal_style_hint_t::unspecified;
};

struct pseudocode_unary_expression_t {
    std::string operation;
    pseudocode_node_id_t operand = invalid_pseudocode_node_id;
    bool postfix = false;
};

struct pseudocode_binary_expression_t {
    std::string operation;
    pseudocode_node_id_t left = invalid_pseudocode_node_id;
    pseudocode_node_id_t right = invalid_pseudocode_node_id;
};

struct pseudocode_ternary_expression_t {
    pseudocode_node_id_t condition = invalid_pseudocode_node_id;
    pseudocode_node_id_t when_true = invalid_pseudocode_node_id;
    pseudocode_node_id_t when_false = invalid_pseudocode_node_id;
};

struct pseudocode_call_expression_t {
    pseudocode_node_id_t callee = invalid_pseudocode_node_id;
    std::vector<pseudocode_node_id_t> arguments;
};

struct pseudocode_cast_expression_t {
    pseudocode_type_t target_type;
    pseudocode_node_id_t operand = invalid_pseudocode_node_id;
    bool explicit_semantic_cast = false;
};

struct pseudocode_member_expression_t {
    pseudocode_node_id_t object = invalid_pseudocode_node_id;
    std::string member_name;
    bool through_pointer = false;
};

struct pseudocode_index_expression_t {
    pseudocode_node_id_t object = invalid_pseudocode_node_id;
    pseudocode_node_id_t index = invalid_pseudocode_node_id;
};

struct pseudocode_sizeof_expression_t {
    pseudocode_node_id_t operand = invalid_pseudocode_node_id;
    pseudocode_type_t target_type;
    bool uses_type = false;
};

struct pseudocode_group_expression_t {
    pseudocode_node_id_t expression = invalid_pseudocode_node_id;
    bool explicit_grouping = true;
};

struct pseudocode_block_t {
    std::vector<pseudocode_node_id_t> statements;
};

struct pseudocode_function_t {
    std::string name;
    pseudocode_type_t return_type;
    std::vector<pseudocode_variable_id_t> parameters;
    pseudocode_node_id_t body = invalid_pseudocode_node_id;
};

struct pseudocode_module_t {
    std::vector<pseudocode_node_id_t> declarations;
};

struct pseudocode_declaration_t {
    pseudocode_variable_id_t variable = invalid_pseudocode_variable_id;
    std::optional<pseudocode_node_id_t> initializer;
};

struct pseudocode_expression_statement_t {
    pseudocode_node_id_t expression = invalid_pseudocode_node_id;
};

struct pseudocode_return_statement_t {
    std::optional<pseudocode_node_id_t> value;
};

struct pseudocode_condition_statement_t {
    pseudocode_node_id_t condition = invalid_pseudocode_node_id;
    pseudocode_node_id_t when_true = invalid_pseudocode_node_id;
    std::optional<pseudocode_node_id_t> when_false;
};

enum class pseudocode_loop_kind_t : std::uint8_t {
    while_loop,
    do_while_loop,
    for_loop
};

struct pseudocode_loop_statement_t {
    pseudocode_loop_kind_t kind = pseudocode_loop_kind_t::while_loop;
    std::optional<pseudocode_node_id_t> initializer;
    std::optional<pseudocode_node_id_t> condition;
    std::optional<pseudocode_node_id_t> iteration;
    pseudocode_node_id_t body = invalid_pseudocode_node_id;
};

struct pseudocode_switch_case_t {
    std::optional<pseudocode_node_id_t> value;
    std::vector<pseudocode_node_id_t> statements;
    pseudocode_source_span_t source;
    pseudocode_annotation_t annotation;
};

struct pseudocode_switch_statement_t {
    pseudocode_node_id_t selector = invalid_pseudocode_node_id;
    std::vector<pseudocode_switch_case_t> cases;
};

struct pseudocode_goto_statement_t {
    std::string label;
};

struct pseudocode_label_statement_t {
    std::string label;
    std::optional<pseudocode_node_id_t> statement;
};

enum class pseudocode_node_kind_t : std::uint8_t {
    module,
    function,
    block,
    declaration,
    expression_statement,
    return_statement,
    condition_statement,
    loop_statement,
    switch_statement,
    break_statement,
    continue_statement,
    goto_statement,
    label_statement,
    identifier_expression,
    literal_expression,
    unary_expression,
    binary_expression,
    ternary_expression,
    call_expression,
    cast_expression,
    member_expression,
    index_expression,
    sizeof_expression,
    group_expression
};

using pseudocode_node_payload_t = std::variant<
    std::monostate,
    pseudocode_module_t,
    pseudocode_function_t,
    pseudocode_block_t,
    pseudocode_declaration_t,
    pseudocode_expression_statement_t,
    pseudocode_return_statement_t,
    pseudocode_condition_statement_t,
    pseudocode_loop_statement_t,
    pseudocode_switch_statement_t,
    pseudocode_goto_statement_t,
    pseudocode_label_statement_t,
    pseudocode_identifier_expression_t,
    pseudocode_literal_expression_t,
    pseudocode_unary_expression_t,
    pseudocode_binary_expression_t,
    pseudocode_ternary_expression_t,
    pseudocode_call_expression_t,
    pseudocode_cast_expression_t,
    pseudocode_member_expression_t,
    pseudocode_index_expression_t,
    pseudocode_sizeof_expression_t,
    pseudocode_group_expression_t>;

struct typed_pseudocode_node_t {
    pseudocode_node_id_t id = invalid_pseudocode_node_id;
    pseudocode_node_kind_t kind = pseudocode_node_kind_t::block;
    pseudocode_type_t type;
    pseudocode_source_span_t source;
    pseudocode_annotation_t annotation;
    pseudocode_node_payload_t payload;
};

struct typed_pseudocode_ast_t {
    pseudocode_node_id_t root = invalid_pseudocode_node_id;
    std::vector<typed_pseudocode_node_t> nodes;
    std::vector<typed_pseudocode_variable_t> variables;
    std::uint64_t revision = 0;
};

struct pseudocode_cache_key_material_t {
    std::string workspace_identity;
    std::uint64_t workspace_generation = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t type_revision = 0;
    std::uint64_t function_address = unknown_pseudocode_address;
    std::uint64_t ast_revision = 0;
    std::uint64_t renderer_policy_revision = 1;
    std::string service_revision;
};

enum class pseudocode_declaration_placement_t : std::uint8_t {
    scope_entry,
    source_order
};

enum class pseudocode_cast_cleanup_policy_t : std::uint8_t {
    preserve_all,
    remove_equivalent
};

enum class pseudocode_literal_format_policy_t : std::uint8_t {
    preserve_source,
    canonical,
    canonical_with_addresses_as_hexadecimal
};

struct pseudocode_render_policy_t {
    pseudocode_declaration_placement_t declaration_placement = pseudocode_declaration_placement_t::scope_entry;
    pseudocode_cast_cleanup_policy_t cast_cleanup = pseudocode_cast_cleanup_policy_t::remove_equivalent;
    pseudocode_literal_format_policy_t literal_format = pseudocode_literal_format_policy_t::canonical_with_addresses_as_hexadecimal;
    bool force_braced_control_flow = true;
    bool allow_else_if = true;
    bool preserve_explicit_groups = true;
    bool trailing_newline = true;
};

struct pseudocode_render_limits_t {
    std::size_t max_nodes = 250000;
    std::size_t max_output_bytes = 4U * 1024U * 1024U;
    std::size_t max_nesting = 256;
    std::size_t max_source_mappings = 250000;
    std::size_t max_annotations = 250000;
};

struct pseudocode_render_control_t {
    const std::atomic_bool* cancellation = nullptr;
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
    std::uint32_t poll_interval = 64;
};

struct pseudocode_render_request_t {
    pseudocode_cache_key_material_t cache_key_material;
    pseudocode_render_policy_t policy;
    pseudocode_render_limits_t limits;
    pseudocode_render_control_t control;
};

enum class pseudocode_variable_action_t : std::uint8_t {
    preserve,
    split,
    coalesce
};

enum class pseudocode_variable_decision_reason_t : std::uint8_t {
    stable_default,
    disjoint_live_ranges,
    explicit_safe_coalesce,
    unsafe_coalesce_request
};

struct pseudocode_variable_segment_t {
    std::string rendered_name;
    pseudocode_live_range_t range;
};

struct pseudocode_variable_decision_t {
    pseudocode_variable_id_t variable = invalid_pseudocode_variable_id;
    pseudocode_variable_action_t action = pseudocode_variable_action_t::preserve;
    pseudocode_variable_decision_reason_t reason = pseudocode_variable_decision_reason_t::stable_default;
    std::vector<pseudocode_variable_segment_t> segments;
    std::optional<pseudocode_variable_id_t> coalesced_into;
};

enum class pseudocode_cast_action_t : std::uint8_t {
    retained,
    removed_equivalent
};

struct pseudocode_cast_decision_t {
    pseudocode_node_id_t node = invalid_pseudocode_node_id;
    pseudocode_cast_action_t action = pseudocode_cast_action_t::retained;
    pseudocode_type_t target_type;
};

struct pseudocode_literal_decision_t {
    pseudocode_node_id_t node = invalid_pseudocode_node_id;
    pseudocode_literal_style_hint_t style = pseudocode_literal_style_hint_t::unspecified;
    std::string rendered_text;
};

enum class pseudocode_parenthesization_action_t : std::uint8_t {
    inserted_for_precedence,
    preserved_explicit_group
};

struct pseudocode_parenthesization_decision_t {
    pseudocode_node_id_t node = invalid_pseudocode_node_id;
    pseudocode_parenthesization_action_t action = pseudocode_parenthesization_action_t::inserted_for_precedence;
    std::string parent_operation;
};

struct pseudocode_source_mapping_t {
    std::size_t output_begin = 0;
    std::size_t output_end = 0;
    pseudocode_node_id_t node = invalid_pseudocode_node_id;
    pseudocode_source_span_t source;
};

struct pseudocode_render_annotation_t {
    std::size_t output_begin = 0;
    std::size_t output_end = 0;
    pseudocode_node_id_t node = invalid_pseudocode_node_id;
    pseudocode_annotation_t annotation;
};

struct pseudocode_render_statistics_t {
    std::size_t input_nodes = 0;
    std::size_t rendered_nodes = 0;
    std::size_t output_bytes = 0;
    std::size_t maximum_nesting = 0;
    bool bounded = false;
    bool partial = false;
};

struct rendered_pseudocode_t {
    std::string text;
    std::string cache_key;
    std::vector<pseudocode_variable_decision_t> variable_decisions;
    std::vector<pseudocode_cast_decision_t> cast_decisions;
    std::vector<pseudocode_literal_decision_t> literal_decisions;
    std::vector<pseudocode_parenthesization_decision_t> parenthesization_decisions;
    std::vector<pseudocode_source_mapping_t> source_mappings;
    std::vector<pseudocode_render_annotation_t> annotations;
    pseudocode_render_statistics_t statistics;
};

enum class pseudocode_render_error_code_t : std::uint8_t {
    invalid_request,
    invalid_ast,
    duplicate_node,
    duplicate_variable,
    missing_node,
    missing_variable,
    inconsistent_payload,
    cyclic_ast,
    output_limit,
    nesting_limit,
    metadata_limit,
    cancelled,
    deadline_exceeded,
    unsupported_node
};

struct pseudocode_render_error_t {
    pseudocode_render_error_code_t code = pseudocode_render_error_code_t::invalid_ast;
    pseudocode_node_id_t node = invalid_pseudocode_node_id;
    pseudocode_variable_id_t variable = invalid_pseudocode_variable_id;
    pseudocode_source_span_t source;
    std::string detail;
};

struct pseudocode_render_result_t {
    std::optional<rendered_pseudocode_t> output;
    std::vector<pseudocode_render_error_t> errors;
    bool cancelled = false;
    bool deadline_exceeded = false;

    bool succeeded() const noexcept;
};

std::string make_pseudocode_cache_key(const pseudocode_cache_key_material_t& material);

pseudocode_render_result_t render_typed_pseudocode(
    const typed_pseudocode_ast_t& ast,
    const pseudocode_render_request_t& request);
pseudocode_render_result_t render_typed_pseudocode(
    const typed_pseudocode_ast_t* ast,
    const pseudocode_render_request_t& request);

}
