#include "typed_ast_v2.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <type_traits>
#include <utility>

namespace aida::analysis {
namespace {

bool is_expression_kind(const typed_pseudocode_ast_node_kind_t kind) noexcept
{
    return kind == typed_pseudocode_ast_node_kind_t::assignment_expression ||
           kind == typed_pseudocode_ast_node_kind_t::unary_expression ||
           kind == typed_pseudocode_ast_node_kind_t::binary_expression ||
           kind == typed_pseudocode_ast_node_kind_t::cast_expression ||
           kind == typed_pseudocode_ast_node_kind_t::call_expression ||
           kind == typed_pseudocode_ast_node_kind_t::member_expression ||
           kind == typed_pseudocode_ast_node_kind_t::index_expression ||
           kind == typed_pseudocode_ast_node_kind_t::identifier ||
           kind == typed_pseudocode_ast_node_kind_t::literal ||
           kind == typed_pseudocode_ast_node_kind_t::unknown_expression;
}

bool is_statement_kind(const typed_pseudocode_ast_node_kind_t kind) noexcept
{
    return kind == typed_pseudocode_ast_node_kind_t::compound_statement ||
           kind == typed_pseudocode_ast_node_kind_t::declaration ||
           kind == typed_pseudocode_ast_node_kind_t::expression_statement ||
           kind == typed_pseudocode_ast_node_kind_t::if_statement ||
           kind == typed_pseudocode_ast_node_kind_t::while_statement ||
           kind == typed_pseudocode_ast_node_kind_t::do_while_statement ||
           kind == typed_pseudocode_ast_node_kind_t::for_statement ||
           kind == typed_pseudocode_ast_node_kind_t::switch_statement ||
           kind == typed_pseudocode_ast_node_kind_t::break_statement ||
           kind == typed_pseudocode_ast_node_kind_t::continue_statement ||
           kind == typed_pseudocode_ast_node_kind_t::return_statement ||
           kind == typed_pseudocode_ast_node_kind_t::throw_statement ||
           kind == typed_pseudocode_ast_node_kind_t::try_statement;
}

bool is_visible_text(const std::string& value) noexcept
{
    return !value.empty() && std::none_of(value.begin(), value.end(), [](const char character) {
        return character == '\r' || character == '\n' || character == '\0';
    });
}

bool is_unary_operator(const std::string& value) noexcept
{
    static const std::set<std::string> values{
        "!", "~", "+", "-", "*", "&", "++", "--"};
    return values.find(value) != values.end();
}

bool is_binary_operator(const std::string& value) noexcept
{
    static const std::set<std::string> values{
        "*", "/", "%", "+", "-", "<<", ">>", "<", "<=", ">", ">=", "==", "!=", "&", "^", "|", "&&", "||"};
    return values.find(value) != values.end();
}

source_coordinate_t translate_coordinate(const source_coordinate_t& value, const decompiler_coordinate_layer_t layer)
{
    auto result = value;
    result.layer = layer;
    if (layer != decompiler_coordinate_layer_t::document)
        result.document_range.reset();
    return result;
}

decompiler_diagnostic_t make_diagnostic(
    const decompiler_diagnostic_code_t code,
    std::string key,
    const std::uint32_t ordinal,
    const std::optional<source_coordinate_t>& coordinate = std::nullopt,
    const decompiler_diagnostic_severity_t severity = decompiler_diagnostic_severity_t::error,
    const std::uint8_t confidence = 100)
{
    decompiler_diagnostic_t result;
    result.severity = severity;
    result.code = code;
    result.localization_key = std::move(key);
    result.coordinate = coordinate;
    result.confidence = confidence;
    result.ordinal = ordinal;
    return result;
}

void append_validation_diagnostics(
    typed_ast_v2_build_result_t& result,
    const decompiler_contract_validation_t& validation)
{
    result.diagnostics.insert(result.diagnostics.end(), validation.diagnostics.begin(), validation.diagnostics.end());
}

std::string function_name(const decompiler_entity_key_t& entity)
{
    return std::visit([](const auto& identity) -> std::string {
        using identity_t = std::decay_t<decltype(identity)>;
        if constexpr (std::is_same_v<identity_t, native_decompiler_entity_identity_t>)
            return identity.canonical_symbol;
        else
            return identity.method_name;
    }, entity.identity);
}

class ast_builder_t {
public:
    ast_builder_t(
        const hir_function_t& hir,
        const type_graph_t& type_graph,
        const typed_ast_v2_build_request_t& request,
        typed_ast_v2_build_result_t& result)
        : hir_(hir), type_graph_(type_graph), request_(request), result_(result)
    {
    }

    bool run()
    {
        if (!preflight())
            return false;
        initialize_ast();
        if (!append_declarations(hir_.parameters, true) || !append_declarations(hir_.locals, false))
            return false;
        if (!append_statements())
            return false;
        if (body_statement_ids_.empty()) {
            fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.v2.empty_proven_body", body_coordinate_);
            return false;
        }
        ast_.nodes[0].child_ids = parameter_declaration_ids_;
        ast_.nodes[0].child_ids.push_back(ast_.body_node_id);
        ast_.nodes[1].child_ids = local_declaration_ids_;
        ast_.nodes[1].child_ids.insert(
            ast_.nodes[1].child_ids.end(), body_statement_ids_.begin(), body_statement_ids_.end());
        ast_.source_coordinates.reserve(hir_.source_coordinates.size() + hir_.blocks.size());
        for (const auto& coordinate : hir_.source_coordinates)
            ast_.source_coordinates.push_back(translate_coordinate(coordinate, decompiler_coordinate_layer_t::typed_ast));
        for (const auto& block : hir_.blocks)
            ast_.source_coordinates.push_back(translate_coordinate(block.coordinate, decompiler_coordinate_layer_t::typed_ast));
        append_diagnostics_and_unknowns();
        const auto validation = validate_typed_ast_v2_semantics(ast_, type_graph_);
        if (!validation.valid()) {
            append_validation_diagnostics(result_, validation);
            return false;
        }
        result_.ast = std::move(ast_);
        return true;
    }

private:
    enum class value_state_t : std::uint8_t {
        unvisited,
        active,
        complete
    };

    bool preflight()
    {
        if (!(hir_.entity == type_graph_.entity) || hir_.type_graph_revision != type_graph_.revision) {
            fail(decompiler_diagnostic_code_t::malformed_type_graph, "decompiler.ast.v2.type_graph_revision");
            return false;
        }
        if (request_.limits.max_hir_values == 0 || request_.limits.max_ast_nodes < 3 ||
            request_.limits.max_expression_nesting == 0) {
            fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.ast.v2.invalid_limits");
            return false;
        }
        if (function_name(hir_.entity).empty()) {
            fail(decompiler_diagnostic_code_t::unresolved_symbol, "decompiler.ast.v2.function_name");
            return false;
        }
        for (const auto& type : type_graph_.nodes)
            types_.emplace(type.id, &type);
        if (types_.find(hir_.return_type_id) == types_.end()) {
            fail(decompiler_diagnostic_code_t::unresolved_type, "decompiler.ast.v2.return_type");
            return false;
        }
        if (!verify_straight_line_control_flow())
            return false;
        std::size_t value_count = 0;
        for (const auto& block : hir_.blocks) {
            for (const auto& value : block.values) {
                if (++value_count > request_.limits.max_hir_values) {
                    fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.ast.v2.hir_value_limit", block.coordinate);
                    return false;
                }
                values_.emplace(value.id, &value);
                states_.emplace(value.id, value_state_t::unvisited);
                if (types_.find(value.type_id) == types_.end()) {
                    fail(decompiler_diagnostic_code_t::unresolved_type, "decompiler.ast.v2.value_type", value.coordinate);
                    return false;
                }
            }
        }
        for (const auto& variable : hir_.parameters) {
            if (types_.find(variable.type_id) == types_.end()) {
                fail(decompiler_diagnostic_code_t::unresolved_type, "decompiler.ast.v2.parameter_type", variable.coordinate);
                return false;
            }
        }
        for (const auto& variable : hir_.locals) {
            if (types_.find(variable.type_id) == types_.end()) {
                fail(decompiler_diagnostic_code_t::unresolved_type, "decompiler.ast.v2.local_type", variable.coordinate);
                return false;
            }
        }
        for (const auto& entry : values_) {
            const auto* value = entry.second;
            for (const auto operand : value->operand_ids) {
                if (values_.find(operand) == values_.end()) {
                    fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.missing_operand", value->coordinate);
                    return false;
                }
                ++use_counts_[operand];
            }
        }
        for (const auto& entry : values_) {
            const auto id = entry.first;
            const auto* value = entry.second;
            if ((value->kind == hir_node_kind_t::assignment || value->kind == hir_node_kind_t::store ||
                 value->kind == hir_node_kind_t::return_value || value->kind == hir_node_kind_t::throw_value) &&
                use_counts_[id] != 0) {
                fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.terminal_value_use", value->coordinate);
                return false;
            }
            if (!supported_hir_kind(value->kind)) {
                fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.v2.unstructured_control_flow", value->coordinate);
                return false;
            }
        }
        return true;
    }

    bool verify_straight_line_control_flow()
    {
        for (std::size_t index = 0; index < hir_.blocks.size(); ++index) {
            const auto& block = hir_.blocks[index];
            if (!block.exception_successor_ids.empty()) {
                fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.v2.unproven_exception_region", block.coordinate);
                return false;
            }
            const bool is_first = index == 0;
            const bool is_last = index + 1 == hir_.blocks.size();
            if (is_first) {
                if (!block.predecessor_ids.empty()) {
                    fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.v2.non_entry_predecessor", block.coordinate);
                    return false;
                }
            } else if (block.predecessor_ids.size() != 1 || block.predecessor_ids.front() != hir_.blocks[index - 1].id) {
                fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.v2.non_linear_predecessor", block.coordinate);
                return false;
            }
            if (is_last) {
                if (!block.successor_ids.empty()) {
                    fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.v2.non_terminal_successor", block.coordinate);
                    return false;
                }
            } else if (block.successor_ids.size() != 1 || block.successor_ids.front() != hir_.blocks[index + 1].id) {
                fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.v2.non_linear_successor", block.coordinate);
                return false;
            }
        }
        return true;
    }

    static bool supported_hir_kind(const hir_node_kind_t kind) noexcept
    {
        return kind == hir_node_kind_t::parameter || kind == hir_node_kind_t::local ||
               kind == hir_node_kind_t::literal || kind == hir_node_kind_t::reference ||
               kind == hir_node_kind_t::unary || kind == hir_node_kind_t::binary ||
               kind == hir_node_kind_t::cast || kind == hir_node_kind_t::assignment ||
               kind == hir_node_kind_t::load || kind == hir_node_kind_t::store ||
               kind == hir_node_kind_t::field || kind == hir_node_kind_t::index ||
               kind == hir_node_kind_t::call || kind == hir_node_kind_t::return_value ||
               kind == hir_node_kind_t::throw_value || kind == hir_node_kind_t::unknown;
    }

    void initialize_ast()
    {
        body_coordinate_ = translate_coordinate(hir_.blocks.front().coordinate, decompiler_coordinate_layer_t::typed_ast);
        ast_.entity = hir_.entity;
        ast_.hir_hash = result_.hir_hash;
        ast_.type_graph_hash = result_.type_graph_hash;
        ast_.root_node_id = append_node(
            typed_pseudocode_ast_node_kind_t::function_definition,
            hir_.return_type_id,
            {},
            function_name(hir_.entity),
            body_coordinate_,
            aggregate_confidence(),
            decompiler_fact_provenance_t::provider_semantics);
        ast_.body_node_id = append_node(
            typed_pseudocode_ast_node_kind_t::compound_statement,
            hir_.return_type_id,
            {},
            {},
            body_coordinate_,
            aggregate_confidence(),
            decompiler_fact_provenance_t::provider_semantics);
    }

    std::uint8_t aggregate_confidence() const noexcept
    {
        std::uint8_t result = 100;
        for (const auto& block : hir_.blocks) {
            for (const auto& value : block.values)
                result = std::min(result, value.confidence);
        }
        return result;
    }

    bool append_declarations(const std::vector<hir_variable_t>& variables, const bool parameter)
    {
        for (const auto& variable : variables) {
            const auto id = append_node(
                typed_pseudocode_ast_node_kind_t::declaration,
                variable.type_id,
                {},
                variable.stable_name,
                translate_coordinate(variable.coordinate, decompiler_coordinate_layer_t::typed_ast),
                variable.confidence,
                variable.provenance);
            if (id == 0)
                return false;
            if (parameter)
                parameter_declaration_ids_.push_back(id);
            else
                local_declaration_ids_.push_back(id);
        }
        return true;
    }

    bool append_statements()
    {
        for (const auto& block : hir_.blocks) {
            for (const auto& value : block.values) {
                std::uint64_t statement_id = 0;
                switch (value.kind) {
                case hir_node_kind_t::assignment:
                case hir_node_kind_t::store:
                    statement_id = append_expression_statement(value);
                    break;
                case hir_node_kind_t::return_value:
                    statement_id = append_terminal_statement(value, typed_pseudocode_ast_node_kind_t::return_statement);
                    break;
                case hir_node_kind_t::throw_value:
                    statement_id = append_terminal_statement(value, typed_pseudocode_ast_node_kind_t::throw_statement);
                    break;
                case hir_node_kind_t::call:
                case hir_node_kind_t::unknown:
                    if (use_counts_[value.id] == 0)
                        statement_id = append_expression_statement(value);
                    break;
                default:
                    break;
                }
                if (failed_)
                    return false;
                if (statement_id != 0)
                    body_statement_ids_.push_back(statement_id);
            }
        }
        return true;
    }

    std::uint64_t append_expression_statement(const hir_value_t& value)
    {
        const auto expression = build_expression(value.id, 0);
        if (expression == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::expression_statement,
            value.type_id,
            {expression},
            {},
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_terminal_statement(
        const hir_value_t& value,
        const typed_pseudocode_ast_node_kind_t kind)
    {
        std::vector<std::uint64_t> children;
        if (value.operand_ids.size() == 1) {
            const auto expression = build_expression(value.operand_ids.front(), 0);
            if (expression == 0)
                return 0;
            children.push_back(expression);
        } else if (value.operand_ids.empty()) {
            if (!is_visible_text(value.stable_value)) {
                fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.missing_terminal_value", value.coordinate);
                return 0;
            }
            const auto literal = append_node(
                typed_pseudocode_ast_node_kind_t::literal,
                value.type_id,
                {},
                value.stable_value,
                translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
                value.confidence,
                value.provenance);
            if (literal == 0)
                return 0;
            children.push_back(literal);
        } else {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.terminal_arity", value.coordinate);
            return 0;
        }
        return append_node(
            kind,
            value.type_id,
            std::move(children),
            {},
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t build_expression(const std::uint64_t value_id, const std::size_t depth)
    {
        if (depth >= request_.limits.max_expression_nesting) {
            const auto iterator = values_.find(value_id);
            fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.ast.v2.expression_nesting",
                 iterator == values_.end() ? std::optional<source_coordinate_t>{} : std::optional<source_coordinate_t>{iterator->second->coordinate});
            return 0;
        }
        const auto value_iterator = values_.find(value_id);
        if (value_iterator == values_.end()) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.expression_value");
            return 0;
        }
        const auto state_iterator = states_.find(value_id);
        if (state_iterator->second == value_state_t::complete)
            return expression_ids_.at(value_id);
        if (state_iterator->second == value_state_t::active) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.expression_cycle", value_iterator->second->coordinate);
            return 0;
        }
        state_iterator->second = value_state_t::active;
        const auto& value = *value_iterator->second;
        std::uint64_t node_id = 0;
        switch (value.kind) {
        case hir_node_kind_t::parameter:
        case hir_node_kind_t::local:
        case hir_node_kind_t::reference:
            node_id = append_leaf(value, typed_pseudocode_ast_node_kind_t::identifier);
            break;
        case hir_node_kind_t::literal:
            node_id = append_leaf(value, typed_pseudocode_ast_node_kind_t::literal);
            break;
        case hir_node_kind_t::unknown:
            node_id = append_leaf(value, typed_pseudocode_ast_node_kind_t::unknown_expression);
            break;
        case hir_node_kind_t::unary:
        case hir_node_kind_t::load:
            node_id = append_unary(value, depth);
            break;
        case hir_node_kind_t::binary:
            node_id = append_binary(value, depth);
            break;
        case hir_node_kind_t::cast:
            node_id = append_cast(value, depth);
            break;
        case hir_node_kind_t::assignment:
        case hir_node_kind_t::store:
            node_id = append_assignment(value, depth);
            break;
        case hir_node_kind_t::field:
            node_id = append_member(value, depth);
            break;
        case hir_node_kind_t::index:
            node_id = append_index(value, depth);
            break;
        case hir_node_kind_t::call:
            node_id = append_call(value, depth);
            break;
        default:
            fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.v2.expression_kind", value.coordinate);
            break;
        }
        if (node_id == 0) {
            state_iterator->second = value_state_t::unvisited;
            return 0;
        }
        expression_ids_[value_id] = node_id;
        state_iterator->second = value_state_t::complete;
        return node_id;
    }

    std::uint64_t append_leaf(const hir_value_t& value, const typed_pseudocode_ast_node_kind_t kind)
    {
        if (!value.operand_ids.empty() || !is_visible_text(value.stable_value)) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.leaf_payload", value.coordinate);
            return 0;
        }
        return append_node(
            kind,
            value.type_id,
            {},
            value.stable_value,
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_unary(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 1) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.unary_arity", value.coordinate);
            return 0;
        }
        const std::string operation = value.kind == hir_node_kind_t::load ? "*" : value.stable_value;
        if (!is_unary_operator(operation)) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.unary_operator", value.coordinate);
            return 0;
        }
        const auto operand = build_expression(value.operand_ids.front(), depth + 1);
        if (operand == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::unary_expression,
            value.type_id,
            {operand},
            operation,
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_binary(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 2 || !is_binary_operator(value.stable_value)) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.binary_payload", value.coordinate);
            return 0;
        }
        const auto left = build_expression(value.operand_ids[0], depth + 1);
        const auto right = build_expression(value.operand_ids[1], depth + 1);
        if (left == 0 || right == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::binary_expression,
            value.type_id,
            {left, right},
            value.stable_value,
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_cast(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 1) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.cast_arity", value.coordinate);
            return 0;
        }
        const auto operand = build_expression(value.operand_ids.front(), depth + 1);
        if (operand == 0)
            return 0;
        const auto type = types_.find(value.type_id);
        return append_node(
            typed_pseudocode_ast_node_kind_t::cast_expression,
            value.type_id,
            {operand},
            type->second->display_name,
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_assignment(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 2) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.assignment_arity", value.coordinate);
            return 0;
        }
        const auto left = build_expression(value.operand_ids[0], depth + 1);
        const auto right = build_expression(value.operand_ids[1], depth + 1);
        if (left == 0 || right == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::assignment_expression,
            value.type_id,
            {left, right},
            "=",
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_member(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 1 || !is_visible_text(value.stable_value)) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.member_payload", value.coordinate);
            return 0;
        }
        const auto object = build_expression(value.operand_ids.front(), depth + 1);
        if (object == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::member_expression,
            value.type_id,
            {object},
            value.stable_value,
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_index(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 2) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.index_arity", value.coordinate);
            return 0;
        }
        const auto object = build_expression(value.operand_ids[0], depth + 1);
        const auto index = build_expression(value.operand_ids[1], depth + 1);
        if (object == 0 || index == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::index_expression,
            value.type_id,
            {object, index},
            {},
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_call(const hir_value_t& value, const std::size_t depth)
    {
        std::vector<std::uint64_t> children;
        if (value.operand_ids.empty()) {
            if (!is_visible_text(value.stable_value)) {
                fail(decompiler_diagnostic_code_t::unresolved_symbol, "decompiler.ast.v2.call_target", value.coordinate);
                return 0;
            }
            const auto callee = append_node(
                typed_pseudocode_ast_node_kind_t::identifier,
                value.type_id,
                {},
                value.stable_value,
                translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
                value.confidence,
                value.provenance);
            if (callee == 0)
                return 0;
            children.push_back(callee);
        } else {
            children.reserve(value.operand_ids.size());
            for (const auto operand_id : value.operand_ids) {
                const auto operand = build_expression(operand_id, depth + 1);
                if (operand == 0)
                    return 0;
                children.push_back(operand);
            }
        }
        return append_node(
            typed_pseudocode_ast_node_kind_t::call_expression,
            value.type_id,
            std::move(children),
            {},
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_node(
        const typed_pseudocode_ast_node_kind_t kind,
        const std::uint64_t type_id,
        std::vector<std::uint64_t> children,
        std::string stable_text,
        source_coordinate_t coordinate,
        const std::uint8_t confidence,
        const decompiler_fact_provenance_t provenance)
    {
        if (ast_.nodes.size() >= request_.limits.max_ast_nodes || next_node_id_ == std::numeric_limits<std::uint64_t>::max()) {
            fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.ast.v2.ast_node_limit", coordinate);
            return 0;
        }
        typed_pseudocode_ast_node_t node;
        node.id = next_node_id_++;
        node.kind = kind;
        node.type_id = type_id;
        node.child_ids = std::move(children);
        node.stable_text = std::move(stable_text);
        node.coordinate = std::move(coordinate);
        node.confidence = confidence;
        node.provenance = provenance;
        ast_.nodes.push_back(std::move(node));
        return ast_.nodes.back().id;
    }

    void append_diagnostics_and_unknowns()
    {
        std::uint32_t ordinal = 1;
        const auto append_diagnostics = [&ordinal, this](const std::vector<decompiler_diagnostic_t>& diagnostics) {
            for (const auto& diagnostic : diagnostics) {
                auto translated = diagnostic;
                translated.ordinal = ordinal++;
                if (translated.coordinate)
                    translated.coordinate = translate_coordinate(*translated.coordinate, decompiler_coordinate_layer_t::typed_ast);
                ast_.diagnostics.push_back(std::move(translated));
            }
        };
        append_diagnostics(hir_.diagnostics);
        append_diagnostics(type_graph_.diagnostics);
        const auto append_unknowns = [this](const std::vector<decompiler_unknown_t>& unknowns) {
            for (const auto& unknown : unknowns) {
                auto translated = unknown;
                translated.coordinate = translate_coordinate(unknown.coordinate, decompiler_coordinate_layer_t::typed_ast);
                ast_.unknowns.push_back(std::move(translated));
            }
        };
        append_unknowns(hir_.unknowns);
        append_unknowns(type_graph_.unknowns);
        result_.diagnostics = ast_.diagnostics;
        result_.unknowns = ast_.unknowns;
    }

    void fail(
        const decompiler_diagnostic_code_t code,
        std::string key,
        const std::optional<source_coordinate_t>& coordinate = std::nullopt)
    {
        if (failed_)
            return;
        failed_ = true;
        std::optional<source_coordinate_t> translated;
        if (coordinate)
            translated = translate_coordinate(*coordinate, decompiler_coordinate_layer_t::typed_ast);
        result_.diagnostics.push_back(make_diagnostic(code, std::move(key), next_diagnostic_ordinal_++, translated));
    }

    const hir_function_t& hir_;
    const type_graph_t& type_graph_;
    const typed_ast_v2_build_request_t& request_;
    typed_ast_v2_build_result_t& result_;
    typed_pseudocode_ast_v2_t ast_;
    source_coordinate_t body_coordinate_;
    std::map<std::uint64_t, const decompiler_type_node_t*> types_;
    std::map<std::uint64_t, const hir_value_t*> values_;
    std::map<std::uint64_t, value_state_t> states_;
    std::map<std::uint64_t, std::uint64_t> expression_ids_;
    std::map<std::uint64_t, std::size_t> use_counts_;
    std::vector<std::uint64_t> parameter_declaration_ids_;
    std::vector<std::uint64_t> local_declaration_ids_;
    std::vector<std::uint64_t> body_statement_ids_;
    std::uint64_t next_node_id_ = 1;
    std::uint32_t next_diagnostic_ordinal_ = 1;
    bool failed_ = false;
};

void append_semantic_error(
    decompiler_contract_validation_t& result,
    const typed_pseudocode_ast_node_t* node,
    const std::string& key,
    std::uint32_t& ordinal)
{
    result.diagnostics.push_back(make_diagnostic(
        decompiler_diagnostic_code_t::malformed_ast,
        key,
        ordinal++,
        node == nullptr ? std::nullopt : std::optional<source_coordinate_t>{node->coordinate}));
}

}

bool typed_ast_v2_build_result_t::succeeded() const noexcept
{
    return ast.has_value();
}

std::string typed_ast_v2_node_layout(const typed_pseudocode_ast_node_kind_t kind)
{
    switch (kind) {
    case typed_pseudocode_ast_node_kind_t::function_definition: return "parameter_declarations_then_body";
    case typed_pseudocode_ast_node_kind_t::compound_statement: return "ordered_statements";
    case typed_pseudocode_ast_node_kind_t::declaration: return "optional_initializer";
    case typed_pseudocode_ast_node_kind_t::expression_statement: return "expression";
    case typed_pseudocode_ast_node_kind_t::if_statement: return "condition_then_body_optional_else_clause";
    case typed_pseudocode_ast_node_kind_t::else_clause: return "body_or_if_statement";
    case typed_pseudocode_ast_node_kind_t::while_statement: return "condition_body";
    case typed_pseudocode_ast_node_kind_t::do_while_statement: return "body_condition";
    case typed_pseudocode_ast_node_kind_t::for_statement: return "initializer_condition_iteration_body";
    case typed_pseudocode_ast_node_kind_t::switch_statement: return "selector_ordered_cases";
    case typed_pseudocode_ast_node_kind_t::switch_case: return "case_value_then_statements_or_default_statements";
    case typed_pseudocode_ast_node_kind_t::break_statement: return "empty";
    case typed_pseudocode_ast_node_kind_t::continue_statement: return "empty";
    case typed_pseudocode_ast_node_kind_t::return_statement: return "optional_expression";
    case typed_pseudocode_ast_node_kind_t::throw_statement: return "optional_expression";
    case typed_pseudocode_ast_node_kind_t::try_statement: return "body_then_catches_or_finally";
    case typed_pseudocode_ast_node_kind_t::catch_clause: return "body";
    case typed_pseudocode_ast_node_kind_t::finally_clause: return "body";
    case typed_pseudocode_ast_node_kind_t::assignment_expression: return "left_right";
    case typed_pseudocode_ast_node_kind_t::unary_expression: return "operand";
    case typed_pseudocode_ast_node_kind_t::binary_expression: return "left_right";
    case typed_pseudocode_ast_node_kind_t::cast_expression: return "operand";
    case typed_pseudocode_ast_node_kind_t::call_expression: return "callee_then_arguments";
    case typed_pseudocode_ast_node_kind_t::member_expression: return "object";
    case typed_pseudocode_ast_node_kind_t::index_expression: return "object_index";
    case typed_pseudocode_ast_node_kind_t::identifier: return "empty";
    case typed_pseudocode_ast_node_kind_t::literal: return "empty";
    case typed_pseudocode_ast_node_kind_t::unknown_expression: return "empty";
    }
    return "invalid";
}

decompiler_contract_validation_t validate_typed_ast_v2_semantics(
    const typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph)
{
    auto result = validate_typed_pseudocode_ast(ast);
    const auto type_validation = validate_type_graph(type_graph);
    result.diagnostics.insert(result.diagnostics.end(), type_validation.diagnostics.begin(), type_validation.diagnostics.end());
    if (!result.valid())
        return result;
    std::map<std::uint64_t, const typed_pseudocode_ast_node_t*> nodes;
    std::set<std::uint64_t> type_ids;
    for (const auto& node : ast.nodes)
        nodes.emplace(node.id, &node);
    for (const auto& type : type_graph.nodes)
        type_ids.insert(type.id);
    std::uint32_t ordinal = 1;
    const auto child = [&nodes](const typed_pseudocode_ast_node_t& node, const std::size_t index) {
        if (index >= node.child_ids.size())
            return static_cast<const typed_pseudocode_ast_node_t*>(nullptr);
        const auto iterator = nodes.find(node.child_ids[index]);
        return iterator == nodes.end() ? static_cast<const typed_pseudocode_ast_node_t*>(nullptr) : iterator->second;
    };
    const auto require_child_kind = [&child, &result, &ordinal](const typed_pseudocode_ast_node_t& node, const std::size_t index,
                                        const typed_pseudocode_ast_node_kind_t kind, const char* key) {
        const auto* value = child(node, index);
        if (value == nullptr || value->kind != kind)
            append_semantic_error(result, &node, key, ordinal);
    };
    const auto require_expression = [&child, &result, &ordinal](const typed_pseudocode_ast_node_t& node, const std::size_t index,
                                    const char* key) {
        const auto* value = child(node, index);
        if (value == nullptr || !is_expression_kind(value->kind))
            append_semantic_error(result, &node, key, ordinal);
    };
    const auto require_statement = [&child, &result, &ordinal](const typed_pseudocode_ast_node_t& node, const std::size_t index,
                                   const char* key) {
        const auto* value = child(node, index);
        if (value == nullptr || !is_statement_kind(value->kind))
            append_semantic_error(result, &node, key, ordinal);
    };
    if (!(ast.entity == type_graph.entity) || ast.type_graph_hash != stable_serialization_hash(type_graph))
        append_semantic_error(result, nullptr, "decompiler.ast.v2.type_graph_identity", ordinal);
    for (const auto& node : ast.nodes) {
        if (type_ids.find(node.type_id) == type_ids.end())
            append_semantic_error(result, &node, "decompiler.ast.v2.node_type", ordinal);
        switch (node.kind) {
        case typed_pseudocode_ast_node_kind_t::function_definition:
            if (node.child_ids.empty() || child(node, node.child_ids.size() - 1) == nullptr ||
                child(node, node.child_ids.size() - 1)->kind != typed_pseudocode_ast_node_kind_t::compound_statement ||
                !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.function_layout", ordinal);
            for (std::size_t index = 0; index + 1 < node.child_ids.size(); ++index)
                require_child_kind(node, index, typed_pseudocode_ast_node_kind_t::declaration, "decompiler.ast.v2.parameter_layout");
            break;
        case typed_pseudocode_ast_node_kind_t::compound_statement:
            for (std::size_t index = 0; index < node.child_ids.size(); ++index)
                require_statement(node, index, "decompiler.ast.v2.compound_statement");
            break;
        case typed_pseudocode_ast_node_kind_t::declaration:
            if (node.child_ids.size() > 1 || !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.declaration_layout", ordinal);
            if (!node.child_ids.empty())
                require_expression(node, 0, "decompiler.ast.v2.declaration_initializer");
            break;
        case typed_pseudocode_ast_node_kind_t::expression_statement:
            if (node.child_ids.size() != 1)
                append_semantic_error(result, &node, "decompiler.ast.v2.expression_statement_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.expression_statement_expression");
            break;
        case typed_pseudocode_ast_node_kind_t::if_statement:
            if (node.child_ids.size() != 2 && node.child_ids.size() != 3)
                append_semantic_error(result, &node, "decompiler.ast.v2.if_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.if_condition");
            require_child_kind(node, 1, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.if_body");
            if (node.child_ids.size() == 3)
                require_child_kind(node, 2, typed_pseudocode_ast_node_kind_t::else_clause, "decompiler.ast.v2.if_else");
            break;
        case typed_pseudocode_ast_node_kind_t::else_clause:
            if (node.child_ids.size() != 1)
                append_semantic_error(result, &node, "decompiler.ast.v2.else_layout", ordinal);
            if (const auto* value = child(node, 0); value == nullptr ||
                (value->kind != typed_pseudocode_ast_node_kind_t::compound_statement && value->kind != typed_pseudocode_ast_node_kind_t::if_statement))
                append_semantic_error(result, &node, "decompiler.ast.v2.else_body", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::while_statement:
            if (node.child_ids.size() != 2)
                append_semantic_error(result, &node, "decompiler.ast.v2.while_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.while_condition");
            require_child_kind(node, 1, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.while_body");
            break;
        case typed_pseudocode_ast_node_kind_t::do_while_statement:
            if (node.child_ids.size() != 2)
                append_semantic_error(result, &node, "decompiler.ast.v2.do_while_layout", ordinal);
            require_child_kind(node, 0, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.do_while_body");
            require_expression(node, 1, "decompiler.ast.v2.do_while_condition");
            break;
        case typed_pseudocode_ast_node_kind_t::for_statement:
            if (node.child_ids.size() != 4)
                append_semantic_error(result, &node, "decompiler.ast.v2.for_layout", ordinal);
            if (const auto* value = child(node, 0); value == nullptr ||
                (value->kind != typed_pseudocode_ast_node_kind_t::declaration && !is_expression_kind(value->kind)))
                append_semantic_error(result, &node, "decompiler.ast.v2.for_initializer", ordinal);
            require_expression(node, 1, "decompiler.ast.v2.for_condition");
            require_expression(node, 2, "decompiler.ast.v2.for_iteration");
            require_child_kind(node, 3, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.for_body");
            break;
        case typed_pseudocode_ast_node_kind_t::switch_statement:
            if (node.child_ids.size() < 2)
                append_semantic_error(result, &node, "decompiler.ast.v2.switch_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.switch_selector");
            for (std::size_t index = 1; index < node.child_ids.size(); ++index)
                require_child_kind(node, index, typed_pseudocode_ast_node_kind_t::switch_case, "decompiler.ast.v2.switch_case");
            break;
        case typed_pseudocode_ast_node_kind_t::switch_case:
            if (node.stable_text == "default") {
                if (node.child_ids.empty())
                    append_semantic_error(result, &node, "decompiler.ast.v2.default_body", ordinal);
                for (std::size_t index = 0; index < node.child_ids.size(); ++index)
                    require_statement(node, index, "decompiler.ast.v2.default_statement");
            } else {
                if (node.stable_text != "case" || node.child_ids.size() < 2)
                    append_semantic_error(result, &node, "decompiler.ast.v2.case_layout", ordinal);
                require_expression(node, 0, "decompiler.ast.v2.case_value");
                for (std::size_t index = 1; index < node.child_ids.size(); ++index)
                    require_statement(node, index, "decompiler.ast.v2.case_statement");
            }
            break;
        case typed_pseudocode_ast_node_kind_t::break_statement:
        case typed_pseudocode_ast_node_kind_t::continue_statement:
            if (!node.child_ids.empty())
                append_semantic_error(result, &node, "decompiler.ast.v2.empty_statement", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::return_statement:
        case typed_pseudocode_ast_node_kind_t::throw_statement:
            if (node.child_ids.size() > 1)
                append_semantic_error(result, &node, "decompiler.ast.v2.terminal_layout", ordinal);
            if (!node.child_ids.empty())
                require_expression(node, 0, "decompiler.ast.v2.terminal_expression");
            break;
        case typed_pseudocode_ast_node_kind_t::try_statement:
            if (node.child_ids.size() < 2)
                append_semantic_error(result, &node, "decompiler.ast.v2.try_layout", ordinal);
            require_child_kind(node, 0, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.try_body");
            for (std::size_t index = 1; index < node.child_ids.size(); ++index) {
                const auto* value = child(node, index);
                if (value == nullptr || (value->kind != typed_pseudocode_ast_node_kind_t::catch_clause &&
                    value->kind != typed_pseudocode_ast_node_kind_t::finally_clause))
                    append_semantic_error(result, &node, "decompiler.ast.v2.try_handler", ordinal);
            }
            break;
        case typed_pseudocode_ast_node_kind_t::catch_clause:
            if (node.child_ids.size() != 1 || !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.catch_layout", ordinal);
            require_child_kind(node, 0, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.catch_body");
            break;
        case typed_pseudocode_ast_node_kind_t::finally_clause:
            if (node.child_ids.size() != 1)
                append_semantic_error(result, &node, "decompiler.ast.v2.finally_layout", ordinal);
            require_child_kind(node, 0, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.finally_body");
            break;
        case typed_pseudocode_ast_node_kind_t::assignment_expression:
        case typed_pseudocode_ast_node_kind_t::binary_expression:
        case typed_pseudocode_ast_node_kind_t::index_expression:
            if (node.child_ids.size() != 2)
                append_semantic_error(result, &node, "decompiler.ast.v2.binary_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.binary_left");
            require_expression(node, 1, "decompiler.ast.v2.binary_right");
            if (node.kind == typed_pseudocode_ast_node_kind_t::binary_expression && !is_binary_operator(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.binary_operator", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::unary_expression:
        case typed_pseudocode_ast_node_kind_t::cast_expression:
        case typed_pseudocode_ast_node_kind_t::member_expression:
            if (node.child_ids.size() != 1)
                append_semantic_error(result, &node, "decompiler.ast.v2.unary_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.unary_operand");
            if (node.kind == typed_pseudocode_ast_node_kind_t::unary_expression && !is_unary_operator(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.unary_operator", ordinal);
            if ((node.kind == typed_pseudocode_ast_node_kind_t::cast_expression || node.kind == typed_pseudocode_ast_node_kind_t::member_expression) &&
                !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.named_expression", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::call_expression:
            if (node.child_ids.empty())
                append_semantic_error(result, &node, "decompiler.ast.v2.call_layout", ordinal);
            for (std::size_t index = 0; index < node.child_ids.size(); ++index)
                require_expression(node, index, "decompiler.ast.v2.call_operand");
            break;
        case typed_pseudocode_ast_node_kind_t::identifier:
        case typed_pseudocode_ast_node_kind_t::literal:
        case typed_pseudocode_ast_node_kind_t::unknown_expression:
            if (!node.child_ids.empty() || !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.leaf_layout", ordinal);
            break;
        }
    }
    return result;
}

typed_ast_v2_build_result_t build_typed_ast_v2(
    const hir_function_t& hir,
    const type_graph_t& type_graph,
    const typed_ast_v2_build_request_t& request)
{
    typed_ast_v2_build_result_t result;
    const auto hir_validation = validate_hir_function(hir);
    const auto type_validation = validate_type_graph(type_graph);
    if (!hir_validation.valid() || !type_validation.valid()) {
        append_validation_diagnostics(result, hir_validation);
        append_validation_diagnostics(result, type_validation);
        return result;
    }
    result.hir_hash = stable_serialization_hash(hir);
    result.type_graph_hash = stable_serialization_hash(type_graph);
    ast_builder_t(hir, type_graph, request, result).run();
    return result;
}

std::string serialize_typed_ast_v2(const typed_pseudocode_ast_v2_t& ast)
{
    return serialize_typed_pseudocode_ast(ast);
}

decompiler_contract_decode_result_t<typed_pseudocode_ast_v2_t> deserialize_typed_ast_v2(const std::string& bytes)
{
    return deserialize_typed_pseudocode_ast(bytes);
}

}
