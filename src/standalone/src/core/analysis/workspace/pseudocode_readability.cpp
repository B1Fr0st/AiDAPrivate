#include "pseudocode_readability.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <functional>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace aida::analysis {

namespace {

constexpr std::size_t k_indent_width = 4;

bool is_known_address(const std::uint64_t address) {
    return address != unknown_pseudocode_address;
}

double clamp_confidence(const double value) {
    return std::max(0.0, std::min(1.0, value));
}

bool type_equivalent(const pseudocode_type_t& left, const pseudocode_type_t& right) {
    if (!left.spelling.empty() || !right.spelling.empty()) {
        return left.spelling == right.spelling && left.pointee_spelling == right.pointee_spelling &&
               left.is_const == right.is_const && left.is_volatile == right.is_volatile;
    }
    return left.kind == right.kind && left.bit_width == right.bit_width &&
           left.is_signed == right.is_signed && left.pointee_spelling == right.pointee_spelling &&
           left.is_const == right.is_const && left.is_volatile == right.is_volatile;
}

std::string type_spelling(const pseudocode_type_t& type) {
    if (!type.spelling.empty()) {
        return type.spelling;
    }

    switch (type.kind) {
        case pseudocode_type_kind_t::void_type:
            return "void";
        case pseudocode_type_kind_t::boolean:
            return "bool";
        case pseudocode_type_kind_t::character:
            return "char";
        case pseudocode_type_kind_t::signed_integer:
            if (type.bit_width == 8 || type.bit_width == 16 || type.bit_width == 32 || type.bit_width == 64) {
                return "int" + std::to_string(type.bit_width) + "_t";
            }
            return "int";
        case pseudocode_type_kind_t::unsigned_integer:
            if (type.bit_width == 8 || type.bit_width == 16 || type.bit_width == 32 || type.bit_width == 64) {
                return "uint" + std::to_string(type.bit_width) + "_t";
            }
            return "unsigned int";
        case pseudocode_type_kind_t::floating_point:
            return type.bit_width == 32 ? "float" : "double";
        case pseudocode_type_kind_t::pointer:
            return type.pointee_spelling.empty() ? "void*" : type.pointee_spelling + "*";
        case pseudocode_type_kind_t::array:
            return "array";
        case pseudocode_type_kind_t::function:
            return "function";
        case pseudocode_type_kind_t::aggregate:
            return "struct";
        case pseudocode_type_kind_t::enumeration:
            return "enum";
        case pseudocode_type_kind_t::unknown:
            return "unknown_t";
    }
    return "unknown_t";
}

bool is_identifier_start(const char character) {
    return std::isalpha(static_cast<unsigned char>(character)) != 0 || character == '_';
}

bool is_identifier_continue(const char character) {
    return std::isalnum(static_cast<unsigned char>(character)) != 0 || character == '_';
}

bool is_reserved_identifier(const std::string_view name) {
    static constexpr std::array<std::string_view, 50> reserved = {
        "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor", "bool", "break",
        "case", "catch", "char", "class", "const", "constexpr", "continue", "default", "delete", "do",
        "double", "else", "enum", "explicit", "extern", "false", "float", "for", "friend", "goto",
        "if", "inline", "int", "long", "namespace", "new", "nullptr", "operator", "or", "private",
        "protected", "public", "return", "short", "signed", "sizeof", "static", "struct", "switch", "true"};
    return std::find(reserved.begin(), reserved.end(), name) != reserved.end() || name == "unsigned" ||
           name == "using" || name == "virtual" || name == "void" || name == "volatile" || name == "while";
}

std::string sanitize_identifier(const std::string_view value) {
    std::string result;
    result.reserve(value.size() + 1);
    for (const char character : value) {
        result.push_back(is_identifier_continue(character) ? character : '_');
    }
    if (result.empty()) {
        return result;
    }
    if (!is_identifier_start(result.front())) {
        result.insert(result.begin(), '_');
    }
    if (is_reserved_identifier(result)) {
        result.push_back('_');
    }
    return result;
}

std::size_t role_order(const pseudocode_variable_role_t role) {
    switch (role) {
        case pseudocode_variable_role_t::parameter:
            return 0;
        case pseudocode_variable_role_t::return_value:
            return 1;
        case pseudocode_variable_role_t::local:
            return 2;
        case pseudocode_variable_role_t::temporary:
            return 3;
        case pseudocode_variable_role_t::global:
            return 4;
        case pseudocode_variable_role_t::unknown:
            return 5;
    }
    return 5;
}

std::string role_name_prefix(const pseudocode_variable_role_t role) {
    switch (role) {
        case pseudocode_variable_role_t::parameter:
            return "arg";
        case pseudocode_variable_role_t::return_value:
            return "result";
        case pseudocode_variable_role_t::local:
            return "local";
        case pseudocode_variable_role_t::temporary:
            return "tmp";
        case pseudocode_variable_role_t::global:
            return "global";
        case pseudocode_variable_role_t::unknown:
            return "value";
    }
    return "value";
}

bool span_before(const pseudocode_source_span_t& left, const pseudocode_source_span_t& right) {
    if (is_known_address(left.begin_address) && is_known_address(right.begin_address)) {
        if (left.begin_address != right.begin_address) {
            return left.begin_address < right.begin_address;
        }
        return left.end_address < right.end_address;
    }
    return is_known_address(left.begin_address) && !is_known_address(right.begin_address);
}

bool range_less(const pseudocode_live_range_t& left, const pseudocode_live_range_t& right) {
    if (span_before(left.source, right.source)) {
        return true;
    }
    if (span_before(right.source, left.source)) {
        return false;
    }
    if (left.first_node != right.first_node) {
        return left.first_node < right.first_node;
    }
    return left.last_node < right.last_node;
}

bool ranges_are_disjoint(std::vector<pseudocode_live_range_t> ranges) {
    if (ranges.size() < 2) {
        return false;
    }
    std::sort(ranges.begin(), ranges.end(), range_less);
    for (std::size_t index = 1; index < ranges.size(); ++index) {
        const auto& previous = ranges[index - 1];
        const auto& current = ranges[index];
        if (is_known_address(previous.source.end_address) && is_known_address(current.source.begin_address)) {
            if (previous.source.end_address > current.source.begin_address) {
                return false;
            }
            continue;
        }
        if (previous.last_node >= current.first_node) {
            return false;
        }
    }
    return true;
}

std::string hexadecimal(const std::uint64_t value) {
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << value;
    return stream.str();
}

std::string signed_decimal(const std::int64_t value) {
    if (value >= 0) {
        return std::to_string(value);
    }
    const std::uint64_t magnitude = static_cast<std::uint64_t>(-(value + 1)) + 1U;
    return "-" + std::to_string(magnitude);
}

std::string escaped_character(const std::uint64_t value) {
    switch (value) {
        case '\\':
            return "'\\\\'";
        case '\'':
            return "'\\\''";
        case '\n':
            return "'\\n'";
        case '\r':
            return "'\\r'";
        case '\t':
            return "'\\t'";
        case 0:
            return "'\\0'";
        default:
            if (value >= 0x20U && value <= 0x7EU) {
                return "'" + std::string(1, static_cast<char>(value)) + "'";
            }
            std::ostringstream stream;
            stream << "'\\x" << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (value & 0xFFU) << "'";
            return stream.str();
    }
}

int binary_precedence(const std::string_view operation) {
    if (operation == "=" || operation == "+=" || operation == "-=" || operation == "*=" || operation == "/=" ||
        operation == "%=" || operation == "<<=" || operation == ">>=" || operation == "&=" || operation == "^=" || operation == "|=") {
        return 1;
    }
    if (operation == "||") {
        return 3;
    }
    if (operation == "&&") {
        return 4;
    }
    if (operation == "|") {
        return 5;
    }
    if (operation == "^") {
        return 6;
    }
    if (operation == "&") {
        return 7;
    }
    if (operation == "==" || operation == "!=") {
        return 8;
    }
    if (operation == "<" || operation == "<=" || operation == ">" || operation == ">=") {
        return 9;
    }
    if (operation == "<<" || operation == ">>") {
        return 10;
    }
    if (operation == "+" || operation == "-") {
        return 11;
    }
    if (operation == "*" || operation == "/" || operation == "%") {
        return 12;
    }
    return 2;
}

bool assignment_operator(const std::string_view operation) {
    return operation == "=" || operation == "+=" || operation == "-=" || operation == "*=" || operation == "/=" ||
           operation == "%=" || operation == "<<=" || operation == ">>=" || operation == "&=" || operation == "^=" || operation == "|=";
}

bool expression_kind(const pseudocode_node_kind_t kind) {
    switch (kind) {
        case pseudocode_node_kind_t::identifier_expression:
        case pseudocode_node_kind_t::literal_expression:
        case pseudocode_node_kind_t::unary_expression:
        case pseudocode_node_kind_t::binary_expression:
        case pseudocode_node_kind_t::ternary_expression:
        case pseudocode_node_kind_t::call_expression:
        case pseudocode_node_kind_t::cast_expression:
        case pseudocode_node_kind_t::member_expression:
        case pseudocode_node_kind_t::index_expression:
        case pseudocode_node_kind_t::sizeof_expression:
        case pseudocode_node_kind_t::group_expression:
            return true;
        default:
            return false;
    }
}

bool payload_matches(const typed_pseudocode_node_t& node) {
    switch (node.kind) {
        case pseudocode_node_kind_t::module:
            return std::holds_alternative<pseudocode_module_t>(node.payload);
        case pseudocode_node_kind_t::function:
            return std::holds_alternative<pseudocode_function_t>(node.payload);
        case pseudocode_node_kind_t::block:
            return std::holds_alternative<pseudocode_block_t>(node.payload);
        case pseudocode_node_kind_t::declaration:
            return std::holds_alternative<pseudocode_declaration_t>(node.payload);
        case pseudocode_node_kind_t::expression_statement:
            return std::holds_alternative<pseudocode_expression_statement_t>(node.payload);
        case pseudocode_node_kind_t::return_statement:
            return std::holds_alternative<pseudocode_return_statement_t>(node.payload);
        case pseudocode_node_kind_t::condition_statement:
            return std::holds_alternative<pseudocode_condition_statement_t>(node.payload);
        case pseudocode_node_kind_t::loop_statement:
            return std::holds_alternative<pseudocode_loop_statement_t>(node.payload);
        case pseudocode_node_kind_t::switch_statement:
            return std::holds_alternative<pseudocode_switch_statement_t>(node.payload);
        case pseudocode_node_kind_t::break_statement:
        case pseudocode_node_kind_t::continue_statement:
            return std::holds_alternative<std::monostate>(node.payload);
        case pseudocode_node_kind_t::goto_statement:
            return std::holds_alternative<pseudocode_goto_statement_t>(node.payload);
        case pseudocode_node_kind_t::label_statement:
            return std::holds_alternative<pseudocode_label_statement_t>(node.payload);
        case pseudocode_node_kind_t::identifier_expression:
            return std::holds_alternative<pseudocode_identifier_expression_t>(node.payload);
        case pseudocode_node_kind_t::literal_expression:
            return std::holds_alternative<pseudocode_literal_expression_t>(node.payload);
        case pseudocode_node_kind_t::unary_expression:
            return std::holds_alternative<pseudocode_unary_expression_t>(node.payload);
        case pseudocode_node_kind_t::binary_expression:
            return std::holds_alternative<pseudocode_binary_expression_t>(node.payload);
        case pseudocode_node_kind_t::ternary_expression:
            return std::holds_alternative<pseudocode_ternary_expression_t>(node.payload);
        case pseudocode_node_kind_t::call_expression:
            return std::holds_alternative<pseudocode_call_expression_t>(node.payload);
        case pseudocode_node_kind_t::cast_expression:
            return std::holds_alternative<pseudocode_cast_expression_t>(node.payload);
        case pseudocode_node_kind_t::member_expression:
            return std::holds_alternative<pseudocode_member_expression_t>(node.payload);
        case pseudocode_node_kind_t::index_expression:
            return std::holds_alternative<pseudocode_index_expression_t>(node.payload);
        case pseudocode_node_kind_t::sizeof_expression:
            return std::holds_alternative<pseudocode_sizeof_expression_t>(node.payload);
        case pseudocode_node_kind_t::group_expression:
            return std::holds_alternative<pseudocode_group_expression_t>(node.payload);
    }
    return false;
}

class renderer_t {
public:
    renderer_t(const typed_pseudocode_ast_t& ast, const pseudocode_render_request_t& request)
        : ast_(ast), request_(request) {
        auto material = request.cache_key_material;
        material.ast_revision = ast.revision;
        output_.cache_key = make_pseudocode_cache_key(material);
    }

    pseudocode_render_result_t run() {
        if (!validate_request() || !index_input() || !validate_root()) {
            return finalize();
        }
        build_variable_decisions();
        if (!stopped_) {
            render_statement(ast_.root, 0);
        }
        if (!stopped_ && request_.policy.trailing_newline && !output_.text.empty() && output_.text.back() != '\n') {
            append("\n");
        }
        return finalize();
    }

private:
    struct rendered_variable_t {
        const typed_pseudocode_variable_t* variable = nullptr;
        pseudocode_variable_decision_t decision;
        std::string declaration_name;
    };

    const typed_pseudocode_ast_t& ast_;
    const pseudocode_render_request_t& request_;
    pseudocode_render_result_t result_;
    rendered_pseudocode_t output_;
    std::unordered_map<pseudocode_node_id_t, const typed_pseudocode_node_t*> nodes_;
    std::unordered_map<pseudocode_variable_id_t, const typed_pseudocode_variable_t*> variables_;
    std::unordered_map<pseudocode_variable_id_t, rendered_variable_t> rendered_variables_;
    std::unordered_map<pseudocode_node_id_t, std::vector<pseudocode_variable_id_t>> declarations_by_scope_;
    std::unordered_set<pseudocode_node_id_t> active_nodes_;
    std::unordered_set<pseudocode_node_id_t> emitted_cast_decisions_;
    std::unordered_set<pseudocode_node_id_t> emitted_literal_decisions_;
    std::size_t indent_ = 0;
    std::size_t nesting_ = 0;
    std::size_t poll_count_ = 0;
    bool stopped_ = false;

    bool validate_request() {
        if (request_.limits.max_nodes == 0 || request_.limits.max_output_bytes == 0 || request_.limits.max_nesting == 0 ||
            request_.limits.max_source_mappings == 0 || request_.limits.max_annotations == 0) {
            fail(pseudocode_render_error_code_t::invalid_request, invalid_pseudocode_node_id,
                 invalid_pseudocode_variable_id, {}, "render limits must be nonzero");
            return false;
        }
        return poll();
    }

    bool index_input() {
        output_.statistics.input_nodes = ast_.nodes.size();
        if (ast_.nodes.size() > request_.limits.max_nodes) {
            output_.statistics.bounded = true;
            fail(pseudocode_render_error_code_t::output_limit, invalid_pseudocode_node_id,
                 invalid_pseudocode_variable_id, {}, "input node count exceeds render limit");
            return false;
        }
        for (const auto& node : ast_.nodes) {
            if (!poll()) {
                return false;
            }
            if (node.id == invalid_pseudocode_node_id) {
                fail(pseudocode_render_error_code_t::invalid_ast, node.id, invalid_pseudocode_variable_id, node.source,
                     "node id is invalid");
                return false;
            }
            if (!nodes_.emplace(node.id, &node).second) {
                fail(pseudocode_render_error_code_t::duplicate_node, node.id, invalid_pseudocode_variable_id, node.source,
                     "node id is duplicated");
                return false;
            }
            if (!payload_matches(node)) {
                fail(pseudocode_render_error_code_t::inconsistent_payload, node.id, invalid_pseudocode_variable_id, node.source,
                     "node kind and payload do not match");
                return false;
            }
        }
        for (const auto& variable : ast_.variables) {
            if (!poll()) {
                return false;
            }
            if (variable.id == invalid_pseudocode_variable_id) {
                fail(pseudocode_render_error_code_t::invalid_ast, invalid_pseudocode_node_id, variable.id, variable.source,
                     "variable id is invalid");
                return false;
            }
            if (!variables_.emplace(variable.id, &variable).second) {
                fail(pseudocode_render_error_code_t::duplicate_variable, invalid_pseudocode_node_id, variable.id, variable.source,
                     "variable id is duplicated");
                return false;
            }
        }
        return true;
    }

    bool validate_root() {
        if (find_node(ast_.root) == nullptr) {
            fail(pseudocode_render_error_code_t::missing_node, ast_.root, invalid_pseudocode_variable_id, {}, "root node is missing");
            return false;
        }
        return true;
    }

    bool poll() {
        const std::uint32_t interval = std::max<std::uint32_t>(1U, request_.control.poll_interval);
        ++poll_count_;
        if ((poll_count_ % interval) != 0U) {
            return !stopped_;
        }
        if (request_.control.cancellation != nullptr && request_.control.cancellation->load(std::memory_order_relaxed)) {
            result_.cancelled = true;
            output_.statistics.partial = true;
            fail(pseudocode_render_error_code_t::cancelled, invalid_pseudocode_node_id,
                 invalid_pseudocode_variable_id, {}, "render cancellation requested");
            return false;
        }
        if (std::chrono::steady_clock::now() >= request_.control.deadline) {
            result_.deadline_exceeded = true;
            output_.statistics.partial = true;
            fail(pseudocode_render_error_code_t::deadline_exceeded, invalid_pseudocode_node_id,
                 invalid_pseudocode_variable_id, {}, "render deadline exceeded");
            return false;
        }
        return !stopped_;
    }

    void fail(const pseudocode_render_error_code_t code, const pseudocode_node_id_t node,
              const pseudocode_variable_id_t variable, const pseudocode_source_span_t& source,
              const std::string_view detail) {
        if (stopped_) {
            return;
        }
        result_.errors.push_back({code, node, variable, source, std::string(detail)});
        stopped_ = true;
        output_.statistics.partial = true;
    }

    pseudocode_render_result_t finalize() {
        output_.statistics.output_bytes = output_.text.size();
        if (output_.statistics.partial || !result_.errors.empty()) {
            result_.output = std::move(output_);
            return result_;
        }
        result_.output = std::move(output_);
        return result_;
    }

    const typed_pseudocode_node_t* find_node(const pseudocode_node_id_t id) const {
        const auto found = nodes_.find(id);
        return found == nodes_.end() ? nullptr : found->second;
    }

    const typed_pseudocode_variable_t* find_variable(const pseudocode_variable_id_t id) const {
        const auto found = variables_.find(id);
        return found == variables_.end() ? nullptr : found->second;
    }

    void build_variable_decisions() {
        std::vector<const typed_pseudocode_variable_t*> ordered;
        ordered.reserve(ast_.variables.size());
        for (const auto& variable : ast_.variables) {
            ordered.push_back(&variable);
        }
        std::sort(ordered.begin(), ordered.end(), [](const auto* left, const auto* right) {
            if (span_before(left->source, right->source)) {
                return true;
            }
            if (span_before(right->source, left->source)) {
                return false;
            }
            if (role_order(left->role) != role_order(right->role)) {
                return role_order(left->role) < role_order(right->role);
            }
            if (left->source_name != right->source_name) {
                return left->source_name < right->source_name;
            }
            return left->id < right->id;
        });

        std::unordered_map<pseudocode_variable_role_t, std::size_t> role_counters;
        std::unordered_set<std::string> occupied_names;
        std::unordered_map<pseudocode_variable_id_t, std::size_t> order;
        for (std::size_t index = 0; index < ordered.size(); ++index) {
            order.emplace(ordered[index]->id, index);
        }

        for (const auto* variable : ordered) {
            if (!poll()) {
                return;
            }
            auto base_name = sanitize_identifier(variable->suggested_name.empty() ? variable->source_name : variable->suggested_name);
            if (base_name.empty()) {
                const std::size_t ordinal = ++role_counters[variable->role];
                base_name = role_name_prefix(variable->role) + "_" + std::to_string(ordinal);
            }
            std::string unique_base = base_name;
            std::size_t collision = 2;
            while (occupied_names.count(unique_base) != 0U) {
                unique_base = base_name + "_" + std::to_string(collision++);
            }
            occupied_names.insert(unique_base);

            rendered_variable_t rendered;
            rendered.variable = variable;
            rendered.declaration_name = unique_base;
            rendered.decision.variable = variable->id;
            rendered.decision.action = pseudocode_variable_action_t::preserve;
            rendered.decision.reason = pseudocode_variable_decision_reason_t::stable_default;

            std::vector<pseudocode_live_range_t> ranges = variable->live_ranges;
            std::sort(ranges.begin(), ranges.end(), range_less);
            const bool can_split = variable->role != pseudocode_variable_role_t::parameter &&
                                   variable->role != pseudocode_variable_role_t::global &&
                                   variable->role != pseudocode_variable_role_t::return_value && ranges_are_disjoint(ranges);
            if (can_split) {
                rendered.decision.action = pseudocode_variable_action_t::split;
                rendered.decision.reason = pseudocode_variable_decision_reason_t::disjoint_live_ranges;
                for (std::size_t index = 0; index < ranges.size(); ++index) {
                    std::string segment_name = index == 0 ? unique_base : unique_base + "_" + std::to_string(index + 1);
                    while (index != 0 && occupied_names.count(segment_name) != 0U) {
                        segment_name += "_";
                    }
                    occupied_names.insert(segment_name);
                    rendered.decision.segments.push_back({segment_name, ranges[index]});
                }
            } else {
                rendered.decision.segments.push_back({unique_base, {}});
            }

            if (variable->coalesce_target.has_value()) {
                const auto target = find_variable(*variable->coalesce_target);
                const auto target_order = order.find(*variable->coalesce_target);
                const bool target_precedes = target_order != order.end() && target_order->second < order[variable->id];
                const bool can_coalesce = target != nullptr && target_precedes && !variable->is_volatile &&
                                          variable->role == pseudocode_variable_role_t::temporary &&
                                          variable->definition_nodes.size() <= 1 && variable->live_ranges.size() <= 1 &&
                                          type_equivalent(variable->type, target->type) && !can_split;
                if (can_coalesce) {
                    const auto rendered_target = rendered_variables_.find(*variable->coalesce_target);
                    if (rendered_target != rendered_variables_.end() &&
                        rendered_target->second.decision.action != pseudocode_variable_action_t::split) {
                        rendered.decision.action = pseudocode_variable_action_t::coalesce;
                        rendered.decision.reason = pseudocode_variable_decision_reason_t::explicit_safe_coalesce;
                        rendered.decision.coalesced_into = *variable->coalesce_target;
                        rendered.decision.segments.clear();
                        rendered.decision.segments.push_back({rendered_target->second.declaration_name, {}});
                        rendered.declaration_name = rendered_target->second.declaration_name;
                    }
                } else {
                    rendered.decision.reason = pseudocode_variable_decision_reason_t::unsafe_coalesce_request;
                }
            }

            if (rendered.decision.action != pseudocode_variable_action_t::coalesce && variable->requires_declaration &&
                variable->role != pseudocode_variable_role_t::parameter && variable->role != pseudocode_variable_role_t::global &&
                variable->declaration_scope != invalid_pseudocode_node_id) {
                declarations_by_scope_[variable->declaration_scope].push_back(variable->id);
            }
            output_.variable_decisions.push_back(rendered.decision);
            rendered_variables_.emplace(variable->id, std::move(rendered));
        }

        for (auto& [scope, declarations] : declarations_by_scope_) {
            std::sort(declarations.begin(), declarations.end(), [this](const auto left, const auto right) {
                const auto& left_name = rendered_variables_.at(left).declaration_name;
                const auto& right_name = rendered_variables_.at(right).declaration_name;
                if (left_name != right_name) {
                    return left_name < right_name;
                }
                return left < right;
            });
        }
    }

    bool append(const std::string_view text) {
        if (!poll()) {
            return false;
        }
        if (text.size() > request_.limits.max_output_bytes - output_.text.size()) {
            output_.statistics.bounded = true;
            fail(pseudocode_render_error_code_t::output_limit, invalid_pseudocode_node_id,
                 invalid_pseudocode_variable_id, {}, "rendered output exceeds byte limit");
            return false;
        }
        output_.text.append(text.data(), text.size());
        return true;
    }

    bool write_indent() {
        return append(std::string(indent_ * k_indent_width, ' '));
    }

    bool write_line_break() {
        return append("\n");
    }

    bool enter_node(const typed_pseudocode_node_t& node, std::size_t& output_begin) {
        if (!poll()) {
            return false;
        }
        if (nesting_ >= request_.limits.max_nesting) {
            output_.statistics.bounded = true;
            fail(pseudocode_render_error_code_t::nesting_limit, node.id, invalid_pseudocode_variable_id, node.source,
                 "typed AST nesting exceeds render limit");
            return false;
        }
        if (!active_nodes_.insert(node.id).second) {
            fail(pseudocode_render_error_code_t::cyclic_ast, node.id, invalid_pseudocode_variable_id, node.source,
                 "typed AST contains a reference cycle");
            return false;
        }
        ++nesting_;
        output_.statistics.maximum_nesting = std::max(output_.statistics.maximum_nesting, nesting_);
        output_begin = output_.text.size();
        return true;
    }

    void leave_node(const typed_pseudocode_node_t& node, const std::size_t output_begin) {
        if (nesting_ != 0) {
            --nesting_;
        }
        active_nodes_.erase(node.id);
        ++output_.statistics.rendered_nodes;
        const std::size_t output_end = output_.text.size();
        if (output_end <= output_begin) {
            return;
        }
        if (is_known_address(node.source.begin_address)) {
            if (output_.source_mappings.size() >= request_.limits.max_source_mappings) {
                output_.statistics.bounded = true;
                fail(pseudocode_render_error_code_t::metadata_limit, node.id, invalid_pseudocode_variable_id, node.source,
                     "source mapping count exceeds render limit");
                return;
            }
            output_.source_mappings.push_back({output_begin, output_end, node.id, node.source});
        }
        if (node.annotation.provenance.kind != pseudocode_provenance_kind_t::unknown ||
            node.annotation.semantic_confidence > 0.0 || node.annotation.type_confidence > 0.0 || node.annotation.user_confirmed) {
            if (output_.annotations.size() >= request_.limits.max_annotations) {
                output_.statistics.bounded = true;
                fail(pseudocode_render_error_code_t::metadata_limit, node.id, invalid_pseudocode_variable_id, node.source,
                     "annotation count exceeds render limit");
                return;
            }
            auto annotation = node.annotation;
            annotation.provenance.confidence = clamp_confidence(annotation.provenance.confidence);
            annotation.semantic_confidence = clamp_confidence(annotation.semantic_confidence);
            annotation.type_confidence = clamp_confidence(annotation.type_confidence);
            output_.annotations.push_back({output_begin, output_end, node.id, std::move(annotation)});
        }
    }

    std::string variable_name(const pseudocode_variable_id_t id, const typed_pseudocode_node_t& use) {
        const auto rendered = rendered_variables_.find(id);
        if (rendered == rendered_variables_.end()) {
            fail(pseudocode_render_error_code_t::missing_variable, use.id, id, use.source, "identifier references an unknown variable");
            return {};
        }
        const auto& decision = rendered->second.decision;
        if (decision.action != pseudocode_variable_action_t::split || decision.segments.empty()) {
            return rendered->second.declaration_name;
        }
        for (const auto& segment : decision.segments) {
            const auto& range = segment.range;
            if (is_known_address(range.source.begin_address) && is_known_address(range.source.end_address) &&
                is_known_address(use.source.begin_address) && use.source.begin_address >= range.source.begin_address &&
                use.source.begin_address < range.source.end_address) {
                return segment.rendered_name;
            }
            if (range.first_node != invalid_pseudocode_node_id && range.last_node != invalid_pseudocode_node_id &&
                use.id >= range.first_node && use.id <= range.last_node) {
                return segment.rendered_name;
            }
        }
        return decision.segments.front().rendered_name;
    }

    int precedence_of(const typed_pseudocode_node_t& node) const {
        switch (node.kind) {
            case pseudocode_node_kind_t::binary_expression:
                return binary_precedence(std::get<pseudocode_binary_expression_t>(node.payload).operation);
            case pseudocode_node_kind_t::ternary_expression:
                return 2;
            case pseudocode_node_kind_t::unary_expression:
            case pseudocode_node_kind_t::cast_expression:
            case pseudocode_node_kind_t::sizeof_expression:
                return 13;
            case pseudocode_node_kind_t::call_expression:
            case pseudocode_node_kind_t::member_expression:
            case pseudocode_node_kind_t::index_expression:
                return 14;
            default:
                return 15;
        }
    }

    bool must_parenthesize(const typed_pseudocode_node_t& node, const int parent_precedence, const bool right_child,
                           const std::string_view parent_operation) const {
        const int child_precedence = precedence_of(node);
        if (child_precedence < parent_precedence) {
            return true;
        }
        if (child_precedence > parent_precedence) {
            return false;
        }
        if (parent_precedence <= 0) {
            return false;
        }
        if (assignment_operator(parent_operation)) {
            return !right_child;
        }
        return right_child;
    }

    bool render_expression(const pseudocode_node_id_t id, const int parent_precedence = 0,
                           const bool right_child = false, const std::string_view parent_operation = {}) {
        const auto* node = find_node(id);
        if (node == nullptr) {
            fail(pseudocode_render_error_code_t::missing_node, id, invalid_pseudocode_variable_id, {}, "expression node is missing");
            return false;
        }
        if (!expression_kind(node->kind)) {
            fail(pseudocode_render_error_code_t::invalid_ast, node->id, invalid_pseudocode_variable_id, node->source,
                 "statement node used where an expression is required");
            return false;
        }
        const bool parenthesize = must_parenthesize(*node, parent_precedence, right_child, parent_operation);
        if (parenthesize) {
            output_.parenthesization_decisions.push_back({node->id, pseudocode_parenthesization_action_t::inserted_for_precedence,
                                                          std::string(parent_operation)});
            if (!append("(")) {
                return false;
            }
        }
        std::size_t output_begin = 0;
        if (!enter_node(*node, output_begin)) {
            return false;
        }
        const bool rendered = render_expression_core(*node);
        leave_node(*node, output_begin);
        if (!rendered || stopped_) {
            return false;
        }
        return !parenthesize || append(")");
    }

    bool render_expression_core(const typed_pseudocode_node_t& node) {
        switch (node.kind) {
            case pseudocode_node_kind_t::identifier_expression: {
                const auto& payload = std::get<pseudocode_identifier_expression_t>(node.payload);
                return append(variable_name(payload.variable, node));
            }
            case pseudocode_node_kind_t::literal_expression:
                return render_literal(node, std::get<pseudocode_literal_expression_t>(node.payload));
            case pseudocode_node_kind_t::unary_expression: {
                const auto& payload = std::get<pseudocode_unary_expression_t>(node.payload);
                if (payload.postfix) {
                    return render_expression(payload.operand, 13, false, payload.operation) && append(payload.operation);
                }
                return append(payload.operation) && render_expression(payload.operand, 13, true, payload.operation);
            }
            case pseudocode_node_kind_t::binary_expression: {
                const auto& payload = std::get<pseudocode_binary_expression_t>(node.payload);
                const int precedence = binary_precedence(payload.operation);
                return render_expression(payload.left, precedence, false, payload.operation) && append(" ") &&
                       append(payload.operation) && append(" ") &&
                       render_expression(payload.right, precedence, true, payload.operation);
            }
            case pseudocode_node_kind_t::ternary_expression: {
                const auto& payload = std::get<pseudocode_ternary_expression_t>(node.payload);
                return render_expression(payload.condition, 2, false, "?:") && append(" ? ") &&
                       render_expression(payload.when_true, 2, false, "?:") && append(" : ") &&
                       render_expression(payload.when_false, 2, true, "?:");
            }
            case pseudocode_node_kind_t::call_expression: {
                const auto& payload = std::get<pseudocode_call_expression_t>(node.payload);
                if (!render_expression(payload.callee, 14, false, "call") || !append("(")) {
                    return false;
                }
                for (std::size_t index = 0; index < payload.arguments.size(); ++index) {
                    if (index != 0 && !append(", ")) {
                        return false;
                    }
                    if (!render_expression(payload.arguments[index])) {
                        return false;
                    }
                }
                return append(")");
            }
            case pseudocode_node_kind_t::cast_expression:
                return render_cast(node, std::get<pseudocode_cast_expression_t>(node.payload));
            case pseudocode_node_kind_t::member_expression: {
                const auto& payload = std::get<pseudocode_member_expression_t>(node.payload);
                return render_expression(payload.object, 14, false, payload.through_pointer ? "->" : ".") &&
                       append(payload.through_pointer ? "->" : ".") && append(sanitize_identifier(payload.member_name));
            }
            case pseudocode_node_kind_t::index_expression: {
                const auto& payload = std::get<pseudocode_index_expression_t>(node.payload);
                return render_expression(payload.object, 14, false, "[]") && append("[") &&
                       render_expression(payload.index) && append("]");
            }
            case pseudocode_node_kind_t::sizeof_expression: {
                const auto& payload = std::get<pseudocode_sizeof_expression_t>(node.payload);
                if (!append("sizeof(")) {
                    return false;
                }
                if (payload.uses_type) {
                    return append(type_spelling(payload.target_type)) && append(")");
                }
                return render_expression(payload.operand) && append(")");
            }
            case pseudocode_node_kind_t::group_expression: {
                const auto& payload = std::get<pseudocode_group_expression_t>(node.payload);
                if (payload.explicit_grouping && request_.policy.preserve_explicit_groups) {
                    output_.parenthesization_decisions.push_back({node.id, pseudocode_parenthesization_action_t::preserved_explicit_group, {}});
                    return append("(") && render_expression(payload.expression) && append(")");
                }
                return render_expression(payload.expression);
            }
            default:
                fail(pseudocode_render_error_code_t::unsupported_node, node.id, invalid_pseudocode_variable_id, node.source,
                     "unsupported expression node");
                return false;
        }
    }

    bool render_literal(const typed_pseudocode_node_t& node, const pseudocode_literal_expression_t& literal) {
        std::string rendered;
        pseudocode_literal_style_hint_t style = literal.style_hint;
        switch (literal.kind) {
            case pseudocode_literal_kind_t::boolean:
                rendered = literal.unsigned_value == 0U ? "false" : "true";
                break;
            case pseudocode_literal_kind_t::null_pointer:
                rendered = "nullptr";
                break;
            case pseudocode_literal_kind_t::character:
                rendered = escaped_character(literal.unsigned_value);
                style = pseudocode_literal_style_hint_t::character;
                break;
            case pseudocode_literal_kind_t::string:
            case pseudocode_literal_kind_t::floating_point:
            case pseudocode_literal_kind_t::enumeration_value:
                rendered = literal.original_spelling.empty() ? "0" : literal.original_spelling;
                break;
            case pseudocode_literal_kind_t::integer:
                if (request_.policy.literal_format == pseudocode_literal_format_policy_t::preserve_source && !literal.original_spelling.empty()) {
                    rendered = literal.original_spelling;
                } else if (style == pseudocode_literal_style_hint_t::character) {
                    rendered = escaped_character(literal.unsigned_value);
                } else if (style == pseudocode_literal_style_hint_t::hexadecimal ||
                           (request_.policy.literal_format == pseudocode_literal_format_policy_t::canonical_with_addresses_as_hexadecimal &&
                            style == pseudocode_literal_style_hint_t::address)) {
                    rendered = hexadecimal(literal.unsigned_value);
                } else if (literal.is_signed) {
                    rendered = signed_decimal(literal.signed_value);
                    style = pseudocode_literal_style_hint_t::decimal;
                } else {
                    rendered = std::to_string(literal.unsigned_value);
                    style = pseudocode_literal_style_hint_t::decimal;
                }
                break;
        }
        if (emitted_literal_decisions_.insert(node.id).second) {
            output_.literal_decisions.push_back({node.id, style, rendered});
        }
        return append(rendered);
    }

    bool render_cast(const typed_pseudocode_node_t& node, const pseudocode_cast_expression_t& cast) {
        const auto* operand = find_node(cast.operand);
        if (operand == nullptr) {
            fail(pseudocode_render_error_code_t::missing_node, cast.operand, invalid_pseudocode_variable_id, node.source,
                 "cast operand is missing");
            return false;
        }
        const bool remove = request_.policy.cast_cleanup == pseudocode_cast_cleanup_policy_t::remove_equivalent &&
                            !cast.explicit_semantic_cast && type_equivalent(cast.target_type, operand->type);
        if (emitted_cast_decisions_.insert(node.id).second) {
            output_.cast_decisions.push_back({node.id, remove ? pseudocode_cast_action_t::removed_equivalent : pseudocode_cast_action_t::retained,
                                               cast.target_type});
        }
        if (remove) {
            return render_expression(cast.operand, 13, true, "cast");
        }
        return append("(") && append(type_spelling(cast.target_type)) && append(")") &&
               render_expression(cast.operand, 13, true, "cast");
    }

    bool render_statement(const pseudocode_node_id_t id, const std::size_t control_depth) {
        const auto* node = find_node(id);
        if (node == nullptr) {
            fail(pseudocode_render_error_code_t::missing_node, id, invalid_pseudocode_variable_id, {}, "statement node is missing");
            return false;
        }
        if (expression_kind(node->kind)) {
            fail(pseudocode_render_error_code_t::invalid_ast, node->id, invalid_pseudocode_variable_id, node->source,
                 "expression node used where a statement is required");
            return false;
        }
        std::size_t output_begin = 0;
        if (!enter_node(*node, output_begin)) {
            return false;
        }
        const bool rendered = render_statement_core(*node, control_depth);
        leave_node(*node, output_begin);
        return rendered && !stopped_;
    }

    bool render_statement_core(const typed_pseudocode_node_t& node, const std::size_t control_depth) {
        switch (node.kind) {
            case pseudocode_node_kind_t::module: {
                const auto& payload = std::get<pseudocode_module_t>(node.payload);
                for (std::size_t index = 0; index < payload.declarations.size(); ++index) {
                    if (index != 0 && !write_line_break()) {
                        return false;
                    }
                    if (!render_statement(payload.declarations[index], control_depth)) {
                        return false;
                    }
                }
                return true;
            }
            case pseudocode_node_kind_t::function:
                return render_function(node, std::get<pseudocode_function_t>(node.payload));
            case pseudocode_node_kind_t::block:
                return render_block(node, std::get<pseudocode_block_t>(node.payload), true, control_depth);
            case pseudocode_node_kind_t::declaration:
                return render_declaration(node, std::get<pseudocode_declaration_t>(node.payload), true);
            case pseudocode_node_kind_t::expression_statement: {
                const auto& payload = std::get<pseudocode_expression_statement_t>(node.payload);
                return write_indent() && render_expression(payload.expression) && append(";") && write_line_break();
            }
            case pseudocode_node_kind_t::return_statement: {
                const auto& payload = std::get<pseudocode_return_statement_t>(node.payload);
                if (!write_indent() || !append("return")) {
                    return false;
                }
                if (payload.value.has_value() && (!append(" ") || !render_expression(*payload.value))) {
                    return false;
                }
                return append(";") && write_line_break();
            }
            case pseudocode_node_kind_t::condition_statement:
                return render_condition(std::get<pseudocode_condition_statement_t>(node.payload), control_depth);
            case pseudocode_node_kind_t::loop_statement:
                return render_loop(std::get<pseudocode_loop_statement_t>(node.payload), control_depth);
            case pseudocode_node_kind_t::switch_statement:
                return render_switch(std::get<pseudocode_switch_statement_t>(node.payload), control_depth);
            case pseudocode_node_kind_t::break_statement:
                return write_indent() && append("break;") && write_line_break();
            case pseudocode_node_kind_t::continue_statement:
                return write_indent() && append("continue;") && write_line_break();
            case pseudocode_node_kind_t::goto_statement: {
                const auto& payload = std::get<pseudocode_goto_statement_t>(node.payload);
                return write_indent() && append("goto ") && append(sanitize_identifier(payload.label)) && append(";") && write_line_break();
            }
            case pseudocode_node_kind_t::label_statement: {
                const auto& payload = std::get<pseudocode_label_statement_t>(node.payload);
                if (!append(sanitize_identifier(payload.label)) || !append(":")) {
                    return false;
                }
                if (!write_line_break()) {
                    return false;
                }
                return !payload.statement.has_value() || render_statement(*payload.statement, control_depth);
            }
            default:
                fail(pseudocode_render_error_code_t::unsupported_node, node.id, invalid_pseudocode_variable_id, node.source,
                     "unsupported statement node");
                return false;
        }
    }

    bool render_function(const typed_pseudocode_node_t& node, const pseudocode_function_t& function) {
        if (!append(type_spelling(function.return_type)) || !append(" ") || !append(sanitize_identifier(function.name)) || !append("(")) {
            return false;
        }
        for (std::size_t index = 0; index < function.parameters.size(); ++index) {
            const auto* variable = find_variable(function.parameters[index]);
            if (variable == nullptr) {
                fail(pseudocode_render_error_code_t::missing_variable, node.id, function.parameters[index], node.source,
                     "function parameter references an unknown variable");
                return false;
            }
            if (index != 0 && !append(", ")) {
                return false;
            }
            if (!append(type_spelling(variable->type)) || !append(" ") || !append(variable_name(variable->id, node))) {
                return false;
            }
        }
        if (!append(") ")) {
            return false;
        }
        const auto* body = find_node(function.body);
        if (body == nullptr) {
            fail(pseudocode_render_error_code_t::missing_node, function.body, invalid_pseudocode_variable_id, node.source,
                 "function body is missing");
            return false;
        }
        if (body->kind != pseudocode_node_kind_t::block) {
            fail(pseudocode_render_error_code_t::invalid_ast, body->id, invalid_pseudocode_variable_id, body->source,
                 "function body must be a block node");
            return false;
        }
        return render_statement(function.body, 0);
    }

    bool render_block(const typed_pseudocode_node_t& node, const pseudocode_block_t& block, const bool braces,
                      const std::size_t control_depth) {
        if (braces && (!append("{") || !write_line_break())) {
            return false;
        }
        if (braces) {
            ++indent_;
        }
        if (request_.policy.declaration_placement == pseudocode_declaration_placement_t::scope_entry) {
            const auto declarations = declarations_by_scope_.find(node.id);
            if (declarations != declarations_by_scope_.end()) {
                for (const auto variable_id : declarations->second) {
                    if (!render_synthetic_declaration(variable_id)) {
                        return false;
                    }
                }
                if (!declarations->second.empty() && !block.statements.empty() && !write_line_break()) {
                    return false;
                }
            }
        }
        for (const auto statement : block.statements) {
            const auto* child = find_node(statement);
            if (child == nullptr) {
                fail(pseudocode_render_error_code_t::missing_node, statement, invalid_pseudocode_variable_id, node.source,
                     "block contains an unknown statement");
                return false;
            }
            if (request_.policy.declaration_placement == pseudocode_declaration_placement_t::scope_entry &&
                child->kind == pseudocode_node_kind_t::declaration) {
                const auto& declaration = std::get<pseudocode_declaration_t>(child->payload);
                if (declaration.initializer.has_value() && !render_declaration_initializer(*child, declaration)) {
                    return false;
                }
                continue;
            }
            if (!render_statement(statement, control_depth)) {
                return false;
            }
        }
        if (braces) {
            --indent_;
            return write_indent() && append("}") && write_line_break();
        }
        return true;
    }

    bool render_synthetic_declaration(const pseudocode_variable_id_t variable_id) {
        const auto* variable = find_variable(variable_id);
        const auto rendered = rendered_variables_.find(variable_id);
        if (variable == nullptr || rendered == rendered_variables_.end()) {
            fail(pseudocode_render_error_code_t::missing_variable, invalid_pseudocode_node_id, variable_id, {},
                 "declaration references an unknown variable");
            return false;
        }
        for (const auto& segment : rendered->second.decision.segments) {
            if (!write_indent() || !append(type_spelling(variable->type)) || !append(" ") ||
                !append(segment.rendered_name) || !append(";") || !write_line_break()) {
                return false;
            }
        }
        return true;
    }

    bool render_declaration(const typed_pseudocode_node_t& node, const pseudocode_declaration_t& declaration,
                            const bool with_indent) {
        const auto* variable = find_variable(declaration.variable);
        if (variable == nullptr) {
            fail(pseudocode_render_error_code_t::missing_variable, node.id, declaration.variable, node.source,
                 "declaration references an unknown variable");
            return false;
        }
        const auto rendered = rendered_variables_.find(declaration.variable);
        if (rendered == rendered_variables_.end()) {
            fail(pseudocode_render_error_code_t::missing_variable, node.id, declaration.variable, node.source,
                 "declaration has no stable variable rendering");
            return false;
        }
        if (rendered->second.decision.action == pseudocode_variable_action_t::coalesce) {
            return true;
        }
        for (std::size_t index = 0; index < rendered->second.decision.segments.size(); ++index) {
            const auto& segment = rendered->second.decision.segments[index];
            if ((with_indent && !write_indent()) || !append(type_spelling(variable->type)) || !append(" ") ||
                !append(segment.rendered_name)) {
                return false;
            }
            if (index == 0 && declaration.initializer.has_value() &&
                (!append(" = ") || !render_expression(*declaration.initializer))) {
                return false;
            }
            if (!append(";") || !write_line_break()) {
                return false;
            }
        }
        return true;
    }

    bool render_declaration_initializer(const typed_pseudocode_node_t& node, const pseudocode_declaration_t& declaration) {
        const auto rendered = rendered_variables_.find(declaration.variable);
        if (rendered == rendered_variables_.end()) {
            fail(pseudocode_render_error_code_t::missing_variable, node.id, declaration.variable, node.source,
                 "declaration initializer has no stable variable rendering");
            return false;
        }
        if (!declaration.initializer.has_value()) {
            return true;
        }
        return write_indent() && append(variable_name(declaration.variable, node)) && append(" = ") &&
               render_expression(*declaration.initializer) && append(";") && write_line_break();
    }

    bool render_control_body(const pseudocode_node_id_t body, const std::size_t control_depth) {
        const auto* node = find_node(body);
        if (node == nullptr) {
            fail(pseudocode_render_error_code_t::missing_node, body, invalid_pseudocode_variable_id, {}, "control-flow body is missing");
            return false;
        }
        if (node->kind == pseudocode_node_kind_t::block) {
            return append(" ") && render_statement(body, control_depth + 1);
        }
        if (!request_.policy.force_braced_control_flow) {
            return write_line_break() && render_statement(body, control_depth + 1);
        }
        if (!append(" {") || !write_line_break()) {
            return false;
        }
        ++indent_;
        const bool rendered = render_statement(body, control_depth + 1);
        --indent_;
        return rendered && write_indent() && append("}") && write_line_break();
    }

    bool render_condition(const pseudocode_condition_statement_t& condition, const std::size_t control_depth) {
        if (!write_indent() || !append("if (") || !render_expression(condition.condition) || !append(")") ||
            !render_control_body(condition.when_true, control_depth)) {
            return false;
        }
        if (!condition.when_false.has_value()) {
            return true;
        }
        const auto* alternate = find_node(*condition.when_false);
        if (alternate == nullptr) {
            fail(pseudocode_render_error_code_t::missing_node, *condition.when_false, invalid_pseudocode_variable_id, {},
                 "conditional alternate is missing");
            return false;
        }
        if (request_.policy.allow_else_if && alternate->kind == pseudocode_node_kind_t::condition_statement) {
            if (!write_indent() || !append("else ")) {
                return false;
            }
            return render_condition_inline(*condition.when_false, control_depth);
        }
        return write_indent() && append("else") && render_control_body(*condition.when_false, control_depth);
    }

    bool render_condition_inline(const pseudocode_node_id_t id, const std::size_t control_depth) {
        const auto* node = find_node(id);
        if (node == nullptr) {
            fail(pseudocode_render_error_code_t::missing_node, id, invalid_pseudocode_variable_id, {}, "conditional alternate is missing");
            return false;
        }
        if (node->kind != pseudocode_node_kind_t::condition_statement) {
            fail(pseudocode_render_error_code_t::invalid_ast, node->id, invalid_pseudocode_variable_id, node->source,
                 "else-if alternate must be a conditional statement");
            return false;
        }
        std::size_t output_begin = 0;
        if (!enter_node(*node, output_begin)) {
            return false;
        }
        const bool rendered = render_condition_inline_core(std::get<pseudocode_condition_statement_t>(node->payload), control_depth);
        leave_node(*node, output_begin);
        return rendered && !stopped_;
    }

    bool render_condition_inline_core(const pseudocode_condition_statement_t& condition, const std::size_t control_depth) {
        if (!append("if (") || !render_expression(condition.condition) || !append(")") ||
            !render_control_body(condition.when_true, control_depth)) {
            return false;
        }
        if (!condition.when_false.has_value()) {
            return true;
        }
        const auto* alternate = find_node(*condition.when_false);
        if (alternate == nullptr) {
            fail(pseudocode_render_error_code_t::missing_node, *condition.when_false, invalid_pseudocode_variable_id, {},
                 "conditional alternate is missing");
            return false;
        }
        if (request_.policy.allow_else_if && alternate->kind == pseudocode_node_kind_t::condition_statement) {
            if (!write_indent() || !append("else ")) {
                return false;
            }
            return render_condition_inline(*condition.when_false, control_depth);
        }
        return write_indent() && append("else") && render_control_body(*condition.when_false, control_depth);
    }

    bool render_loop(const pseudocode_loop_statement_t& loop, const std::size_t control_depth) {
        if (!write_indent()) {
            return false;
        }
        if (loop.kind == pseudocode_loop_kind_t::do_while_loop) {
            if (!append("do") || !render_control_body(loop.body, control_depth)) {
                return false;
            }
            if (!write_indent() || !append("while (")) {
                return false;
            }
            if (loop.condition.has_value() && !render_expression(*loop.condition)) {
                return false;
            }
            return append(");") && write_line_break();
        }
        if (loop.kind == pseudocode_loop_kind_t::while_loop) {
            if (!append("while (")) {
                return false;
            }
            if (loop.condition.has_value() && !render_expression(*loop.condition)) {
                return false;
            }
            return append(")") && render_control_body(loop.body, control_depth);
        }
        if (!append("for (")) {
            return false;
        }
        if (loop.initializer.has_value() && !render_for_component(*loop.initializer)) {
            return false;
        }
        if (!append("; ")) {
            return false;
        }
        if (loop.condition.has_value() && !render_expression(*loop.condition)) {
            return false;
        }
        if (!append("; ")) {
            return false;
        }
        if (loop.iteration.has_value() && !render_for_component(*loop.iteration)) {
            return false;
        }
        return append(")") && render_control_body(loop.body, control_depth);
    }

    bool render_for_component(const pseudocode_node_id_t id) {
        const auto* node = find_node(id);
        if (node == nullptr) {
            fail(pseudocode_render_error_code_t::missing_node, id, invalid_pseudocode_variable_id, {}, "for-loop component is missing");
            return false;
        }
        if (expression_kind(node->kind)) {
            return render_expression(id);
        }
        if (node->kind == pseudocode_node_kind_t::declaration) {
            const auto& declaration = std::get<pseudocode_declaration_t>(node->payload);
            const auto* variable = find_variable(declaration.variable);
            if (variable == nullptr) {
                fail(pseudocode_render_error_code_t::missing_variable, node->id, declaration.variable, node->source,
                     "for-loop declaration references an unknown variable");
                return false;
            }
            return append(type_spelling(variable->type)) && append(" ") && append(variable_name(variable->id, *node)) &&
                   (!declaration.initializer.has_value() || (append(" = ") && render_expression(*declaration.initializer)));
        }
        fail(pseudocode_render_error_code_t::invalid_ast, node->id, invalid_pseudocode_variable_id, node->source,
             "for-loop component must be an expression or declaration");
        return false;
    }

    bool render_switch(const pseudocode_switch_statement_t& switch_statement, const std::size_t control_depth) {
        if (!write_indent() || !append("switch (") || !render_expression(switch_statement.selector) || !append(") {") ||
            !write_line_break()) {
            return false;
        }
        ++indent_;
        for (const auto& switch_case : switch_statement.cases) {
            if (!write_indent()) {
                return false;
            }
            if (switch_case.value.has_value()) {
                if (!append("case ") || !render_expression(*switch_case.value) || !append(":")) {
                    return false;
                }
            } else if (!append("default:")) {
                return false;
            }
            if (!write_line_break()) {
                return false;
            }
            ++indent_;
            for (const auto statement : switch_case.statements) {
                if (!render_statement(statement, control_depth + 1)) {
                    return false;
                }
            }
            --indent_;
        }
        --indent_;
        return write_indent() && append("}") && write_line_break();
    }
};

void append_integer_field(std::string& destination, const std::string_view name, const std::uint64_t value) {
    destination.append(name.data(), name.size());
    destination.push_back('=');
    destination.append(std::to_string(value));
    destination.push_back(';');
}

void append_string_field(std::string& destination, const std::string_view name, const std::string& value) {
    destination.append(name.data(), name.size());
    destination.push_back('=');
    destination.append(std::to_string(value.size()));
    destination.push_back(':');
    destination.append(value);
    destination.push_back(';');
}

}

bool pseudocode_render_result_t::succeeded() const noexcept {
    return output.has_value() && errors.empty() && !cancelled && !deadline_exceeded && !output->statistics.partial;
}

std::string make_pseudocode_cache_key(const pseudocode_cache_key_material_t& material) {
    std::string key;
    key.reserve(material.workspace_identity.size() + material.service_revision.size() + 192U);
    append_string_field(key, "workspace", material.workspace_identity);
    append_integer_field(key, "generation", material.workspace_generation);
    append_integer_field(key, "overlay", material.overlay_revision);
    append_integer_field(key, "types", material.type_revision);
    append_integer_field(key, "function", material.function_address);
    append_integer_field(key, "ast", material.ast_revision);
    append_integer_field(key, "policy", material.renderer_policy_revision);
    append_string_field(key, "service", material.service_revision);
    return key;
}

pseudocode_render_result_t render_typed_pseudocode(
    const typed_pseudocode_ast_t& ast,
    const pseudocode_render_request_t& request) {
    return renderer_t(ast, request).run();
}

pseudocode_render_result_t render_typed_pseudocode(
    const typed_pseudocode_ast_t* ast,
    const pseudocode_render_request_t& request) {
    if (ast)
        return render_typed_pseudocode(*ast, request);
    pseudocode_render_result_t result;
    result.errors.push_back({pseudocode_render_error_code_t::invalid_ast,
        invalid_pseudocode_node_id, invalid_pseudocode_variable_id, {},
        "typed pseudocode rendering requires a typed AST"});
    return result;
}

}
