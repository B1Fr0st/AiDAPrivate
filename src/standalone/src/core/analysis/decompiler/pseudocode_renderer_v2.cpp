#include "pseudocode_renderer_v2.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <utility>

namespace aida::analysis {
namespace {

bool visible_text(const std::string& value) noexcept
{
    return !value.empty() && std::none_of(value.begin(), value.end(), [](const char character) {
        return character == '\r' || character == '\n' || character == '\0';
    });
}

bool identifier_text(const std::string& value) noexcept
{
    if (!visible_text(value))
        return false;
    bool component_start = true;
    for (std::size_t index = 0; index < value.size(); ++index) {
        const unsigned char character = static_cast<unsigned char>(value[index]);
        if (component_start) {
            if (!(std::isalpha(character) != 0 || value[index] == '_' || value[index] == '$'))
                return false;
            component_start = false;
            continue;
        }
        if (std::isalnum(character) != 0 || value[index] == '_' || value[index] == '$')
            continue;
        if (value[index] == ':' && index + 1 < value.size() && value[index + 1] == ':') {
            ++index;
            component_start = true;
            continue;
        }
        return false;
    }
    return !component_start;
}

bool unary_operator(const std::string& value) noexcept
{
    return value == "!" || value == "~" || value == "+" || value == "-" || value == "*" || value == "&" ||
           value == "++" || value == "--";
}

int binary_precedence(const std::string& value) noexcept
{
    if (value == "||") return 2;
    if (value == "&&") return 3;
    if (value == "|") return 4;
    if (value == "^") return 5;
    if (value == "&") return 6;
    if (value == "==" || value == "!=") return 7;
    if (value == "<" || value == "<=" || value == ">" || value == ">=") return 8;
    if (value == "<<" || value == ">>") return 9;
    if (value == "+" || value == "-") return 10;
    if (value == "*" || value == "/" || value == "%") return 11;
    return 0;
}

source_coordinate_t document_coordinate(const source_coordinate_t& source, const decompiler_token_range_t range)
{
    auto result = source;
    result.layer = decompiler_coordinate_layer_t::document;
    result.document_range = range;
    return result;
}

decompiler_diagnostic_t renderer_diagnostic(
    const decompiler_diagnostic_code_t code,
    std::string key,
    const std::uint32_t ordinal,
    const std::optional<source_coordinate_t>& coordinate = std::nullopt)
{
    decompiler_diagnostic_t result;
    result.severity = decompiler_diagnostic_severity_t::error;
    result.code = code;
    result.localization_key = std::move(key);
    result.coordinate = coordinate;
    result.confidence = 100;
    result.ordinal = ordinal;
    return result;
}

std::string provenance_name(const decompiler_fact_provenance_t value)
{
    switch (value) {
    case decompiler_fact_provenance_t::loader_metadata: return "loader_metadata";
    case decompiler_fact_provenance_t::debug_metadata: return "debug_metadata";
    case decompiler_fact_provenance_t::provider_semantics: return "provider_semantics";
    case decompiler_fact_provenance_t::bytecode_verifier: return "bytecode_verifier";
    case decompiler_fact_provenance_t::rtti: return "rtti";
    case decompiler_fact_provenance_t::objc_metadata: return "objc_metadata";
    case decompiler_fact_provenance_t::swift_metadata: return "swift_metadata";
    case decompiler_fact_provenance_t::call_signature: return "call_signature";
    case decompiler_fact_provenance_t::semantic_proof: return "semantic_proof";
    case decompiler_fact_provenance_t::user_overlay: return "user_overlay";
    case decompiler_fact_provenance_t::unknown: return "unknown";
    }
    return "unknown";
}

std::string quote_unknown(const std::string& value)
{
    std::string result;
    result.reserve(value.size() + 2);
    result.push_back('"');
    for (const char character : value) {
        switch (character) {
        case '\\': result.append("\\\\"); break;
        case '"': result.append("\\\""); break;
        case '\t': result.append("\\t"); break;
        default: result.push_back(character); break;
        }
    }
    result.push_back('"');
    return result;
}

class renderer_t {
public:
    renderer_t(
        const typed_pseudocode_ast_v2_t& ast,
        const type_graph_t& type_graph,
        const pseudocode_renderer_v2_request_t& request)
        : ast_(ast), type_graph_(type_graph), request_(request), settings_(request.settings.style_id.empty()
              ? pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced)
              : request.settings)
    {
    }

    pseudocode_renderer_v2_result_t run()
    {
        if (!prepare())
            return result_;
        document_.entity = ast_.entity;
        document_.ast = ast_;
        document_.ast_hash = stable_serialization_hash(ast_);
        document_.type_graph_hash = stable_serialization_hash(type_graph_);
        document_.profile = request_.profile;
        document_.renderer = settings_;
        if (!render_function(ast_.root_node_id) || failed_)
            return result_;
        if (request_.require_complete_source_map && document_.tokens.size() != document_.source_maps.size()) {
            fail(decompiler_diagnostic_code_t::source_map_rejected, "decompiler.renderer.v2.source_map_coverage", nullptr);
            return result_;
        }
        append_document_metadata();
        const auto validation = validate_decompiler_document(document_);
        if (!validation.valid()) {
            result_.diagnostics.insert(result_.diagnostics.end(), validation.diagnostics.begin(), validation.diagnostics.end());
            return result_;
        }
        result_.document = std::move(document_);
        result_.diagnostics = result_.document->diagnostics;
        result_.unknowns = result_.document->unknowns;
        return result_;
    }

private:
    bool prepare()
    {
        if (request_.limits.max_ast_nodes == 0 || request_.limits.max_output_bytes == 0 || request_.limits.max_tokens == 0 ||
            request_.limits.max_source_maps == 0 || request_.limits.max_nesting == 0 ||
            request_.limits.max_output_bytes > std::numeric_limits<std::uint32_t>::max() ||
            (settings_.schema_version != 2 && settings_.schema_version != 3) || settings_.style_id.empty() ||
            settings_.indentation_spaces == 0 || settings_.indentation_spaces > 16) {
            fail(decompiler_diagnostic_code_t::invalid_contract, "decompiler.renderer.v2.request", nullptr);
            return false;
        }
        if (ast_.nodes.size() > request_.limits.max_ast_nodes) {
            fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.renderer.v2.ast_node_limit", nullptr);
            return false;
        }
        const auto semantic_validation = validate_typed_ast_v2_semantics(ast_, type_graph_);
        if (!semantic_validation.valid()) {
            result_.diagnostics.insert(result_.diagnostics.end(), semantic_validation.diagnostics.begin(), semantic_validation.diagnostics.end());
            return false;
        }
        if (ast_.type_graph_hash != stable_serialization_hash(type_graph_)) {
            fail(decompiler_diagnostic_code_t::malformed_type_graph, "decompiler.renderer.v2.type_graph_hash", nullptr);
            return false;
        }
        for (const auto& node : ast_.nodes)
            nodes_.emplace(node.id, &node);
        for (const auto& type : type_graph_.nodes)
            types_.emplace(type.id, &type);
        build_evidence_maps();
        return true;
    }

    void build_evidence_maps()
    {
        if (request_.evidence == nullptr)
            return;
        constexpr std::size_t k_max_evidence_map_entries = 262144;
        for (const auto& entry : request_.evidence->symbols) {
            if (resolved_symbols_.size() >= k_max_evidence_map_entries)
                break;
            if (!entry.unresolved_text.empty() && !entry.resolved_name.empty() &&
                identifier_text(entry.resolved_name))
                resolved_symbols_.emplace(entry.unresolved_text, entry.resolved_name);
        }
        for (const auto& entry : request_.evidence->vtable_slots) {
            if (vtable_slots_.size() >= k_max_evidence_map_entries)
                break;
            if (!entry.vtable_selector.empty() && !entry.method_name.empty() &&
                identifier_text(entry.method_name))
                vtable_slots_.emplace(vtable_slot_key(entry.vtable_selector, entry.slot_index), entry.method_name);
        }
    }

    static std::string vtable_slot_key(const std::string& selector, const std::uint64_t slot_index)
    {
        return selector + "#" + std::to_string(slot_index);
    }

    bool emit(
        const std::string& text,
        const decompiler_document_token_kind_t kind,
        const typed_pseudocode_ast_node_t& node)
    {
        if (text.empty())
            return true;
        if (document_.tokens.size() >= request_.limits.max_tokens || document_.source_maps.size() >= request_.limits.max_source_maps ||
            text.size() > request_.limits.max_output_bytes - document_.rendered_text.size()) {
            fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.renderer.v2.output_limit", &node);
            return false;
        }
        const auto begin = static_cast<std::uint32_t>(document_.rendered_text.size());
        document_.rendered_text.append(text);
        const auto end = static_cast<std::uint32_t>(document_.rendered_text.size());
        const decompiler_token_range_t range{begin, end};
        document_.tokens.push_back({kind, range, node.id});
        decompiler_document_source_map_t source_map;
        source_map.document_range = range;
        source_map.coordinates.push_back(document_coordinate(node.coordinate, range));
        document_.source_maps.push_back(std::move(source_map));
        return true;
    }

    bool emit_indent(const typed_pseudocode_ast_node_t& node)
    {
        return emit(std::string(indent_ * settings_.indentation_spaces, ' '), decompiler_document_token_kind_t::whitespace, node);
    }

    bool emit_space(const typed_pseudocode_ast_node_t& node)
    {
        return emit(" ", decompiler_document_token_kind_t::whitespace, node);
    }

    bool emit_newline(const typed_pseudocode_ast_node_t& node)
    {
        return emit("\n", decompiler_document_token_kind_t::whitespace, node);
    }

    bool retract_trailing_newline()
    {
        if (document_.tokens.empty() || document_.source_maps.empty() ||
            document_.tokens.size() != document_.source_maps.size() || document_.rendered_text.empty() ||
            document_.rendered_text.back() != '\n')
            return false;
        const auto& last = document_.tokens.back();
        if (last.kind != decompiler_document_token_kind_t::whitespace ||
            last.range.end != document_.rendered_text.size() || last.range.begin + 1 != last.range.end)
            return false;
        document_.rendered_text.pop_back();
        document_.tokens.pop_back();
        document_.source_maps.pop_back();
        return true;
    }

    bool emit_comment_content(const typed_pseudocode_ast_node_t& node)
    {
        return emit("// ", decompiler_document_token_kind_t::comment, node) &&
               emit(node.stable_text, decompiler_document_token_kind_t::comment, node);
    }

    bool render_standalone_comment(const typed_pseudocode_ast_node_t& node)
    {
        return emit_indent(node) && emit_comment_content(node) && emit_newline(node);
    }

    bool attach_trailing_comments(const std::vector<std::uint64_t>& siblings, std::size_t& index)
    {
        const auto* anchor = node(siblings[index]);
        if (anchor != nullptr && anchor->kind == typed_pseudocode_ast_node_kind_t::comment_statement)
            return true;
        bool attached = false;
        while (index + 1 < siblings.size()) {
            const auto* comment = node(siblings[index + 1]);
            if (comment == nullptr || comment->kind != typed_pseudocode_ast_node_kind_t::comment_statement)
                break;
            if (!settings_.emit_comments) {
                ++index;
                attached = true;
                continue;
            }
            if (!attached) {
                if (!retract_trailing_newline() || !emit_space(*comment))
                    return false;
            } else if (!emit_indent(*comment)) {
                return false;
            }
            if (!emit_comment_content(*comment) || !emit_newline(*comment))
                return false;
            ++index;
            attached = true;
        }
        return true;
    }

    bool emit_annotation(const typed_pseudocode_ast_node_t& node)
    {
        if (!settings_.emit_provenance_annotations)
            return true;
        return emit("[[aida::confidence(", decompiler_document_token_kind_t::unknown, node) &&
               emit(std::to_string(node.confidence), decompiler_document_token_kind_t::literal, node) &&
               emit("), aida::provenance(", decompiler_document_token_kind_t::unknown, node) &&
               emit(provenance_name(node.provenance), decompiler_document_token_kind_t::identifier, node) &&
               emit(")]]", decompiler_document_token_kind_t::unknown, node) && emit_newline(node);
    }

    bool render_type(const typed_pseudocode_ast_node_t& node)
    {
        const auto iterator = types_.find(node.type_id);
        if (iterator == types_.end() || !visible_text(iterator->second->display_name)) {
            fail(decompiler_diagnostic_code_t::unresolved_type, "decompiler.renderer.v2.type_name", &node);
            return false;
        }
        return emit(iterator->second->display_name, decompiler_document_token_kind_t::type_name, node);
    }

    const typed_pseudocode_ast_node_t* node(const std::uint64_t id)
    {
        const auto iterator = nodes_.find(id);
        if (iterator == nodes_.end()) {
            fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.renderer.v2.node_reference", nullptr);
            return nullptr;
        }
        return iterator->second;
    }

    int precedence(const typed_pseudocode_ast_node_t& value) const noexcept
    {
        switch (value.kind) {
        case typed_pseudocode_ast_node_kind_t::assignment_expression: return 1;
        case typed_pseudocode_ast_node_kind_t::binary_expression: return binary_precedence(value.stable_text);
        case typed_pseudocode_ast_node_kind_t::cast_expression:
        case typed_pseudocode_ast_node_kind_t::unary_expression: return 12;
        case typed_pseudocode_ast_node_kind_t::call_expression:
        case typed_pseudocode_ast_node_kind_t::member_expression:
        case typed_pseudocode_ast_node_kind_t::index_expression: return 13;
        default: return 14;
        }
    }

    bool render_function(const std::uint64_t id)
    {
        const auto* value = node(id);
        if (value == nullptr || value->kind != typed_pseudocode_ast_node_kind_t::function_definition)
            return false;
        if (!emit_annotation(*value))
            return false;
        if (settings_.emit_type_annotations) {
            if (!render_type(*value) || !emit_space(*value))
                return false;
        } else if (!emit("function", decompiler_document_token_kind_t::keyword, *value) || !emit_space(*value)) {
            return false;
        }
        if (!identifier_text(value->stable_text)) {
            fail(decompiler_diagnostic_code_t::unresolved_symbol, "decompiler.renderer.v2.function_identifier", value);
            return false;
        }
        if (!emit(value->stable_text, decompiler_document_token_kind_t::identifier, *value) ||
            !emit("(", decompiler_document_token_kind_t::punctuation, *value))
            return false;
        for (std::size_t index = 0; index + 1 < value->child_ids.size(); ++index) {
            const auto* parameter = node(value->child_ids[index]);
            if (parameter == nullptr || parameter->kind != typed_pseudocode_ast_node_kind_t::declaration)
                return false;
            if (index != 0 && !emit(",", decompiler_document_token_kind_t::punctuation, *value))
                return false;
            if (index != 0 && !emit_space(*value))
                return false;
            if (!render_declaration_inline(*parameter))
                return false;
        }
        if (!emit(")", decompiler_document_token_kind_t::punctuation, *value) || !emit_space(*value))
            return false;
        return render_compound(value->child_ids.back());
    }

    bool render_compound(const std::uint64_t id)
    {
        const auto* value = node(id);
        if (value == nullptr || value->kind != typed_pseudocode_ast_node_kind_t::compound_statement)
            return false;
        if (!emit("{", decompiler_document_token_kind_t::punctuation, *value) || !emit_newline(*value))
            return false;
        ++indent_;
        for (std::size_t index = 0; index < value->child_ids.size(); ++index) {
            if (!render_statement(value->child_ids[index]) || !attach_trailing_comments(value->child_ids, index)) {
                --indent_;
                return false;
            }
        }
        --indent_;
        return emit_indent(*value) && emit("}", decompiler_document_token_kind_t::punctuation, *value) && emit_newline(*value);
    }

    bool render_statement(const std::uint64_t id)
    {
        const auto* value = node(id);
        if (value == nullptr)
            return false;
        if (++nesting_ > request_.limits.max_nesting) {
            --nesting_;
            fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.renderer.v2.nesting", value);
            return false;
        }
        bool rendered = false;
        switch (value->kind) {
        case typed_pseudocode_ast_node_kind_t::compound_statement:
            rendered = emit_indent(*value) && render_compound(id);
            break;
        case typed_pseudocode_ast_node_kind_t::declaration:
            rendered = render_declaration(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::expression_statement:
            rendered = render_expression_statement(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::if_statement:
            rendered = render_if(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::while_statement:
            rendered = render_while(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::do_while_statement:
            rendered = render_do_while(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::for_statement:
            rendered = render_for(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::switch_statement:
            rendered = render_switch(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::break_statement:
            rendered = emit_indent(*value) && emit("break", decompiler_document_token_kind_t::keyword, *value) &&
                       emit(";", decompiler_document_token_kind_t::punctuation, *value) && emit_newline(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::continue_statement:
            rendered = emit_indent(*value) && emit("continue", decompiler_document_token_kind_t::keyword, *value) &&
                       emit(";", decompiler_document_token_kind_t::punctuation, *value) && emit_newline(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::return_statement:
            rendered = render_terminal(*value, "return");
            break;
        case typed_pseudocode_ast_node_kind_t::throw_statement:
            rendered = render_terminal(*value, "throw");
            break;
        case typed_pseudocode_ast_node_kind_t::goto_statement:
            rendered = render_goto(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::label_statement:
            rendered = render_label(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::try_statement:
            rendered = render_try(*value);
            break;
        case typed_pseudocode_ast_node_kind_t::comment_statement:
            rendered = !settings_.emit_comments || render_standalone_comment(*value);
            break;
        default:
            fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.renderer.v2.statement_kind", value);
            break;
        }
        --nesting_;
        return rendered && !failed_;
    }

    bool render_declaration_inline(const typed_pseudocode_ast_node_t& value)
    {
        if (!identifier_text(value.stable_text)) {
            fail(decompiler_diagnostic_code_t::unresolved_symbol, "decompiler.renderer.v2.declaration_identifier", &value);
            return false;
        }
        if (settings_.emit_type_annotations) {
            if (!render_type(value) || !emit_space(value))
                return false;
        } else if (!emit("var", decompiler_document_token_kind_t::keyword, value) || !emit_space(value)) {
            return false;
        }
        if (!emit(value.stable_text, decompiler_document_token_kind_t::identifier, value))
            return false;
        if (!value.child_ids.empty()) {
            if (!emit_space(value) || !emit("=", decompiler_document_token_kind_t::operator_token, value) || !emit_space(value))
                return false;
            return render_expression(value.child_ids.front(), 1);
        }
        return true;
    }

    bool render_declaration(const typed_pseudocode_ast_node_t& value)
    {
        return emit_annotation(value) && emit_indent(value) && render_declaration_inline(value) &&
               emit(";", decompiler_document_token_kind_t::punctuation, value) && emit_newline(value);
    }

    bool render_expression_statement(const typed_pseudocode_ast_node_t& value)
    {
        return emit_annotation(value) && emit_indent(value) && render_expression(value.child_ids.front(), 1) &&
               emit(";", decompiler_document_token_kind_t::punctuation, value) && emit_newline(value);
    }

    bool render_control_body(const std::uint64_t id, const typed_pseudocode_ast_node_t& owner)
    {
        if (!emit_space(owner))
            return false;
        return render_compound(id);
    }

    bool render_if(const typed_pseudocode_ast_node_t& value)
    {
        if (!emit_annotation(value) || !emit_indent(value) || !emit("if", decompiler_document_token_kind_t::keyword, value) ||
            !emit_space(value) || !emit("(", decompiler_document_token_kind_t::punctuation, value) ||
            !render_expression(value.child_ids[0], 1) || !emit(")", decompiler_document_token_kind_t::punctuation, value) ||
            !render_control_body(value.child_ids[1], value))
            return false;
        if (value.child_ids.size() == 2)
            return true;
        const auto* alternate = node(value.child_ids[2]);
        if (alternate == nullptr)
            return false;
        const auto* alternate_body = node(alternate->child_ids.front());
        if (alternate_body == nullptr)
            return false;
        if (!emit_indent(value) || !emit("else", decompiler_document_token_kind_t::keyword, value))
            return false;
        if (alternate_body->kind == typed_pseudocode_ast_node_kind_t::if_statement) {
            if (!emit_space(value))
                return false;
            return render_if_inline(*alternate_body);
        }
        return render_control_body(alternate->child_ids.front(), value);
    }

    bool render_if_inline(const typed_pseudocode_ast_node_t& value)
    {
        if (!emit("if", decompiler_document_token_kind_t::keyword, value) || !emit_space(value) ||
            !emit("(", decompiler_document_token_kind_t::punctuation, value) || !render_expression(value.child_ids[0], 1) ||
            !emit(")", decompiler_document_token_kind_t::punctuation, value) || !render_control_body(value.child_ids[1], value))
            return false;
        if (value.child_ids.size() == 2)
            return true;
        const auto* alternate = node(value.child_ids[2]);
        if (alternate == nullptr)
            return false;
        const auto* alternate_body = node(alternate->child_ids.front());
        if (alternate_body == nullptr || !emit_indent(value) || !emit("else", decompiler_document_token_kind_t::keyword, value))
            return false;
        if (alternate_body->kind == typed_pseudocode_ast_node_kind_t::if_statement)
            return emit_space(value) && render_if_inline(*alternate_body);
        return render_control_body(alternate->child_ids.front(), value);
    }

    bool render_while(const typed_pseudocode_ast_node_t& value)
    {
        return emit_annotation(value) && emit_indent(value) && emit("while", decompiler_document_token_kind_t::keyword, value) &&
               emit_space(value) && emit("(", decompiler_document_token_kind_t::punctuation, value) &&
               render_expression(value.child_ids[0], 1) && emit(")", decompiler_document_token_kind_t::punctuation, value) &&
               render_control_body(value.child_ids[1], value);
    }

    bool render_do_while(const typed_pseudocode_ast_node_t& value)
    {
        if (!emit_annotation(value) || !emit_indent(value) || !emit("do", decompiler_document_token_kind_t::keyword, value) ||
            !render_control_body(value.child_ids[0], value) || !emit_indent(value) ||
            !emit("while", decompiler_document_token_kind_t::keyword, value) || !emit_space(value) ||
            !emit("(", decompiler_document_token_kind_t::punctuation, value) || !render_expression(value.child_ids[1], 1) ||
            !emit(")", decompiler_document_token_kind_t::punctuation, value) ||
            !emit(";", decompiler_document_token_kind_t::punctuation, value))
            return false;
        return emit_newline(value);
    }

    bool render_for_component(const std::uint64_t id)
    {
        const auto* value = node(id);
        if (value == nullptr)
            return false;
        if (value->kind == typed_pseudocode_ast_node_kind_t::declaration)
            return render_declaration_inline(*value);
        return render_expression(id, 1);
    }

    bool render_for(const typed_pseudocode_ast_node_t& value)
    {
        return emit_annotation(value) && emit_indent(value) && emit("for", decompiler_document_token_kind_t::keyword, value) &&
               emit_space(value) && emit("(", decompiler_document_token_kind_t::punctuation, value) &&
               render_for_component(value.child_ids[0]) && emit(";", decompiler_document_token_kind_t::punctuation, value) &&
               emit_space(value) && render_expression(value.child_ids[1], 1) &&
               emit(";", decompiler_document_token_kind_t::punctuation, value) && emit_space(value) &&
               render_expression(value.child_ids[2], 1) && emit(")", decompiler_document_token_kind_t::punctuation, value) &&
               render_control_body(value.child_ids[3], value);
    }

    bool render_switch(const typed_pseudocode_ast_node_t& value)
    {
        const auto saved_selector_type = switch_selector_type_id_;
        switch_selector_type_id_ = 0;
        if (!value.child_ids.empty()) {
            const auto selector_iterator = nodes_.find(value.child_ids[0]);
            if (selector_iterator != nodes_.end())
                switch_selector_type_id_ = selector_iterator->second->type_id;
        }
        const auto restore = [this, saved_selector_type]() { switch_selector_type_id_ = saved_selector_type; };
        if (!emit_annotation(value) || !emit_indent(value) || !emit("switch", decompiler_document_token_kind_t::keyword, value) ||
            !emit_space(value) || !emit("(", decompiler_document_token_kind_t::punctuation, value) ||
            !render_expression(value.child_ids[0], 1) || !emit(")", decompiler_document_token_kind_t::punctuation, value) ||
            !emit_space(value) || !emit("{", decompiler_document_token_kind_t::punctuation, value) || !emit_newline(value)) {
            restore();
            return false;
        }
        ++indent_;
        for (std::size_t index = 1; index < value.child_ids.size(); ++index) {
            const auto* case_value = node(value.child_ids[index]);
            if (case_value == nullptr || !render_switch_case(*case_value)) {
                --indent_;
                restore();
                return false;
            }
        }
        --indent_;
        restore();
        return emit_indent(value) && emit("}", decompiler_document_token_kind_t::punctuation, value) && emit_newline(value);
    }

    bool render_switch_case(const typed_pseudocode_ast_node_t& value)
    {
        if (!emit_indent(value))
            return false;
        std::size_t statement_begin = 0;
        if (value.stable_text == "default") {
            if (!emit("default", decompiler_document_token_kind_t::keyword, value) ||
                !emit(":", decompiler_document_token_kind_t::punctuation, value) || !emit_newline(value))
                return false;
        } else {
            const auto* case_literal = node(value.child_ids[0]);
            const auto enum_name = case_literal != nullptr &&
                    case_literal->kind == typed_pseudocode_ast_node_kind_t::literal
                ? enum_case_name(*case_literal)
                : std::optional<std::string>{};
            if (enum_name) {
                if (!emit("case", decompiler_document_token_kind_t::keyword, value) || !emit_space(value) ||
                    !emit(*enum_name, decompiler_document_token_kind_t::identifier, *case_literal) ||
                    !emit(":", decompiler_document_token_kind_t::punctuation, value) || !emit_newline(value))
                    return false;
            } else if (!emit("case", decompiler_document_token_kind_t::keyword, value) || !emit_space(value) ||
                !render_expression(value.child_ids[0], 1) || !emit(":", decompiler_document_token_kind_t::punctuation, value) ||
                !emit_newline(value)) {
                return false;
            }
            statement_begin = 1;
        }
        ++indent_;
        for (std::size_t index = statement_begin; index < value.child_ids.size(); ++index) {
            if (!render_statement(value.child_ids[index]) || !attach_trailing_comments(value.child_ids, index)) {
                --indent_;
                return false;
            }
        }
        --indent_;
        return true;
    }

    bool render_terminal(const typed_pseudocode_ast_node_t& value, const char* keyword)
    {
        if (!emit_annotation(value) || !emit_indent(value) || !emit(keyword, decompiler_document_token_kind_t::keyword, value))
            return false;
        if (!value.child_ids.empty() && (!emit_space(value) || !render_expression(value.child_ids.front(), 1)))
            return false;
        return emit(";", decompiler_document_token_kind_t::punctuation, value) && emit_newline(value);
    }

    bool render_goto(const typed_pseudocode_ast_node_t& value)
    {
        if (!emit_annotation(value) || !emit_indent(value) || !emit("goto", decompiler_document_token_kind_t::keyword, value) ||
            !emit_space(value))
            return false;
        if (!identifier_text(value.stable_text)) {
            fail(decompiler_diagnostic_code_t::unresolved_symbol, "decompiler.renderer.v2.goto_label", &value);
            return false;
        }
        if (!emit(value.stable_text, decompiler_document_token_kind_t::identifier, value) ||
            !emit(";", decompiler_document_token_kind_t::punctuation, value))
            return false;
        return emit_newline(value);
    }

    bool render_label(const typed_pseudocode_ast_node_t& value)
    {
        if (!emit_annotation(value) || !emit_indent(value))
            return false;
        if (!identifier_text(value.stable_text)) {
            fail(decompiler_diagnostic_code_t::unresolved_symbol, "decompiler.renderer.v2.label_name", &value);
            return false;
        }
        if (!emit(value.stable_text, decompiler_document_token_kind_t::identifier, value) ||
            !emit(":", decompiler_document_token_kind_t::punctuation, value))
            return false;
        return emit_newline(value);
    }

    bool render_try(const typed_pseudocode_ast_node_t& value)
    {
        if (!emit_annotation(value) || !emit_indent(value) || !emit("try", decompiler_document_token_kind_t::keyword, value) ||
            !render_control_body(value.child_ids.front(), value))
            return false;
        for (std::size_t index = 1; index < value.child_ids.size(); ++index) {
            const auto* handler = node(value.child_ids[index]);
            if (handler == nullptr || !emit_indent(*handler))
                return false;
            if (handler->kind == typed_pseudocode_ast_node_kind_t::catch_clause) {
                if (!visible_text(handler->stable_text) || !emit("catch", decompiler_document_token_kind_t::keyword, *handler) ||
                    !emit_space(*handler) || !emit("(", decompiler_document_token_kind_t::punctuation, *handler) ||
                    !emit(handler->stable_text, decompiler_document_token_kind_t::type_name, *handler) ||
                    !emit(")", decompiler_document_token_kind_t::punctuation, *handler) ||
                    !render_control_body(handler->child_ids.front(), *handler))
                    return false;
            } else if (handler->kind == typed_pseudocode_ast_node_kind_t::finally_clause) {
                if (!emit("finally", decompiler_document_token_kind_t::keyword, *handler) ||
                    !render_control_body(handler->child_ids.front(), *handler))
                    return false;
            } else {
                fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.renderer.v2.try_handler", handler);
                return false;
            }
        }
        return true;
    }

    bool render_expression(const std::uint64_t id, const int parent_precedence)
    {
        const auto* value = node(id);
        if (value == nullptr)
            return false;
        if (++nesting_ > request_.limits.max_nesting) {
            --nesting_;
            fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.renderer.v2.expression_nesting", value);
            return false;
        }
        const int current_precedence = precedence(*value);
        const bool parenthesized = current_precedence < parent_precedence;
        bool rendered = !parenthesized || emit("(", decompiler_document_token_kind_t::punctuation, *value);
        if (!rendered) {
            --nesting_;
            return false;
        }
        switch (value->kind) {
        case typed_pseudocode_ast_node_kind_t::identifier:
            if (!identifier_text(value->stable_text)) {
                fail(decompiler_diagnostic_code_t::unresolved_symbol, "decompiler.renderer.v2.identifier", value);
                rendered = false;
            } else {
                rendered = emit(value->stable_text, decompiler_document_token_kind_t::identifier, *value);
            }
            break;
        case typed_pseudocode_ast_node_kind_t::literal:
            if (!visible_text(value->stable_text)) {
                fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.renderer.v2.literal", value);
                rendered = false;
            } else {
                rendered = emit(value->stable_text, decompiler_document_token_kind_t::literal, *value);
            }
            break;
        case typed_pseudocode_ast_node_kind_t::unknown_expression:
            if (!settings_.emit_unknown_tokens || !visible_text(value->stable_text)) {
                fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.renderer.v2.unknown_expression", value);
                rendered = false;
            } else {
                rendered = emit("unknown<", decompiler_document_token_kind_t::unknown, *value) &&
                           emit(quote_unknown(value->stable_text), decompiler_document_token_kind_t::unknown, *value) &&
                           emit(">", decompiler_document_token_kind_t::unknown, *value);
            }
            break;
        case typed_pseudocode_ast_node_kind_t::assignment_expression:
            rendered = render_expression(value->child_ids[0], current_precedence + 1) && emit_space(*value) &&
                       emit("=", decompiler_document_token_kind_t::operator_token, *value) && emit_space(*value) &&
                       render_expression(value->child_ids[1], current_precedence);
            break;
        case typed_pseudocode_ast_node_kind_t::unary_expression:
            rendered = unary_operator(value->stable_text) &&
                       emit(value->stable_text, decompiler_document_token_kind_t::operator_token, *value) &&
                       render_expression(value->child_ids[0], current_precedence);
            if (!rendered && !failed_)
                fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.renderer.v2.unary_operator", value);
            break;
        case typed_pseudocode_ast_node_kind_t::binary_expression:
            rendered = render_expression(value->child_ids[0], current_precedence) && emit_space(*value) &&
                       emit(value->stable_text, decompiler_document_token_kind_t::operator_token, *value) && emit_space(*value) &&
                       render_expression(value->child_ids[1], current_precedence + 1);
            break;
        case typed_pseudocode_ast_node_kind_t::cast_expression:
            rendered = emit("(", decompiler_document_token_kind_t::punctuation, *value) && render_type(*value) &&
                       emit(")", decompiler_document_token_kind_t::punctuation, *value) &&
                       render_expression(value->child_ids[0], current_precedence);
            break;
        case typed_pseudocode_ast_node_kind_t::call_expression:
            rendered = render_call_callee(*value, current_precedence) &&
                       emit("(", decompiler_document_token_kind_t::punctuation, *value);
            for (std::size_t index = 1; rendered && index < value->child_ids.size(); ++index) {
                if (index != 1)
                    rendered = emit(",", decompiler_document_token_kind_t::punctuation, *value) && emit_space(*value);
                if (rendered)
                    rendered = render_expression(value->child_ids[index], 1);
            }
            if (rendered)
                rendered = emit(")", decompiler_document_token_kind_t::punctuation, *value);
            break;
        case typed_pseudocode_ast_node_kind_t::member_expression:
            if (!identifier_text(value->stable_text)) {
                fail(decompiler_diagnostic_code_t::unresolved_symbol, "decompiler.renderer.v2.member_identifier", value);
                rendered = false;
            } else {
                rendered = render_expression(value->child_ids[0], current_precedence) &&
                           emit(member_access_operator(*value), decompiler_document_token_kind_t::operator_token, *value) &&
                           emit(value->stable_text, decompiler_document_token_kind_t::identifier, *value);
            }
            break;
        case typed_pseudocode_ast_node_kind_t::index_expression:
            rendered = render_expression(value->child_ids[0], current_precedence) &&
                       emit("[", decompiler_document_token_kind_t::punctuation, *value) && render_expression(value->child_ids[1], 1) &&
                       emit("]", decompiler_document_token_kind_t::punctuation, *value);
            break;
        default:
            fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.renderer.v2.expression_kind", value);
            rendered = false;
            break;
        }
        if (rendered && parenthesized)
            rendered = emit(")", decompiler_document_token_kind_t::punctuation, *value);
        --nesting_;
        return rendered && !failed_;
    }

    const char* member_access_operator(const typed_pseudocode_ast_node_t& member) const
    {
        if (member.child_ids.empty())
            return ".";
        const auto object_iterator = nodes_.find(member.child_ids[0]);
        if (object_iterator == nodes_.end())
            return ".";
        const auto type_iterator = types_.find(object_iterator->second->type_id);
        if (type_iterator == types_.end())
            return ".";
        return type_iterator->second->kind == decompiler_type_kind_t::pointer ? "->" : ".";
    }

    bool render_call_callee(const typed_pseudocode_ast_node_t& call, const int parent_precedence)
    {
        const auto* callee = node(call.child_ids[0]);
        if (callee == nullptr)
            return false;
        if (settings_.emit_resolved_symbols && !resolved_symbols_.empty() &&
            callee->kind == typed_pseudocode_ast_node_kind_t::identifier) {
            const auto resolved = resolved_symbols_.find(callee->stable_text);
            if (resolved != resolved_symbols_.end())
                return emit(resolved->second, decompiler_document_token_kind_t::identifier, *callee);
        }
        if (settings_.emit_resolved_symbols && !vtable_slots_.empty() &&
            callee->kind == typed_pseudocode_ast_node_kind_t::index_expression && callee->child_ids.size() == 2)
            return render_vtable_call_callee(call, *callee, parent_precedence);
        return render_expression(call.child_ids[0], parent_precedence);
    }

    bool render_vtable_call_callee(const typed_pseudocode_ast_node_t& call,
                                   const typed_pseudocode_ast_node_t& callee,
                                   const int parent_precedence)
    {
        const auto* member = node(callee.child_ids[0]);
        const auto* slot = node(callee.child_ids[1]);
        if (member == nullptr || slot == nullptr ||
            member->kind != typed_pseudocode_ast_node_kind_t::member_expression || member->child_ids.size() != 1 ||
            slot->kind != typed_pseudocode_ast_node_kind_t::literal || !identifier_text(member->stable_text))
            return render_expression(call.child_ids[0], parent_precedence);
        const auto slot_index = parse_unsigned_literal(slot->stable_text);
        if (!slot_index)
            return render_expression(call.child_ids[0], parent_precedence);
        const auto method = vtable_slots_.find(vtable_slot_key(member->stable_text, *slot_index));
        if (method == vtable_slots_.end())
            return render_expression(call.child_ids[0], parent_precedence);
        const auto* object = node(member->child_ids[0]);
        if (object == nullptr)
            return false;
        const auto object_type = types_.find(object->type_id);
        const char* access = object_type != types_.end() &&
                object_type->second->kind == decompiler_type_kind_t::pointer
            ? "->" : ".";
        return render_expression(member->child_ids[0], 13) &&
               emit(access, decompiler_document_token_kind_t::operator_token, *member) &&
               emit(member->stable_text, decompiler_document_token_kind_t::identifier, *member) &&
               emit("->", decompiler_document_token_kind_t::operator_token, callee) &&
               emit(method->second, decompiler_document_token_kind_t::identifier, *slot);
    }

    static std::optional<std::uint64_t> parse_unsigned_literal(const std::string& text)
    {
        if (text.empty() || text.size() > 20)
            return std::nullopt;
        std::uint64_t value = 0;
        int base = 10;
        std::size_t offset = 0;
        if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
            base = 16;
            offset = 2;
        }
        if (offset == text.size())
            return std::nullopt;
        for (std::size_t index = offset; index < text.size(); ++index) {
            const char character = text[index];
            const auto digit = base == 16
                ? (character >= '0' && character <= '9' ? character - '0'
                    : character >= 'a' && character <= 'f' ? character - 'a' + 10
                    : character >= 'A' && character <= 'F' ? character - 'A' + 10 : -1)
                : (character >= '0' && character <= '9' ? character - '0' : -1);
            if (digit < 0)
                return std::nullopt;
            if (value > (std::numeric_limits<std::uint64_t>::max() - 15ULL) / 16ULL)
                return std::nullopt;
            value = value * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(digit);
        }
        return value;
    }

    std::optional<std::string> enum_case_name(const typed_pseudocode_ast_node_t& literal_node) const
    {
        if (!settings_.emit_enum_case_names || switch_selector_type_id_ == 0)
            return std::nullopt;
        const auto type_iterator = types_.find(switch_selector_type_id_);
        if (type_iterator == types_.end() || type_iterator->second->kind != decompiler_type_kind_t::enumeration)
            return std::nullopt;
        const auto value = parse_unsigned_literal(literal_node.stable_text);
        if (!value)
            return std::nullopt;
        const decompiler_type_edge_t* best = nullptr;
        for (const auto& edge : type_graph_.edges) {
            if (edge.source_type_id != switch_selector_type_id_ ||
                edge.kind != decompiler_type_edge_kind_t::member || !edge.byte_offset.has_value() ||
                *edge.byte_offset != *value || edge.stable_name.empty() ||
                !identifier_text(edge.stable_name))
                continue;
            if (best == nullptr || edge.confidence > best->confidence)
                best = &edge;
        }
        if (best == nullptr)
            return std::nullopt;
        return best->stable_name;
    }

    void append_document_metadata()
    {
        const decompiler_token_range_t range{0, static_cast<std::uint32_t>(document_.rendered_text.size())};
        std::uint32_t ordinal = 1;
        for (const auto& diagnostic : ast_.diagnostics) {
            auto translated = diagnostic;
            translated.ordinal = ordinal++;
            if (translated.coordinate)
                translated.coordinate = document_coordinate(*translated.coordinate, range);
            document_.diagnostics.push_back(std::move(translated));
        }
        for (const auto& unknown : ast_.unknowns) {
            auto translated = unknown;
            translated.coordinate = document_coordinate(unknown.coordinate, range);
            document_.unknowns.push_back(std::move(translated));
        }
    }

    void fail(
        const decompiler_diagnostic_code_t code,
        std::string key,
        const typed_pseudocode_ast_node_t* value)
    {
        if (failed_)
            return;
        failed_ = true;
        std::optional<source_coordinate_t> coordinate;
        if (value != nullptr)
            coordinate = value->coordinate;
        result_.diagnostics.push_back(renderer_diagnostic(code, std::move(key), next_diagnostic_ordinal_++, coordinate));
    }

    const typed_pseudocode_ast_v2_t& ast_;
    const type_graph_t& type_graph_;
    const pseudocode_renderer_v2_request_t& request_;
    const decompiler_renderer_settings_t settings_;
    pseudocode_renderer_v2_result_t result_;
    decompiler_document_t document_;
    std::map<std::uint64_t, const typed_pseudocode_ast_node_t*> nodes_;
    std::map<std::uint64_t, const decompiler_type_node_t*> types_;
    std::map<std::string, std::string> resolved_symbols_;
    std::map<std::string, std::string> vtable_slots_;
    std::uint64_t switch_selector_type_id_ = 0;
    std::size_t indent_ = 0;
    std::size_t nesting_ = 0;
    std::uint32_t next_diagnostic_ordinal_ = 1;
    bool failed_ = false;
};

}

bool pseudocode_renderer_v2_result_t::succeeded() const noexcept
{
    return document.has_value();
}

decompiler_renderer_settings_t pseudocode_renderer_v2_style_settings(
    const pseudocode_renderer_v2_style_profile_t profile)
{
    decompiler_renderer_settings_t result;
    switch (profile) {
    case pseudocode_renderer_v2_style_profile_t::compact:
        result.style_id = "aida.pseudocode.v2.compact";
        result.indentation_spaces = 2;
        result.emit_type_annotations = true;
        result.emit_provenance_annotations = false;
        result.emit_unknown_tokens = true;
        result.emit_comments = false;
        result.readability.enable_expression_simplification = false;
        result.readability.enable_temporary_coalescing = false;
        result.readability.enable_identity_simplification = false;
        result.readability.enable_cast_simplification = false;
        result.readability.enable_comparison_normalization = false;
        result.readability.enable_compound_assignment_marking = false;
        result.readability.enable_double_negation_simplification = false;
        result.readability.enable_single_use_inlining = false;
        result.readability.enable_copy_propagation = false;
        result.readability.enable_dead_store_elimination = false;
        break;
    case pseudocode_renderer_v2_style_profile_t::balanced:
        result.style_id = "aida.pseudocode.v2.balanced";
        result.indentation_spaces = 4;
        result.emit_type_annotations = true;
        result.emit_provenance_annotations = false;
        result.emit_unknown_tokens = true;
        break;
    case pseudocode_renderer_v2_style_profile_t::audit:
        result.style_id = "aida.pseudocode.v2.audit";
        result.indentation_spaces = 4;
        result.emit_type_annotations = true;
        result.emit_provenance_annotations = true;
        result.emit_unknown_tokens = true;
        result.readability.max_transform_iterations = 8;
        break;
    }
    return result;
}

pseudocode_renderer_v2_result_t render_pseudocode_v2(
    const typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    const pseudocode_renderer_v2_request_t& request)
{
    return renderer_t(ast, type_graph, request).run();
}

std::string serialize_pseudocode_document_v2(const decompiler_document_t& document)
{
    return serialize_decompiler_document(document);
}

decompiler_contract_decode_result_t<decompiler_document_t> deserialize_pseudocode_document_v2(const std::string& bytes)
{
    return deserialize_decompiler_document(bytes);
}

}
