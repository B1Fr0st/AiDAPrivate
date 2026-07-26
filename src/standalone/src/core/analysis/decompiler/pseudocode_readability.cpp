#include "pseudocode_readability.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <map>
#include <set>
#include <string_view>

namespace aida::analysis {
namespace {

enum class identifier_style_t : std::uint8_t {
    flat_lower,
    flat_upper,
    lower_snake,
    upper_snake,
    lower_camel,
    upper_camel,
    mixed
};

decompiler_diagnostic_t readability_diagnostic(
    const decompiler_diagnostic_code_t code,
    std::string key,
    const std::uint32_t ordinal)
{
    decompiler_diagnostic_t result;
    result.severity = decompiler_diagnostic_severity_t::error;
    result.code = code;
    result.localization_key = std::move(key);
    result.confidence = 100;
    result.ordinal = ordinal;
    return result;
}

std::uint32_t next_ordinal(const std::vector<decompiler_diagnostic_t>& diagnostics) noexcept
{
    std::uint32_t result = 1;
    for (const auto& diagnostic : diagnostics) {
        if (diagnostic.ordinal >= result && diagnostic.ordinal != std::numeric_limits<std::uint32_t>::max())
            result = diagnostic.ordinal + 1;
    }
    return result;
}

void append_u32(std::string& output, const std::uint32_t value)
{
    for (unsigned int shift = 0; shift != 32; shift += 8)
        output.push_back(static_cast<char>((value >> shift) & 0xffU));
}

void append_u64(std::string& output, const std::uint64_t value)
{
    for (unsigned int shift = 0; shift != 64; shift += 8)
        output.push_back(static_cast<char>((value >> shift) & 0xffULL));
}

void append_bytes(std::string& output, const std::string& value)
{
    append_u64(output, static_cast<std::uint64_t>(value.size()));
    output.append(value);
}

bool visible_text(const std::string& value) noexcept
{
    return !value.empty() && std::none_of(value.begin(), value.end(), [](const char character) {
        return character == '\r' || character == '\n' || character == '\0';
    });
}

bool valid_limits(const pseudocode_readability_limits_t& limits) noexcept
{
    return limits.max_ast_nodes != 0 && limits.max_traversal_edges != 0 && limits.max_nesting != 0 &&
           limits.max_document_bytes != 0 && limits.max_tokens != 0 && limits.max_source_maps != 0 &&
           limits.max_diagnostics != 0 && limits.max_unknowns != 0 && limits.max_baseline_bytes != 0 &&
           limits.max_fixture_id_bytes != 0 &&
           limits.max_document_bytes <= std::numeric_limits<std::uint32_t>::max() &&
           limits.max_baseline_bytes <= std::numeric_limits<std::uint32_t>::max();
}

bool expression_kind(const typed_pseudocode_ast_node_kind_t kind) noexcept
{
    return kind >= typed_pseudocode_ast_node_kind_t::assignment_expression &&
           kind <= typed_pseudocode_ast_node_kind_t::unknown_expression;
}

bool control_kind(const typed_pseudocode_ast_node_kind_t kind) noexcept
{
    switch (kind) {
    case typed_pseudocode_ast_node_kind_t::if_statement:
    case typed_pseudocode_ast_node_kind_t::while_statement:
    case typed_pseudocode_ast_node_kind_t::do_while_statement:
    case typed_pseudocode_ast_node_kind_t::for_statement:
    case typed_pseudocode_ast_node_kind_t::switch_statement:
    case typed_pseudocode_ast_node_kind_t::switch_case:
    case typed_pseudocode_ast_node_kind_t::try_statement:
    case typed_pseudocode_ast_node_kind_t::catch_clause:
    case typed_pseudocode_ast_node_kind_t::finally_clause:
        return true;
    default:
        return false;
    }
}

std::string identifier_component(std::string value)
{
    const auto scope = value.rfind("::");
    if (scope != std::string::npos)
        value.erase(0, scope + 2);
    const auto first = value.find_first_not_of('_');
    if (first == std::string::npos)
        return {};
    value.erase(0, first);
    return value;
}

identifier_style_t identifier_style(std::string value)
{
    value = identifier_component(std::move(value));
    if (value.empty())
        return identifier_style_t::mixed;
    bool has_upper = false;
    bool has_lower = false;
    bool has_underscore = false;
    for (const char raw : value) {
        const auto character = static_cast<unsigned char>(raw);
        has_upper = has_upper || std::isupper(character) != 0;
        has_lower = has_lower || std::islower(character) != 0;
        has_underscore = has_underscore || raw == '_';
    }
    if (has_underscore) {
        if (has_lower && !has_upper)
            return identifier_style_t::lower_snake;
        if (has_upper && !has_lower)
            return identifier_style_t::upper_snake;
        return identifier_style_t::mixed;
    }
    const auto first = static_cast<unsigned char>(value.front());
    if (has_lower && !has_upper)
        return identifier_style_t::flat_lower;
    if (has_upper && !has_lower)
        return identifier_style_t::flat_upper;
    if (std::islower(first) != 0)
        return identifier_style_t::lower_camel;
    if (std::isupper(first) != 0)
        return identifier_style_t::upper_camel;
    return identifier_style_t::mixed;
}

double naming_consistency(const std::set<std::string>& identifiers) noexcept
{
    if (identifiers.empty())
        return 1.0;
    std::array<std::size_t, 7> counts{};
    for (const auto& identifier : identifiers)
        ++counts[static_cast<std::size_t>(identifier_style(identifier))];
    const auto maximum = *std::max_element(counts.begin(), counts.end());
    return static_cast<double>(maximum) / static_cast<double>(identifiers.size());
}

bool complete_source_map(const decompiler_document_t& document, std::size_t& mapped_bytes) noexcept
{
    mapped_bytes = 0;
    if (document.tokens.size() != document.source_maps.size())
        return false;
    std::uint32_t expected = 0;
    for (std::size_t index = 0; index < document.tokens.size(); ++index) {
        const auto& token = document.tokens[index];
        const auto& source_map = document.source_maps[index];
        if (token.range.begin != expected || token.range.begin != source_map.document_range.begin ||
            token.range.end != source_map.document_range.end)
            return false;
        mapped_bytes += source_map.document_range.end - source_map.document_range.begin;
        expected = source_map.document_range.end;
    }
    return expected == document.rendered_text.size() && mapped_bytes == document.rendered_text.size();
}

struct traversal_result_t {
    pseudocode_readability_metrics_t metrics;
    std::set<std::string> identifiers;
    std::size_t visited_nodes = 0;
    std::size_t traversed_edges = 0;
    std::uint64_t confidence_sum = 0;
    std::uint8_t minimum_confidence = 100;
    bool valid = false;
    std::string error_key;
};

traversal_result_t traverse_ast(
    const typed_pseudocode_ast_v2_t& ast,
    const pseudocode_readability_limits_t& limits)
{
    traversal_result_t result;
    std::map<std::uint64_t, std::size_t> indices;
    for (std::size_t index = 0; index < ast.nodes.size(); ++index)
        indices.emplace(ast.nodes[index].id, index);
    const auto root = indices.find(ast.root_node_id);
    if (root == indices.end()) {
        result.error_key = "decompiler.readability.v2.root";
        return result;
    }
    struct frame_t {
        std::size_t node_index = 0;
        std::size_t next_child = 0;
        std::size_t expression_depth = 0;
        std::size_t control_depth = 0;
        bool entered = false;
    };
    std::vector<frame_t> stack;
    std::vector<bool> active(ast.nodes.size(), false);
    std::vector<bool> counted(ast.nodes.size(), false);
    stack.push_back({root->second, 0, 0, 0, false});
    while (!stack.empty()) {
        auto& frame = stack.back();
        const auto& node = ast.nodes[frame.node_index];
        if (!frame.entered) {
            if (active[frame.node_index]) {
                result.error_key = "decompiler.readability.v2.cyclic_ast";
                return result;
            }
            active[frame.node_index] = true;
            frame.entered = true;
            const bool expression = expression_kind(node.kind);
            frame.expression_depth = expression ? frame.expression_depth + 1 : 0;
            frame.control_depth = control_kind(node.kind) ? frame.control_depth + 1 : frame.control_depth;
            if ((std::max)(frame.expression_depth, frame.control_depth) > limits.max_nesting) {
                result.error_key = "decompiler.readability.v2.nesting_limit";
                return result;
            }
            result.metrics.max_expression_depth = (std::max)(result.metrics.max_expression_depth,
                static_cast<std::uint64_t>(frame.expression_depth));
            result.metrics.max_control_nesting = (std::max)(result.metrics.max_control_nesting,
                static_cast<std::uint64_t>(frame.control_depth));
            if (!counted[frame.node_index]) {
                counted[frame.node_index] = true;
                ++result.visited_nodes;
                result.confidence_sum += node.confidence;
                result.minimum_confidence = (std::min)(result.minimum_confidence, node.confidence);
                if (node.kind == typed_pseudocode_ast_node_kind_t::declaration)
                    ++result.metrics.declaration_count;
                if (node.kind == typed_pseudocode_ast_node_kind_t::cast_expression)
                    ++result.metrics.cast_count;
                if (node.kind == typed_pseudocode_ast_node_kind_t::unknown_expression)
                    ++result.metrics.dead_placeholder_count;
                if ((node.kind == typed_pseudocode_ast_node_kind_t::function_definition ||
                     node.kind == typed_pseudocode_ast_node_kind_t::declaration ||
                     node.kind == typed_pseudocode_ast_node_kind_t::identifier) &&
                    visible_text(node.stable_text))
                    result.identifiers.insert(node.stable_text);
            }
        }
        if (frame.next_child == node.child_ids.size()) {
            active[frame.node_index] = false;
            stack.pop_back();
            continue;
        }
        if (++result.traversed_edges > limits.max_traversal_edges) {
            result.error_key = "decompiler.readability.v2.traversal_limit";
            return result;
        }
        const auto child = indices.find(node.child_ids[frame.next_child++]);
        if (child == indices.end()) {
            result.error_key = "decompiler.readability.v2.missing_child";
            return result;
        }
        if (active[child->second]) {
            result.error_key = "decompiler.readability.v2.cyclic_ast";
            return result;
        }
        stack.push_back({child->second, 0, frame.expression_depth, frame.control_depth, false});
    }
    if (result.visited_nodes != ast.nodes.size()) {
        result.error_key = "decompiler.readability.v2.unreachable_node";
        return result;
    }
    result.metrics.naming_consistency_ratio = naming_consistency(result.identifiers);
    result.valid = true;
    return result;
}

sha256_digest_t baseline_capture_hash(const pseudocode_baseline_capture_t& capture)
{
    std::string canonical;
    append_u32(canonical, capture.schema_version);
    canonical.push_back(static_cast<char>(capture.provider));
    append_bytes(canonical, capture.provider_build_hash.to_hex());
    append_bytes(canonical, capture.fixture_set_hash.to_hex());
    append_bytes(canonical, capture.fixture_id);
    append_bytes(canonical, capture.rendered_text);
    append_u64(canonical, static_cast<std::uint64_t>(capture.diagnostics.size()));
    for (const auto& diagnostic : capture.diagnostics)
        append_bytes(canonical, serialize_decompiler_diagnostic(diagnostic));
    return stable_serialization_hash(canonical);
}

}

bool pseudocode_baseline_capture_result_t::succeeded() const noexcept
{
    return capture.has_value();
}

bool pseudocode_readability_result_t::succeeded() const noexcept
{
    return report.has_value();
}

pseudocode_baseline_capture_result_t capture_pseudocode_readability_baseline(
    const pseudocode_baseline_capture_request_t& request,
    const pseudocode_readability_limits_t& limits)
{
    pseudocode_baseline_capture_result_t result;
    result.diagnostics = request.diagnostics;
    const std::uint32_t ordinal = next_ordinal(result.diagnostics);
    if (!valid_limits(limits) ||
        (request.provider != pseudocode_baseline_provider_t::ghidra_printc &&
         request.provider != pseudocode_baseline_provider_t::aida_current) ||
        request.provider_build_hash.empty() || request.fixture_set_hash.empty() ||
        !visible_text(request.fixture_id) || request.fixture_id.size() > limits.max_fixture_id_bytes ||
        request.rendered_text.empty() || request.rendered_text.size() > limits.max_baseline_bytes ||
        request.diagnostics.size() > limits.max_diagnostics) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.readability.v2.baseline_contract", ordinal));
        return result;
    }
    try {
        for (const auto& diagnostic : request.diagnostics)
            static_cast<void>(serialize_decompiler_diagnostic(diagnostic));
        pseudocode_baseline_capture_t capture;
        capture.provider = request.provider;
        capture.provider_build_hash = request.provider_build_hash;
        capture.fixture_set_hash = request.fixture_set_hash;
        capture.fixture_id = request.fixture_id;
        capture.rendered_text = request.rendered_text;
        capture.diagnostics = request.diagnostics;
        capture.rendered_text_hash = stable_serialization_hash(capture.rendered_text);
        capture.capture_hash = baseline_capture_hash(capture);
        result.capture = std::move(capture);
    } catch (const std::exception&) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.readability.v2.baseline_diagnostic", ordinal));
    }
    return result;
}

pseudocode_readability_result_t analyze_pseudocode_readability(
    const typed_pseudocode_ast_v2_t* ast,
    const decompiler_document_t* document,
    const pseudocode_readability_request_t& request)
{
    pseudocode_readability_result_t result;
    if (document != nullptr)
        result.diagnostics = document->diagnostics;
    std::uint32_t ordinal = next_ordinal(result.diagnostics);
    if (ast == nullptr || document == nullptr) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.readability.v2.ast_and_document_required", ordinal));
        return result;
    }
    if (!valid_limits(request.limits)) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.readability.v2.limits", ordinal));
        return result;
    }
    if (ast->nodes.size() > request.limits.max_ast_nodes ||
        document->rendered_text.size() > request.limits.max_document_bytes ||
        document->tokens.size() > request.limits.max_tokens ||
        document->source_maps.size() > request.limits.max_source_maps ||
        document->diagnostics.size() > request.limits.max_diagnostics ||
        document->unknowns.size() > request.limits.max_unknowns) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::resource_limit,
            "decompiler.readability.v2.resource_limit", ordinal));
        return result;
    }
    if (!typed_ast_has_proven_function_body(*ast)) {
        result.diagnostics.push_back(readability_diagnostic(
            decompiler_diagnostic_code_t::malformed_ast,
            "decompiler.readability.v2.fabricated_body", ordinal));
        return result;
    }
    const auto ast_validation = validate_typed_pseudocode_ast(*ast);
    const auto document_validation = validate_decompiler_document(*document);
    if (!ast_validation.valid() || !document_validation.valid()) {
        result.diagnostics.insert(result.diagnostics.end(), ast_validation.diagnostics.begin(), ast_validation.diagnostics.end());
        result.diagnostics.insert(result.diagnostics.end(), document_validation.diagnostics.begin(), document_validation.diagnostics.end());
        return result;
    }
    if (!(ast->entity == document->entity) || document->ast_hash != stable_serialization_hash(*ast) ||
        stable_serialization_hash(document->ast) != stable_serialization_hash(*ast)) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::malformed_document,
            "decompiler.readability.v2.ast_document_binding", ordinal));
        return result;
    }
    std::size_t mapped_bytes = 0;
    const bool source_map_complete = complete_source_map(*document, mapped_bytes);
    if (request.require_complete_source_map && !source_map_complete) {
        result.diagnostics.push_back(readability_diagnostic(decompiler_diagnostic_code_t::source_map_rejected,
            "decompiler.readability.v2.source_map_coverage", ordinal));
        return result;
    }
    auto traversal = traverse_ast(*ast, request.limits);
    if (!traversal.valid) {
        result.diagnostics.push_back(readability_diagnostic(
            traversal.error_key == "decompiler.readability.v2.nesting_limit" ||
                    traversal.error_key == "decompiler.readability.v2.traversal_limit"
                ? decompiler_diagnostic_code_t::resource_limit
                : decompiler_diagnostic_code_t::malformed_ast,
            std::move(traversal.error_key), ordinal));
        return result;
    }
    pseudocode_readability_report_t report;
    report.entity = document->entity;
    report.metrics = traversal.metrics;
    report.ast_node_count = ast->nodes.size();
    report.document_bytes = document->rendered_text.size();
    report.source_mapped_bytes = mapped_bytes;
    report.source_map_coverage_ratio = document->rendered_text.empty()
        ? 0.0 : static_cast<double>(mapped_bytes) / static_cast<double>(document->rendered_text.size());
    report.mean_confidence = traversal.visited_nodes == 0
        ? 0.0 : static_cast<double>(traversal.confidence_sum) / static_cast<double>(traversal.visited_nodes) / 100.0;
    report.minimum_confidence = traversal.visited_nodes == 0 ? 0 : traversal.minimum_confidence;
    report.explicit_unknown_ratio = ast->nodes.empty()
        ? 0.0 : static_cast<double>(document->unknowns.size()) / static_cast<double>(ast->nodes.size());
    report.ast_hash = stable_serialization_hash(*ast);
    report.document_hash = stable_serialization_hash(*document);
    report.source_map_hash = hash_decompiler_source_maps(document->source_maps);
    report.diagnostics = document->diagnostics;
    report.unknowns = document->unknowns;
    if (request.baseline) {
        auto baseline = capture_pseudocode_readability_baseline(*request.baseline, request.limits);
        if (!baseline.succeeded()) {
            result.diagnostics.insert(result.diagnostics.end(), baseline.diagnostics.begin(), baseline.diagnostics.end());
            return result;
        }
        report.baseline = std::move(*baseline.capture);
    }
    result.report = std::move(report);
    return result;
}

bool readability_transform_result_t::succeeded() const noexcept
{
    return transformed;
}

pseudocode_readability_result_t analyze_pseudocode_readability(
    const typed_pseudocode_ast_v2_t& ast,
    const decompiler_document_t& document,
    const pseudocode_readability_request_t& request)
{
    return analyze_pseudocode_readability(&ast, &document, request);
}

}
