#include "legacy_document_adapter.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <string_view>

namespace aida::analysis {
namespace {

decompiler_diagnostic_t adapter_diagnostic(
    const decompiler_diagnostic_severity_t severity,
    const decompiler_diagnostic_code_t code,
    std::string key,
    const std::uint32_t ordinal)
{
    decompiler_diagnostic_t result;
    result.severity = severity;
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

std::optional<std::uint64_t> first_address(const decompiler_document_source_map_t& source_map)
{
    for (const auto& coordinate : source_map.coordinates) {
        if (coordinate.address_range)
            return coordinate.address_range->begin.value;
    }
    return std::nullopt;
}

bool source_maps_cover_tokens(const decompiler_document_t& document) noexcept
{
    if (document.tokens.size() != document.source_maps.size())
        return false;
    std::uint32_t expected = 0;
    for (std::size_t index = 0; index < document.tokens.size(); ++index) {
        const auto& token = document.tokens[index];
        const auto& source_map = document.source_maps[index];
        if (token.range.begin != expected || token.range.begin != source_map.document_range.begin ||
            token.range.end != source_map.document_range.end)
            return false;
        expected = token.range.end;
    }
    return expected == document.rendered_text.size();
}

bool annotation_token(const decompiler_document_token_kind_t kind) noexcept
{
    return kind == decompiler_document_token_kind_t::identifier ||
           kind == decompiler_document_token_kind_t::type_name ||
           kind == decompiler_document_token_kind_t::literal ||
           kind == decompiler_document_token_kind_t::operator_token ||
           kind == decompiler_document_token_kind_t::unknown;
}

std::size_t bounded_token_count(
    const decompiler_document_t& document,
    const legacy_document_adapter_limits_t& limits)
{
    const std::size_t maximum = (std::min)({document.tokens.size(), limits.max_tokens, limits.max_source_maps});
    std::size_t result = 0;
    std::size_t annotation_count = 0;
    for (; result < maximum; ++result) {
        const auto& token = document.tokens[result];
        if (token.range.end > limits.max_text_bytes)
            break;
        if (annotation_token(token.kind)) {
            if (annotation_count == limits.max_annotations)
                break;
            ++annotation_count;
        }
    }
    return result;
}

std::string token_text(const decompiler_document_t& document, const decompiler_document_token_t& token)
{
    return document.rendered_text.substr(token.range.begin, token.range.end - token.range.begin);
}

std::vector<std::pair<int, std::uint64_t>> line_mappings(
    const std::string& text,
    const std::vector<decompiler_document_source_map_t>& source_maps,
    const std::size_t maximum,
    std::size_t& original_count)
{
    std::vector<std::optional<std::uint64_t>> addresses(1);
    for (const char character : text) {
        if (character == '\n')
            addresses.emplace_back();
    }
    std::size_t line = 0;
    std::size_t cursor = 0;
    for (const auto& source_map : source_maps) {
        while (cursor < source_map.document_range.begin && cursor < text.size()) {
            if (text[cursor++] == '\n')
                ++line;
        }
        const auto address = first_address(source_map);
        std::size_t map_cursor = source_map.document_range.begin;
        while (map_cursor < source_map.document_range.end && map_cursor < text.size()) {
            if (address && line < addresses.size() && !addresses[line])
                addresses[line] = *address;
            if (text[map_cursor++] == '\n')
                ++line;
        }
        cursor = (std::max)(cursor, map_cursor);
    }
    original_count = static_cast<std::size_t>(std::count_if(addresses.begin(), addresses.end(),
        [](const std::optional<std::uint64_t>& value) { return value.has_value(); }));
    std::vector<std::pair<int, std::uint64_t>> result;
    result.reserve((std::min)(maximum, original_count));
    for (std::size_t index = 0; index < addresses.size() && result.size() < maximum; ++index) {
        if (!addresses[index])
            continue;
        if (index >= static_cast<std::size_t>(std::numeric_limits<int>::max()))
            break;
        result.emplace_back(static_cast<int>(index + 1), *addresses[index]);
    }
    return result;
}

std::optional<std::size_t> first_token_offset(
    const decompiler_document_t& document,
    const std::uint64_t node_id,
    const std::size_t prefix_bytes)
{
    for (const auto& token : document.tokens) {
        if (token.range.begin >= prefix_bytes)
            break;
        if (token.ast_node_id == node_id)
            return token.range.begin;
    }
    return std::nullopt;
}

const typed_pseudocode_ast_node_t* find_node(
    const typed_pseudocode_ast_v2_t& ast,
    const std::uint64_t id) noexcept
{
    const auto iterator = std::lower_bound(ast.nodes.begin(), ast.nodes.end(), id,
        [](const typed_pseudocode_ast_node_t& node, const std::uint64_t candidate) {
            return node.id < candidate;
        });
    return iterator == ast.nodes.end() || iterator->id != id ? nullptr : &*iterator;
}

std::string callee_name(const typed_pseudocode_ast_v2_t& ast, const typed_pseudocode_ast_node_t& call)
{
    if (call.child_ids.empty())
        return {};
    const auto* callee = find_node(ast, call.child_ids.front());
    if (callee == nullptr)
        return {};
    if (callee->kind == typed_pseudocode_ast_node_kind_t::identifier ||
        callee->kind == typed_pseudocode_ast_node_kind_t::member_expression)
        return callee->stable_text;
    return {};
}

std::vector<std::pair<std::string, std::uint64_t>> legacy_callees(
    const decompiler_document_t& document,
    const std::size_t prefix_bytes,
    const std::size_t maximum,
    std::size_t& original_count)
{
    struct candidate_t {
        std::size_t offset = 0;
        std::string name;
        std::uint64_t address = 0;
    };
    std::vector<candidate_t> candidates;
    std::set<std::pair<std::string, std::uint64_t>> seen;
    for (const auto& node : document.ast.nodes) {
        if (node.kind != typed_pseudocode_ast_node_kind_t::call_expression)
            continue;
        const std::string name = callee_name(document.ast, node);
        if (name.empty())
            continue;
        auto offset = first_token_offset(document, node.id, prefix_bytes);
        if (!offset && !node.child_ids.empty())
            offset = first_token_offset(document, node.child_ids.front(), prefix_bytes);
        if (!offset)
            continue;
        const std::uint64_t address = node.coordinate.address_range
            ? node.coordinate.address_range->begin.value : 0;
        if (!seen.emplace(name, address).second)
            continue;
        candidates.push_back({*offset, name, address});
    }
    std::sort(candidates.begin(), candidates.end(), [](const candidate_t& lhs, const candidate_t& rhs) {
        if (lhs.offset != rhs.offset)
            return lhs.offset < rhs.offset;
        if (lhs.name != rhs.name)
            return lhs.name < rhs.name;
        return lhs.address < rhs.address;
    });
    original_count = candidates.size();
    std::vector<std::pair<std::string, std::uint64_t>> result;
    result.reserve((std::min)(maximum, candidates.size()));
    for (std::size_t index = 0; index < candidates.size() && index < maximum; ++index)
        result.emplace_back(std::move(candidates[index].name), candidates[index].address);
    return result;
}

sha256_digest_t legacy_view_hash(const legacy_document_view_t& view)
{
    std::string canonical;
    append_u32(canonical, view.schema_version);
    canonical.push_back(static_cast<char>(view.status));
    append_bytes(canonical, serialize_decompiler_entity_key(view.entity));
    append_bytes(canonical, view.pseudocode);
    append_bytes(canonical, view.source_map_hash.to_hex());
    append_u64(canonical, static_cast<std::uint64_t>(view.annotations.size()));
    for (const auto& annotation : view.annotations) {
        canonical.push_back(static_cast<char>(annotation.kind));
        append_u64(canonical, static_cast<std::uint64_t>(annotation.start));
        append_u64(canonical, static_cast<std::uint64_t>(annotation.end));
        append_u64(canonical, annotation.address);
        append_bytes(canonical, annotation.name);
        append_u64(canonical, annotation.ast_node_id);
    }
    append_u64(canonical, static_cast<std::uint64_t>(view.line_to_address.size()));
    for (const auto& mapping : view.line_to_address) {
        append_u64(canonical, static_cast<std::uint64_t>(mapping.first));
        append_u64(canonical, mapping.second);
    }
    append_u64(canonical, static_cast<std::uint64_t>(view.callees.size()));
    for (const auto& callee : view.callees) {
        append_bytes(canonical, callee.first);
        append_u64(canonical, callee.second);
    }
    append_u64(canonical, static_cast<std::uint64_t>(view.diagnostics.size()));
    for (const auto& diagnostic : view.diagnostics)
        append_bytes(canonical, serialize_decompiler_diagnostic(diagnostic));
    append_u64(canonical, static_cast<std::uint64_t>(view.unknowns.size()));
    for (const auto& unknown : view.unknowns) {
        append_u32(canonical, static_cast<std::uint32_t>(unknown.reason));
        append_bytes(canonical, unknown.stable_token);
        append_bytes(canonical, serialize_source_coordinate(unknown.coordinate));
        canonical.push_back(static_cast<char>(unknown.confidence));
        canonical.push_back(static_cast<char>(unknown.provenance));
    }
    return stable_serialization_hash(canonical);
}

}

bool legacy_document_view_t::complete() const noexcept
{
    return status == legacy_document_view_status_t::complete;
}

bool legacy_document_adapter_result_t::succeeded() const noexcept
{
    return view.has_value();
}

sha256_digest_t hash_decompiler_source_maps(
    const std::vector<decompiler_document_source_map_t>& source_maps)
{
    std::string canonical;
    append_u64(canonical, static_cast<std::uint64_t>(source_maps.size()));
    for (const auto& source_map : source_maps) {
        append_u32(canonical, source_map.document_range.begin);
        append_u32(canonical, source_map.document_range.end);
        append_u64(canonical, static_cast<std::uint64_t>(source_map.coordinates.size()));
        for (const auto& coordinate : source_map.coordinates)
            append_bytes(canonical, serialize_source_coordinate(coordinate));
    }
    return stable_serialization_hash(canonical);
}

bool typed_ast_has_proven_function_body(
    const typed_pseudocode_ast_v2_t& ast) noexcept
{
    if (ast.root_node_id == 0 || ast.body_node_id == 0 || ast.nodes.empty())
        return false;
    const auto root = std::find_if(ast.nodes.begin(), ast.nodes.end(),
        [&ast](const typed_pseudocode_ast_node_t& node) {
            return node.id == ast.root_node_id;
        });
    const auto body = std::find_if(ast.nodes.begin(), ast.nodes.end(),
        [&ast](const typed_pseudocode_ast_node_t& node) {
            return node.id == ast.body_node_id;
        });
    return root != ast.nodes.end() && body != ast.nodes.end() &&
           root->kind == typed_pseudocode_ast_node_kind_t::function_definition &&
           body->kind == typed_pseudocode_ast_node_kind_t::compound_statement &&
           !body->child_ids.empty() &&
           std::find(root->child_ids.begin(), root->child_ids.end(), ast.body_node_id) !=
               root->child_ids.end();
}

legacy_document_adapter_result_t adapt_decompiler_document_for_legacy(
    const decompiler_document_t* document,
    const legacy_document_adapter_limits_t& limits)
{
    legacy_document_adapter_result_t result;
    if (document == nullptr) {
        result.diagnostics.push_back(adapter_diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.legacy_adapter.document_required", 1));
        return result;
    }
    result.diagnostics = document->diagnostics;
    std::uint32_t ordinal = next_ordinal(result.diagnostics);
    if (limits.max_text_bytes == 0 || limits.max_tokens == 0 || limits.max_source_maps == 0 ||
        limits.max_annotations == 0 || limits.max_line_mappings == 0 || limits.max_callees == 0 ||
        limits.max_diagnostics == 0 || limits.max_unknowns == 0 ||
        limits.max_text_bytes > std::numeric_limits<std::uint32_t>::max()) {
        result.diagnostics.push_back(adapter_diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.legacy_adapter.limits", ordinal));
        return result;
    }
    if (!typed_ast_has_proven_function_body(document->ast)) {
        result.diagnostics.push_back(adapter_diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_ast,
            "decompiler.legacy_adapter.fabricated_body", ordinal));
        return result;
    }
    const auto validation = validate_decompiler_document(*document);
    if (!validation.valid()) {
        result.diagnostics.insert(result.diagnostics.end(), validation.diagnostics.begin(), validation.diagnostics.end());
        return result;
    }
    if (!source_maps_cover_tokens(*document)) {
        result.diagnostics.push_back(adapter_diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::source_map_rejected,
            "decompiler.legacy_adapter.complete_source_map_required", ordinal));
        return result;
    }
    if (document->diagnostics.size() > limits.max_diagnostics || document->unknowns.size() > limits.max_unknowns) {
        result.diagnostics.push_back(adapter_diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::resource_limit,
            "decompiler.legacy_adapter.metadata_limit", ordinal));
        return result;
    }
    const std::size_t token_count = bounded_token_count(*document, limits);
    if (token_count == 0) {
        result.diagnostics.push_back(adapter_diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::resource_limit,
            "decompiler.legacy_adapter.empty_bounded_view", ordinal));
        return result;
    }
    const std::size_t prefix_bytes = document->tokens[token_count - 1].range.end;
    legacy_document_view_t view;
    view.entity = document->entity;
    view.pseudocode.assign(document->rendered_text.data(), prefix_bytes);
    view.source_maps.assign(document->source_maps.begin(), document->source_maps.begin() + token_count);
    view.diagnostics = document->diagnostics;
    view.unknowns = document->unknowns;
    view.document_hash = stable_serialization_hash(*document);
    view.source_map_hash = hash_decompiler_source_maps(view.source_maps);
    view.original_text_bytes = document->rendered_text.size();
    view.original_token_count = document->tokens.size();
    view.original_source_map_count = document->source_maps.size();
    view.original_annotation_count = static_cast<std::size_t>(std::count_if(
        document->tokens.begin(), document->tokens.end(),
        [](const decompiler_document_token_t& token) { return annotation_token(token.kind); }));
    view.annotations.reserve((std::min)(view.original_annotation_count, limits.max_annotations));
    for (std::size_t index = 0; index < token_count; ++index) {
        const auto& token = document->tokens[index];
        if (!annotation_token(token.kind))
            continue;
        legacy_document_annotation_t annotation;
        annotation.kind = static_cast<std::uint8_t>(token.kind);
        annotation.start = token.range.begin;
        annotation.end = token.range.end;
        annotation.ast_node_id = token.ast_node_id;
        annotation.name = token_text(*document, token);
        if (const auto address = first_address(document->source_maps[index]))
            annotation.address = *address;
        view.annotations.push_back(std::move(annotation));
    }
    view.line_to_address = line_mappings(view.pseudocode, view.source_maps,
        limits.max_line_mappings, view.original_line_mapping_count);
    view.callees = legacy_callees(*document, prefix_bytes, limits.max_callees,
        view.original_callee_count);
    view.visible_source_map_complete = source_maps_cover_tokens(decompiler_document_t{
        document->schema_version,
        document->entity,
        document->ast,
        document->ast_hash,
        document->type_graph_hash,
        document->profile,
        document->renderer,
        view.pseudocode,
        std::vector<decompiler_document_token_t>(document->tokens.begin(), document->tokens.begin() + token_count),
        view.source_maps,
        document->unknowns,
        document->diagnostics});
    const bool complete = prefix_bytes == document->rendered_text.size() &&
        token_count == document->tokens.size() &&
        view.annotations.size() == view.original_annotation_count &&
        view.line_to_address.size() == view.original_line_mapping_count &&
        view.callees.size() == view.original_callee_count;
    view.status = complete ? legacy_document_view_status_t::complete
                           : legacy_document_view_status_t::bounded_prefix;
    if (!complete) {
        const auto bounded = adapter_diagnostic(decompiler_diagnostic_severity_t::warning,
            decompiler_diagnostic_code_t::resource_limit,
            "decompiler.legacy_adapter.bounded_view", ordinal);
        view.diagnostics.push_back(bounded);
        result.diagnostics.push_back(bounded);
    }
    view.view_hash = legacy_view_hash(view);
    result.view = std::move(view);
    return result;
}

legacy_document_adapter_result_t adapt_decompiler_document_for_legacy(
    const decompiler_document_t& document,
    const legacy_document_adapter_limits_t& limits)
{
    return adapt_decompiler_document_for_legacy(&document, limits);
}

}
