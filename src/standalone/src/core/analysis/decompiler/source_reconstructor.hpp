#pragma once

#include "legacy_document_adapter.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis {

constexpr std::uint32_t k_source_reconstruction_schema_version = 2;

struct source_reconstruction_limits_t {
    std::size_t max_documents = 65536;
    std::size_t max_total_output_bytes = 256U * 1024U * 1024U;
    std::size_t max_source_maps = 2000000;
    std::size_t max_diagnostics = 262144;
    std::size_t max_unknowns = 262144;
    std::size_t max_relative_path_bytes = 512;
    std::size_t max_function_name_bytes = 1024;
};

struct source_reconstruction_input_t {
    const decompiler_document_t* document = nullptr;
    std::string relative_path;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct reconstructed_source_map_t {
    decompiler_token_range_t output_range;
    decompiler_token_range_t document_range;
    std::uint64_t ast_node_id = 0;
    std::vector<source_coordinate_t> coordinates;
};

struct reconstructed_function_declaration_t {
    std::string text;
    decompiler_token_range_t document_range;
    std::vector<reconstructed_source_map_t> source_maps;
    std::size_t synthetic_suffix_bytes = 0;
    sha256_digest_t content_hash;
};

struct reconstructed_source_artifact_t {
    std::uint32_t schema_version = k_source_reconstruction_schema_version;
    decompiler_entity_key_t entity;
    std::string relative_path;
    std::string function_name;
    std::string content;
    reconstructed_function_declaration_t declaration;
    std::vector<reconstructed_source_map_t> source_maps;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::vector<decompiler_unknown_t> unknowns;
    sha256_digest_t document_hash;
    sha256_digest_t content_hash;
    sha256_digest_t source_map_hash;
    bool source_evidence_complete = false;
};

struct source_reconstruction_output_t {
    std::uint32_t schema_version = k_source_reconstruction_schema_version;
    std::vector<reconstructed_source_artifact_t> artifacts;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::size_t total_output_bytes = 0;
    std::size_t total_source_maps = 0;
    std::size_t total_unknowns = 0;
    sha256_digest_t reconstruction_hash;
};

struct source_reconstruction_request_t {
    std::vector<source_reconstruction_input_t> inputs;
    source_reconstruction_limits_t limits;
};

struct source_reconstruction_result_t {
    std::optional<source_reconstruction_output_t> output;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept {
        return output.has_value();
    }
};

namespace source_reconstruction_detail {

inline decompiler_diagnostic_t diagnostic(
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

inline std::uint32_t next_ordinal(const std::vector<decompiler_diagnostic_t>& diagnostics) noexcept
{
    std::uint32_t result = 1;
    for (const auto& value : diagnostics) {
        if (value.ordinal >= result && value.ordinal != std::numeric_limits<std::uint32_t>::max())
            result = value.ordinal + 1;
    }
    return result;
}

inline bool add_size(std::size_t& target, const std::size_t value) noexcept
{
    if (value > std::numeric_limits<std::size_t>::max() - target)
        return false;
    target += value;
    return true;
}

inline void append_u32(std::string& output, const std::uint32_t value)
{
    for (unsigned int shift = 0; shift != 32; shift += 8)
        output.push_back(static_cast<char>((value >> shift) & 0xffU));
}

inline void append_u64(std::string& output, const std::uint64_t value)
{
    for (unsigned int shift = 0; shift != 64; shift += 8)
        output.push_back(static_cast<char>((value >> shift) & 0xffULL));
}

inline void append_bytes(std::string& output, const std::string& value)
{
    append_u64(output, static_cast<std::uint64_t>(value.size()));
    output.append(value);
}

inline bool valid_limits(const source_reconstruction_limits_t& limits) noexcept
{
    return limits.max_documents != 0 && limits.max_total_output_bytes != 0 &&
           limits.max_source_maps != 0 && limits.max_diagnostics != 0 &&
           limits.max_unknowns != 0 && limits.max_relative_path_bytes != 0 &&
           limits.max_function_name_bytes != 0 &&
           limits.max_total_output_bytes <= std::numeric_limits<std::uint32_t>::max();
}

inline bool complete_source_maps(const decompiler_document_t& document) noexcept
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

inline const typed_pseudocode_ast_node_t* root_node(const decompiler_document_t& document) noexcept
{
    const auto iterator = std::lower_bound(document.ast.nodes.begin(), document.ast.nodes.end(),
        document.ast.root_node_id,
        [](const typed_pseudocode_ast_node_t& node, const std::uint64_t id) { return node.id < id; });
    return iterator == document.ast.nodes.end() || iterator->id != document.ast.root_node_id
        ? nullptr : &*iterator;
}

inline bool valid_relative_path(const std::string& path, const std::size_t maximum) noexcept
{
    if (path.empty() || path.size() > maximum || path.front() == '/' || path.front() == '\\')
        return false;
    std::size_t component_begin = 0;
    for (std::size_t index = 0; index <= path.size(); ++index) {
        if (index != path.size() && path[index] != '/') {
            const auto character = static_cast<unsigned char>(path[index]);
            if (path[index] == '\\' || path[index] == ':' || std::iscntrl(character) != 0)
                return false;
            continue;
        }
        if (index == component_begin)
            return false;
        const std::string component = path.substr(component_begin, index - component_begin);
        if (component == "." || component == "..")
            return false;
        component_begin = index + 1;
    }
    return true;
}

inline std::string safe_function_component(const std::string& value)
{
    std::string result;
    result.reserve((std::min)(value.size(), static_cast<std::size_t>(96)));
    for (const char raw : value) {
        const auto character = static_cast<unsigned char>(raw);
        const char translated = std::isalnum(character) != 0 || raw == '_' ? raw : '_';
        if (result.empty() && std::isdigit(static_cast<unsigned char>(translated)) != 0)
            result.append("fn_");
        if (result.size() == 96)
            break;
        result.push_back(translated);
    }
    if (result.empty())
        result = "function";
    return result;
}

inline std::string derived_relative_path(const decompiler_document_t& document, const std::string& function_name)
{
    const std::string entity_hash = stable_serialization_hash(document.entity).to_hex();
    return "src/" + safe_function_component(function_name) + "_" + entity_hash.substr(0, 16) + ".cpp";
}

inline reconstructed_source_map_t source_map(
    const decompiler_document_t& document,
    const std::size_t index,
    const std::uint32_t output_offset = 0)
{
    const auto& original = document.source_maps[index];
    reconstructed_source_map_t result;
    result.output_range = {
        static_cast<std::uint32_t>(original.document_range.begin + output_offset),
        static_cast<std::uint32_t>(original.document_range.end + output_offset)};
    result.document_range = original.document_range;
    result.ast_node_id = document.tokens[index].ast_node_id;
    result.coordinates = original.coordinates;
    return result;
}

inline std::optional<reconstructed_function_declaration_t> declaration(
    const decompiler_document_t& document)
{
    std::optional<std::size_t> body_token_index;
    for (std::size_t index = 0; index < document.tokens.size(); ++index) {
        const auto& token = document.tokens[index];
        if (token.ast_node_id != document.ast.body_node_id || token.range.end - token.range.begin != 1)
            continue;
        if (document.rendered_text[token.range.begin] == '{') {
            body_token_index = index;
            break;
        }
    }
    if (!body_token_index)
        return std::nullopt;
    std::size_t semantic_end = document.tokens[*body_token_index].range.begin;
    while (semantic_end != 0) {
        const auto character = static_cast<unsigned char>(document.rendered_text[semantic_end - 1]);
        if (std::isspace(character) == 0)
            break;
        --semantic_end;
    }
    if (semantic_end == 0 || semantic_end > std::numeric_limits<std::uint32_t>::max())
        return std::nullopt;
    reconstructed_function_declaration_t result;
    result.text.assign(document.rendered_text.data(), semantic_end);
    result.text.append(";\n");
    result.document_range = {0, static_cast<std::uint32_t>(semantic_end)};
    for (std::size_t index = 0; index < *body_token_index; ++index) {
        if (document.source_maps[index].document_range.end > semantic_end)
            break;
        result.source_maps.push_back(source_map(document, index));
    }
    result.synthetic_suffix_bytes = 2;
    result.content_hash = stable_serialization_hash(result.text);
    return result;
}

inline sha256_digest_t reconstruction_hash(const source_reconstruction_output_t& output)
{
    std::string canonical;
    append_u32(canonical, output.schema_version);
    append_u64(canonical, static_cast<std::uint64_t>(output.artifacts.size()));
    for (const auto& artifact : output.artifacts) {
        append_bytes(canonical, serialize_decompiler_entity_key(artifact.entity));
        append_bytes(canonical, artifact.relative_path);
        append_bytes(canonical, artifact.function_name);
        append_bytes(canonical, artifact.content_hash.to_hex());
        append_bytes(canonical, artifact.source_map_hash.to_hex());
        append_bytes(canonical, artifact.declaration.content_hash.to_hex());
        append_u64(canonical, static_cast<std::uint64_t>(artifact.diagnostics.size()));
        for (const auto& value : artifact.diagnostics)
            append_bytes(canonical, serialize_decompiler_diagnostic(value));
        append_u64(canonical, static_cast<std::uint64_t>(artifact.unknowns.size()));
        for (const auto& unknown : artifact.unknowns) {
            append_bytes(canonical, unknown.stable_token);
            append_bytes(canonical, serialize_source_coordinate(unknown.coordinate));
        }
    }
    return stable_serialization_hash(canonical);
}

}

inline source_reconstruction_result_t reconstruct_source_documents(
    const source_reconstruction_request_t& request)
{
    source_reconstruction_result_t result;
    if (!source_reconstruction_detail::valid_limits(request.limits) || request.inputs.empty() ||
        request.inputs.size() > request.limits.max_documents) {
        result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
            decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.source_reconstruction.request", 1));
        return result;
    }
    for (const auto& input : request.inputs)
        result.diagnostics.insert(result.diagnostics.end(), input.diagnostics.begin(), input.diagnostics.end());
    std::uint32_t ordinal = source_reconstruction_detail::next_ordinal(result.diagnostics);
    for (const auto& input : request.inputs) {
        if (input.document == nullptr) {
            result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
                decompiler_diagnostic_code_t::malformed_document,
                "decompiler.source_reconstruction.document_required", ordinal));
            return result;
        }
        result.diagnostics.insert(result.diagnostics.end(), input.document->diagnostics.begin(), input.document->diagnostics.end());
    }
    ordinal = source_reconstruction_detail::next_ordinal(result.diagnostics);
    if (result.diagnostics.size() > request.limits.max_diagnostics) {
        result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
            decompiler_diagnostic_code_t::resource_limit,
            "decompiler.source_reconstruction.diagnostic_limit", ordinal));
        return result;
    }
    std::vector<const source_reconstruction_input_t*> ordered;
    ordered.reserve(request.inputs.size());
    for (const auto& input : request.inputs)
        ordered.push_back(&input);
    std::sort(ordered.begin(), ordered.end(), [](const source_reconstruction_input_t* lhs,
                                                 const source_reconstruction_input_t* rhs) {
        if (lhs->document->entity != rhs->document->entity)
            return lhs->document->entity < rhs->document->entity;
        return lhs->relative_path < rhs->relative_path;
    });
    source_reconstruction_output_t output;
    output.diagnostics = result.diagnostics;
    output.artifacts.reserve(ordered.size());
    std::set<decompiler_entity_key_t> entities;
    std::set<std::string> paths;
    for (const auto* input : ordered) {
        const auto& document = *input->document;
        const auto validation = validate_decompiler_document(document);
        if (!validation.valid()) {
            result.diagnostics.insert(result.diagnostics.end(), validation.diagnostics.begin(), validation.diagnostics.end());
            return result;
        }
        if (!source_reconstruction_detail::complete_source_maps(document)) {
            result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
                decompiler_diagnostic_code_t::source_map_rejected,
                "decompiler.source_reconstruction.complete_source_map_required", ordinal));
            return result;
        }
        const auto* root = source_reconstruction_detail::root_node(document);
        if (root == nullptr || root->stable_text.empty() ||
            root->stable_text.size() > request.limits.max_function_name_bytes) {
            result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
                decompiler_diagnostic_code_t::malformed_ast,
                "decompiler.source_reconstruction.function_identity", ordinal));
            return result;
        }
        auto extracted_declaration = source_reconstruction_detail::declaration(document);
        if (!extracted_declaration) {
            result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
                decompiler_diagnostic_code_t::malformed_document,
                "decompiler.source_reconstruction.declaration_evidence", ordinal));
            return result;
        }
        std::string relative_path = input->relative_path.empty()
            ? source_reconstruction_detail::derived_relative_path(document, root->stable_text)
            : input->relative_path;
        if (!source_reconstruction_detail::valid_relative_path(relative_path,
                request.limits.max_relative_path_bytes)) {
            result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
                decompiler_diagnostic_code_t::invalid_contract,
                "decompiler.source_reconstruction.relative_path", ordinal));
            return result;
        }
        if (!entities.insert(document.entity).second || !paths.insert(relative_path).second) {
            result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
                decompiler_diagnostic_code_t::invalid_contract,
                "decompiler.source_reconstruction.duplicate_output", ordinal));
            return result;
        }
        std::size_t candidate_bytes = output.total_output_bytes;
        if (!source_reconstruction_detail::add_size(candidate_bytes, document.rendered_text.size()) ||
            !source_reconstruction_detail::add_size(candidate_bytes, extracted_declaration->text.size()) ||
            candidate_bytes > request.limits.max_total_output_bytes) {
            result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "decompiler.source_reconstruction.output_limit", ordinal));
            return result;
        }
        std::size_t candidate_maps = output.total_source_maps;
        if (!source_reconstruction_detail::add_size(candidate_maps, document.source_maps.size()) ||
            !source_reconstruction_detail::add_size(candidate_maps, extracted_declaration->source_maps.size()) ||
            candidate_maps > request.limits.max_source_maps) {
            result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "decompiler.source_reconstruction.source_map_limit", ordinal));
            return result;
        }
        std::size_t candidate_unknowns = output.total_unknowns;
        if (!source_reconstruction_detail::add_size(candidate_unknowns, document.unknowns.size()) ||
            candidate_unknowns > request.limits.max_unknowns) {
            result.diagnostics.push_back(source_reconstruction_detail::diagnostic(
                decompiler_diagnostic_code_t::resource_limit,
                "decompiler.source_reconstruction.unknown_limit", ordinal));
            return result;
        }
        reconstructed_source_artifact_t artifact;
        artifact.entity = document.entity;
        artifact.relative_path = std::move(relative_path);
        artifact.function_name = root->stable_text;
        artifact.content = document.rendered_text;
        artifact.declaration = std::move(*extracted_declaration);
        artifact.source_maps.reserve(document.source_maps.size());
        for (std::size_t index = 0; index < document.source_maps.size(); ++index)
            artifact.source_maps.push_back(source_reconstruction_detail::source_map(document, index));
        artifact.diagnostics = input->diagnostics;
        artifact.diagnostics.insert(artifact.diagnostics.end(), document.diagnostics.begin(), document.diagnostics.end());
        artifact.unknowns = document.unknowns;
        artifact.document_hash = stable_serialization_hash(document);
        artifact.content_hash = stable_serialization_hash(artifact.content);
        artifact.source_map_hash = hash_decompiler_source_maps(document.source_maps);
        artifact.source_evidence_complete = artifact.source_maps.size() == document.source_maps.size() &&
            artifact.content == document.rendered_text;
        output.total_output_bytes = candidate_bytes;
        output.total_source_maps = candidate_maps;
        output.total_unknowns = candidate_unknowns;
        output.artifacts.push_back(std::move(artifact));
    }
    output.reconstruction_hash = source_reconstruction_detail::reconstruction_hash(output);
    result.output = std::move(output);
    return result;
}

}
