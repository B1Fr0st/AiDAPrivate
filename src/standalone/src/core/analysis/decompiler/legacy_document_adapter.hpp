#pragma once

#include "decompiler_contracts.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis {

constexpr std::uint32_t k_legacy_document_adapter_schema_version = 1;

enum class legacy_document_view_status_t : std::uint8_t {
    complete = 1,
    bounded_prefix = 2
};

struct legacy_document_adapter_limits_t {
    std::size_t max_text_bytes = 4U * 1024U * 1024U;
    std::size_t max_tokens = 250000;
    std::size_t max_source_maps = 250000;
    std::size_t max_annotations = 250000;
    std::size_t max_line_mappings = 250000;
    std::size_t max_callees = 65536;
    std::size_t max_diagnostics = 65536;
    std::size_t max_unknowns = 65536;
};

struct legacy_document_annotation_t {
    std::uint8_t kind = 0;
    std::size_t start = 0;
    std::size_t end = 0;
    std::uint64_t address = 0;
    std::string name;
    std::uint64_t ast_node_id = 0;
};

struct legacy_document_view_t {
    std::uint32_t schema_version = k_legacy_document_adapter_schema_version;
    legacy_document_view_status_t status = legacy_document_view_status_t::complete;
    decompiler_entity_key_t entity;
    std::string pseudocode;
    std::vector<legacy_document_annotation_t> annotations;
    std::vector<std::pair<int, std::uint64_t>> line_to_address;
    std::vector<std::pair<std::string, std::uint64_t>> callees;
    std::vector<decompiler_document_source_map_t> source_maps;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::vector<decompiler_unknown_t> unknowns;
    sha256_digest_t document_hash;
    sha256_digest_t source_map_hash;
    sha256_digest_t view_hash;
    std::size_t original_text_bytes = 0;
    std::size_t original_token_count = 0;
    std::size_t original_source_map_count = 0;
    std::size_t original_annotation_count = 0;
    std::size_t original_line_mapping_count = 0;
    std::size_t original_callee_count = 0;
    bool visible_source_map_complete = false;

    bool complete() const noexcept;
};

struct legacy_document_adapter_result_t {
    std::optional<legacy_document_view_t> view;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept;
};

sha256_digest_t hash_decompiler_source_maps(
    const std::vector<decompiler_document_source_map_t>& source_maps);

legacy_document_adapter_result_t adapt_decompiler_document_for_legacy(
    const decompiler_document_t* document,
    const legacy_document_adapter_limits_t& limits = {});

legacy_document_adapter_result_t adapt_decompiler_document_for_legacy(
    const decompiler_document_t& document,
    const legacy_document_adapter_limits_t& limits = {});

}
