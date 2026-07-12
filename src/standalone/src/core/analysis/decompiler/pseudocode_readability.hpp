#pragma once

#include "legacy_document_adapter.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

constexpr std::uint32_t k_pseudocode_readability_schema_version = 2;

enum class pseudocode_baseline_provider_t : std::uint8_t {
    ghidra_printc = 1,
    aida_current = 2
};

struct pseudocode_readability_limits_t {
    std::size_t max_ast_nodes = 500000;
    std::size_t max_traversal_edges = 2000000;
    std::size_t max_nesting = 512;
    std::size_t max_document_bytes = 8U * 1024U * 1024U;
    std::size_t max_tokens = 500000;
    std::size_t max_source_maps = 500000;
    std::size_t max_diagnostics = 65536;
    std::size_t max_unknowns = 65536;
    std::size_t max_baseline_bytes = 8U * 1024U * 1024U;
    std::size_t max_fixture_id_bytes = 512;
};

struct pseudocode_readability_metrics_t {
    std::uint64_t declaration_count = 0;
    double naming_consistency_ratio = 1.0;
    std::uint64_t max_expression_depth = 0;
    std::uint64_t max_control_nesting = 0;
    std::uint64_t dead_placeholder_count = 0;
    std::uint64_t cast_count = 0;
    std::uint64_t fabricated_body_count = 0;
};

struct pseudocode_baseline_capture_request_t {
    pseudocode_baseline_provider_t provider = pseudocode_baseline_provider_t::aida_current;
    sha256_digest_t provider_build_hash;
    sha256_digest_t fixture_set_hash;
    std::string fixture_id;
    std::string rendered_text;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct pseudocode_baseline_capture_t {
    std::uint32_t schema_version = k_pseudocode_readability_schema_version;
    pseudocode_baseline_provider_t provider = pseudocode_baseline_provider_t::aida_current;
    sha256_digest_t provider_build_hash;
    sha256_digest_t fixture_set_hash;
    std::string fixture_id;
    std::string rendered_text;
    std::vector<decompiler_diagnostic_t> diagnostics;
    sha256_digest_t rendered_text_hash;
    sha256_digest_t capture_hash;
};

struct pseudocode_baseline_capture_result_t {
    std::optional<pseudocode_baseline_capture_t> capture;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept;
};

struct pseudocode_readability_request_t {
    pseudocode_readability_limits_t limits;
    std::optional<pseudocode_baseline_capture_request_t> baseline;
    bool require_complete_source_map = true;
};

struct pseudocode_readability_report_t {
    std::uint32_t schema_version = k_pseudocode_readability_schema_version;
    decompiler_entity_key_t entity;
    pseudocode_readability_metrics_t metrics;
    std::size_t ast_node_count = 0;
    std::size_t document_bytes = 0;
    std::size_t source_mapped_bytes = 0;
    double source_map_coverage_ratio = 0.0;
    double mean_confidence = 0.0;
    std::uint8_t minimum_confidence = 0;
    double explicit_unknown_ratio = 0.0;
    sha256_digest_t ast_hash;
    sha256_digest_t document_hash;
    sha256_digest_t source_map_hash;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::vector<decompiler_unknown_t> unknowns;
    std::optional<pseudocode_baseline_capture_t> baseline;
};

struct pseudocode_readability_result_t {
    std::optional<pseudocode_readability_report_t> report;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept;
};

pseudocode_baseline_capture_result_t capture_pseudocode_readability_baseline(
    const pseudocode_baseline_capture_request_t& request,
    const pseudocode_readability_limits_t& limits = {});

pseudocode_readability_result_t analyze_pseudocode_readability(
    const typed_pseudocode_ast_v2_t* ast,
    const decompiler_document_t* document,
    const pseudocode_readability_request_t& request = {});

pseudocode_readability_result_t analyze_pseudocode_readability(
    const typed_pseudocode_ast_v2_t& ast,
    const decompiler_document_t& document,
    const pseudocode_readability_request_t& request = {});

}
