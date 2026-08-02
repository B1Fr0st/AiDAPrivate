#pragma once

#include "typed_ast_v2.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

constexpr std::uint32_t k_pseudocode_renderer_v2_schema_version = 1;

enum class pseudocode_renderer_v2_style_profile_t : std::uint8_t {
    compact = 1,
    balanced = 2,
    audit = 3
};

struct pseudocode_renderer_v2_limits_t {
    std::size_t max_ast_nodes = 500000;
    std::size_t max_output_bytes = 8U * 1024U * 1024U;
    std::size_t max_tokens = 500000;
    std::size_t max_source_maps = 500000;
    std::size_t max_nesting = 512;
};

struct pseudocode_renderer_v2_request_t {
    decompiler_profile_id_t profile = decompiler_profile_id_t::balanced;
    decompiler_renderer_settings_t settings;
    pseudocode_renderer_v2_limits_t limits;
    std::shared_ptr<const decompiler_render_evidence_t> evidence;
    bool require_complete_source_map = true;
};

struct pseudocode_renderer_v2_result_t {
    std::optional<decompiler_document_t> document;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::vector<decompiler_unknown_t> unknowns;

    bool succeeded() const noexcept;
};

decompiler_renderer_settings_t pseudocode_renderer_v2_style_settings(
    pseudocode_renderer_v2_style_profile_t profile);

pseudocode_renderer_v2_result_t render_pseudocode_v2(
    const typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph,
    const pseudocode_renderer_v2_request_t& request = {});

pseudocode_renderer_v2_result_t rerender_document_with_local_renames(
    const decompiler_document_t& source,
    const type_graph_t& type_graph,
    const pseudocode_renderer_v2_request_t& request,
    const std::vector<std::pair<std::string, std::string>>& renames);

std::string serialize_pseudocode_document_v2(const decompiler_document_t& document);

decompiler_contract_decode_result_t<decompiler_document_t> deserialize_pseudocode_document_v2(const std::string& bytes);

}
