#pragma once

#include "decompiler_contracts.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

constexpr std::uint32_t k_typed_ast_v2_builder_schema_version = 1;

struct typed_ast_v2_build_limits_t {
    std::size_t max_hir_values = 250000;
    std::size_t max_ast_nodes = 500000;
    std::size_t max_expression_nesting = 512;
};

struct typed_ast_v2_build_request_t {
    typed_ast_v2_build_limits_t limits;
};

struct typed_ast_v2_build_result_t {
    std::optional<typed_pseudocode_ast_v2_t> ast;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::vector<decompiler_unknown_t> unknowns;
    sha256_digest_t hir_hash;
    sha256_digest_t type_graph_hash;

    bool succeeded() const noexcept;
};

std::string typed_ast_v2_node_layout(typed_pseudocode_ast_node_kind_t kind);

decompiler_contract_validation_t validate_typed_ast_v2_semantics(
    const typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph);

typed_ast_v2_build_result_t build_typed_ast_v2(
    const hir_function_t& hir,
    const type_graph_t& type_graph,
    const typed_ast_v2_build_request_t& request = {});

std::string serialize_typed_ast_v2(const typed_pseudocode_ast_v2_t& ast);

decompiler_contract_decode_result_t<typed_pseudocode_ast_v2_t> deserialize_typed_ast_v2(const std::string& bytes);

}
