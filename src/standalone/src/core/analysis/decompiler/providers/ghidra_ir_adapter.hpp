#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "../decompiler_contracts.hpp"

namespace ghidra {
class Funcdata;
}

namespace aida::analysis::ghidra_ir_adapter {

enum class capture_value_kind_t : std::uint8_t {
    pcode,
    parameter,
    local,
    constant
};

struct capture_type_edge_t {
    std::uint64_t target_type_id = 0;
    decompiler_type_edge_kind_t kind = decompiler_type_edge_kind_t::alias;
    std::string stable_name;
    std::optional<std::uint64_t> byte_offset;
};

struct capture_type_t {
    std::uint64_t id = 0;
    decompiler_type_kind_t kind = decompiler_type_kind_t::unknown;
    std::string canonical_name;
    std::string display_name;
    std::optional<std::uint64_t> byte_size;
    std::uint32_t alignment = 1;
    bool is_signed = false;
    std::vector<capture_type_edge_t> edges;
};

struct capture_value_t {
    std::uint64_t id = 0;
    capture_value_kind_t kind = capture_value_kind_t::pcode;
    std::uint16_t pcode_opcode = 0;
    std::uint64_t type_id = 0;
    std::vector<std::uint64_t> operand_ids;
    std::uint64_t address = 0;
    std::string stable_immediate;
    std::string stable_symbol;
};

struct capture_block_t {
    std::uint64_t id = 0;
    std::vector<std::uint64_t> predecessor_ids;
    std::vector<std::uint64_t> successor_ids;
    std::vector<std::uint64_t> exception_successor_ids;
    std::vector<capture_value_t> values;
    std::uint64_t address = 0;
};

struct capture_high_variable_t {
    std::uint64_t id = 0;
    bool parameter = false;
    std::string stable_name;
    std::uint64_t type_id = 0;
    std::uint64_t address = 0;
};

struct capture_request_t {
    decompiler_provider_identity_t provider;
    decompiler_language_identity_t language;
    decompiler_entity_key_t entity;
    std::uint64_t workspace_generation = 0;
    std::uint64_t type_graph_revision = 0;
    std::uint64_t return_type_id = 0;
};

struct capture_t {
    capture_request_t request;
    std::uint64_t entry_block_id = 0;
    std::vector<capture_type_t> types;
    std::vector<capture_block_t> blocks;
    std::vector<capture_high_variable_t> high_variables;
};

struct typed_artifacts_t {
    provider_ir_t provider_ir;
    hir_function_t hir;
    type_graph_t type_graph;
};

struct extraction_result_t {
    std::optional<typed_artifacts_t> artifacts;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept { return artifacts.has_value(); }
};

extraction_result_t normalize(const capture_t& capture);
extraction_result_t extract(const ghidra::Funcdata& function, const capture_request_t& request);

std::string serialize_artifacts(const typed_artifacts_t& artifacts);
std::optional<typed_artifacts_t> deserialize_artifacts(const std::string& bytes,
                                                       std::vector<decompiler_diagnostic_t>& diagnostics);

}
