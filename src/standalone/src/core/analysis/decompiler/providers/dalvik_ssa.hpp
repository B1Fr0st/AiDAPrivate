#pragma once

#include "../decompiler_contracts.hpp"
#include "../workspace/dex_image.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis::dalvik_ssa {

enum class dalvik_ssa_value_kind_t : std::uint8_t {
    register_def = 1,
    parameter = 2,
    constant = 3,
    literal = 4,
    phi = 5,
    call_result = 6,
    field_reference = 7,
    array_reference = 8,
    type_reference = 9,
    string_reference = 10,
    method_reference = 11,
    exception_entry = 12,
    monitor = 13,
    unknown = 14
};

enum class dalvik_format_t : std::uint8_t {
    f10x = 1,
    f12x = 2,
    f11n = 3,
    f11x = 4,
    f10t = 5,
    f20t = 6,
    f22x = 7,
    f21t = 8,
    f21s = 9,
    f21h = 10,
    f21c = 11,
    f23x = 12,
    f22b = 13,
    f22t = 14,
    f22s = 15,
    f22c = 16,
    f30t = 17,
    f32x = 18,
    f31i = 19,
    f31t = 20,
    f31c = 21,
    f35c = 22,
    f3rc = 23,
    f45cc = 24,
    f4rcc = 25,
    f51l = 26,
    fpayload = 27,
    funknown = 28
};

struct dalvik_ssa_type_ref_t {
    std::uint64_t id = 0;
    decompiler_type_kind_t kind = decompiler_type_kind_t::unknown;
    std::string descriptor;
    std::string display_name;
    std::optional<std::uint64_t> byte_size;
    bool is_wide = false;
    bool is_object = false;
    bool is_array = false;
    std::string element_descriptor;
    std::vector<std::pair<std::uint64_t, decompiler_type_edge_kind_t>> edges;
};

struct dalvik_ssa_value_t {
    std::uint64_t id = 0;
    dalvik_ssa_value_kind_t kind = dalvik_ssa_value_kind_t::unknown;
    std::uint16_t dalvik_opcode = 0;
    std::uint64_t type_id = 0;
    std::vector<std::uint64_t> operand_ids;
    std::uint32_t register_number = 0;
    std::uint32_t ssa_version = 0;
    std::uint32_t code_unit_offset = 0;
    std::string stable_immediate;
    std::string stable_symbol;
    bool is_wide = false;
    std::optional<std::uint32_t> reference_index;
    std::optional<std::uint32_t> secondary_reference_index;
    dalvik_reference_kind_t reference_kind = dalvik_reference_kind_t::none;
};

struct dalvik_ssa_block_t {
    std::uint64_t id = 0;
    std::vector<std::uint64_t> predecessor_ids;
    std::vector<std::uint64_t> successor_ids;
    std::vector<std::uint64_t> exception_successor_ids;
    std::vector<dalvik_ssa_value_t> values;
    std::uint32_t start_offset = 0;
    std::uint32_t end_offset = 0;
    bool is_exception_handler = false;
};

struct dalvik_ssa_variable_t {
    std::uint32_t register_number = 0;
    std::string stable_name;
    std::uint64_t type_id = 0;
    bool is_parameter = false;
    bool is_wide = false;
};

struct dalvik_ssa_request_t {
    decompiler_provider_identity_t provider;
    decompiler_language_identity_t language;
    decompiler_entity_key_t entity;
    std::uint64_t workspace_generation = 0;
    std::uint64_t type_graph_revision = 0;
    std::uint64_t return_type_id = 0;
    std::string dex_version;
};

struct dalvik_ssa_capture_t {
    dalvik_ssa_request_t request;
    std::shared_ptr<const dex_code_item_t> code_item;
    std::vector<std::uint16_t> code_units;
    std::vector<dex_string_t> strings;
    std::vector<dex_type_t> types;
    std::vector<dex_proto_t> protos;
    std::vector<dex_field_t> fields;
    std::vector<dex_method_t> methods;
    std::uint32_t method_id = 0;
    std::string class_descriptor;
    std::string method_name;
    std::string prototype;
    std::string shorty;
    std::uint64_t entry_block_id = 0;
    std::vector<dalvik_ssa_type_ref_t> types_internal;
    std::vector<dalvik_ssa_block_t> blocks;
    std::vector<dalvik_ssa_variable_t> variables;
};

struct dalvik_ssa_typed_artifacts_t {
    provider_ir_t provider_ir;
    hir_function_t hir;
    type_graph_t type_graph;
};

struct dalvik_ssa_result_t {
    std::optional<dalvik_ssa_typed_artifacts_t> artifacts;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept { return artifacts.has_value(); }
};

dalvik_ssa_result_t normalize(const dalvik_ssa_capture_t& capture);

dalvik_format_t instruction_format(std::uint8_t opcode) noexcept;

const char* format_name(dalvik_format_t format) noexcept;

std::string serialize_capture(const dalvik_ssa_capture_t& capture);
std::optional<dalvik_ssa_capture_t> deserialize_capture(
    const std::string& bytes, std::vector<decompiler_diagnostic_t>& diagnostics);
std::string serialize_artifacts(const dalvik_ssa_typed_artifacts_t& artifacts);
std::optional<dalvik_ssa_typed_artifacts_t> deserialize_artifacts(
    const std::string& bytes, std::vector<decompiler_diagnostic_t>& diagnostics);

}
