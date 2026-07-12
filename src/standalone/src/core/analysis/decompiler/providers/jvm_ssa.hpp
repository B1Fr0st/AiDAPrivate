#pragma once

#include "../decompiler_contracts.hpp"
#include "../../workspace/classfile_parser.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis::jvm_ssa {

constexpr std::uint32_t k_jvm_ssa_worker_protocol_version = 1;

struct jvm_method_context_t {
    std::string class_internal_name;
    std::string method_name;
    std::string method_descriptor;
    std::string generic_signature;
    std::uint16_t access_flags = 0;
    std::uint16_t max_stack = 0;
    std::uint16_t max_locals = 0;
    std::vector<std::uint8_t> code;
    std::vector<jvm_code_exception_t> exceptions;
    std::vector<jvm_line_number_t> line_numbers;
    std::vector<jvm_local_variable_t> local_variables;
    std::vector<jvm_constant_pool_entry_t> constant_pool;
    std::vector<jvm_bootstrap_method_t> bootstrap_methods;
    std::uint32_t code_offset = 0;
};

struct jvm_method_input_t {
    jvm_method_context_t context;
    decompiler_entity_key_t entity;
    decompiler_provider_identity_t provider;
    decompiler_language_identity_t language;
    std::uint64_t workspace_generation = 0;
    std::uint64_t type_graph_revision = 0;
};

struct jvm_ssa_result_t {
    std::optional<provider_ir_t> provider_ir;
    std::optional<hir_function_t> hir;
    std::optional<type_graph_t> type_graph;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept {
        return provider_ir.has_value() && hir.has_value() && type_graph.has_value();
    }
};

jvm_ssa_result_t decompile_method(const jvm_method_input_t& input);

jvm_method_context_t extract_method_context(const classfile_image_t& classfile,
                                             std::uint32_t method_index);

std::string serialize_jvm_ssa_result(const jvm_ssa_result_t& result);
std::optional<jvm_ssa_result_t> deserialize_jvm_ssa_result(const std::string& bytes,
                                                            std::vector<decompiler_diagnostic_t>& diagnostics);

}
