#include "managed_reader_contracts.hpp"

#include "cli_metadata_reader.hpp"
#include "classfile_reader.hpp"
#include "dex_reader.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <unordered_set>

namespace aida::analysis::readers::managed {

const char* managed_artifact_kind_name(managed_artifact_kind_t kind) noexcept {
    switch (kind) {
        case managed_artifact_kind_t::cli_metadata: return "cli-metadata";
        case managed_artifact_kind_t::java_classfile: return "java-classfile";
        case managed_artifact_kind_t::dex: return "dex";
        case managed_artifact_kind_t::oat: return "oat";
        case managed_artifact_kind_t::vdex: return "vdex";
        case managed_artifact_kind_t::multidex_container: return "multidex-container";
    }
    return "unknown";
}

const char* managed_reference_kind_name(managed_reference_kind_t kind) noexcept {
    switch (kind) {
        case managed_reference_kind_t::type_reference: return "type-reference";
        case managed_reference_kind_t::method_reference: return "method-reference";
        case managed_reference_kind_t::field_reference: return "field-reference";
        case managed_reference_kind_t::assembly_reference: return "assembly-reference";
    }
    return "unknown";
}

const char* managed_token_type_name(managed_token_type_t type) noexcept {
    switch (type) {
        case managed_token_type_t::unknown: return "unknown";
        case managed_token_type_t::module: return "Module";
        case managed_token_type_t::type_ref: return "TypeRef";
        case managed_token_type_t::type_def: return "TypeDef";
        case managed_token_type_t::field_def: return "FieldDef";
        case managed_token_type_t::method_def: return "MethodDef";
        case managed_token_type_t::param: return "Param";
        case managed_token_type_t::interface_impl: return "InterfaceImpl";
        case managed_token_type_t::member_ref: return "MemberRef";
        case managed_token_type_t::constant: return "Constant";
        case managed_token_type_t::custom_attribute: return "CustomAttribute";
        case managed_token_type_t::assembly: return "Assembly";
        case managed_token_type_t::assembly_ref: return "AssemblyRef";
        case managed_token_type_t::file_table: return "File";
        case managed_token_type_t::exported_type: return "ExportedType";
        case managed_token_type_t::manifest_resource: return "ManifestResource";
        case managed_token_type_t::nested_class: return "NestedClass";
        case managed_token_type_t::generic_param: return "GenericParam";
        case managed_token_type_t::method_spec: return "MethodSpec";
        case managed_token_type_t::generic_param_constraint: return "GenericParamConstraint";
    }
    return "unknown";
}

std::string format_cli_token(std::uint32_t token) noexcept {
    char buffer[16];
    const auto table = static_cast<std::uint8_t>(token >> 24);
    const auto row = token & 0x00FFFFFFu;
    std::snprintf(buffer, sizeof(buffer), "0x%02X%06X", table, row);
    return std::string(buffer);
}

cli_decompiler_entity_identity_t
build_cli_entity_identity(const managed_artifact_t& artifact, std::uint32_t method_index) {
    cli_decompiler_entity_identity_t identity;
    identity.module_hash = artifact.module_identity.artifact_hash;
    identity.assembly_identity = artifact.module_identity.assembly_name;
    identity.module_name = artifact.module_identity.module_name;
    if (method_index < artifact.methods.size()) {
        const auto& method = artifact.methods[method_index];
        identity.metadata_token = method.metadata_token;
        identity.declaring_type = method.declaring_type_name;
        identity.method_name = method.method_name;
        identity.method_signature = method.method_signature;
        identity.generic_arity = method.generic_arity;
    }
    return identity;
}

jvm_decompiler_entity_identity_t
build_jvm_entity_identity(const managed_artifact_t& artifact, std::uint32_t method_index) {
    jvm_decompiler_entity_identity_t identity;
    identity.class_artifact_hash = artifact.module_identity.artifact_hash;
    identity.class_internal_name = artifact.module_identity.assembly_name;
    if (method_index < artifact.methods.size()) {
        const auto& method = artifact.methods[method_index];
        identity.method_name = method.method_name;
        identity.method_descriptor = method.method_signature;
        identity.method_index = method_index;
        identity.code_offset = method.code_offset;
    }
    return identity;
}

dalvik_decompiler_entity_identity_t
build_dalvik_entity_identity(const managed_artifact_t& artifact, std::uint32_t method_index) {
    dalvik_decompiler_entity_identity_t identity;
    identity.dex_hash = artifact.module_identity.artifact_hash;
    if (method_index < artifact.methods.size()) {
        const auto& method = artifact.methods[method_index];
        identity.class_descriptor = method.declaring_type_name;
        identity.method_name = method.method_name;
        identity.prototype = method.method_signature;
        identity.method_id = method.method_index;
        identity.code_item_offset = method.code_offset;
    }
    return identity;
}

decompiler_entity_key_t
build_cli_entity_key(const managed_artifact_t& artifact, std::uint32_t method_index) {
    decompiler_entity_key_t key;
    key.schema_version = k_decompiler_contract_schema_version;
    key.kind = decompiler_entity_kind_t::cli_method;
    key.format = format_id_t::pe32_plus;
    key.architecture = architecture_id_t::x86_64;
    key.architecture_mode = architecture_mode_t::x86_64;
    key.endian = endian_t::little;
    key.identity = build_cli_entity_identity(artifact, method_index);
    return key;
}

decompiler_entity_key_t
build_jvm_entity_key(const managed_artifact_t& artifact, std::uint32_t method_index) {
    decompiler_entity_key_t key;
    key.schema_version = k_decompiler_contract_schema_version;
    key.kind = decompiler_entity_kind_t::jvm_method;
    key.format = format_id_t::classfile;
    key.architecture = architecture_id_t::jvm_bytecode;
    key.architecture_mode = architecture_mode_t::jvm;
    key.endian = endian_t::big;
    key.identity = build_jvm_entity_identity(artifact, method_index);
    return key;
}

decompiler_entity_key_t
build_dalvik_entity_key(const managed_artifact_t& artifact, std::uint32_t method_index) {
    decompiler_entity_key_t key;
    key.schema_version = k_decompiler_contract_schema_version;
    key.kind = decompiler_entity_kind_t::dalvik_method;
    key.format = format_id_t::dex;
    key.architecture = architecture_id_t::dalvik_bytecode;
    key.architecture_mode = architecture_mode_t::dalvik;
    key.endian = endian_t::little;
    key.identity = build_dalvik_entity_identity(artifact, method_index);
    return key;
}

workspace_result_t<managed_artifact_t>
read_cli_metadata(const byte_provider_t& provider,
                  const managed_reader_limits_t& limits,
                  const cancellation_token_t& cancel) {
    cli_metadata_parse_limits_t cli_limits;
    cli_limits.max_metadata_bytes = limits.max_metadata_bytes;
    cli_limits.max_table_rows = limits.max_table_rows;
    cli_limits.max_method_bodies = limits.max_methods;
    cli_limits.max_total_code_bytes = limits.max_code_bytes;
    cli_limits.max_exception_clauses_per_method = limits.max_exception_regions;

    auto metadata_result = parse_cli_metadata(provider, cli_limits, cancel);
    if (!metadata_result)
        return workspace_result_t<managed_artifact_t>::failure(std::move(metadata_result.error()));
    return build_cli_artifact(metadata_result.take_value(), provider, limits, cancel);
}

workspace_result_t<managed_artifact_t>
read_classfile(const byte_provider_t& provider,
               const managed_reader_limits_t& limits,
               const cancellation_token_t& cancel) {
    classfile_parse_limits_t cf_limits;
    cf_limits.max_methods = limits.max_methods;
    cf_limits.max_fields = limits.max_fields;
    cf_limits.max_member_references = limits.max_member_references;
    cf_limits.max_annotations = limits.max_annotations;
    cf_limits.max_exception_regions = limits.max_exception_regions;
    cf_limits.max_code_ranges = limits.max_code_ranges;
    cf_limits.max_code_bytes = limits.max_code_bytes;
    cf_limits.max_string_bytes = limits.max_string_bytes;

    auto metadata_result = parse_classfile_metadata(provider, cf_limits, cancel);
    if (!metadata_result)
        return workspace_result_t<managed_artifact_t>::failure(std::move(metadata_result.error()));
    return build_classfile_artifact(metadata_result.take_value(), provider, limits, cancel);
}

workspace_result_t<managed_artifact_t>
read_dex(const byte_provider_t& provider,
         const managed_reader_limits_t& limits,
         const cancellation_token_t& cancel) {
    dex_parse_limits_t dex_limits;
    dex_limits.max_types = limits.max_types;
    dex_limits.max_methods = limits.max_methods;
    dex_limits.max_fields = limits.max_fields;
    dex_limits.max_member_references = limits.max_member_references;
    dex_limits.max_annotations = limits.max_annotations;
    dex_limits.max_exception_regions = limits.max_exception_regions;
    dex_limits.max_code_ranges = limits.max_code_ranges;
    dex_limits.max_code_bytes = limits.max_code_bytes;
    dex_limits.max_string_bytes = limits.max_string_bytes;
    dex_limits.max_dex_files = limits.max_dex_files;

    auto metadata_result = parse_dex_metadata(provider, dex_limits, cancel);
    if (!metadata_result)
        return workspace_result_t<managed_artifact_t>::failure(std::move(metadata_result.error()));
    return build_dex_artifact(metadata_result.take_value(), provider, limits, cancel);
}

workspace_result_t<managed_multidex_t>
read_multidex_container(const byte_provider_t& provider,
                        const managed_reader_limits_t& limits,
                        const cancellation_token_t& cancel) {
    dex_parse_limits_t dex_limits;
    dex_limits.max_types = limits.max_types;
    dex_limits.max_methods = limits.max_methods;
    dex_limits.max_fields = limits.max_fields;
    dex_limits.max_member_references = limits.max_member_references;
    dex_limits.max_annotations = limits.max_annotations;
    dex_limits.max_exception_regions = limits.max_exception_regions;
    dex_limits.max_code_ranges = limits.max_code_ranges;
    dex_limits.max_code_bytes = limits.max_code_bytes;
    dex_limits.max_string_bytes = limits.max_string_bytes;
    dex_limits.max_dex_files = limits.max_dex_files;

    auto multidex_result = parse_multidex_metadata(provider, dex_limits, cancel);
    if (!multidex_result)
        return workspace_result_t<managed_multidex_t>::failure(std::move(multidex_result.error()));
    return build_multidex_artifact(multidex_result.take_value(), provider, limits, cancel);
}

workspace_result_t<managed_artifact_t>
read_managed_artifact(const byte_provider_t& provider,
                      const managed_reader_limits_t& limits,
                      const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<managed_artifact_t>::failure(
            make_workspace_error(workspace_error_code_t::cancelled,
                                 "managed artifact detection cancelled", "managed.detect"));

    auto prefix_result = provider.read_vector(0, 8, 8, cancel);
    if (!prefix_result)
        return workspace_result_t<managed_artifact_t>::failure(std::move(prefix_result.error()));
    const auto& prefix = prefix_result.value();
    if (prefix.size() < 4)
        return workspace_result_t<managed_artifact_t>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_format,
                                 "input is too small for managed artifact detection", "managed.detect"));

    if (prefix.size() >= 8 && prefix[0] == 'd' && prefix[1] == 'e' && prefix[2] == 'x' && prefix[3] == '\n') {
        return read_dex(provider, limits, cancel);
    }
    if (prefix.size() >= 4 && prefix[0] == 0xCA && prefix[1] == 0xFE && prefix[2] == 0xBA && prefix[3] == 0xBE) {
        return read_classfile(provider, limits, cancel);
    }
    if (prefix.size() >= 2 && prefix[0] == 'M' && prefix[1] == 'Z') {
        return read_cli_metadata(provider, limits, cancel);
    }
    if (prefix.size() >= 4 && prefix[0] == 'o' && prefix[1] == 'a' && prefix[2] == 't' && prefix[3] == '\n') {
        return read_dex(provider, limits, cancel);
    }
    if (prefix.size() >= 4 && prefix[0] == 'v' && prefix[1] == 'd' && prefix[2] == 'e' && prefix[3] == 'x') {
        return read_dex(provider, limits, cancel);
    }

    return workspace_result_t<managed_artifact_t>::failure(
        make_workspace_error(workspace_error_code_t::unsupported_format,
                             "input is not a recognized managed artifact format", "managed.detect"));
}

}
