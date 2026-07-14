#include "managed_reader_contracts.hpp"

#include "cli_metadata_reader.hpp"
#include "classfile_reader.hpp"
#include "dex_reader.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>
#include <unordered_set>

namespace aida::analysis::readers::managed {
namespace {

workspace_result_t<void> validate_managed_reader_request(
    const managed_reader_limits_t& limits,
    const cancellation_token_t& cancel,
    std::string phase) {
    if (!limits.valid())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "managed reader limits are invalid", std::move(phase)));
    if (!cancel.stop_requested())
        return workspace_result_t<void>::success();
    auto error = make_workspace_error(
        cancel.deadline_exceeded()
            ? workspace_error_code_t::deadline_exceeded
            : workspace_error_code_t::cancelled,
        "managed artifact operation was cancelled", std::move(phase));
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return workspace_result_t<void>::failure(std::move(error));
}

}

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
    identity.dex_ordinal = artifact.module_identity.artifact_ordinal;
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
    key.format = artifact.normalized.format;
    key.architecture = artifact.normalized.architecture;
    key.mode = artifact.normalized.architecture_mode;
    key.endian = artifact.normalized.endian;
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
    key.mode = architecture_mode_t::jvm;
    key.endian = endian_t::big;
    key.identity = build_jvm_entity_identity(artifact, method_index);
    return key;
}

decompiler_entity_key_t
build_dalvik_entity_key(const managed_artifact_t& artifact, std::uint32_t method_index) {
    decompiler_entity_key_t key;
    key.schema_version = k_decompiler_contract_schema_version;
    key.kind = decompiler_entity_kind_t::dalvik_method;
    key.format = artifact.kind == managed_artifact_kind_t::oat
        ? format_id_t::oat
        : artifact.kind == managed_artifact_kind_t::vdex
            ? format_id_t::vdex
            : format_id_t::dex;
    key.architecture = architecture_id_t::dalvik_bytecode;
    key.mode = architecture_mode_t::dalvik;
    key.endian = endian_t::little;
    key.identity = build_dalvik_entity_identity(artifact, method_index);
    return key;
}

workspace_result_t<managed_artifact_t>
read_cli_metadata(const byte_provider_t& provider,
                  const managed_reader_limits_t& limits,
                  const cancellation_token_t& cancel) {
    auto request = validate_managed_reader_request(
        limits, cancel, "managed.cli");
    if (!request)
        return workspace_result_t<managed_artifact_t>::failure(request.error());
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
    auto request = validate_managed_reader_request(
        limits, cancel, "managed.classfile");
    if (!request)
        return workspace_result_t<managed_artifact_t>::failure(request.error());
    classfile_parse_limits_t cf_limits;
    cf_limits.max_methods = limits.max_methods;
    cf_limits.max_fields = limits.max_fields;
    cf_limits.max_member_references = limits.max_member_references;
    cf_limits.max_annotations = limits.max_annotations;
    cf_limits.max_exception_regions = limits.max_exception_regions;
    cf_limits.max_code_ranges = limits.max_code_ranges;
    cf_limits.max_code_bytes = limits.max_code_bytes;
    cf_limits.max_string_bytes = limits.max_string_bytes;
    cf_limits.parser_limits.max_classfile_bytes = (std::min)(
        cf_limits.parser_limits.max_classfile_bytes,
        limits.max_metadata_bytes);
    cf_limits.parser_limits.max_constant_pool_entries = (std::min)(
        cf_limits.parser_limits.max_constant_pool_entries,
        limits.max_constant_pool_entries);
    cf_limits.parser_limits.max_fields = (std::min)(
        cf_limits.parser_limits.max_fields, limits.max_fields);
    cf_limits.parser_limits.max_methods = (std::min)(
        cf_limits.parser_limits.max_methods, limits.max_methods);
    cf_limits.parser_limits.max_total_attribute_bytes = (std::min)(
        cf_limits.parser_limits.max_total_attribute_bytes,
        limits.max_metadata_bytes);
    cf_limits.parser_limits.max_total_code_bytes = (std::min)(
        cf_limits.parser_limits.max_total_code_bytes,
        limits.max_code_bytes);
    cf_limits.parser_limits.max_bytecode_per_method = (std::min)(
        cf_limits.parser_limits.max_bytecode_per_method,
        limits.max_code_bytes);
    cf_limits.parser_limits.max_utf8_length = (std::min)(
        cf_limits.parser_limits.max_utf8_length,
        limits.max_string_bytes);
    cf_limits.parser_limits.max_exception_table_entries = (std::min)(
        cf_limits.parser_limits.max_exception_table_entries,
        static_cast<std::uint64_t>(limits.max_exception_regions));
    cf_limits.parser_limits.max_instructions_per_method = (std::min)(
        cf_limits.parser_limits.max_instructions_per_method,
        static_cast<std::uint64_t>(limits.max_code_ranges));

    auto metadata_result = parse_classfile_metadata(provider, cf_limits, cancel);
    if (!metadata_result)
        return workspace_result_t<managed_artifact_t>::failure(std::move(metadata_result.error()));
    return build_classfile_artifact(metadata_result.take_value(), provider, limits, cancel);
}

workspace_result_t<managed_artifact_t>
read_dex(const byte_provider_t& provider,
         const managed_reader_limits_t& limits,
         const cancellation_token_t& cancel) {
    auto request = validate_managed_reader_request(
        limits, cancel, "managed.dex");
    if (!request)
        return workspace_result_t<managed_artifact_t>::failure(request.error());
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
    dex_limits.parser_limits.max_embedded_dex_files = (std::min)(
        dex_limits.parser_limits.max_embedded_dex_files,
        limits.max_dex_files);
    dex_limits.parser_limits.max_string_ids = (std::min)(
        dex_limits.parser_limits.max_string_ids, limits.max_table_rows);
    dex_limits.parser_limits.max_type_ids = (std::min)(
        dex_limits.parser_limits.max_type_ids, limits.max_types);
    dex_limits.parser_limits.max_proto_ids = (std::min)(
        dex_limits.parser_limits.max_proto_ids, limits.max_table_rows);
    dex_limits.parser_limits.max_field_ids = (std::min)(
        dex_limits.parser_limits.max_field_ids, limits.max_fields);
    dex_limits.parser_limits.max_method_ids = (std::min)(
        dex_limits.parser_limits.max_method_ids, limits.max_methods);
    dex_limits.parser_limits.max_class_defs = (std::min)(
        dex_limits.parser_limits.max_class_defs, limits.max_types);
    dex_limits.parser_limits.max_class_data_items = (std::min)(
        dex_limits.parser_limits.max_class_data_items, limits.max_types);
    const auto code_units = limits.max_code_bytes / 2ULL;
    dex_limits.parser_limits.max_code_units_per_method = (std::min)(
        dex_limits.parser_limits.max_code_units_per_method,
        static_cast<std::uint32_t>((std::min<std::uint64_t>)(
            code_units, (std::numeric_limits<std::uint32_t>::max)())));
    dex_limits.parser_limits.max_total_code_units = (std::min)(
        dex_limits.parser_limits.max_total_code_units, code_units);
    dex_limits.parser_limits.max_instruction_records_per_method = (std::min)(
        dex_limits.parser_limits.max_instruction_records_per_method,
        limits.max_code_ranges);
    dex_limits.parser_limits.max_total_instruction_records = (std::min)(
        dex_limits.parser_limits.max_total_instruction_records,
        static_cast<std::uint64_t>(limits.max_code_ranges));
    dex_limits.parser_limits.max_try_items_per_method = (std::min)(
        dex_limits.parser_limits.max_try_items_per_method,
        limits.max_exception_regions);
    dex_limits.parser_limits.max_catch_handlers_per_method = (std::min)(
        dex_limits.parser_limits.max_catch_handlers_per_method,
        limits.max_exception_regions);
    dex_limits.parser_limits.max_debug_positions_per_method = (std::min)(
        dex_limits.parser_limits.max_debug_positions_per_method,
        limits.max_code_ranges);
    dex_limits.parser_limits.max_total_debug_positions = (std::min)(
        dex_limits.parser_limits.max_total_debug_positions,
        static_cast<std::uint64_t>(limits.max_code_ranges));
    dex_limits.parser_limits.max_string_bytes = (std::min)(
        dex_limits.parser_limits.max_string_bytes,
        limits.max_string_bytes);
    dex_limits.parser_limits.max_single_string_bytes = (std::min)(
        dex_limits.parser_limits.max_single_string_bytes,
        limits.max_string_bytes);

    auto container_kind = detect_dex_container(provider, cancel);
    if (!container_kind)
        return workspace_result_t<managed_artifact_t>::failure(
            container_kind.error());
    if (container_kind.value().kind == dex_container_kind_t::oat ||
        container_kind.value().kind == dex_container_kind_t::vdex) {
        auto multidex_result = parse_multidex_metadata(provider, dex_limits, cancel);
        if (!multidex_result)
            return workspace_result_t<managed_artifact_t>::failure(
                multidex_result.error());
        auto artifacts = build_multidex_artifact(
            multidex_result.value(), provider, limits, cancel);
        if (!artifacts)
            return workspace_result_t<managed_artifact_t>::failure(
                artifacts.error());
        if (artifacts.value().artifacts.size() != 1)
            return workspace_result_t<managed_artifact_t>::failure(
                make_workspace_error(workspace_error_code_t::target_ambiguous,
                    "runtime container has multiple DEX artifacts",
                    "dex.read"));
        return workspace_result_t<managed_artifact_t>::success(
            std::move(artifacts.value().artifacts.front()));
    }

    auto metadata_result = parse_dex_metadata(provider, dex_limits, cancel);
    if (!metadata_result)
        return workspace_result_t<managed_artifact_t>::failure(std::move(metadata_result.error()));
    return build_dex_artifact(metadata_result.take_value(), provider, limits, cancel);
}

workspace_result_t<managed_multidex_t>
read_multidex_container(const byte_provider_t& provider,
                        const managed_reader_limits_t& limits,
                        const cancellation_token_t& cancel) {
    auto request = validate_managed_reader_request(
        limits, cancel, "managed.multidex");
    if (!request)
        return workspace_result_t<managed_multidex_t>::failure(request.error());
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
    dex_limits.parser_limits.max_embedded_dex_files = (std::min)(
        dex_limits.parser_limits.max_embedded_dex_files,
        limits.max_dex_files);
    dex_limits.parser_limits.max_string_ids = (std::min)(
        dex_limits.parser_limits.max_string_ids, limits.max_table_rows);
    dex_limits.parser_limits.max_type_ids = (std::min)(
        dex_limits.parser_limits.max_type_ids, limits.max_types);
    dex_limits.parser_limits.max_proto_ids = (std::min)(
        dex_limits.parser_limits.max_proto_ids, limits.max_table_rows);
    dex_limits.parser_limits.max_field_ids = (std::min)(
        dex_limits.parser_limits.max_field_ids, limits.max_fields);
    dex_limits.parser_limits.max_method_ids = (std::min)(
        dex_limits.parser_limits.max_method_ids, limits.max_methods);
    dex_limits.parser_limits.max_class_defs = (std::min)(
        dex_limits.parser_limits.max_class_defs, limits.max_types);
    dex_limits.parser_limits.max_class_data_items = (std::min)(
        dex_limits.parser_limits.max_class_data_items, limits.max_types);
    const auto code_units = limits.max_code_bytes / 2ULL;
    dex_limits.parser_limits.max_code_units_per_method = (std::min)(
        dex_limits.parser_limits.max_code_units_per_method,
        static_cast<std::uint32_t>((std::min<std::uint64_t>)(
            code_units, (std::numeric_limits<std::uint32_t>::max)())));
    dex_limits.parser_limits.max_total_code_units = (std::min)(
        dex_limits.parser_limits.max_total_code_units, code_units);
    dex_limits.parser_limits.max_instruction_records_per_method = (std::min)(
        dex_limits.parser_limits.max_instruction_records_per_method,
        limits.max_code_ranges);
    dex_limits.parser_limits.max_total_instruction_records = (std::min)(
        dex_limits.parser_limits.max_total_instruction_records,
        static_cast<std::uint64_t>(limits.max_code_ranges));
    dex_limits.parser_limits.max_try_items_per_method = (std::min)(
        dex_limits.parser_limits.max_try_items_per_method,
        limits.max_exception_regions);
    dex_limits.parser_limits.max_catch_handlers_per_method = (std::min)(
        dex_limits.parser_limits.max_catch_handlers_per_method,
        limits.max_exception_regions);
    dex_limits.parser_limits.max_debug_positions_per_method = (std::min)(
        dex_limits.parser_limits.max_debug_positions_per_method,
        limits.max_code_ranges);
    dex_limits.parser_limits.max_total_debug_positions = (std::min)(
        dex_limits.parser_limits.max_total_debug_positions,
        static_cast<std::uint64_t>(limits.max_code_ranges));
    dex_limits.parser_limits.max_string_bytes = (std::min)(
        dex_limits.parser_limits.max_string_bytes,
        limits.max_string_bytes);
    dex_limits.parser_limits.max_single_string_bytes = (std::min)(
        dex_limits.parser_limits.max_single_string_bytes,
        limits.max_string_bytes);

    auto multidex_result = parse_multidex_metadata(provider, dex_limits, cancel);
    if (!multidex_result)
        return workspace_result_t<managed_multidex_t>::failure(std::move(multidex_result.error()));
    return build_multidex_artifact(multidex_result.take_value(), provider, limits, cancel);
}

workspace_result_t<managed_artifact_t>
read_managed_artifact(const byte_provider_t& provider,
                      const managed_reader_limits_t& limits,
                      const cancellation_token_t& cancel) {
    auto request = validate_managed_reader_request(
        limits, cancel, "managed.detect");
    if (!request)
        return workspace_result_t<managed_artifact_t>::failure(request.error());

    auto prefix_result = provider.read_vector(0, 8, 8, cancel);
    if (!prefix_result)
        return workspace_result_t<managed_artifact_t>::failure(std::move(prefix_result.error()));
    const auto& prefix = prefix_result.value();
    if (prefix.size() < 4)
        return workspace_result_t<managed_artifact_t>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_format,
                                 "input is too small for managed artifact detection", "managed.detect"));

    if (prefix.size() >= 8 &&
        ((prefix[0] == 'd' && prefix[1] == 'e' && prefix[2] == 'x' && prefix[3] == '\n') ||
         (prefix[0] == 'c' && prefix[1] == 'd' && prefix[2] == 'e' && prefix[3] == 'x'))) {
        return read_dex(provider, limits, cancel);
    }
    if (prefix.size() >= 4 && prefix[0] == 0xCA && prefix[1] == 0xFE && prefix[2] == 0xBA && prefix[3] == 0xBE) {
        return read_classfile(provider, limits, cancel);
    }
    if (prefix.size() >= 2 && prefix[0] == 'M' && prefix[1] == 'Z') {
        return read_cli_metadata(provider, limits, cancel);
    }
    if (prefix.size() >= 4 &&
        ((prefix[0] == 'o' && prefix[1] == 'a' && prefix[2] == 't' && prefix[3] == '\n') ||
         (prefix[0] == 'v' && prefix[1] == 'd' && prefix[2] == 'e' && prefix[3] == 'x'))) {
        auto container = read_multidex_container(provider, limits, cancel);
        if (!container)
            return workspace_result_t<managed_artifact_t>::failure(container.error());
        if (container.value().artifacts.size() != 1) {
            auto error = make_workspace_error(
                workspace_error_code_t::target_ambiguous,
                "managed runtime container requires an explicit DEX member",
                "managed.detect");
            error.details.emplace_back(
                "artifact_count", std::to_string(container.value().artifacts.size()));
            return workspace_result_t<managed_artifact_t>::failure(std::move(error));
        }
        return workspace_result_t<managed_artifact_t>::success(
            std::move(container.value().artifacts.front()));
    }

    return workspace_result_t<managed_artifact_t>::failure(
        make_workspace_error(workspace_error_code_t::unsupported_format,
                             "input is not a recognized managed artifact format", "managed.detect"));
}

}
