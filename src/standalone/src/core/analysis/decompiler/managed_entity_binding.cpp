#include "managed_entity_binding.hpp"

#include "providers/dalvik_ssa.hpp"
#include "providers/jvm_ssa.hpp"
#include "../workspace/analysis_workspace.hpp"
#include "../workspace/classfile_parser.hpp"
#include "../workspace/dex_image.hpp"
#include "../workspace/pe_image.hpp"
#include "../subrange_provider.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>

namespace aida::analysis {
namespace {

workspace_error_t binding_error(workspace_error_code_t code,
                                std::string message,
                                std::string phase) {
    return make_workspace_error(code, std::move(message), std::move(phase));
}

workspace_error_t stop_error(const cancellation_token_t& cancel,
                             std::string phase) {
    auto error = binding_error(
        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                   : workspace_error_code_t::cancelled,
        "managed entity operation was cancelled", std::move(phase));
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

workspace_result_t<sha256_digest_t> current_provider_hash(
    const byte_provider_t& provider,
    const cancellation_token_t& cancel) {
    if (provider.identity().content_sha256 &&
        !provider.identity().content_sha256->empty())
        return workspace_result_t<sha256_digest_t>::success(
            *provider.identity().content_sha256);
    return provider.compute_content_sha256(cancel);
}

std::uint16_t read_u16_le(const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint32_t>(bytes[0]) |
        (static_cast<std::uint32_t>(bytes[1]) << 8U));
}

std::uint32_t read_u32_le(const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0]) |
        static_cast<std::uint32_t>(bytes[1]) << 8 |
        static_cast<std::uint32_t>(bytes[2]) << 16 |
        static_cast<std::uint32_t>(bytes[3]) << 24;
}

workspace_result_t<bool> pe_has_cli_directory(
    const byte_provider_t& provider,
    const cancellation_token_t& cancel) {
    auto dos = provider.read_vector(0, 64, 64, cancel);
    if (!dos)
        return workspace_result_t<bool>::failure(dos.error());
    if (dos.value().size() != 64 || dos.value()[0] != 'M' ||
        dos.value()[1] != 'Z')
        return workspace_result_t<bool>::success(false);
    const auto pe_offset = read_u32_le(dos.value().data() + 0x3c);
    if (pe_offset > provider.size() || provider.size() - pe_offset < 24)
        return workspace_result_t<bool>::failure(binding_error(
            workspace_error_code_t::malformed_image,
            "PE header range is invalid during CLI detection",
            "managed.binding.detect_cli"));
    const auto remaining = provider.size() - pe_offset;
    const auto probe_size = (std::min<std::uint64_t>)(remaining, 512);
    auto pe = provider.read_vector(pe_offset, probe_size, 512, cancel);
    if (!pe)
        return workspace_result_t<bool>::failure(pe.error());
    if (pe.value().size() < 24 || pe.value()[0] != 'P' || pe.value()[1] != 'E' ||
        pe.value()[2] != 0 || pe.value()[3] != 0)
        return workspace_result_t<bool>::failure(binding_error(
            workspace_error_code_t::malformed_image,
            "PE signature is invalid during CLI detection",
            "managed.binding.detect_cli"));
    const auto optional_size = read_u16_le(pe.value().data() + 20);
    if (optional_size < 96 || pe.value().size() < 26)
        return workspace_result_t<bool>::failure(binding_error(
            workspace_error_code_t::malformed_image,
            "PE optional header is truncated during CLI detection",
            "managed.binding.detect_cli"));
    const auto* optional = pe.value().data() + 24;
    const auto magic = read_u16_le(optional);
    const std::uint64_t directory_count_offset = magic == 0x10b ? 92 :
        magic == 0x20b ? 108 : (std::numeric_limits<std::uint64_t>::max)();
    const std::uint64_t directories_offset = magic == 0x10b ? 96 :
        magic == 0x20b ? 112 : (std::numeric_limits<std::uint64_t>::max)();
    if (directory_count_offset == (std::numeric_limits<std::uint64_t>::max)())
        return workspace_result_t<bool>::failure(binding_error(
            workspace_error_code_t::unsupported_format,
            "PE optional-header kind is unsupported for CLI detection",
            "managed.binding.detect_cli"));
    if (optional_size < directory_count_offset + 4 ||
        pe.value().size() < 24ULL + directory_count_offset + 4)
        return workspace_result_t<bool>::failure(binding_error(
            workspace_error_code_t::malformed_image,
            "PE directory count is truncated during CLI detection",
            "managed.binding.detect_cli"));
    const auto directory_count = read_u32_le(optional + directory_count_offset);
    if (directory_count <= 14)
        return workspace_result_t<bool>::success(false);
    const auto cli_offset = directories_offset + 14ULL * 8ULL;
    if (optional_size < cli_offset + 8 ||
        pe.value().size() < 24ULL + cli_offset + 8)
        return workspace_result_t<bool>::failure(binding_error(
            workspace_error_code_t::malformed_image,
            "PE CLI directory is truncated",
            "managed.binding.detect_cli"));
    return workspace_result_t<bool>::success(
        read_u32_le(optional + cli_offset) != 0 &&
        read_u32_le(optional + cli_offset + 4) != 0);
}

workspace_result_t<std::shared_ptr<const byte_provider_t>> artifact_provider(
    const analysis_publication_t& publication,
    const managed_artifact_binding_record_t& artifact) {
    if (!publication.provider || artifact.provider_size == 0 ||
        artifact.provider_offset > publication.provider->size() ||
        artifact.provider_size >
            publication.provider->size() - artifact.provider_offset)
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
            binding_error(workspace_error_code_t::out_of_range,
                "managed artifact range exceeds the bound provider",
                "managed.binding.artifact_provider"));
    if (artifact.provider_offset == 0 &&
        artifact.provider_size == publication.provider->size())
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::success(
            publication.provider);
    auto subrange = subrange_provider_t::create(
        publication.provider, artifact.provider_offset, artifact.provider_size,
        "managed_artifact_" + std::to_string(artifact.artifact_ordinal));
    if (!subrange)
        return workspace_result_t<std::shared_ptr<const byte_provider_t>>::failure(
            subrange.error());
    return workspace_result_t<std::shared_ptr<const byte_provider_t>>::success(
        std::static_pointer_cast<const byte_provider_t>(subrange.take_value()));
}

workspace_result_t<void> append_artifact(
    managed_artifact_publication_t& publication,
    managed_artifact_record_index_t& records,
    const readers::managed::managed_artifact_t& artifact,
    std::uint32_t artifact_index,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(
            stop_error(cancel, "managed.binding.compact"));
    if (!artifact.valid() || artifact.schema_version !=
            readers::managed::managed_reader_schema_version ||
        artifact.module_identity.artifact_hash.empty() ||
        artifact.module_identity.artifact_size == 0 ||
        artifact.module_identity.artifact_offset > publication.provider_size ||
        artifact.module_identity.artifact_size > publication.provider_size -
            artifact.module_identity.artifact_offset)
        return workspace_result_t<void>::failure(binding_error(
            workspace_error_code_t::integrity_failure,
            "managed reader returned an invalid artifact identity",
            "managed.binding.compact"));
    if (records.methods.size() >
            (std::numeric_limits<std::uint32_t>::max)() ||
        artifact.methods.size() >
            static_cast<std::size_t>(
                (std::numeric_limits<std::uint32_t>::max)()) -
                records.methods.size())
        return workspace_result_t<void>::failure(binding_error(
            workspace_error_code_t::limit_exceeded,
            "managed method index exceeds publication limits",
            "managed.binding.compact"));
    managed_artifact_binding_record_t record;
    record.kind = artifact.kind;
    record.artifact_hash = artifact.module_identity.artifact_hash;
    record.provider_offset = artifact.module_identity.artifact_offset;
    record.provider_size = artifact.module_identity.artifact_size;
    record.artifact_ordinal = artifact.module_identity.artifact_ordinal;
    record.assembly_identity = artifact.module_identity.assembly_name;
    record.module_name = artifact.module_identity.module_name;
    record.version = artifact.module_identity.version;
    record.first_method = static_cast<std::uint32_t>(records.methods.size());
    record.method_count = static_cast<std::uint32_t>(artifact.methods.size());
    records.artifacts.push_back(std::move(record));
    for (std::uint32_t index = 0;
         index < static_cast<std::uint32_t>(artifact.methods.size()); ++index) {
        if ((index & 255U) == 0 && cancel.stop_requested())
            return workspace_result_t<void>::failure(
                stop_error(cancel, "managed.binding.compact"));
        const auto& method = artifact.methods[index];
        managed_method_binding_record_t method_record;
        method_record.artifact_index = artifact_index;
        method_record.entity_token = method.metadata_token;
        method_record.method_index = method.method_index;
        method_record.provider_code_offset = artifact.module_identity.artifact_offset;
        if (method.code_offset >
            (std::numeric_limits<std::uint64_t>::max)() -
                method_record.provider_code_offset)
            return workspace_result_t<void>::failure(binding_error(
                workspace_error_code_t::range_overflow,
                "managed method code offset overflowed",
                "managed.binding.compact"));
        method_record.provider_code_offset += method.code_offset;
        method_record.code_size = method.code_size;
        method_record.has_body = method.has_body && method.code_size != 0;
        switch (artifact.kind) {
        case readers::managed::managed_artifact_kind_t::cli_metadata:
            method_record.entity = readers::managed::build_cli_entity_key(
                artifact, index);
            break;
        case readers::managed::managed_artifact_kind_t::java_classfile:
            method_record.entity = readers::managed::build_jvm_entity_key(
                artifact, index);
            break;
        case readers::managed::managed_artifact_kind_t::dex:
        case readers::managed::managed_artifact_kind_t::oat:
        case readers::managed::managed_artifact_kind_t::vdex:
        case readers::managed::managed_artifact_kind_t::multidex_container:
            method_record.entity = readers::managed::build_dalvik_entity_key(
                artifact, index);
            break;
        }
        if (!validate_decompiler_entity_key(method_record.entity).valid())
            return workspace_result_t<void>::failure(binding_error(
                workspace_error_code_t::integrity_failure,
                "managed reader produced an invalid decompiler entity",
                "managed.binding.compact"));
        records.methods.push_back(std::move(method_record));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::vector<readers::managed::managed_artifact_t>>
read_artifacts(const workspace_identity_t& identity,
               const byte_provider_t& provider,
               const std::shared_ptr<const pe_image_t>& pe_image,
               const readers::managed::managed_reader_limits_t& limits,
               const cancellation_token_t& cancel) {
    using namespace readers::managed;
    std::vector<managed_artifact_t> artifacts;
    if (identity.format() == format_id_t::pe32 ||
        identity.format() == format_id_t::pe32_plus) {
        bool has_cli = false;
        if (pe_image) {
            const auto directory = std::find_if(
                pe_image->directories().begin(), pe_image->directories().end(),
                [](const pe_data_directory_t& entry) {
                    return entry.index == 14;
                });
            has_cli = directory != pe_image->directories().end() &&
                directory->rva != 0 && directory->size != 0;
        } else {
            auto cli = pe_has_cli_directory(provider, cancel);
            if (!cli)
                return workspace_result_t<std::vector<managed_artifact_t>>::failure(
                    cli.error());
            has_cli = cli.value();
        }
        if (!has_cli)
            return workspace_result_t<std::vector<managed_artifact_t>>::success({});
        auto artifact = read_cli_metadata(provider, limits, cancel);
        if (!artifact)
            return workspace_result_t<std::vector<managed_artifact_t>>::failure(
                artifact.error());
        artifacts.push_back(artifact.take_value());
    } else if (identity.format() == format_id_t::classfile) {
        auto artifact = read_classfile(provider, limits, cancel);
        if (!artifact)
            return workspace_result_t<std::vector<managed_artifact_t>>::failure(
                artifact.error());
        artifacts.push_back(artifact.take_value());
    } else if (identity.format() == format_id_t::dex ||
               identity.format() == format_id_t::oat ||
               identity.format() == format_id_t::vdex) {
        auto multidex = read_multidex_container(provider, limits, cancel);
        if (!multidex)
            return workspace_result_t<std::vector<managed_artifact_t>>::failure(
                multidex.error());
        artifacts = std::move(multidex.value().artifacts);
    }
    return workspace_result_t<std::vector<managed_artifact_t>>::success(
        std::move(artifacts));
}

const managed_method_binding_record_t* find_method_record(
    const managed_artifact_publication_t& publication,
    const generation_bound_decompiler_entity_t& binding) noexcept {
    if (!publication.records || !binding.artifact_index ||
        !binding.method_index ||
        *binding.artifact_index >= publication.records->artifacts.size())
        return nullptr;
    const auto& artifact = publication.records->artifacts[
        *binding.artifact_index];
    const auto begin = static_cast<std::uint64_t>(artifact.first_method);
    const auto end = begin + artifact.method_count;
    for (std::uint64_t index = begin;
         index < end && index < publication.records->methods.size(); ++index) {
        const auto& method = publication.records->methods[
            static_cast<std::size_t>(index)];
        if (method.method_index == *binding.method_index &&
            method.entity == binding.entity)
            return &method;
    }
    return nullptr;
}

bool entity_matches_artifact(
    const decompiler_entity_key_t& entity,
    const managed_artifact_binding_record_t& artifact) noexcept {
    using readers::managed::managed_artifact_kind_t;
    switch (artifact.kind) {
    case managed_artifact_kind_t::cli_metadata: {
        const auto* identity =
            std::get_if<cli_decompiler_entity_identity_t>(&entity.identity);
        return entity.kind == decompiler_entity_kind_t::cli_method &&
            identity && identity->module_hash == artifact.artifact_hash;
    }
    case managed_artifact_kind_t::java_classfile: {
        const auto* identity =
            std::get_if<jvm_decompiler_entity_identity_t>(&entity.identity);
        return entity.kind == decompiler_entity_kind_t::jvm_method &&
            entity.format == format_id_t::classfile && identity &&
            identity->class_artifact_hash == artifact.artifact_hash;
    }
    case managed_artifact_kind_t::dex:
    case managed_artifact_kind_t::oat:
    case managed_artifact_kind_t::vdex:
    case managed_artifact_kind_t::multidex_container: {
        const auto* identity =
            std::get_if<dalvik_decompiler_entity_identity_t>(&entity.identity);
        const auto expected_format = artifact.kind == managed_artifact_kind_t::oat
            ? format_id_t::oat
            : artifact.kind == managed_artifact_kind_t::vdex
                ? format_id_t::vdex
                : format_id_t::dex;
        return entity.kind == decompiler_entity_kind_t::dalvik_method &&
            entity.format == expected_format && identity &&
            identity->dex_hash == artifact.artifact_hash &&
            identity->dex_ordinal == artifact.artifact_ordinal;
    }
    }
    return false;
}

bool binding_matches_managed_publication(
    const analysis_publication_t& publication,
    const generation_bound_decompiler_entity_t& binding) noexcept {
    if (!publication.provider || !publication.managed_artifacts ||
        !binding.artifact_index || !binding.method_index ||
        binding.binary_id != publication.binary_id ||
        binding.load_profile_hash != publication.load_profile_hash ||
        binding.provider_size != publication.provider->size() ||
        binding.generation != publication.generation ||
        binding.analysis_revision != publication.analysis_revision ||
        binding.overlay_revision != publication.overlay_revision ||
        binding.type_graph_revision != publication.analysis_revision ||
        binding.reader_schema_version !=
            publication.managed_artifacts->reader_schema_version ||
        binding.provider_hash != publication.managed_artifacts->provider_hash ||
        !publication.managed_artifacts->records ||
        *binding.artifact_index >= publication.managed_artifacts->artifacts().size())
        return false;
    const auto& artifact = publication.managed_artifacts->artifacts()[
        *binding.artifact_index];
    return artifact.artifact_hash == binding.artifact_hash &&
        entity_matches_artifact(binding.entity, artifact) &&
        find_method_record(*publication.managed_artifacts, binding) != nullptr;
}

::aida::analysis::classfile_parse_limits_t classfile_capture_limits(
    const managed_artifact_publication_t& publication,
    const managed_artifact_binding_record_t& artifact) noexcept {
    ::aida::analysis::classfile_parse_limits_t limits;
    limits.max_classfile_bytes = (std::min)(
        limits.max_classfile_bytes, artifact.provider_size);
    limits.max_constant_pool_entries = (std::min)(
        limits.max_constant_pool_entries,
        publication.reader_limits.max_constant_pool_entries);
    limits.max_fields = (std::min)(
        limits.max_fields, publication.reader_limits.max_fields);
    limits.max_methods = (std::min)(
        limits.max_methods, publication.reader_limits.max_methods);
    limits.max_total_attribute_bytes = (std::min)(
        limits.max_total_attribute_bytes,
        publication.reader_limits.max_metadata_bytes);
    limits.max_total_code_bytes = (std::min)(
        limits.max_total_code_bytes,
        publication.reader_limits.max_code_bytes);
    limits.max_bytecode_per_method = (std::min)(
        limits.max_bytecode_per_method,
        publication.reader_limits.max_code_bytes);
    limits.max_utf8_length = (std::min)(
        limits.max_utf8_length,
        publication.reader_limits.max_string_bytes);
    limits.max_exception_table_entries = (std::min)(
        limits.max_exception_table_entries,
        static_cast<std::uint64_t>(
            publication.reader_limits.max_exception_regions));
    limits.max_instructions_per_method = (std::min)(
        limits.max_instructions_per_method,
        static_cast<std::uint64_t>(publication.reader_limits.max_code_ranges));
    return limits;
}

::aida::analysis::dex_parse_limits_t dalvik_capture_limits(
    const managed_artifact_publication_t& publication,
    const managed_artifact_binding_record_t& artifact) noexcept {
    ::aida::analysis::dex_parse_limits_t limits;
    limits.max_file_size = (std::min)(limits.max_file_size,
        artifact.provider_size);
    limits.max_embedded_dex_files = 1;
    limits.max_string_ids = (std::min)(limits.max_string_ids,
        publication.reader_limits.max_table_rows);
    limits.max_type_ids = (std::min)(limits.max_type_ids,
        publication.reader_limits.max_types);
    limits.max_proto_ids = (std::min)(limits.max_proto_ids,
        publication.reader_limits.max_table_rows);
    limits.max_field_ids = (std::min)(limits.max_field_ids,
        publication.reader_limits.max_fields);
    limits.max_method_ids = (std::min)(limits.max_method_ids,
        publication.reader_limits.max_methods);
    limits.max_class_defs = (std::min)(limits.max_class_defs,
        publication.reader_limits.max_types);
    limits.max_class_data_items = (std::min)(limits.max_class_data_items,
        publication.reader_limits.max_types);
    const auto code_units = publication.reader_limits.max_code_bytes / 2ULL;
    limits.max_code_units_per_method = (std::min)(
        limits.max_code_units_per_method,
        static_cast<std::uint32_t>((std::min<std::uint64_t>)(
            code_units, (std::numeric_limits<std::uint32_t>::max)())));
    limits.max_total_code_units = (std::min)(
        limits.max_total_code_units, code_units);
    limits.max_instruction_records_per_method = (std::min)(
        limits.max_instruction_records_per_method,
        publication.reader_limits.max_code_ranges);
    limits.max_total_instruction_records = (std::min)(
        limits.max_total_instruction_records,
        static_cast<std::uint64_t>(publication.reader_limits.max_code_ranges));
    limits.max_try_items_per_method = (std::min)(
        limits.max_try_items_per_method,
        publication.reader_limits.max_exception_regions);
    limits.max_catch_handlers_per_method = (std::min)(
        limits.max_catch_handlers_per_method,
        publication.reader_limits.max_exception_regions);
    limits.max_debug_positions_per_method = (std::min)(
        limits.max_debug_positions_per_method,
        publication.reader_limits.max_code_ranges);
    limits.max_total_debug_positions = (std::min)(
        limits.max_total_debug_positions,
        static_cast<std::uint64_t>(publication.reader_limits.max_code_ranges));
    limits.max_string_bytes = (std::min)(limits.max_string_bytes,
        publication.reader_limits.max_string_bytes);
    limits.max_single_string_bytes = (std::min)(
        limits.max_single_string_bytes,
        publication.reader_limits.max_string_bytes);
    return limits;
}

}

bool managed_artifact_publication_t::coherent_with(
    const workspace_identity_t& identity,
    const byte_provider_t& provider,
    std::uint64_t expected_generation,
    std::uint64_t expected_analysis_revision,
    std::uint64_t expected_overlay_revision) const noexcept {
    if (schema_version != managed_entity_binding_schema_version ||
        reader_schema_version != readers::managed::managed_reader_schema_version ||
        !reader_limits.valid() ||
        binary_id != identity.binary_id() ||
        load_profile_hash != identity.load_profile_hash() || provider_hash.empty() ||
        provider_source.empty() || provider_source != provider.identity().normalized_source ||
        provider_size != provider.size() || generation != expected_generation ||
        analysis_revision != expected_analysis_revision ||
        overlay_revision != expected_overlay_revision || !records ||
        records->artifacts.empty())
        return false;
    if (provider.identity().content_sha256 &&
        provider_hash != *provider.identity().content_sha256)
        return false;
    const auto& artifacts = records->artifacts;
    const auto& methods = records->methods;
    const auto kind_matches_workspace = [&](const auto kind) noexcept {
        using readers::managed::managed_artifact_kind_t;
        switch (identity.format()) {
        case format_id_t::pe32:
        case format_id_t::pe32_plus:
            return kind == managed_artifact_kind_t::cli_metadata;
        case format_id_t::classfile:
            return kind == managed_artifact_kind_t::java_classfile;
        case format_id_t::dex:
            return kind == managed_artifact_kind_t::dex;
        case format_id_t::oat:
            return kind == managed_artifact_kind_t::oat;
        case format_id_t::vdex:
            return kind == managed_artifact_kind_t::vdex;
        default:
            return false;
        }
    };
    std::uint64_t expected_method = 0;
    for (std::size_t artifact_index = 0;
         artifact_index < artifacts.size(); ++artifact_index) {
        const auto& artifact = artifacts[artifact_index];
        for (std::size_t prior = 0; prior < artifact_index; ++prior)
            if (artifacts[prior].artifact_ordinal == artifact.artifact_ordinal)
                return false;
        if (artifact.artifact_hash.empty() || artifact.provider_size == 0 ||
            !kind_matches_workspace(artifact.kind) ||
            artifact.provider_offset > provider_size ||
            artifact.provider_size > provider_size - artifact.provider_offset ||
            artifact.first_method != expected_method)
            return false;
        expected_method += artifact.method_count;
        if (expected_method > methods.size())
            return false;
        for (std::uint64_t method_index = artifact.first_method;
             method_index < expected_method; ++method_index) {
            const auto& method = methods[static_cast<std::size_t>(method_index)];
            if (method.artifact_index != artifact_index ||
                method.method_index >= artifact.method_count ||
                method.entity.format != identity.format() ||
                method.entity.architecture != identity.architecture() ||
                method.entity.mode != identity.architecture_mode() ||
                method.entity.endian != identity.endian() ||
                !entity_matches_artifact(method.entity, artifact))
                return false;
        }
    }
    if (expected_method != methods.size())
        return false;
    for (const auto& method : methods) {
        if (method.artifact_index >= artifacts.size())
            return false;
        const auto& artifact = artifacts[method.artifact_index];
        if (method.provider_code_offset < artifact.provider_offset ||
            method.provider_code_offset > artifact.provider_offset +
                artifact.provider_size ||
            method.code_size > artifact.provider_offset + artifact.provider_size -
                method.provider_code_offset ||
            method.has_body != (method.code_size != 0))
            return false;
    }
    return true;
}

workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>
build_managed_artifact_publication(
    const workspace_identity_t& identity,
    const byte_provider_t& provider,
    const std::shared_ptr<const pe_image_t>& pe_image,
    std::uint64_t generation,
    std::uint64_t analysis_revision,
    std::uint64_t overlay_revision,
    const readers::managed::managed_reader_limits_t& limits,
    const cancellation_token_t& cancel) try {
    if (identity.target_kind() != target_kind_t::static_file)
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            binding_error(workspace_error_code_t::live_target_bulk_analysis_unsupported,
                "managed baseline admission is unavailable for live targets",
                "managed.binding.admit"));
    if (generation == 0 || analysis_revision == 0 ||
        !limits.valid() ||
        provider.identity().normalized_source.empty() ||
        provider.identity().size != provider.size())
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            binding_error(workspace_error_code_t::invalid_argument,
                "managed publication identity or reader limits are incomplete",
                "managed.binding.admit"));
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            stop_error(cancel, "managed.binding.admit"));
    auto artifacts = read_artifacts(identity, provider, pe_image, limits, cancel);
    if (!artifacts)
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            artifacts.error());
    if (artifacts.value().empty())
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::success(
            nullptr);
    auto provider_hash = current_provider_hash(provider, cancel);
    if (!provider_hash) {
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            provider_hash.error());
    }
        auto publication = std::make_shared<managed_artifact_publication_t>();
        publication->binary_id = identity.binary_id();
        publication->load_profile_hash = identity.load_profile_hash();
        publication->provider_hash = provider_hash.value();
        publication->reader_limits = limits;
        publication->provider_source = provider.identity().normalized_source;
        publication->provider_size = provider.size();
        publication->generation = generation;
        publication->analysis_revision = analysis_revision;
        publication->overlay_revision = overlay_revision;
        auto records = std::make_shared<managed_artifact_record_index_t>();
        records->artifacts.reserve(artifacts.value().size());
        std::size_t method_count = 0;
        for (const auto& artifact : artifacts.value()) {
            if (artifact.methods.size() >
                (std::numeric_limits<std::size_t>::max)() - method_count)
                return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                    binding_error(workspace_error_code_t::limit_exceeded,
                        "managed publication method count overflowed",
                        "managed.binding.admit"));
            method_count += artifact.methods.size();
        }
        records->methods.reserve(method_count);
        for (std::uint32_t index = 0;
             index < static_cast<std::uint32_t>(artifacts.value().size()); ++index) {
            auto appended = append_artifact(
                *publication, *records, artifacts.value()[index], index, cancel);
            if (!appended)
                return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                    appended.error());
        }
        publication->records = std::static_pointer_cast<
            const managed_artifact_record_index_t>(std::move(records));
        if (!publication->coherent_with(identity, provider, generation,
                analysis_revision, overlay_revision))
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                binding_error(workspace_error_code_t::integrity_failure,
                    "managed publication failed coherence validation",
                    "managed.binding.admit"));
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::success(
            std::static_pointer_cast<const managed_artifact_publication_t>(
                std::move(publication)));
} catch (const std::bad_alloc&) {
    return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
        binding_error(workspace_error_code_t::limit_exceeded,
            "managed publication allocation failed",
            "managed.binding.admit"));
}

workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>
rebind_managed_artifact_publication(
    const managed_artifact_publication_t& source,
    const workspace_identity_t& identity,
    const byte_provider_t& provider,
    const std::shared_ptr<const pe_image_t>& pe_image,
    std::uint64_t generation,
    std::uint64_t analysis_revision,
    std::uint64_t overlay_revision,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            stop_error(cancel, "managed.binding.rebind"));
    if (generation == 0 || analysis_revision == 0 || !source.records ||
        !source.reader_limits.valid())
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            binding_error(workspace_error_code_t::invalid_argument,
                "managed publication rebind input is incomplete",
                "managed.binding.rebind"));
    if (source.binary_id == identity.binary_id() &&
        source.load_profile_hash == identity.load_profile_hash() &&
        source.provider_size == provider.size() &&
        source.provider_source == provider.identity().normalized_source &&
        provider.identity().content_sha256 &&
        source.provider_hash == *provider.identity().content_sha256) {
        try {
            auto rebound = std::make_shared<managed_artifact_publication_t>(source);
            rebound->generation = generation;
            rebound->analysis_revision = analysis_revision;
            rebound->overlay_revision = overlay_revision;
            if (!rebound->coherent_with(identity, provider, generation,
                    analysis_revision, overlay_revision))
                return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                    binding_error(workspace_error_code_t::integrity_failure,
                        "managed publication revision rebind failed",
                        "managed.binding.rebind"));
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::success(
                std::static_pointer_cast<const managed_artifact_publication_t>(
                    std::move(rebound)));
        } catch (const std::bad_alloc&) {
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                binding_error(workspace_error_code_t::limit_exceeded,
                    "managed publication rebind allocation failed",
                    "managed.binding.rebind"));
        }
    }
    auto provider_hash = current_provider_hash(provider, cancel);
    if (!provider_hash)
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            provider_hash.error());
    if (provider_hash.value() == source.provider_hash &&
        source.binary_id == identity.binary_id() &&
        source.load_profile_hash == identity.load_profile_hash() &&
        source.provider_size == provider.size() &&
        source.provider_source == provider.identity().normalized_source) {
        try {
            auto rebound = std::make_shared<managed_artifact_publication_t>(source);
            rebound->generation = generation;
            rebound->analysis_revision = analysis_revision;
            rebound->overlay_revision = overlay_revision;
            if (!rebound->coherent_with(identity, provider, generation,
                    analysis_revision, overlay_revision))
                return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                    binding_error(workspace_error_code_t::integrity_failure,
                        "managed publication revision rebind failed",
                        "managed.binding.rebind"));
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::success(
                std::static_pointer_cast<const managed_artifact_publication_t>(
                    std::move(rebound)));
        } catch (const std::bad_alloc&) {
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                binding_error(workspace_error_code_t::limit_exceeded,
                    "managed publication rebind allocation failed",
                    "managed.binding.rebind"));
        }
    }
    return build_managed_artifact_publication(identity, provider, pe_image,
        generation, analysis_revision, overlay_revision,
        source.reader_limits, cancel);
}

workspace_result_t<generation_bound_decompiler_entity_t>
resolve_generation_bound_entity(
    const workspace_identity_t& identity,
    const analysis_publication_t& publication,
    const decompiler_entity_locator_t& locator,
    const cancellation_token_t& cancel) try {
    if (cancel.stop_requested())
        return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
            stop_error(cancel, "managed.binding.resolve"));
    if ((locator.address.has_value() == locator.token.has_value()) ||
        !publication.coherent_with(identity) || !publication.snapshot ||
        publication.analysis_revision == 0)
        return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
            binding_error(workspace_error_code_t::invalid_argument,
                "entity locator or workspace publication is invalid",
                "managed.binding.resolve"));
    const managed_method_binding_record_t* managed_match = nullptr;
    bool managed_ambiguous = false;
    const auto record_managed_match = [&](const auto* method) noexcept {
        if (!managed_match)
            managed_match = method;
        else if (managed_match != method)
            managed_ambiguous = true;
    };
    if (publication.managed_artifacts) {
        for (const auto& method : publication.managed_artifacts->methods()) {
            if (cancel.stop_requested())
                return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                    stop_error(cancel, "managed.binding.resolve"));
            if (locator.expected_kind && method.entity.kind != *locator.expected_kind)
                continue;
            if (method.artifact_index >=
                publication.managed_artifacts->artifacts().size())
                return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                    binding_error(workspace_error_code_t::integrity_failure,
                        "managed method references an invalid artifact",
                        "managed.binding.resolve"));
            const auto& artifact = publication.managed_artifacts->artifacts()[
                method.artifact_index];
            if (locator.artifact_ordinal &&
                artifact.artifact_ordinal != *locator.artifact_ordinal)
                continue;
            if (locator.token && method.entity_token == *locator.token)
                record_managed_match(&method);
            if (locator.address && method.has_body) {
                if (method.code_size >
                    (std::numeric_limits<std::uint64_t>::max)() -
                        method.provider_code_offset)
                    return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                        binding_error(workspace_error_code_t::range_overflow,
                            "managed method range overflowed during resolution",
                            "managed.binding.resolve"));
                const auto method_end =
                    method.provider_code_offset + method.code_size;
                if (*locator.address >= method.provider_code_offset &&
                    *locator.address < method_end)
                    record_managed_match(&method);
            }
        }
    }
    if (locator.address &&
        (!locator.expected_kind ||
         *locator.expected_kind == decompiler_entity_kind_t::native_function)) {
        const auto image_base = publication.snapshot->normalized_image
            ? publication.snapshot->normalized_image->image_base : 0;
        for (const auto& function : publication.snapshot->functions) {
            const auto relative = function.start.space ==
                    address_space_id_t::relative_virtual
                ? function.start.value
                : function.start.value >= image_base
                    ? function.start.value - image_base
                    : (std::numeric_limits<std::uint64_t>::max)();
            const auto relative_end = function.end.space ==
                    address_space_id_t::relative_virtual
                ? function.end.value
                : function.end.value >= image_base
                    ? function.end.value - image_base
                    : 0;
            const bool relative_match =
                relative != (std::numeric_limits<std::uint64_t>::max)() &&
                relative_end > relative && *locator.address >= relative &&
                *locator.address < relative_end;
            const bool runtime_range_valid =
                relative != (std::numeric_limits<std::uint64_t>::max)() &&
                relative_end > relative &&
                relative_end <= (std::numeric_limits<std::uint64_t>::max)() -
                    image_base;
            const bool runtime_match = runtime_range_valid &&
                *locator.address >= image_base + relative &&
                *locator.address < image_base + relative_end;
            if (relative_match || runtime_match) {
                if (managed_match || managed_ambiguous)
                    return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
                        binding_error(workspace_error_code_t::target_ambiguous,
                            "address resolves to both native and managed entities",
                            "managed.binding.resolve"));
                generation_bound_decompiler_entity_t result;
                result.binary_id = publication.binary_id;
                result.load_profile_hash = publication.load_profile_hash;
                result.provider_hash = publication.provider->identity().content_sha256
                    ? *publication.provider->identity().content_sha256
                    : publication.snapshot->normalized_image
                        ? publication.snapshot->normalized_image->provider_content_hash
                        : identity.content_hash();
                result.artifact_hash = result.provider_hash;
                result.provider_size = publication.provider->size();
                result.generation = publication.generation;
                result.analysis_revision = publication.analysis_revision;
                result.overlay_revision = publication.overlay_revision;
                result.type_graph_revision = publication.analysis_revision;
                result.entity.kind = decompiler_entity_kind_t::native_function;
                result.entity.format = identity.format();
                result.entity.architecture = identity.architecture();
                result.entity.mode = identity.architecture_mode();
                result.entity.endian = identity.endian();
                native_decompiler_entity_identity_t native;
                native.function_id = function.id;
                native.entry = function.start;
                native.end = function.end;
                native.canonical_symbol = "function_" +
                    std::to_string(function.id);
                result.entity.identity = std::move(native);
                return workspace_result_t<generation_bound_decompiler_entity_t>::success(
                    std::move(result));
            }
        }
    }
    if (!managed_match)
        return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
            binding_error(workspace_error_code_t::target_not_found,
                "no decompiler entity matches the requested locator",
                "managed.binding.resolve"));
    if (managed_ambiguous)
        return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
            binding_error(workspace_error_code_t::target_ambiguous,
                "decompiler entity locator matches multiple managed methods",
                "managed.binding.resolve"));
    const auto* method = managed_match;
    if (!method->has_body)
        return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
            binding_error(workspace_error_code_t::unsupported_format,
                "managed method has no executable body",
                "managed.binding.resolve"));
    const auto artifact_index = method->artifact_index;
    const auto& artifact = publication.managed_artifacts->artifacts()[artifact_index];
    generation_bound_decompiler_entity_t result;
    result.binary_id = publication.binary_id;
    result.load_profile_hash = publication.load_profile_hash;
    result.provider_hash = publication.managed_artifacts->provider_hash;
    result.artifact_hash = artifact.artifact_hash;
    result.provider_size = publication.provider->size();
    result.generation = publication.generation;
    result.analysis_revision = publication.analysis_revision;
    result.overlay_revision = publication.overlay_revision;
    result.type_graph_revision = publication.analysis_revision;
    result.reader_schema_version = publication.managed_artifacts->reader_schema_version;
    result.artifact_index = artifact_index;
    result.method_index = method->method_index;
    result.entity = method->entity;
    return workspace_result_t<generation_bound_decompiler_entity_t>::success(
        std::move(result));
} catch (const std::bad_alloc&) {
    return workspace_result_t<generation_bound_decompiler_entity_t>::failure(
        binding_error(workspace_error_code_t::limit_exceeded,
            "decompiler entity resolution allocation failed",
            "managed.binding.resolve"));
}

workspace_result_t<void> validate_generation_bound_entity(
    const workspace_identity_t& identity,
    const analysis_publication_t& publication,
    const generation_bound_decompiler_entity_t& binding,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(
            stop_error(cancel, "managed.binding.validate"));
    if (!publication.coherent_with(identity) ||
        binding.schema_version != managed_entity_binding_schema_version ||
        binding.binary_id != publication.binary_id ||
        binding.load_profile_hash != publication.load_profile_hash ||
        binding.provider_size != publication.provider->size() ||
        binding.generation != publication.generation ||
        binding.analysis_revision != publication.analysis_revision ||
        binding.overlay_revision != publication.overlay_revision ||
        binding.type_graph_revision != publication.analysis_revision ||
        binding.entity.format != identity.format() ||
        binding.entity.architecture != identity.architecture() ||
        binding.entity.mode != identity.architecture_mode() ||
        binding.entity.endian != identity.endian() ||
        !validate_decompiler_entity_key(binding.entity).valid())
        return workspace_result_t<void>::failure(binding_error(
            workspace_error_code_t::target_stale,
            "decompiler entity binding is stale or cross-workspace",
            "managed.binding.validate"));
    if (binding.entity.kind == decompiler_entity_kind_t::native_function) {
        const auto* native = std::get_if<native_decompiler_entity_identity_t>(
            &binding.entity.identity);
        if (!native)
            return workspace_result_t<void>::failure(binding_error(
                workspace_error_code_t::integrity_failure,
                "native entity binding has an invalid identity",
                "managed.binding.validate"));
        const auto expected_provider_hash =
            publication.provider->identity().content_sha256
                ? *publication.provider->identity().content_sha256
                : publication.snapshot->normalized_image
                    ? publication.snapshot->normalized_image->provider_content_hash
                    : identity.content_hash();
        if (expected_provider_hash.empty() ||
            binding.provider_hash != expected_provider_hash ||
            (native->function_bytes_hash.empty()
                ? binding.artifact_hash != expected_provider_hash
                : binding.artifact_hash != native->function_bytes_hash))
            return workspace_result_t<void>::failure(binding_error(
                workspace_error_code_t::target_stale,
                "native entity provider identity changed",
                "managed.binding.validate"));
        const auto found = std::find_if(
            publication.snapshot->functions.begin(),
            publication.snapshot->functions.end(),
            [native](const function_record_t& function) {
                return function.id == native->function_id &&
                    function.start == native->entry && function.end == native->end;
            });
        return found == publication.snapshot->functions.end()
            ? workspace_result_t<void>::failure(binding_error(
                workspace_error_code_t::target_stale,
                "native entity no longer exists in the workspace revision",
                "managed.binding.validate"))
            : workspace_result_t<void>::success();
    }
    if (!binding_matches_managed_publication(publication, binding))
        return workspace_result_t<void>::failure(binding_error(
            workspace_error_code_t::target_stale,
            "managed entity no longer exists in the workspace revision",
            "managed.binding.validate"));
    return workspace_result_t<void>::success();
}

workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>
capture_managed_artifact_snapshot(
    const analysis_publication_t& publication,
    const generation_bound_decompiler_entity_t& binding,
    std::uint64_t maximum_bytes,
    const cancellation_token_t& cancel) try {
    if (maximum_bytes == 0 ||
        !binding_matches_managed_publication(publication, binding))
        return workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>::failure(
            binding_error(workspace_error_code_t::invalid_argument,
                "managed artifact snapshot binding or limit is invalid",
                "managed.binding.snapshot"));
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>::failure(
            stop_error(cancel, "managed.binding.snapshot"));
    const auto& artifact = publication.managed_artifacts->artifacts()[
        *binding.artifact_index];
    if (artifact.provider_size > maximum_bytes)
        return workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>::failure(
            binding_error(workspace_error_code_t::limit_exceeded,
                "managed artifact exceeds the snapshot budget",
                "managed.binding.snapshot"));
    auto source = artifact_provider(publication, artifact);
    if (!source)
        return workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>::failure(
            source.error());
    auto hash = source.value()->compute_content_sha256(cancel);
    if (!hash)
        return workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>::failure(
            hash.error());
    if (hash.value() != artifact.artifact_hash)
        return workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>::failure(
            binding_error(workspace_error_code_t::provider_binding_mismatch,
                "managed artifact changed before snapshot capture",
                "managed.binding.snapshot"));
    auto bytes = source.value()->read_vector(
        0, artifact.provider_size, maximum_bytes, cancel);
    if (!bytes)
        return workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>::failure(
            bytes.error());
    auto snapshot = std::make_shared<const std::vector<std::uint8_t>>(
        bytes.take_value());
    return workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>::success(
        std::move(snapshot));
} catch (const std::bad_alloc&) {
    return workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>::failure(
        binding_error(workspace_error_code_t::limit_exceeded,
            "managed artifact snapshot allocation failed",
            "managed.binding.snapshot"));
}

workspace_result_t<std::shared_ptr<const jvm_ssa::jvm_method_input_t>>
capture_jvm_entity_input(
    const analysis_publication_t& publication,
    const generation_bound_decompiler_entity_t& binding,
    const decompiler_provider_identity_t& provider,
    const cancellation_token_t& cancel) try {
    if (!binding_matches_managed_publication(publication, binding) ||
        binding.entity.kind != decompiler_entity_kind_t::jvm_method)
        return workspace_result_t<std::shared_ptr<const jvm_ssa::jvm_method_input_t>>::failure(
            binding_error(workspace_error_code_t::invalid_argument,
                "JVM capture requires a JVM entity binding",
                "managed.binding.jvm"));
    const auto& artifact = publication.managed_artifacts->artifacts()[
        *binding.artifact_index];
    auto source = artifact_provider(publication, artifact);
    if (!source)
        return workspace_result_t<std::shared_ptr<const jvm_ssa::jvm_method_input_t>>::failure(
            source.error());
    auto hash = source.value()->compute_content_sha256(cancel);
    if (!hash)
        return workspace_result_t<std::shared_ptr<const jvm_ssa::jvm_method_input_t>>::failure(
            hash.error());
    if (hash.value() != artifact.artifact_hash)
        return workspace_result_t<std::shared_ptr<const jvm_ssa::jvm_method_input_t>>::failure(
            binding_error(workspace_error_code_t::provider_binding_mismatch,
                "JVM artifact hash changed before capture",
                "managed.binding.jvm"));
    const auto limits = classfile_capture_limits(
        *publication.managed_artifacts, artifact);
    auto image = parse_classfile_image(*source.value(), limits, cancel);
    if (!image)
        return workspace_result_t<std::shared_ptr<const jvm_ssa::jvm_method_input_t>>::failure(
            image.error());
    if (*binding.method_index >= image.value().methods.size()) {
        return workspace_result_t<std::shared_ptr<const jvm_ssa::jvm_method_input_t>>::failure(
            binding_error(workspace_error_code_t::target_stale,
                "JVM method index is absent after verified capture",
                "managed.binding.jvm"));
    }
        auto input = std::make_shared<jvm_ssa::jvm_method_input_t>();
        input->context = jvm_ssa::extract_method_context(
            image.value(), *binding.method_index);
        input->entity = binding.entity;
        input->provider = provider;
        input->language.language_id = "jvm-bytecode";
        input->language.language_version =
            std::to_string(image.value().major_version) + "." +
            std::to_string(image.value().minor_version);
        input->language.compiler_spec_id = "jvm-classfile";
        input->language.language_spec_hash = stable_serialization_hash(
            "jvm-classfile|" + input->language.language_version);
        input->language.architecture = architecture_id_t::jvm_bytecode;
        input->language.mode = architecture_mode_t::jvm;
        input->language.endian = endian_t::big;
        input->workspace_generation = binding.generation;
        input->type_graph_revision = binding.type_graph_revision;
        return workspace_result_t<std::shared_ptr<const jvm_ssa::jvm_method_input_t>>::success(
            std::static_pointer_cast<const jvm_ssa::jvm_method_input_t>(
                std::move(input)));
} catch (const std::bad_alloc&) {
    return workspace_result_t<std::shared_ptr<const jvm_ssa::jvm_method_input_t>>::failure(
        binding_error(workspace_error_code_t::limit_exceeded,
            "JVM capture allocation failed",
            "managed.binding.jvm"));
}

workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>
capture_dalvik_entity_input(
    const analysis_publication_t& publication,
    const generation_bound_decompiler_entity_t& binding,
    const decompiler_provider_identity_t& provider,
    const cancellation_token_t& cancel) try {
    if (!binding_matches_managed_publication(publication, binding) ||
        binding.entity.kind != decompiler_entity_kind_t::dalvik_method)
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            binding_error(workspace_error_code_t::invalid_argument,
                "Dalvik capture requires a Dalvik entity binding",
                "managed.binding.dalvik"));
    const auto& artifact = publication.managed_artifacts->artifacts()[
        *binding.artifact_index];
    auto source = artifact_provider(publication, artifact);
    if (!source)
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            source.error());
    auto hash = source.value()->compute_content_sha256(cancel);
    if (!hash)
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            hash.error());
    if (hash.value() != artifact.artifact_hash)
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            binding_error(workspace_error_code_t::provider_binding_mismatch,
                "Dalvik artifact hash changed before capture",
                "managed.binding.dalvik"));
    const auto limits = dalvik_capture_limits(
        *publication.managed_artifacts, artifact);
    auto image = parse_dex_image(*source.value(), limits, cancel);
    if (!image)
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            image.error());
    if (*binding.method_index >= image.value().methods.size())
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            binding_error(workspace_error_code_t::target_stale,
                "Dalvik method index is absent after verified capture",
                "managed.binding.dalvik"));
    const auto& method = image.value().methods[*binding.method_index];
    std::shared_ptr<const dex_code_item_t> code;
    std::string source_path;
    std::uint64_t visited_methods = 0;
    for (const auto& cls : image.value().classes) {
        if ((visited_methods & 255U) == 0 && cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
                stop_error(cancel, "managed.binding.dalvik"));
        for (const auto& encoded : cls.direct_methods) {
            if ((visited_methods++ & 255U) == 0 && cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
                    stop_error(cancel, "managed.binding.dalvik"));
            if (encoded.method_index == *binding.method_index) {
                code = encoded.code;
                if (cls.source_file)
                    source_path = *cls.source_file;
                break;
            }
        }
        if (code)
            break;
        for (const auto& encoded : cls.virtual_methods) {
            if ((visited_methods++ & 255U) == 0 && cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
                    stop_error(cancel, "managed.binding.dalvik"));
            if (encoded.method_index == *binding.method_index) {
                code = encoded.code;
                if (cls.source_file)
                    source_path = *cls.source_file;
                break;
            }
        }
        if (code)
            break;
    }
    if (!code || code->instruction_count == 0)
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            binding_error(workspace_error_code_t::unsupported_format,
                "Dalvik method has no code item",
                "managed.binding.dalvik"));
    if (source_path.size() > dalvik_ssa::k_max_source_path_bytes)
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            binding_error(workspace_error_code_t::limit_exceeded,
                "Dalvik source file metadata exceeds the capture budget",
                "managed.binding.dalvik"));
    if (source_path.find('\0') != std::string::npos)
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            binding_error(workspace_error_code_t::malformed_image,
                "Dalvik source file metadata contains an embedded null",
                "managed.binding.dalvik"));
    const auto byte_count = static_cast<std::uint64_t>(code->instruction_count) * 2ULL;
    if (byte_count > publication.managed_artifacts->reader_limits.max_code_bytes)
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            binding_error(workspace_error_code_t::limit_exceeded,
                "Dalvik code item exceeds the capture budget",
                "managed.binding.dalvik"));
    if (code->instructions.empty() ||
        code->instructions.front().code_unit_offset != 0 ||
        code->instructions_offset > source.value()->size() ||
        byte_count > source.value()->size() - code->instructions_offset)
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            binding_error(workspace_error_code_t::out_of_range,
                "Dalvik code units exceed the artifact",
                "managed.binding.dalvik"));
    auto bytes = source.value()->read_vector(
        code->instructions_offset,
        byte_count,
        publication.managed_artifacts->reader_limits.max_code_bytes,
        cancel);
    if (!bytes) {
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
            bytes.error());
    }
        auto capture = std::make_shared<dalvik_ssa::dalvik_ssa_capture_t>();
        capture->request.provider = provider;
        capture->request.language.language_id = "dalvik-bytecode";
        capture->request.language.language_version =
            image.value().managed_identity.version;
        capture->request.language.compiler_spec_id = "android-dex";
        capture->request.language.language_spec_hash = stable_serialization_hash(
            "android-dex|" + capture->request.language.language_version);
        capture->request.language.architecture = architecture_id_t::dalvik_bytecode;
        capture->request.language.mode = architecture_mode_t::dalvik;
        capture->request.language.endian = endian_t::little;
        capture->request.entity = binding.entity;
        capture->request.workspace_generation = binding.generation;
        capture->request.type_graph_revision = binding.type_graph_revision;
        capture->request.dex_version = image.value().managed_identity.version;
        capture->request.source_path = std::move(source_path);
        capture->code_item = code;
        capture->code_units.reserve(code->instruction_count);
        for (std::size_t index = 0; index < bytes.value().size(); index += 2)
            capture->code_units.push_back(read_u16_le(bytes.value().data() + index));
        capture->strings = std::move(image.value().strings);
        capture->types = std::move(image.value().types);
        capture->protos = std::move(image.value().protos);
        capture->fields = std::move(image.value().fields);
        capture->methods = std::move(image.value().methods);
        capture->method_id = method.index;
        capture->class_descriptor = method.class_descriptor;
        capture->method_name = method.name;
        capture->prototype = method.descriptor;
        if (method.proto_index < capture->protos.size())
            capture->shorty = capture->protos[method.proto_index].shorty;
        return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::success(
            std::static_pointer_cast<const dalvik_ssa::dalvik_ssa_capture_t>(
                std::move(capture)));
} catch (const std::bad_alloc&) {
    return workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>::failure(
        binding_error(workspace_error_code_t::limit_exceeded,
            "Dalvik capture allocation failed",
            "managed.binding.dalvik"));
}

}
