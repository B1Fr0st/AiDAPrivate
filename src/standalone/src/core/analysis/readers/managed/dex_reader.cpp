#include "dex_reader.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <unordered_set>

namespace aida::analysis::readers::managed {
namespace {

workspace_error_t dex_managed_error(workspace_error_code_t code, std::string message,
                                     std::string phase) {
    return make_workspace_error(code, std::move(message), std::move(phase));
}

void collect_dex_references(const dex_image_t& image,
                             std::vector<std::pair<std::uint32_t, std::string>>& method_refs,
                             std::vector<std::pair<std::uint32_t, std::string>>& field_refs,
                             std::vector<std::pair<std::uint32_t, std::string>>& type_refs) {
    for (const auto& cls : image.classes) {
        for (const auto& encoded : cls.direct_methods) {
            if (encoded.method_index < image.methods.size()) {
                const auto& m = image.methods[encoded.method_index];
                method_refs.emplace_back(encoded.method_index,
                    m.class_descriptor + "->" + m.name + m.descriptor);
            }
            if (encoded.code) {
                for (const auto& instr : encoded.code->instructions) {
                    if (instr.reference_kind == dalvik_reference_kind_t::method &&
                        instr.reference_index && *instr.reference_index < image.methods.size()) {
                        const auto& ref_m = image.methods[*instr.reference_index];
                        method_refs.emplace_back(*instr.reference_index,
                            ref_m.class_descriptor + "->" + ref_m.name + ref_m.descriptor);
                    } else if (instr.reference_kind == dalvik_reference_kind_t::field &&
                               instr.reference_index && *instr.reference_index < image.fields.size()) {
                        const auto& ref_f = image.fields[*instr.reference_index];
                        field_refs.emplace_back(*instr.reference_index,
                            ref_f.class_descriptor + "." + ref_f.name);
                    } else if (instr.reference_kind == dalvik_reference_kind_t::type &&
                               instr.reference_index && *instr.reference_index < image.types.size()) {
                        type_refs.emplace_back(*instr.reference_index,
                            image.types[*instr.reference_index].descriptor);
                    }
                }
            }
        }
        for (const auto& encoded : cls.virtual_methods) {
            if (encoded.method_index < image.methods.size()) {
                const auto& m = image.methods[encoded.method_index];
                method_refs.emplace_back(encoded.method_index,
                    m.class_descriptor + "->" + m.name + m.descriptor);
            }
            if (encoded.code) {
                for (const auto& instr : encoded.code->instructions) {
                    if (instr.reference_kind == dalvik_reference_kind_t::method &&
                        instr.reference_index && *instr.reference_index < image.methods.size()) {
                        const auto& ref_m = image.methods[*instr.reference_index];
                        method_refs.emplace_back(*instr.reference_index,
                            ref_m.class_descriptor + "->" + ref_m.name + ref_m.descriptor);
                    } else if (instr.reference_kind == dalvik_reference_kind_t::field &&
                               instr.reference_index && *instr.reference_index < image.fields.size()) {
                        const auto& ref_f = image.fields[*instr.reference_index];
                        field_refs.emplace_back(*instr.reference_index,
                            ref_f.class_descriptor + "." + ref_f.name);
                    } else if (instr.reference_kind == dalvik_reference_kind_t::type &&
                               instr.reference_index && *instr.reference_index < image.types.size()) {
                        type_refs.emplace_back(*instr.reference_index,
                            image.types[*instr.reference_index].descriptor);
                    }
                }
            }
        }
    }
}

std::uint32_t read_u32_le(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 4 > data.size())
        return 0;
    return static_cast<std::uint32_t>(data[offset]) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::optional<std::uint32_t> read_uleb128(const std::vector<std::uint8_t>& data,
                                           std::size_t& cursor) {
    std::uint32_t result = 0;
    std::uint32_t shift = 0;
    while (cursor < data.size()) {
        const auto byte = data[cursor++];
        result |= static_cast<std::uint32_t>(byte & 0x7fu) << shift;
        if ((byte & 0x80u) == 0u)
            return result;
        shift += 7;
        if (shift >= 35)
            return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> read_dex_bytes(
    const byte_provider_t& provider, std::uint64_t abs_offset, std::uint64_t needed,
    std::uint64_t dex_end, const cancellation_token_t& cancel) {
    if (abs_offset >= dex_end)
        return std::nullopt;
    const auto available = dex_end - abs_offset;
    const auto to_read = (std::min)(needed, available);
    auto result = provider.read_vector(abs_offset, to_read, 64ULL * 1024ULL * 1024ULL, cancel);
    if (!result)
        return std::nullopt;
    return result.take_value();
}

void collect_annotation_item(const dex_image_t& image,
                             const byte_provider_t& provider,
                             std::uint32_t item_offset,
                             std::vector<dex_annotation_info_t>& annotations,
                             std::uint32_t max_annotations,
                             std::uint64_t dex_end,
                             const cancellation_token_t& cancel) {
    if (annotations.size() >= max_annotations || item_offset == 0)
        return;
    const auto abs = image.dex_offset + item_offset;
    auto data_opt = read_dex_bytes(provider, abs, 16, dex_end, cancel);
    if (!data_opt || data_opt->empty())
        return;
    const auto& data = *data_opt;
    dex_annotation_info_t info;
    info.visibility = data[0];
    std::size_t cursor = 1;
    auto type_idx = read_uleb128(data, cursor);
    if (!type_idx || *type_idx >= image.types.size())
        return;
    info.type_descriptor = image.types[*type_idx].descriptor;
    annotations.push_back(std::move(info));
}

void collect_annotation_set(const dex_image_t& image,
                            const byte_provider_t& provider,
                            std::uint32_t set_offset,
                            std::vector<dex_annotation_info_t>& annotations,
                            std::uint32_t max_annotations,
                            std::uint64_t dex_end,
                            const cancellation_token_t& cancel) {
    if (set_offset == 0)
        return;
    const auto abs = image.dex_offset + set_offset;
    auto header_opt = read_dex_bytes(provider, abs, 4, dex_end, cancel);
    if (!header_opt || header_opt->size() < 4)
        return;
    const auto set_size = read_u32_le(*header_opt, 0);
    if (set_size == 0 || set_size > 65536)
        return;
    const auto set_total = 4u + static_cast<std::uint64_t>(set_size) * 4u;
    auto set_data_opt = read_dex_bytes(provider, abs, set_total, dex_end, cancel);
    if (!set_data_opt)
        return;
    const auto& set_data = *set_data_opt;
    for (std::uint32_t i = 0; i < set_size; ++i) {
        if (annotations.size() >= max_annotations)
            return;
        if (cancel.stop_requested())
            return;
        const auto entry_off = read_u32_le(set_data, 4 + i * 4);
        if (entry_off == 0)
            continue;
        collect_annotation_item(image, provider, entry_off, annotations,
                                max_annotations, dex_end, cancel);
    }
}

void collect_dex_annotations(const dex_image_t& image,
                             const byte_provider_t& provider,
                             std::vector<dex_annotation_info_t>& annotations,
                             std::uint32_t max_annotations,
                             const cancellation_token_t& cancel) {
    const auto dex_end = image.dex_offset + image.header.file_size;
    for (const auto& cls : image.classes) {
        if (cancel.stop_requested())
            return;
        if (annotations.size() >= max_annotations)
            return;
        if (cls.annotations_offset == 0)
            continue;
        const auto abs = image.dex_offset + cls.annotations_offset;
        auto hdr_opt = read_dex_bytes(provider, abs, 16, dex_end, cancel);
        if (!hdr_opt || hdr_opt->size() < 16)
            continue;
        const auto& hdr = *hdr_opt;
        const auto class_annotations_off = read_u32_le(hdr, 0);
        const auto fields_size = read_u32_le(hdr, 4);
        const auto methods_size = read_u32_le(hdr, 8);
        const auto params_size = read_u32_le(hdr, 12);
        if (class_annotations_off != 0)
            collect_annotation_set(image, provider, class_annotations_off,
                                   annotations, max_annotations, dex_end, cancel);
        const auto dir_total = 16u +
            static_cast<std::uint64_t>(fields_size) * 8u +
            static_cast<std::uint64_t>(methods_size) * 8u +
            static_cast<std::uint64_t>(params_size) * 8u;
        if (dir_total <= 16u || dir_total > 4u * 1024u * 1024u)
            continue;
        auto dir_opt = read_dex_bytes(provider, abs, dir_total, dex_end, cancel);
        if (!dir_opt)
            continue;
        const auto& dir = *dir_opt;
        std::size_t cursor = 16;
        for (std::uint32_t i = 0; i < fields_size; ++i) {
            if (cursor + 8 > dir.size())
                break;
            const auto ann_off = read_u32_le(dir, cursor + 4);
            cursor += 8;
            if (ann_off != 0)
                collect_annotation_set(image, provider, ann_off,
                                       annotations, max_annotations, dex_end, cancel);
        }
        for (std::uint32_t i = 0; i < methods_size; ++i) {
            if (cursor + 8 > dir.size())
                break;
            const auto ann_off = read_u32_le(dir, cursor + 4);
            cursor += 8;
            if (ann_off != 0)
                collect_annotation_set(image, provider, ann_off,
                                       annotations, max_annotations, dex_end, cancel);
        }
    }
}

}

workspace_result_t<dex_metadata_t>
parse_dex_metadata(const byte_provider_t& provider,
                   const dex_parse_limits_t& limits,
                   const cancellation_token_t& cancel) {
    auto container_result = detect_dex_container(provider, cancel);
    if (!container_result)
        return workspace_result_t<dex_metadata_t>::failure(std::move(container_result.error()));
    auto container = container_result.take_value();

    if (container.kind == dex_container_kind_t::oat ||
        container.kind == dex_container_kind_t::vdex) {
        auto image_result = parse_dex_image(provider, limits.parser_limits, cancel);
        if (!image_result)
            return workspace_result_t<dex_metadata_t>::failure(std::move(image_result.error()));
        dex_metadata_t metadata;
        metadata.image = image_result.take_value();
        metadata.container = container;
        metadata.dex_ordinal = 0;
        collect_dex_references(metadata.image, metadata.method_references,
                               metadata.field_references, metadata.type_references);
        collect_dex_annotations(metadata.image, provider, metadata.annotations,
                                limits.max_annotations, cancel);
        return workspace_result_t<dex_metadata_t>::success(std::move(metadata));
    }

    if (container.kind == dex_container_kind_t::compact_dex) {
        return workspace_result_t<dex_metadata_t>::failure(
            dex_managed_error(workspace_error_code_t::unsupported_format,
                              "compact DEX is not supported by the managed reader",
                              "dex.parse"));
    }

    auto image_result = parse_dex_image(provider, limits.parser_limits, cancel);
    if (!image_result)
        return workspace_result_t<dex_metadata_t>::failure(std::move(image_result.error()));
    dex_metadata_t metadata;
    metadata.image = image_result.take_value();
    metadata.container = container;
    metadata.dex_ordinal = 0;
    collect_dex_references(metadata.image, metadata.method_references,
                           metadata.field_references, metadata.type_references);
    collect_dex_annotations(metadata.image, provider, metadata.annotations,
                            limits.max_annotations, cancel);
    return workspace_result_t<dex_metadata_t>::success(std::move(metadata));
}

workspace_result_t<multidex_metadata_t>
parse_multidex_metadata(const byte_provider_t& provider,
                        const dex_parse_limits_t& limits,
                        const cancellation_token_t& cancel) {
    auto container_result = detect_dex_container(provider, cancel);
    if (!container_result)
        return workspace_result_t<multidex_metadata_t>::failure(std::move(container_result.error()));
    auto container = container_result.take_value();

    multidex_metadata_t multidex;
    multidex.container = container;
    multidex.container_version = container.version;

    if (container.kind == dex_container_kind_t::dex) {
        auto single_result = parse_dex_metadata(provider, limits, cancel);
        if (!single_result)
            return workspace_result_t<multidex_metadata_t>::failure(std::move(single_result.error()));
        auto single = single_result.take_value();
        single.dex_ordinal = 0;
        multidex.dex_entries.push_back(std::move(single));
        return workspace_result_t<multidex_metadata_t>::success(std::move(multidex));
    }

    if (container.kind == dex_container_kind_t::compact_dex) {
        return workspace_result_t<multidex_metadata_t>::failure(
            dex_managed_error(workspace_error_code_t::unsupported_format,
                              "compact DEX is not supported by the managed reader",
                              "dex.multidex"));
    }

    std::uint32_t ordinal = 0;
    for (std::size_t off_idx = 0; off_idx < container.embedded_dex_offsets.size(); ++off_idx) {
        if (ordinal >= limits.max_dex_files)
            break;
        if (cancel.stop_requested())
            return workspace_result_t<multidex_metadata_t>::failure(
                dex_managed_error(workspace_error_code_t::cancelled,
                                  "Multidex parsing cancelled", "dex.multidex"));
        const auto dex_offset = container.embedded_dex_offsets[off_idx];
        if (dex_offset >= provider.size())
            continue;
        const auto end_offset = (off_idx + 1 < container.embedded_dex_offsets.size())
            ? container.embedded_dex_offsets[off_idx + 1]
            : provider.size();
        if (end_offset <= dex_offset)
            continue;
        const auto dex_length = end_offset - dex_offset;
        auto provider_ptr = std::shared_ptr<const byte_provider_t>(
            std::addressof(provider), [](const byte_provider_t*) {});
        auto subrange_result = subrange_provider_t::create(
            std::move(provider_ptr), dex_offset, dex_length,
            "dex_" + std::to_string(ordinal));
        if (!subrange_result)
            continue;
        auto subrange = subrange_result.take_value();
        auto image_result = parse_dex_image(*subrange, limits.parser_limits, cancel);
        if (!image_result)
            continue;
        dex_metadata_t entry;
        entry.image = image_result.take_value();
        entry.container = container;
        entry.dex_ordinal = ordinal;
        collect_dex_references(entry.image, entry.method_references,
                               entry.field_references, entry.type_references);
        collect_dex_annotations(entry.image, *subrange, entry.annotations,
                                limits.max_annotations, cancel);
        multidex.dex_entries.push_back(std::move(entry));
        ++ordinal;
    }

    if (multidex.dex_entries.empty()) {
        auto single_result = parse_dex_metadata(provider, limits, cancel);
        if (!single_result)
            return workspace_result_t<multidex_metadata_t>::failure(std::move(single_result.error()));
        auto single = single_result.take_value();
        single.dex_ordinal = 0;
        multidex.dex_entries.push_back(std::move(single));
    }

    return workspace_result_t<multidex_metadata_t>::success(std::move(multidex));
}

workspace_result_t<managed_artifact_t>
build_dex_artifact(const dex_metadata_t& metadata,
                   const byte_provider_t& provider,
                   const managed_reader_limits_t& limits,
                   const cancellation_token_t& cancel) {
    managed_artifact_t artifact;
    artifact.kind = managed_artifact_kind_t::dex;
    artifact.module_identity.kind = managed_artifact_kind_t::dex;
    artifact.module_identity.version = metadata.image.managed_identity.version;
    artifact.module_identity.artifact_offset = metadata.image.dex_offset;
    artifact.module_identity.artifact_size = metadata.image.header.file_size;

    auto hash_result = provider.compute_content_sha256(cancel);
    if (hash_result)
        artifact.module_identity.artifact_hash = hash_result.value();

    std::string dex_name;
    if (hash_result) {
        const auto hex = hash_result.value().to_hex();
        dex_name = "dex_" + hex.substr(0, 16);
    } else if (!metadata.image.classes.empty()) {
        dex_name = metadata.image.classes[0].class_descriptor;
    } else {
        dex_name = "dex_unknown";
    }
    artifact.module_identity.assembly_name = dex_name;
    artifact.module_identity.module_name = dex_name;

    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(metadata.image.classes.size()); ++i) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_error(workspace_error_code_t::cancelled,
                                  "DEX artifact building cancelled", "dex.build"));
        if (artifact.types.size() >= limits.max_types)
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                                  "DEX type identity count exceeds limit", "dex.build"));
        const auto& cls = metadata.image.classes[i];
        managed_type_identity_t type;
        type.type_name = cls.class_descriptor;
        type.fully_qualified_name = cls.class_descriptor;
        type.metadata_token = cls.class_type_index;
        type.access_flags = cls.access_flags;
        type.signature = cls.class_descriptor;
        if (cls.superclass_descriptor)
            type.base_type_name = *cls.superclass_descriptor;
        for (const auto iface_idx : cls.interface_type_indices) {
            if (iface_idx < metadata.image.types.size())
                type.interface_names.push_back(metadata.image.types[iface_idx].descriptor);
        }
        for (const auto& encoded : cls.direct_methods) {
            type.method_tokens.push_back(encoded.method_index);
        }
        for (const auto& encoded : cls.virtual_methods) {
            type.method_tokens.push_back(encoded.method_index);
        }
        for (const auto& encoded : cls.static_fields) {
            type.field_tokens.push_back(encoded.field_index);
        }
        for (const auto& encoded : cls.instance_fields) {
            type.field_tokens.push_back(encoded.field_index);
        }
        artifact.types.push_back(std::move(type));
    }

    for (const auto& cls : metadata.image.classes) {
        for (const auto& encoded : cls.direct_methods) {
            if (cancel.stop_requested())
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_error(workspace_error_code_t::cancelled,
                                      "DEX artifact building cancelled", "dex.build"));
            if (artifact.methods.size() >= limits.max_methods)
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_error(workspace_error_code_t::limit_exceeded,
                                      "DEX method identity count exceeds limit", "dex.build"));
            if (encoded.method_index >= metadata.image.methods.size())
                continue;
            const auto& m = metadata.image.methods[encoded.method_index];
            managed_method_identity_t method;
            method.declaring_type_name = m.class_descriptor;
            method.method_name = m.name;
            method.method_signature = m.descriptor;
            method.method_index = encoded.method_index;
            method.metadata_token = encoded.method_index;
            method.access_flags = encoded.access_flags;
            method.is_direct = encoded.is_direct;
            method.is_static = (encoded.access_flags & 0x0008u) != 0;
            method.has_body = encoded.code != nullptr;
            if (encoded.code) {
                method.code_offset = encoded.code->offset;
                method.code_size = static_cast<std::uint64_t>(encoded.code->instruction_count) * 2u;
                method.max_stack = 0;
                method.max_locals = encoded.code->registers_size;
            }
            artifact.methods.push_back(std::move(method));
        }
        for (const auto& encoded : cls.virtual_methods) {
            if (cancel.stop_requested())
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_error(workspace_error_code_t::cancelled,
                                      "DEX artifact building cancelled", "dex.build"));
            if (artifact.methods.size() >= limits.max_methods)
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_error(workspace_error_code_t::limit_exceeded,
                                      "DEX method identity count exceeds limit", "dex.build"));
            if (encoded.method_index >= metadata.image.methods.size())
                continue;
            const auto& m = metadata.image.methods[encoded.method_index];
            managed_method_identity_t method;
            method.declaring_type_name = m.class_descriptor;
            method.method_name = m.name;
            method.method_signature = m.descriptor;
            method.method_index = encoded.method_index;
            method.metadata_token = encoded.method_index;
            method.access_flags = encoded.access_flags;
            method.is_direct = encoded.is_direct;
            method.is_static = (encoded.access_flags & 0x0008u) != 0;
            method.is_virtual = !encoded.is_direct;
            method.has_body = encoded.code != nullptr;
            if (encoded.code) {
                method.code_offset = encoded.code->offset;
                method.code_size = static_cast<std::uint64_t>(encoded.code->instruction_count) * 2u;
                method.max_stack = 0;
                method.max_locals = encoded.code->registers_size;
            }
            artifact.methods.push_back(std::move(method));
        }
    }

    for (const auto& cls : metadata.image.classes) {
        for (const auto& encoded : cls.static_fields) {
            if (cancel.stop_requested())
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_error(workspace_error_code_t::cancelled,
                                      "DEX artifact building cancelled", "dex.build"));
            if (artifact.fields.size() >= limits.max_fields)
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_error(workspace_error_code_t::limit_exceeded,
                                      "DEX field identity count exceeds limit", "dex.build"));
            if (encoded.field_index >= metadata.image.fields.size())
                continue;
            const auto& f = metadata.image.fields[encoded.field_index];
            managed_field_identity_t field;
            field.declaring_type_name = f.class_descriptor;
            field.field_name = f.name;
            field.field_signature = f.type_descriptor;
            field.field_index = encoded.field_index;
            field.metadata_token = encoded.field_index;
            field.access_flags = encoded.access_flags;
            field.is_static = encoded.is_static;
            artifact.fields.push_back(std::move(field));
        }
        for (const auto& encoded : cls.instance_fields) {
            if (artifact.fields.size() >= limits.max_fields)
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_error(workspace_error_code_t::limit_exceeded,
                                      "DEX field identity count exceeds limit", "dex.build"));
            if (encoded.field_index >= metadata.image.fields.size())
                continue;
            const auto& f = metadata.image.fields[encoded.field_index];
            managed_field_identity_t field;
            field.declaring_type_name = f.class_descriptor;
            field.field_name = f.name;
            field.field_signature = f.type_descriptor;
            field.field_index = encoded.field_index;
            field.metadata_token = encoded.field_index;
            field.access_flags = encoded.access_flags;
            field.is_static = false;
            artifact.fields.push_back(std::move(field));
        }
    }

    for (const auto& [idx, ref_str] : metadata.method_references) {
        if (artifact.member_references.size() >= limits.max_member_references)
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                                  "DEX member reference count exceeds limit", "dex.build"));
        managed_member_reference_t ref;
        ref.kind = managed_reference_kind_t::method_reference;
        ref.member_name = ref_str;
        ref.reference_token = idx;
        artifact.member_references.push_back(std::move(ref));
    }
    for (const auto& [idx, ref_str] : metadata.field_references) {
        if (artifact.member_references.size() >= limits.max_member_references)
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                                  "DEX member reference count exceeds limit", "dex.build"));
        managed_member_reference_t ref;
        ref.kind = managed_reference_kind_t::field_reference;
        ref.member_name = ref_str;
        ref.reference_token = idx;
        artifact.member_references.push_back(std::move(ref));
    }
    for (const auto& [idx, ref_str] : metadata.type_references) {
        if (artifact.member_references.size() >= limits.max_member_references)
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                                  "DEX member reference count exceeds limit", "dex.build"));
        managed_member_reference_t ref;
        ref.kind = managed_reference_kind_t::type_reference;
        ref.member_name = ref_str;
        ref.reference_token = idx;
        artifact.member_references.push_back(std::move(ref));
    }

    for (const auto& cls : metadata.image.classes) {
        for (const auto& encoded : cls.direct_methods) {
            if (encoded.code) {
                managed_code_range_t range;
                range.offset = encoded.code->offset;
                range.size = static_cast<std::uint64_t>(encoded.code->instruction_count) * 2u;
                range.max_stack = 0;
                range.max_locals = encoded.code->registers_size;
                range.method_token = encoded.method_index;
                artifact.code_ranges.push_back(std::move(range));
                artifact.total_code_bytes += static_cast<std::uint64_t>(encoded.code->instruction_count) * 2u;
                if (artifact.total_code_bytes > limits.max_code_bytes)
                    return workspace_result_t<managed_artifact_t>::failure(
                        dex_managed_error(workspace_error_code_t::limit_exceeded,
                                          "DEX cumulative code bytes exceed limit", "dex.build"));
                for (const auto& try_item : encoded.code->tries) {
                    if (artifact.exception_regions.size() >= limits.max_exception_regions)
                        return workspace_result_t<managed_artifact_t>::failure(
                            dex_managed_error(workspace_error_code_t::limit_exceeded,
                                              "DEX exception region count exceeds limit", "dex.build"));
                    managed_exception_region_t region;
                    region.start_offset = try_item.start_address * 2u;
                    region.end_offset = (try_item.start_address + try_item.instruction_count) * 2u;
                    region.method_token = encoded.method_index;
                    const auto handler_it = std::find_if(
                        encoded.code->catch_handlers.begin(),
                        encoded.code->catch_handlers.end(),
                        [&](const dex_catch_handler_t& h) {
                            return h.relative_offset == try_item.handler_offset;
                        });
                    if (handler_it != encoded.code->catch_handlers.end()) {
                        if (handler_it->catch_all_address) {
                            region.is_catch_all = true;
                            region.handler_offset = *handler_it->catch_all_address * 2u;
                        }
                        if (!handler_it->typed_handlers.empty()) {
                            region.handler_offset = handler_it->typed_handlers[0].second * 2u;
                            if (handler_it->typed_handlers[0].first < metadata.image.types.size())
                                region.catch_type_name = metadata.image.types[handler_it->typed_handlers[0].first].descriptor;
                        }
                    }
                    artifact.exception_regions.push_back(std::move(region));
                }
            }
        }
        for (const auto& encoded : cls.virtual_methods) {
            if (encoded.code) {
                managed_code_range_t range;
                range.offset = encoded.code->offset;
                range.size = static_cast<std::uint64_t>(encoded.code->instruction_count) * 2u;
                range.max_stack = 0;
                range.max_locals = encoded.code->registers_size;
                range.method_token = encoded.method_index;
                artifact.code_ranges.push_back(std::move(range));
                artifact.total_code_bytes += static_cast<std::uint64_t>(encoded.code->instruction_count) * 2u;
                for (const auto& try_item : encoded.code->tries) {
                    if (artifact.exception_regions.size() >= limits.max_exception_regions)
                        return workspace_result_t<managed_artifact_t>::failure(
                            dex_managed_error(workspace_error_code_t::limit_exceeded,
                                              "DEX exception region count exceeds limit", "dex.build"));
                    managed_exception_region_t region;
                    region.start_offset = try_item.start_address * 2u;
                    region.end_offset = (try_item.start_address + try_item.instruction_count) * 2u;
                    region.method_token = encoded.method_index;
                    const auto handler_it = std::find_if(
                        encoded.code->catch_handlers.begin(),
                        encoded.code->catch_handlers.end(),
                        [&](const dex_catch_handler_t& h) {
                            return h.relative_offset == try_item.handler_offset;
                        });
                    if (handler_it != encoded.code->catch_handlers.end()) {
                        if (handler_it->catch_all_address) {
                            region.is_catch_all = true;
                            region.handler_offset = *handler_it->catch_all_address * 2u;
                        }
                        if (!handler_it->typed_handlers.empty()) {
                            region.handler_offset = handler_it->typed_handlers[0].second * 2u;
                            if (handler_it->typed_handlers[0].first < metadata.image.types.size())
                                region.catch_type_name = metadata.image.types[handler_it->typed_handlers[0].first].descriptor;
                        }
                    }
                    artifact.exception_regions.push_back(std::move(region));
                }
            }
        }
    }

    for (const auto& ann : metadata.annotations) {
        if (artifact.annotations.size() >= limits.max_annotations)
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                                  "DEX annotation count exceeds limit", "dex.build"));
        managed_annotation_t annotation;
        annotation.annotation_type = ann.type_descriptor;
        annotation.is_runtime_visible = (ann.visibility == 0x01u || ann.visibility == 0x02u);
        annotation.is_runtime_invisible = (ann.visibility == 0x00u);
        artifact.annotations.push_back(std::move(annotation));
    }

    std::unordered_set<std::string> seen_method_keys;
    for (const auto& method : artifact.methods) {
        const auto key = method.declaring_type_name + "->" + method.method_name + method.method_signature;
        if (!seen_method_keys.insert(key).second) {
            managed_duplicate_identity_t dup;
            dup.identity_key = key;
            dup.description = "Duplicate DEX method identity";
            artifact.duplicate_identities.push_back(std::move(dup));
        }
    }

    std::unordered_set<std::uint32_t> seen_type_indices;
    for (const auto& type : artifact.types) {
        if (!seen_type_indices.insert(type.metadata_token).second) {
            managed_duplicate_identity_t dup;
            dup.identity_key = std::to_string(type.metadata_token);
            dup.description = "Duplicate DEX type index";
            artifact.duplicate_identities.push_back(std::move(dup));
        }
    }

    artifact.normalized = metadata.image.normalized;
    artifact.normalized.format_name = "dex:" + metadata.image.managed_identity.version;

    return workspace_result_t<managed_artifact_t>::success(std::move(artifact));
}

workspace_result_t<managed_multidex_t>
build_multidex_artifact(const multidex_metadata_t& metadata,
                        const byte_provider_t& provider,
                        const managed_reader_limits_t& limits,
                        const cancellation_token_t& cancel) {
    managed_multidex_t multidex;
    multidex.container_version = metadata.container_version;
    multidex.container_kind = managed_artifact_kind_t::multidex_container;
    multidex.embedded_offsets = metadata.container.embedded_dex_offsets;

    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(metadata.dex_entries.size()); ++i) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_multidex_t>::failure(
                dex_managed_error(workspace_error_code_t::cancelled,
                                  "Multidex artifact building cancelled", "dex.multidex"));
        auto artifact_result = build_dex_artifact(metadata.dex_entries[i], provider, limits, cancel);
        if (!artifact_result)
            return workspace_result_t<managed_multidex_t>::failure(std::move(artifact_result.error()));
        auto artifact = artifact_result.take_value();
        if (metadata.container.kind == dex_container_kind_t::oat)
            artifact.kind = managed_artifact_kind_t::oat;
        else if (metadata.container.kind == dex_container_kind_t::vdex)
            artifact.kind = managed_artifact_kind_t::vdex;
        for (const auto& cls_desc : artifact.types) {
            multidex.dex_class_descriptors.push_back(cls_desc.fully_qualified_name);
        }
        multidex.artifacts.push_back(std::move(artifact));
    }

    return workspace_result_t<managed_multidex_t>::success(std::move(multidex));
}

}
