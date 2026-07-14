#include "classfile_reader.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <unordered_set>

namespace aida::analysis::readers::managed {
namespace {

workspace_error_t classfile_managed_error(workspace_error_code_t code, std::string message,
                                           std::string phase) {
    return make_workspace_error(code, std::move(message), std::move(phase));
}

workspace_error_t classfile_managed_stop_error(
    const cancellation_token_t& cancel,
    std::string message,
    std::string phase) {
    auto error = classfile_managed_error(
        cancel.deadline_exceeded()
            ? workspace_error_code_t::deadline_exceeded
            : workspace_error_code_t::cancelled,
        std::move(message), std::move(phase));
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

std::string jvm_internal_name_from_class_ref(const classfile_image_t& image, std::uint16_t index) {
    if (index == 0 || index >= image.constant_pool.size())
        return {};
    const auto& entry = image.constant_pool[index];
    if (entry.tag != jvm_constant_tag_t::class_ref || entry.ref_index1 == 0 ||
        entry.ref_index1 >= image.constant_pool.size())
        return {};
    const auto& utf8 = image.constant_pool[entry.ref_index1];
    if (utf8.tag != jvm_constant_tag_t::utf8)
        return {};
    return utf8.utf8_value;
}

std::string jvm_name_and_type_name(const classfile_image_t& image, std::uint16_t index) {
    if (index == 0 || index >= image.constant_pool.size())
        return {};
    const auto& nat = image.constant_pool[index];
    if (nat.tag != jvm_constant_tag_t::name_and_type || nat.ref_index1 == 0 ||
        nat.ref_index1 >= image.constant_pool.size())
        return {};
    const auto& name = image.constant_pool[nat.ref_index1];
    if (name.tag != jvm_constant_tag_t::utf8)
        return {};
    return name.utf8_value;
}

std::string jvm_name_and_type_descriptor(const classfile_image_t& image, std::uint16_t index) {
    if (index == 0 || index >= image.constant_pool.size())
        return {};
    const auto& nat = image.constant_pool[index];
    if (nat.tag != jvm_constant_tag_t::name_and_type || nat.ref_index2 == 0 ||
        nat.ref_index2 >= image.constant_pool.size())
        return {};
    const auto& desc = image.constant_pool[nat.ref_index2];
    if (desc.tag != jvm_constant_tag_t::utf8)
        return {};
    return desc.utf8_value;
}

std::string jvm_member_ref_class(const classfile_image_t& image, std::uint16_t index) {
    if (index == 0 || index >= image.constant_pool.size())
        return {};
    const auto& ref = image.constant_pool[index];
    if (ref.ref_index1 == 0 || ref.ref_index1 >= image.constant_pool.size())
        return {};
    return jvm_internal_name_from_class_ref(image, ref.ref_index1);
}

std::string jvm_member_ref_name(const classfile_image_t& image, std::uint16_t index) {
    if (index == 0 || index >= image.constant_pool.size())
        return {};
    const auto& ref = image.constant_pool[index];
    return jvm_name_and_type_name(image, ref.ref_index2);
}

std::string jvm_member_ref_descriptor(const classfile_image_t& image, std::uint16_t index) {
    if (index == 0 || index >= image.constant_pool.size())
        return {};
    const auto& ref = image.constant_pool[index];
    return jvm_name_and_type_descriptor(image, ref.ref_index2);
}

std::string jvm_resolve_utf8(const classfile_image_t& image, std::uint16_t index) {
    if (index == 0 || index >= image.constant_pool.size())
        return {};
    const auto& entry = image.constant_pool[index];
    if (entry.tag != jvm_constant_tag_t::utf8)
        return {};
    return entry.utf8_value;
}

bool skip_element_value(const std::vector<std::uint8_t>& data, std::size_t& cursor);

bool skip_annotation(const std::vector<std::uint8_t>& data, std::size_t& cursor) {
    if (cursor + 4 > data.size())
        return false;
    cursor += 2;
    const auto num_pairs = (static_cast<std::uint16_t>(data[cursor]) << 8) |
                           static_cast<std::uint16_t>(data[cursor + 1]);
    cursor += 2;
    for (std::uint16_t i = 0; i < num_pairs; ++i) {
        if (cursor + 2 > data.size())
            return false;
        cursor += 2;
        if (!skip_element_value(data, cursor))
            return false;
    }
    return true;
}

bool skip_element_value(const std::vector<std::uint8_t>& data, std::size_t& cursor) {
    if (cursor >= data.size())
        return false;
    const auto tag = data[cursor++];
    switch (tag) {
        case 'B': case 'C': case 'D': case 'F':
        case 'I': case 'J': case 'S': case 'Z':
        case 's':
            if (cursor + 2 > data.size()) return false;
            cursor += 2;
            return true;
        case 'e':
            if (cursor + 4 > data.size()) return false;
            cursor += 4;
            return true;
        case 'c':
            if (cursor + 2 > data.size()) return false;
            cursor += 2;
            return true;
        case '@':
            return skip_annotation(data, cursor);
        case '[': {
            if (cursor + 2 > data.size()) return false;
            const auto array_count = (static_cast<std::uint16_t>(data[cursor]) << 8) |
                                     static_cast<std::uint16_t>(data[cursor + 1]);
            cursor += 2;
            for (std::uint16_t i = 0; i < array_count; ++i) {
                if (!skip_element_value(data, cursor))
                    return false;
            }
            return true;
        }
        default:
            return false;
    }
}

void extract_annotations_from_attribute(const classfile_image_t& image,
                                        const jvm_attribute_t& attr,
                                        std::vector<classfile_annotation_info_t>& annotations) {
    if (attr.name != "RuntimeVisibleAnnotations" && attr.name != "RuntimeInvisibleAnnotations")
        return;
    if (attr.raw_data.size() < 2)
        return;

    const bool is_runtime_visible = (attr.name == "RuntimeVisibleAnnotations");

    const auto count = (static_cast<std::uint16_t>(attr.raw_data[0]) << 8) |
                       static_cast<std::uint16_t>(attr.raw_data[1]);
    std::size_t cursor = 2;
    for (std::uint16_t i = 0; i < count; ++i) {
        if (cursor + 2 > attr.raw_data.size())
            return;
        const auto type_index = (static_cast<std::uint16_t>(attr.raw_data[cursor]) << 8) |
                                static_cast<std::uint16_t>(attr.raw_data[cursor + 1]);
        cursor += 2;

        const auto type_desc = jvm_resolve_utf8(image, type_index);
        if (!type_desc.empty()) {
            classfile_annotation_info_t info;
            info.type_descriptor = type_desc;
            info.is_runtime_visible = is_runtime_visible;
            annotations.push_back(std::move(info));
        }

        if (cursor + 2 > attr.raw_data.size())
            return;
        const auto num_pairs = (static_cast<std::uint16_t>(attr.raw_data[cursor]) << 8) |
                               static_cast<std::uint16_t>(attr.raw_data[cursor + 1]);
        cursor += 2;
        for (std::uint16_t j = 0; j < num_pairs; ++j) {
            if (cursor + 2 > attr.raw_data.size())
                return;
            cursor += 2;
            if (!skip_element_value(attr.raw_data, cursor))
                return;
        }
    }
}

}

workspace_result_t<classfile_metadata_t>
parse_classfile_metadata(const byte_provider_t& provider,
                         const classfile_parse_limits_t& limits,
                         const cancellation_token_t& cancel) {
    auto image_result = parse_classfile_image(provider, limits.parser_limits, cancel);
    if (!image_result)
        return workspace_result_t<classfile_metadata_t>::failure(std::move(image_result.error()));
    classfile_metadata_t metadata;
    metadata.image = image_result.take_value();

    for (const auto& attr : metadata.image.attributes) {
        extract_annotations_from_attribute(metadata.image, attr, metadata.annotations);
    }
    for (const auto& method : metadata.image.methods) {
        for (const auto& attr : method.attributes) {
            extract_annotations_from_attribute(metadata.image, attr, metadata.annotations);
        }
    }
    for (const auto& field : metadata.image.fields) {
        for (const auto& attr : field.attributes) {
            extract_annotations_from_attribute(metadata.image, attr, metadata.annotations);
        }
    }

    for (std::uint16_t i = 1; i < static_cast<std::uint16_t>(metadata.image.constant_pool.size()); ++i) {
        const auto& entry = metadata.image.constant_pool[i];
        if (entry.tag == jvm_constant_tag_t::fieldref ||
            entry.tag == jvm_constant_tag_t::methodref ||
            entry.tag == jvm_constant_tag_t::interface_methodref) {
            metadata.member_reference_cp_indices.push_back(i);
            const auto class_name = jvm_member_ref_class(metadata.image, i);
            const auto member_name = jvm_member_ref_name(metadata.image, i);
            metadata.constant_pool_refs.emplace_back(i, class_name + "." + member_name);
        }
    }

    for (const auto& iface_index : metadata.image.interfaces) {
        metadata.interface_names_resolved.push_back(
            jvm_internal_name_from_class_ref(metadata.image, iface_index));
    }

    for (const auto& method : metadata.image.methods) {
        if (method.code) {
            for (const auto& exc : method.code->exceptions) {
                metadata.all_exception_regions.push_back(exc);
            }
            for (const auto& instr : method.code->instructions) {
                metadata.all_instructions.push_back(instr);
            }
        }
    }

    return workspace_result_t<classfile_metadata_t>::success(std::move(metadata));
}

workspace_result_t<managed_artifact_t>
build_classfile_artifact(const classfile_metadata_t& metadata,
                         const byte_provider_t& provider,
                         const managed_reader_limits_t& limits,
                         const cancellation_token_t& cancel) {
    managed_artifact_t artifact;
    artifact.kind = managed_artifact_kind_t::java_classfile;
    artifact.module_identity.kind = managed_artifact_kind_t::java_classfile;
    artifact.module_identity.assembly_name = metadata.image.this_class_name;
    artifact.module_identity.module_name = metadata.image.this_class_name;
    artifact.module_identity.version = std::to_string(metadata.image.major_version);
    artifact.module_identity.artifact_size = provider.size();
    artifact.module_identity.artifact_offset = 0;

    auto hash_result = provider.compute_content_sha256(cancel);
    if (!hash_result)
        return workspace_result_t<managed_artifact_t>::failure(hash_result.error());
    artifact.module_identity.artifact_hash = hash_result.take_value();

    managed_type_identity_t type;
    type.type_name = metadata.image.this_class_name;
    type.fully_qualified_name = metadata.image.this_class_name;
    type.metadata_token = metadata.image.this_class;
    type.access_flags = metadata.image.access_flags;
    type.is_interface = metadata.image.is_interface;
    type.is_abstract = metadata.image.is_abstract;
    type.is_final = metadata.image.is_final;
    type.is_annotation = metadata.image.is_annotation;
    type.is_enum = metadata.image.is_enum;
    type.signature = metadata.image.signature.value_or("");
    type.base_type_name = metadata.image.super_class_name.empty()
        ? std::optional<std::string>{} : std::optional<std::string>(metadata.image.super_class_name);
    type.interface_names = metadata.interface_names_resolved;
    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(metadata.image.methods.size()); ++i) {
        type.method_tokens.push_back(i + 1);
    }
    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(metadata.image.fields.size()); ++i) {
        type.field_tokens.push_back(i + 1);
    }
    artifact.types.push_back(std::move(type));

    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(metadata.image.methods.size()); ++i) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                classfile_managed_stop_error(cancel,
                    "Classfile artifact building cancelled", "classfile.build"));
        if (artifact.methods.size() >= limits.max_methods)
            return workspace_result_t<managed_artifact_t>::failure(
                classfile_managed_error(workspace_error_code_t::limit_exceeded,
                                        "JVM method identity count exceeds limit", "classfile.build"));
        const auto& m = metadata.image.methods[i];
        managed_method_identity_t method;
        method.declaring_type_name = metadata.image.this_class_name;
        method.method_name = m.name;
        method.method_signature = m.descriptor;
        method.method_index = i;
        method.metadata_token = i + 1;
        method.access_flags = m.access_flags;
        method.is_static = m.is_static;
        method.is_abstract = m.is_abstract;
        method.is_native = m.is_native;
        method.has_body = m.code.has_value();
        if (m.code) {
            method.code_offset = m.code->code_offset;
            method.code_size = m.code->code_length;
            method.max_stack = m.code->max_stack;
            method.max_locals = m.code->max_locals;
        }
        for (const auto& attr : m.attributes) {
            if (attr.name == "Signature") {
                managed_signature_t sig;
                sig.raw_signature = std::string(attr.raw_data.begin(), attr.raw_data.end());
                sig.method_token = i + 1;
                sig.artifact_kind = managed_artifact_kind_t::java_classfile;
                artifact.signatures.push_back(std::move(sig));
            }
        }
        artifact.methods.push_back(std::move(method));
    }

    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(metadata.image.fields.size()); ++i) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                classfile_managed_stop_error(cancel,
                    "Classfile artifact building cancelled", "classfile.build"));
        if (artifact.fields.size() >= limits.max_fields)
            return workspace_result_t<managed_artifact_t>::failure(
                classfile_managed_error(workspace_error_code_t::limit_exceeded,
                                        "JVM field identity count exceeds limit", "classfile.build"));
        const auto& f = metadata.image.fields[i];
        managed_field_identity_t field;
        field.declaring_type_name = metadata.image.this_class_name;
        field.field_name = f.name;
        field.field_signature = f.descriptor;
        field.field_index = i;
        field.metadata_token = i + 1;
        field.access_flags = f.access_flags;
        field.is_static = f.is_static;
        artifact.fields.push_back(std::move(field));
    }

    for (const auto& cp_index : metadata.member_reference_cp_indices) {
        if (artifact.member_references.size() >= limits.max_member_references)
            return workspace_result_t<managed_artifact_t>::failure(
                classfile_managed_error(workspace_error_code_t::limit_exceeded,
                                        "JVM member reference count exceeds limit", "classfile.build"));
        const auto& entry = metadata.image.constant_pool[cp_index];
        managed_member_reference_t ref;
        ref.declaring_type_name = jvm_member_ref_class(metadata.image, cp_index);
        ref.member_name = jvm_member_ref_name(metadata.image, cp_index);
        ref.member_signature = jvm_member_ref_descriptor(metadata.image, cp_index);
        ref.reference_token = cp_index;
        if (entry.tag == jvm_constant_tag_t::fieldref)
            ref.kind = managed_reference_kind_t::field_reference;
        else
            ref.kind = managed_reference_kind_t::method_reference;
        artifact.member_references.push_back(std::move(ref));
    }

    for (const auto& m : metadata.image.methods) {
        if (m.code) {
            managed_code_range_t range;
            range.offset = m.code->code_offset;
            range.size = m.code->code_length;
            range.max_stack = m.code->max_stack;
            range.max_locals = m.code->max_locals;
            range.code_bytes = m.code->code;
            artifact.code_ranges.push_back(std::move(range));
            artifact.total_code_bytes += m.code->code_length;
            if (artifact.total_code_bytes > limits.max_code_bytes)
                return workspace_result_t<managed_artifact_t>::failure(
                    classfile_managed_error(workspace_error_code_t::limit_exceeded,
                                            "JVM cumulative code bytes exceed limit", "classfile.build"));
            for (const auto& exc : m.code->exceptions) {
                if (artifact.exception_regions.size() >= limits.max_exception_regions)
                    return workspace_result_t<managed_artifact_t>::failure(
                        classfile_managed_error(workspace_error_code_t::limit_exceeded,
                                                "JVM exception region count exceeds limit", "classfile.build"));
                managed_exception_region_t region;
                region.start_offset = exc.start_pc;
                region.end_offset = exc.end_pc;
                region.handler_offset = exc.handler_pc;
                region.catch_type_name = exc.catch_class_name;
                region.is_catch_all = (exc.catch_type == 0);
                artifact.exception_regions.push_back(std::move(region));
            }
        }
    }

    for (const auto& ann : metadata.annotations) {
        if (artifact.annotations.size() >= limits.max_annotations)
            return workspace_result_t<managed_artifact_t>::failure(
                classfile_managed_error(workspace_error_code_t::limit_exceeded,
                                        "JVM annotation count exceeds limit", "classfile.build"));
        managed_annotation_t annotation;
        annotation.annotation_type = ann.type_descriptor;
        annotation.is_runtime_visible = ann.is_runtime_visible;
        annotation.is_runtime_invisible = !ann.is_runtime_visible;
        artifact.annotations.push_back(std::move(annotation));
    }

    for (const auto& inner : metadata.image.inner_classes) {
        if (!inner.inner_class_name.empty()) {
            managed_type_identity_t inner_type;
            inner_type.type_name = inner.inner_class_name;
            inner_type.fully_qualified_name = inner.inner_class_name;
            inner_type.metadata_token = inner.inner_class_info_index;
            inner_type.access_flags = inner.access_flags;
            inner_type.is_nested = true;
            inner_type.declaring_type_name = inner.outer_class_name;
            artifact.types.push_back(std::move(inner_type));
        }
    }

    std::unordered_set<std::string> seen_method_keys;
    for (const auto& method : artifact.methods) {
        const auto key = method.declaring_type_name + "." + method.method_name + method.method_signature;
        if (!seen_method_keys.insert(key).second) {
            managed_duplicate_identity_t dup;
            dup.identity_key = key;
            dup.description = "Duplicate JVM method identity";
            artifact.duplicate_identities.push_back(std::move(dup));
        }
    }

    artifact.normalized.format = format_id_t::classfile;
    artifact.normalized.architecture = architecture_id_t::jvm_bytecode;
    artifact.normalized.architecture_mode = architecture_mode_t::jvm;
    artifact.normalized.abi = abi_id_t::jvm;
    artifact.normalized.endian = endian_t::big;
    artifact.normalized.address_width_bits = 32;
    artifact.normalized.image_base = 0;
    artifact.normalized.image_size = provider.size();
    artifact.normalized.header_size = 10;
    artifact.normalized.format_name = "classfile:" + std::to_string(metadata.image.major_version);
    artifact.normalized.provider_source = provider.identity().normalized_source;
    artifact.normalized.provider_size = provider.size();

    return workspace_result_t<managed_artifact_t>::success(std::move(artifact));
}

}
