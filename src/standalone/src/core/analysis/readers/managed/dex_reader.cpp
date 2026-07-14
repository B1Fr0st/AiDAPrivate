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

workspace_error_t dex_managed_stop_error(
    const cancellation_token_t& cancel,
    std::string message,
    std::string phase) {
    auto error = dex_managed_error(
        cancel.deadline_exceeded()
            ? workspace_error_code_t::deadline_exceeded
            : workspace_error_code_t::cancelled,
        std::move(message), std::move(phase));
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

workspace_result_t<void> collect_dex_references(
    const dex_image_t& image,
    std::vector<std::pair<std::uint32_t, std::string>>& method_refs,
    std::vector<std::pair<std::uint32_t, std::string>>& field_refs,
    std::vector<std::pair<std::uint32_t, std::string>>& type_refs,
    std::uint32_t maximum_references,
    const cancellation_token_t& cancel) {
    std::uint64_t visited = 0;
    const auto append_allowed = [&]() {
        return method_refs.size() + field_refs.size() + type_refs.size() <
            maximum_references;
    };
    const auto collect_methods = [&](const std::vector<dex_encoded_method_t>& methods)
        -> workspace_result_t<void> {
        for (const auto& encoded : methods) {
            if ((visited++ & 1023U) == 0 && cancel.stop_requested())
                return workspace_result_t<void>::failure(
                    dex_managed_stop_error(cancel,
                        "DEX reference collection cancelled",
                        "dex.references"));
            if (encoded.method_index < image.methods.size()) {
                if (!append_allowed())
                    return workspace_result_t<void>::failure(
                        dex_managed_error(workspace_error_code_t::limit_exceeded,
                            "DEX member reference count exceeds limit",
                            "dex.references"));
                const auto& m = image.methods[encoded.method_index];
                method_refs.emplace_back(encoded.method_index,
                    m.class_descriptor + "->" + m.name + m.descriptor);
            }
            if (encoded.code) {
                for (const auto& instr : encoded.code->instructions) {
                    if ((visited++ & 1023U) == 0 && cancel.stop_requested())
                        return workspace_result_t<void>::failure(
                            dex_managed_stop_error(cancel,
                                "DEX reference collection cancelled",
                                "dex.references"));
                    if (instr.reference_kind == dalvik_reference_kind_t::method &&
                        instr.reference_index && *instr.reference_index < image.methods.size()) {
                        if (!append_allowed())
                            return workspace_result_t<void>::failure(
                                dex_managed_error(workspace_error_code_t::limit_exceeded,
                                    "DEX member reference count exceeds limit",
                                    "dex.references"));
                        const auto& ref_m = image.methods[*instr.reference_index];
                        method_refs.emplace_back(*instr.reference_index,
                            ref_m.class_descriptor + "->" + ref_m.name + ref_m.descriptor);
                    } else if (instr.reference_kind == dalvik_reference_kind_t::field &&
                               instr.reference_index && *instr.reference_index < image.fields.size()) {
                        if (!append_allowed())
                            return workspace_result_t<void>::failure(
                                dex_managed_error(workspace_error_code_t::limit_exceeded,
                                    "DEX member reference count exceeds limit",
                                    "dex.references"));
                        const auto& ref_f = image.fields[*instr.reference_index];
                        field_refs.emplace_back(*instr.reference_index,
                            ref_f.class_descriptor + "." + ref_f.name);
                    } else if (instr.reference_kind == dalvik_reference_kind_t::type &&
                               instr.reference_index && *instr.reference_index < image.types.size()) {
                        if (!append_allowed())
                            return workspace_result_t<void>::failure(
                                dex_managed_error(workspace_error_code_t::limit_exceeded,
                                    "DEX member reference count exceeds limit",
                                    "dex.references"));
                        type_refs.emplace_back(*instr.reference_index,
                            image.types[*instr.reference_index].descriptor);
                    }
                }
            }
        }
        return workspace_result_t<void>::success();
    };
    for (const auto& cls : image.classes) {
        auto direct = collect_methods(cls.direct_methods);
        if (!direct)
            return direct;
        auto virtual_methods = collect_methods(cls.virtual_methods);
        if (!virtual_methods)
            return virtual_methods;
    }
    return workspace_result_t<void>::success();
}

std::uint32_t read_u32_le(const std::vector<std::uint8_t>& data, std::size_t offset) {
    if (offset + 4 > data.size())
        return 0;
    return static_cast<std::uint32_t>(data[offset]) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>
scan_runtime_dex_members(const byte_provider_t& provider,
                         const dex_parse_limits_t& limits,
                         const cancellation_token_t& cancel) {
    constexpr std::uint64_t standard_header_size = 112;
    constexpr std::uint64_t compact_header_size = 136;
    const auto chunk_size = (std::min<std::uint64_t>)(
        limits.parser_limits.max_container_scan_bytes, 4ULL << 20);
    if (chunk_size < 8 || limits.max_dex_files == 0)
        return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
            dex_managed_error(workspace_error_code_t::invalid_argument,
                "runtime DEX scan limits are invalid", "dex.multidex.scan"));
    std::vector<std::pair<std::uint64_t, std::uint64_t>> members;
    std::uint64_t offset = 0;
    std::uint64_t covered_until = 0;
    while (offset < provider.size()) {
        if (cancel.stop_requested()) {
            auto error = dex_managed_error(
                cancel.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "runtime DEX scan cancelled", "dex.multidex.scan");
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                std::move(error));
        }
        const auto read_size = (std::min<std::uint64_t>)(
            chunk_size, provider.size() - offset);
        auto bytes = provider.read_vector(offset, read_size, chunk_size, cancel);
        if (!bytes)
            return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                bytes.error());
        const auto& scan = bytes.value();
        for (std::size_t index = 0; index + 8 <= scan.size(); ++index) {
            if ((index & 0xfffU) == 0 && cancel.stop_requested()) {
                auto error = dex_managed_error(
                    cancel.deadline_exceeded()
                        ? workspace_error_code_t::deadline_exceeded
                        : workspace_error_code_t::cancelled,
                    "runtime DEX scan cancelled", "dex.multidex.scan");
                error.deadline = cancel.deadline_exceeded();
                error.cancellation = !error.deadline;
                return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                    std::move(error));
            }
            const auto standard =
                scan[index] == 'd' && scan[index + 1] == 'e' &&
                scan[index + 2] == 'x' && scan[index + 3] == '\n' &&
                scan[index + 4] >= '0' && scan[index + 4] <= '9' &&
                scan[index + 5] >= '0' && scan[index + 5] <= '9' &&
                scan[index + 6] >= '0' && scan[index + 6] <= '9' &&
                scan[index + 7] == 0;
            const auto compact =
                scan[index] == 'c' && scan[index + 1] == 'd' &&
                scan[index + 2] == 'e' && scan[index + 3] == 'x' &&
                scan[index + 4] == '0' && scan[index + 5] == '0' &&
                scan[index + 6] == '1' && scan[index + 7] == 0;
            if (!standard && !compact)
                continue;
            const auto candidate_offset = offset + index;
            if (candidate_offset < covered_until)
                continue;
            const auto header_size = compact ? compact_header_size : standard_header_size;
            if (candidate_offset > provider.size() ||
                provider.size() - candidate_offset < header_size)
                continue;
            auto header = provider.read_vector(
                candidate_offset, header_size, header_size, cancel);
            if (!header)
                return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                    header.error());
            const auto file_size = read_u32_le(header.value(), 32);
            const auto declared_header_size = read_u32_le(header.value(), 36);
            const auto endian_tag = read_u32_le(header.value(), 40);
            if (declared_header_size != header_size || endian_tag != 0x12345678U)
                continue;
            std::uint64_t member_size = file_size;
            if (compact) {
                const auto data_size = read_u32_le(header.value(), 104);
                const auto data_offset = read_u32_le(header.value(), 108);
                member_size = static_cast<std::uint64_t>(data_offset) + data_size;
                if (data_size == 0 || data_offset < file_size ||
                    member_size < file_size)
                    return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                        dex_managed_error(workspace_error_code_t::malformed_image,
                            "embedded compact DEX shared-data span is invalid",
                            "dex.multidex.scan"));
            }
            if (file_size < header_size ||
                member_size > provider.size() - candidate_offset)
                return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                    dex_managed_error(workspace_error_code_t::malformed_image,
                        "embedded DEX header is invalid", "dex.multidex.scan"));
            if (member_size > limits.parser_limits.max_file_size)
                return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                    dex_managed_error(workspace_error_code_t::limit_exceeded,
                        "embedded DEX member exceeds the parser limit",
                        "dex.multidex.scan"));
            if (members.size() >= limits.max_dex_files)
                return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
                    dex_managed_error(workspace_error_code_t::limit_exceeded,
                        "embedded DEX member count exceeds the reader limit",
                        "dex.multidex.scan"));
            members.emplace_back(candidate_offset, member_size);
            covered_until = candidate_offset + file_size;
        }
        if (read_size == provider.size() - offset)
            break;
        const auto next = offset + read_size - 7;
        offset = (std::max)(next, covered_until);
    }
    if (members.empty())
        return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::failure(
            dex_managed_error(workspace_error_code_t::target_not_found,
                "runtime container has no supported embedded DEX members",
                "dex.multidex.scan"));
    return workspace_result_t<std::vector<std::pair<std::uint64_t, std::uint64_t>>>::success(
        std::move(members));
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

std::optional<std::uint64_t> dex_data_absolute_offset(
    const dex_image_t& image,
    std::uint32_t raw_offset) {
    std::uint64_t local_offset = raw_offset;
    if (image.container.kind == dex_container_kind_t::compact_dex)
        local_offset += image.header.data_offset;
    if (local_offset >= image.payload_size ||
        image.dex_offset > (std::numeric_limits<std::uint64_t>::max)() -
            local_offset)
        return std::nullopt;
    return image.dex_offset + local_offset;
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
    const auto abs = dex_data_absolute_offset(image, item_offset);
    if (!abs)
        return;
    auto data_opt = read_dex_bytes(provider, *abs, 16, dex_end, cancel);
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
    const auto abs = dex_data_absolute_offset(image, set_offset);
    if (!abs)
        return;
    auto header_opt = read_dex_bytes(provider, *abs, 4, dex_end, cancel);
    if (!header_opt || header_opt->size() < 4)
        return;
    const auto set_size = read_u32_le(*header_opt, 0);
    if (set_size == 0 || set_size > 65536)
        return;
    const auto set_total = 4u + static_cast<std::uint64_t>(set_size) * 4u;
    auto set_data_opt = read_dex_bytes(provider, *abs, set_total, dex_end, cancel);
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

void collect_parameter_annotation_list(
    const dex_image_t& image,
    const byte_provider_t& provider,
    std::uint32_t list_offset,
    std::vector<dex_annotation_info_t>& annotations,
    std::uint32_t max_annotations,
    std::uint64_t dex_end,
    const cancellation_token_t& cancel) {
    if (list_offset == 0 || annotations.size() >= max_annotations)
        return;
    const auto absolute = dex_data_absolute_offset(image, list_offset);
    if (!absolute)
        return;
    auto header = read_dex_bytes(provider, *absolute, 4, dex_end, cancel);
    if (!header || header->size() != 4)
        return;
    const auto parameter_count = read_u32_le(*header, 0);
    if (parameter_count == 0 || parameter_count > 65536)
        return;
    const auto byte_count = 4ULL +
        static_cast<std::uint64_t>(parameter_count) * 4ULL;
    auto list = read_dex_bytes(
        provider, *absolute, byte_count, dex_end, cancel);
    if (!list)
        return;
    for (std::uint32_t index = 0; index < parameter_count; ++index) {
        if (cancel.stop_requested() || annotations.size() >= max_annotations)
            return;
        const auto set_offset = read_u32_le(*list, 4U + index * 4U);
        if (set_offset != 0)
            collect_annotation_set(image, provider, set_offset, annotations,
                max_annotations, dex_end, cancel);
    }
}

void collect_dex_annotations(const dex_image_t& image,
                             const byte_provider_t& provider,
                             std::vector<dex_annotation_info_t>& annotations,
                             std::uint32_t max_annotations,
                             const cancellation_token_t& cancel) {
    const auto dex_end = image.dex_offset + image.payload_size;
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
        for (std::uint32_t i = 0; i < params_size; ++i) {
            if (cursor + 8 > dir.size())
                break;
            const auto list_offset = read_u32_le(dir, cursor + 4);
            cursor += 8;
            if (list_offset != 0)
                collect_parameter_annotation_list(
                    image, provider, list_offset, annotations,
                    max_annotations, dex_end, cancel);
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
        auto references = collect_dex_references(
            metadata.image, metadata.method_references,
            metadata.field_references, metadata.type_references,
            limits.max_member_references, cancel);
        if (!references)
            return workspace_result_t<dex_metadata_t>::failure(
                references.error());
        const auto annotation_probe_limit = limits.max_annotations ==
                (std::numeric_limits<std::uint32_t>::max)()
            ? limits.max_annotations
            : limits.max_annotations + 1U;
        collect_dex_annotations(metadata.image, provider, metadata.annotations,
                                annotation_probe_limit, cancel);
        if (cancel.stop_requested())
            return workspace_result_t<dex_metadata_t>::failure(
                dex_managed_stop_error(cancel,
                    "DEX annotation collection cancelled", "dex.annotations"));
        if (metadata.annotations.size() > limits.max_annotations)
            return workspace_result_t<dex_metadata_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                    "DEX annotation count exceeds the reader limit",
                    "dex.annotations"));
        return workspace_result_t<dex_metadata_t>::success(std::move(metadata));
    }

    auto image_result = parse_dex_image(provider, limits.parser_limits, cancel);
    if (!image_result)
        return workspace_result_t<dex_metadata_t>::failure(std::move(image_result.error()));
    dex_metadata_t metadata;
    metadata.image = image_result.take_value();
    metadata.container = container;
    metadata.dex_ordinal = 0;
    auto references = collect_dex_references(
        metadata.image, metadata.method_references,
        metadata.field_references, metadata.type_references,
        limits.max_member_references, cancel);
    if (!references)
        return workspace_result_t<dex_metadata_t>::failure(
            references.error());
    const auto annotation_probe_limit = limits.max_annotations ==
            (std::numeric_limits<std::uint32_t>::max)()
        ? limits.max_annotations
        : limits.max_annotations + 1U;
    collect_dex_annotations(metadata.image, provider, metadata.annotations,
                            annotation_probe_limit, cancel);
    if (cancel.stop_requested())
        return workspace_result_t<dex_metadata_t>::failure(
            dex_managed_stop_error(cancel,
                "DEX annotation collection cancelled", "dex.annotations"));
    if (metadata.annotations.size() > limits.max_annotations)
        return workspace_result_t<dex_metadata_t>::failure(
            dex_managed_error(workspace_error_code_t::limit_exceeded,
                "DEX annotation count exceeds the reader limit",
                "dex.annotations"));
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

    if (container.kind == dex_container_kind_t::dex ||
        container.kind == dex_container_kind_t::compact_dex) {
        auto single_result = parse_dex_metadata(provider, limits, cancel);
        if (!single_result)
            return workspace_result_t<multidex_metadata_t>::failure(std::move(single_result.error()));
        auto single = single_result.take_value();
        single.dex_ordinal = 0;
        multidex.dex_entries.push_back(std::move(single));
        return workspace_result_t<multidex_metadata_t>::success(std::move(multidex));
    }

    if (container.kind != dex_container_kind_t::oat &&
        container.kind != dex_container_kind_t::vdex)
        return workspace_result_t<multidex_metadata_t>::failure(
            dex_managed_error(workspace_error_code_t::unsupported_format,
                "input is not a DEX, OAT, or VDEX container",
                "dex.multidex"));

    auto members = scan_runtime_dex_members(provider, limits, cancel);
    if (!members)
        return workspace_result_t<multidex_metadata_t>::failure(members.error());
    container.embedded_dex_offsets.clear();
    container.embedded_dex_offsets.reserve(members.value().size());
    for (const auto& member : members.value())
        container.embedded_dex_offsets.push_back(member.first);
    multidex.container = container;
    std::uint32_t ordinal = 0;
    std::uint64_t total_types = 0;
    std::uint64_t total_methods = 0;
    std::uint64_t total_fields = 0;
    std::uint64_t total_references = 0;
    std::uint64_t total_annotations = 0;
    std::uint64_t total_code_bytes = 0;
    std::uint64_t total_string_bytes = 0;
    for (const auto& member : members.value()) {
        if (cancel.stop_requested())
            return workspace_result_t<multidex_metadata_t>::failure(
                dex_managed_stop_error(cancel,
                    "Multidex parsing cancelled", "dex.multidex"));
        auto provider_ptr = std::shared_ptr<const byte_provider_t>(
            std::addressof(provider), [](const byte_provider_t*) {});
        auto subrange_result = subrange_provider_t::create(
            std::move(provider_ptr), member.first, member.second,
            "dex_" + std::to_string(ordinal));
        if (!subrange_result)
            return workspace_result_t<multidex_metadata_t>::failure(
                subrange_result.error());
        auto subrange = subrange_result.take_value();
        auto image_result = parse_dex_image(*subrange, limits.parser_limits, cancel);
        if (!image_result)
            return workspace_result_t<multidex_metadata_t>::failure(
                image_result.error());
        dex_metadata_t entry;
        entry.image = image_result.take_value();
        entry.container = container;
        entry.dex_ordinal = ordinal;
        const auto exceeds = [](std::uint64_t current, std::uint64_t added,
                                std::uint64_t limit) {
            return current > limit || added > limit - current;
        };
        std::uint64_t image_code_bytes = 0;
        for (const auto& cls : entry.image.classes) {
            for (const auto& encoded : cls.direct_methods) {
                if (encoded.code &&
                    exceeds(image_code_bytes,
                        static_cast<std::uint64_t>(
                            encoded.code->instruction_count) * 2ULL,
                        limits.max_code_bytes))
                    return workspace_result_t<multidex_metadata_t>::failure(
                        dex_managed_error(workspace_error_code_t::limit_exceeded,
                            "multidex code bytes exceed the reader limit",
                            "dex.multidex"));
                if (encoded.code)
                    image_code_bytes +=
                        static_cast<std::uint64_t>(
                            encoded.code->instruction_count) * 2ULL;
            }
            for (const auto& encoded : cls.virtual_methods) {
                if (encoded.code &&
                    exceeds(image_code_bytes,
                        static_cast<std::uint64_t>(
                            encoded.code->instruction_count) * 2ULL,
                        limits.max_code_bytes))
                    return workspace_result_t<multidex_metadata_t>::failure(
                        dex_managed_error(workspace_error_code_t::limit_exceeded,
                            "multidex code bytes exceed the reader limit",
                            "dex.multidex"));
                if (encoded.code)
                    image_code_bytes +=
                        static_cast<std::uint64_t>(
                            encoded.code->instruction_count) * 2ULL;
            }
        }
        std::uint64_t image_string_bytes = 0;
        for (const auto& string : entry.image.strings) {
            if (exceeds(image_string_bytes, string.utf8.size(),
                        limits.max_string_bytes))
                return workspace_result_t<multidex_metadata_t>::failure(
                    dex_managed_error(workspace_error_code_t::limit_exceeded,
                        "multidex string bytes exceed the reader limit",
                        "dex.multidex"));
            image_string_bytes += string.utf8.size();
        }
        if (exceeds(total_types, entry.image.types.size(), limits.max_types) ||
            exceeds(total_methods, entry.image.methods.size(), limits.max_methods) ||
            exceeds(total_fields, entry.image.fields.size(), limits.max_fields) ||
            exceeds(total_code_bytes, image_code_bytes, limits.max_code_bytes) ||
            exceeds(total_string_bytes, image_string_bytes,
                limits.max_string_bytes))
            return workspace_result_t<multidex_metadata_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                    "multidex aggregate metadata exceeds its reader limits",
                    "dex.multidex"));
        const auto remaining_references = static_cast<std::uint32_t>(
            limits.max_member_references - total_references);
        auto references = collect_dex_references(
            entry.image, entry.method_references,
            entry.field_references, entry.type_references,
            remaining_references, cancel);
        if (!references)
            return workspace_result_t<multidex_metadata_t>::failure(
                references.error());
        const auto reference_count = entry.method_references.size() +
            entry.field_references.size() + entry.type_references.size();
        if (exceeds(total_references, reference_count,
                    limits.max_member_references))
            return workspace_result_t<multidex_metadata_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                    "multidex references exceed the reader limit",
                    "dex.multidex"));
        const auto remaining_annotations = static_cast<std::uint32_t>(
            limits.max_annotations - total_annotations);
        const auto annotation_probe_limit = remaining_annotations ==
                (std::numeric_limits<std::uint32_t>::max)()
            ? remaining_annotations
            : remaining_annotations + 1U;
        collect_dex_annotations(entry.image, *subrange, entry.annotations,
                                annotation_probe_limit, cancel);
        if (cancel.stop_requested())
            return workspace_result_t<multidex_metadata_t>::failure(
                dex_managed_stop_error(cancel,
                    "DEX annotation collection cancelled", "dex.annotations"));
        if (entry.annotations.size() > remaining_annotations)
            return workspace_result_t<multidex_metadata_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                    "multidex annotations exceed the reader limit",
                    "dex.annotations"));
        total_types += entry.image.types.size();
        total_methods += entry.image.methods.size();
        total_fields += entry.image.fields.size();
        total_references += reference_count;
        total_annotations += entry.annotations.size();
        total_code_bytes += image_code_bytes;
        total_string_bytes += image_string_bytes;
        multidex.dex_entries.push_back(std::move(entry));
        ++ordinal;
    }

    return workspace_result_t<multidex_metadata_t>::success(std::move(multidex));
}

workspace_result_t<managed_artifact_t>
build_dex_artifact(const dex_metadata_t& metadata,
                   const byte_provider_t& provider,
                   const managed_reader_limits_t& limits,
                   const cancellation_token_t& cancel) {
    if (!limits.valid())
        return workspace_result_t<managed_artifact_t>::failure(
            dex_managed_error(workspace_error_code_t::invalid_argument,
                "DEX artifact limits are invalid", "dex.build"));
    if (cancel.stop_requested())
        return workspace_result_t<managed_artifact_t>::failure(
            dex_managed_stop_error(cancel,
                "DEX artifact building cancelled", "dex.build"));
    managed_artifact_t artifact;
    artifact.kind = managed_artifact_kind_t::dex;
    artifact.module_identity.kind = managed_artifact_kind_t::dex;
    artifact.module_identity.version = metadata.image.managed_identity.version;
    artifact.module_identity.artifact_offset = metadata.image.dex_offset;
    artifact.module_identity.artifact_size = metadata.image.payload_size;

    auto hash_result = provider.compute_content_sha256(cancel);
    if (!hash_result)
        return workspace_result_t<managed_artifact_t>::failure(hash_result.error());
    artifact.module_identity.artifact_hash = hash_result.value();

    std::string dex_name;
    const auto hex = hash_result.value().to_hex();
    dex_name = "dex_" + hex.substr(0, 16);
    artifact.module_identity.assembly_name = dex_name;
    artifact.module_identity.module_name = dex_name;

    for (const auto& string : metadata.image.strings) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_stop_error(cancel,
                    "DEX artifact building cancelled", "dex.build"));
        if (string.utf8.size() >
            limits.max_string_bytes - artifact.total_string_bytes)
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                    "DEX cumulative string bytes exceed limit", "dex.build"));
        artifact.total_string_bytes += string.utf8.size();
    }

    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(metadata.image.classes.size()); ++i) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_stop_error(cancel,
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
                    dex_managed_stop_error(cancel,
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
                method.code_offset = encoded.code->instructions_offset;
                method.code_size = static_cast<std::uint64_t>(encoded.code->instruction_count) * 2u;
                method.max_stack = 0;
                method.max_locals = encoded.code->registers_size;
            }
            artifact.methods.push_back(std::move(method));
        }
        for (const auto& encoded : cls.virtual_methods) {
            if (cancel.stop_requested())
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_stop_error(cancel,
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
                method.code_offset = encoded.code->instructions_offset;
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
                    dex_managed_stop_error(cancel,
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
            if (cancel.stop_requested())
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_stop_error(cancel,
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
            field.is_static = false;
            artifact.fields.push_back(std::move(field));
        }
    }

    for (const auto& [idx, ref_str] : metadata.method_references) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_stop_error(cancel,
                    "DEX artifact building cancelled", "dex.build"));
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
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_stop_error(cancel,
                    "DEX artifact building cancelled", "dex.build"));
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
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_stop_error(cancel,
                    "DEX artifact building cancelled", "dex.build"));
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
            if (cancel.stop_requested())
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_stop_error(cancel,
                        "DEX artifact building cancelled", "dex.build"));
            if (encoded.code) {
                if (artifact.code_ranges.size() >= limits.max_code_ranges)
                    return workspace_result_t<managed_artifact_t>::failure(
                        dex_managed_error(workspace_error_code_t::limit_exceeded,
                            "DEX code range count exceeds limit", "dex.build"));
                const auto code_bytes =
                    static_cast<std::uint64_t>(encoded.code->instruction_count) * 2U;
                if (code_bytes > limits.max_code_bytes - artifact.total_code_bytes)
                    return workspace_result_t<managed_artifact_t>::failure(
                        dex_managed_error(workspace_error_code_t::limit_exceeded,
                            "DEX cumulative code bytes exceed limit", "dex.build"));
                managed_code_range_t range;
                range.offset = encoded.code->instructions_offset;
                range.size = code_bytes;
                range.max_stack = 0;
                range.max_locals = encoded.code->registers_size;
                range.method_token = encoded.method_index;
                artifact.code_ranges.push_back(std::move(range));
                artifact.total_code_bytes += code_bytes;
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
            if (cancel.stop_requested())
                return workspace_result_t<managed_artifact_t>::failure(
                    dex_managed_stop_error(cancel,
                        "DEX artifact building cancelled", "dex.build"));
            if (encoded.code) {
                if (artifact.code_ranges.size() >= limits.max_code_ranges)
                    return workspace_result_t<managed_artifact_t>::failure(
                        dex_managed_error(workspace_error_code_t::limit_exceeded,
                            "DEX code range count exceeds limit", "dex.build"));
                const auto code_bytes =
                    static_cast<std::uint64_t>(encoded.code->instruction_count) * 2U;
                if (code_bytes > limits.max_code_bytes - artifact.total_code_bytes)
                    return workspace_result_t<managed_artifact_t>::failure(
                        dex_managed_error(workspace_error_code_t::limit_exceeded,
                            "DEX cumulative code bytes exceed limit", "dex.build"));
                managed_code_range_t range;
                range.offset = encoded.code->instructions_offset;
                range.size = code_bytes;
                range.max_stack = 0;
                range.max_locals = encoded.code->registers_size;
                range.method_token = encoded.method_index;
                artifact.code_ranges.push_back(std::move(range));
                artifact.total_code_bytes += code_bytes;
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
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_stop_error(cancel,
                    "DEX artifact building cancelled", "dex.build"));
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
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_stop_error(cancel,
                    "DEX artifact building cancelled", "dex.build"));
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
        if (cancel.stop_requested())
            return workspace_result_t<managed_artifact_t>::failure(
                dex_managed_stop_error(cancel,
                    "DEX artifact building cancelled", "dex.build"));
        if (!seen_type_indices.insert(type.metadata_token).second) {
            managed_duplicate_identity_t dup;
            dup.identity_key = std::to_string(type.metadata_token);
            dup.description = "Duplicate DEX type index";
            artifact.duplicate_identities.push_back(std::move(dup));
        }
    }

    artifact.normalized = metadata.image.normalized;
    artifact.normalized.format_name =
        std::string(metadata.image.container.kind == dex_container_kind_t::compact_dex
                        ? "compact-dex:"
                        : "dex:") +
        metadata.image.managed_identity.version;

    if (!artifact.valid())
        return workspace_result_t<managed_artifact_t>::failure(
            dex_managed_error(workspace_error_code_t::integrity_failure,
                "DEX artifact failed its publication invariant", "dex.build"));

    return workspace_result_t<managed_artifact_t>::success(std::move(artifact));
}

workspace_result_t<managed_multidex_t>
build_multidex_artifact(const multidex_metadata_t& metadata,
                        const byte_provider_t& provider,
                        const managed_reader_limits_t& limits,
                        const cancellation_token_t& cancel) {
    if (!limits.valid() || metadata.dex_entries.empty() ||
        metadata.dex_entries.size() > limits.max_dex_files)
        return workspace_result_t<managed_multidex_t>::failure(
            dex_managed_error(workspace_error_code_t::invalid_argument,
                "multidex artifact input or limits are invalid",
                "dex.multidex"));
    managed_multidex_t multidex;
    multidex.container_version = metadata.container_version;
    multidex.container_kind = metadata.container.kind == dex_container_kind_t::oat
        ? managed_artifact_kind_t::oat
        : metadata.container.kind == dex_container_kind_t::vdex
            ? managed_artifact_kind_t::vdex
            : (metadata.container.kind == dex_container_kind_t::dex ||
               metadata.container.kind == dex_container_kind_t::compact_dex)
                ? managed_artifact_kind_t::dex
                : managed_artifact_kind_t::multidex_container;
    multidex.embedded_offsets = metadata.container.embedded_dex_offsets;
    if (multidex.embedded_offsets.empty()) {
        multidex.embedded_offsets.reserve(metadata.dex_entries.size());
        for (const auto& entry : metadata.dex_entries)
            multidex.embedded_offsets.push_back(entry.image.dex_offset);
    }
    if (multidex.embedded_offsets.size() != metadata.dex_entries.size())
        return workspace_result_t<managed_multidex_t>::failure(
            dex_managed_error(workspace_error_code_t::integrity_failure,
                "multidex member offsets do not match its artifacts",
                "dex.multidex"));

    std::uint64_t total_types = 0;
    std::uint64_t total_methods = 0;
    std::uint64_t total_fields = 0;
    std::uint64_t total_references = 0;
    std::uint64_t total_annotations = 0;
    std::uint64_t total_exceptions = 0;
    std::uint64_t total_code_ranges = 0;
    std::uint64_t total_code_bytes = 0;
    std::uint64_t total_string_bytes = 0;

    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(metadata.dex_entries.size()); ++i) {
        if (cancel.stop_requested())
            return workspace_result_t<managed_multidex_t>::failure(
                dex_managed_stop_error(cancel,
                    "Multidex artifact building cancelled", "dex.multidex"));
        const auto& entry = metadata.dex_entries[i];
        const auto dex_offset = i < metadata.container.embedded_dex_offsets.size()
            ? metadata.container.embedded_dex_offsets[i]
            : entry.image.dex_offset;
        const auto dex_size = entry.image.payload_size;
        if (dex_size == 0 || dex_offset > provider.size() ||
            dex_size > provider.size() - dex_offset) {
            return workspace_result_t<managed_multidex_t>::failure(
                dex_managed_error(workspace_error_code_t::out_of_range,
                                  "embedded DEX range exceeds its container",
                                  "dex.multidex"));
        }
        auto provider_ptr = std::shared_ptr<const byte_provider_t>(
            std::addressof(provider), [](const byte_provider_t*) {});
        auto subrange_result = subrange_provider_t::create(
            std::move(provider_ptr), dex_offset, dex_size,
            "dex_" + std::to_string(i));
        if (!subrange_result)
            return workspace_result_t<managed_multidex_t>::failure(subrange_result.error());
        auto artifact_result = build_dex_artifact(
            entry, *subrange_result.value(), limits, cancel);
        if (!artifact_result)
            return workspace_result_t<managed_multidex_t>::failure(std::move(artifact_result.error()));
        auto artifact = artifact_result.take_value();
        artifact.module_identity.artifact_offset = dex_offset;
        artifact.module_identity.artifact_size = dex_size;
        artifact.module_identity.artifact_ordinal = i;
        if (metadata.container.kind == dex_container_kind_t::oat) {
            artifact.kind = managed_artifact_kind_t::oat;
            artifact.module_identity.kind = managed_artifact_kind_t::oat;
            artifact.normalized.format = format_id_t::oat;
            artifact.normalized.format_name = "oat:" +
                metadata.container_version + "/dex:" +
                artifact.module_identity.version;
        } else if (metadata.container.kind == dex_container_kind_t::vdex) {
            artifact.kind = managed_artifact_kind_t::vdex;
            artifact.module_identity.kind = managed_artifact_kind_t::vdex;
            artifact.normalized.format = format_id_t::vdex;
            artifact.normalized.format_name = "vdex:" +
                metadata.container_version + "/dex:" +
                artifact.module_identity.version;
        }
        const auto exceeds = [](std::uint64_t current, std::size_t added,
                                std::uint64_t limit) {
            return current > limit || added > limit - current;
        };
        if (exceeds(total_types, artifact.types.size(), limits.max_types) ||
            exceeds(total_methods, artifact.methods.size(), limits.max_methods) ||
            exceeds(total_fields, artifact.fields.size(), limits.max_fields) ||
            exceeds(total_references, artifact.member_references.size(),
                limits.max_member_references) ||
            exceeds(total_annotations, artifact.annotations.size(),
                limits.max_annotations) ||
            exceeds(total_exceptions, artifact.exception_regions.size(),
                limits.max_exception_regions) ||
            exceeds(total_code_ranges, artifact.code_ranges.size(),
                limits.max_code_ranges) ||
            artifact.total_code_bytes > limits.max_code_bytes - total_code_bytes ||
            artifact.total_string_bytes >
                limits.max_string_bytes - total_string_bytes)
            return workspace_result_t<managed_multidex_t>::failure(
                dex_managed_error(workspace_error_code_t::limit_exceeded,
                    "multidex aggregate metadata exceeds its reader limits",
                    "dex.multidex"));
        total_types += artifact.types.size();
        total_methods += artifact.methods.size();
        total_fields += artifact.fields.size();
        total_references += artifact.member_references.size();
        total_annotations += artifact.annotations.size();
        total_exceptions += artifact.exception_regions.size();
        total_code_ranges += artifact.code_ranges.size();
        total_code_bytes += artifact.total_code_bytes;
        total_string_bytes += artifact.total_string_bytes;
        for (const auto& cls_desc : artifact.types) {
            multidex.dex_class_descriptors.push_back(cls_desc.fully_qualified_name);
        }
        multidex.artifacts.push_back(std::move(artifact));
    }

    if (!multidex.valid())
        return workspace_result_t<managed_multidex_t>::failure(
            dex_managed_error(workspace_error_code_t::integrity_failure,
                "multidex artifact failed its publication invariant",
                "dex.multidex"));

    return workspace_result_t<managed_multidex_t>::success(std::move(multidex));
}

}
