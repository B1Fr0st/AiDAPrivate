#include "elf_reader.hpp"

#include "../workspace/checked_range.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace aida::analysis {
namespace {

constexpr std::uint32_t invalid_section_index =
    (std::numeric_limits<std::uint32_t>::max)();

workspace_error_t reader_error(workspace_error_code_t code, std::string message,
                               std::uint64_t offset = 0, std::uint64_t size = 0) {
    auto error = make_workspace_error(code, std::move(message), "elf_reader");
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_result_t<void> poll(const cancellation_token_t& cancel,
                              std::uint64_t iteration) {
    if ((iteration & 255U) != 0 || !cancel.stop_requested())
        return workspace_result_t<void>::success();
    auto error = make_workspace_error(
        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                   : workspace_error_code_t::cancelled,
        "ELF metadata read cancelled", "elf_reader");
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return workspace_result_t<void>::failure(std::move(error));
}

workspace_result_t<void> charge_count(std::size_t current, std::uint64_t limit,
                                      const char* message) {
    if (current < limit)
        return workspace_result_t<void>::success();
    return workspace_result_t<void>::failure(reader_error(
        workspace_error_code_t::limit_exceeded, message,
        static_cast<std::uint64_t>(current) + 1, limit));
}

workspace_result_t<void> charge_string(std::uint64_t& total, std::size_t size,
                                       const elf_metadata_reader_limits_t& limits) {
    const auto value = static_cast<std::uint64_t>(size);
    if (total > limits.max_materialized_string_bytes ||
        value > limits.max_materialized_string_bytes - total) {
        return workspace_result_t<void>::failure(reader_error(
            workspace_error_code_t::limit_exceeded,
            "ELF metadata string budget exceeded", total, value));
    }
    total += value;
    return workspace_result_t<void>::success();
}

std::uint32_t read_u32(const std::uint8_t* data, endian_t endian) noexcept {
    if (endian == endian_t::big) {
        return (static_cast<std::uint32_t>(data[0]) << 24) |
               (static_cast<std::uint32_t>(data[1]) << 16) |
               (static_cast<std::uint32_t>(data[2]) << 8) |
               static_cast<std::uint32_t>(data[3]);
    }
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) |
           (static_cast<std::uint32_t>(data[3]) << 24);
}

bool align_up_4(std::size_t value, std::size_t& result) noexcept {
    if (value > (std::numeric_limits<std::size_t>::max)() - 3U)
        return false;
    result = (value + 3U) & ~std::size_t{3U};
    return true;
}

std::string encode_hex(const std::uint8_t* bytes, std::size_t count) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.resize(count * 2U);
    for (std::size_t index = 0; index < count; ++index) {
        output[index * 2U] = digits[bytes[index] >> 4U];
        output[index * 2U + 1U] = digits[bytes[index] & 0x0fU];
    }
    return output;
}

std::optional<address_t> section_address(const elf_image_t& image,
                                         std::uint32_t section_index) {
    const auto section = std::find_if(
        image.normalized.sections.begin(), image.normalized.sections.end(),
        [section_index](const image_section_t& value) { return value.index == section_index; });
    if (section == image.normalized.sections.end())
        return std::nullopt;
    return address_t{address_space_id_t::relative_virtual, section->virtual_address,
                     image.normalized.architecture, image.normalized.architecture_mode};
}

std::optional<address_t> symbol_address(const elf_image_t& image,
                                        const elf_symbol_t& symbol) {
    if (symbol.is_undefined || symbol.is_absolute || symbol.is_common)
        return std::nullopt;
    std::uint64_t rva = 0;
    if (image.filetype == elf_filetype_t::relocatable) {
        const auto section = std::find_if(
            image.normalized.sections.begin(), image.normalized.sections.end(),
            [&symbol](const image_section_t& value) { return value.index == symbol.section_index; });
        if (section == image.normalized.sections.end() ||
            symbol.value >= section->virtual_size ||
            !checked_add_u64(section->virtual_address, symbol.value, rva)) {
            return std::nullopt;
        }
    } else {
        if (symbol.value < image.normalized.image_base)
            return std::nullopt;
        rva = symbol.value - image.normalized.image_base;
    }
    address_t address{address_space_id_t::relative_virtual, rva,
                      image.normalized.architecture, image.normalized.architecture_mode};
    if (!workspace_image_contains(image.normalized, address))
        return std::nullopt;
    return address;
}

elf_metadata_region_t make_section_region(const elf_image_t& image,
                                          const elf_section_t& section) {
    elf_metadata_region_t region;
    region.section_index = section.index;
    region.name = section.name;
    region.file_offset = section.offset;
    region.size = section.size;
    region.address = section_address(image, section.index);
    region.compressed = section.is_compressed;
    return region;
}

elf_metadata_region_t make_segment_region(const elf_image_t& image,
                                          const elf_segment_t& segment) {
    elf_metadata_region_t region;
    region.section_index = invalid_section_index;
    region.segment_index = segment.index;
    region.name = segment.type_name;
    region.file_offset = segment.offset;
    region.size = segment.filesz;
    if (segment.memsz != 0 && segment.vaddr >= image.normalized.image_base) {
        const auto rva = segment.vaddr - image.normalized.image_base;
        address_t address{address_space_id_t::relative_virtual, rva,
                          image.normalized.architecture, image.normalized.architecture_mode};
        if (workspace_image_contains(image.normalized, address))
            region.address = address;
    }
    return region;
}

std::optional<elf_type_seed_kind_t> type_seed_kind(std::string_view name) {
    if (name == ".debug_info" || name == ".zdebug_info")
        return elf_type_seed_kind_t::dwarf_info;
    if (name == ".debug_types" || name == ".zdebug_types")
        return elf_type_seed_kind_t::dwarf_types;
    if (name == ".debug_names" || name == ".zdebug_names")
        return elf_type_seed_kind_t::dwarf_names;
    if (name == ".debug_abbrev" || name == ".zdebug_abbrev")
        return elf_type_seed_kind_t::dwarf_abbrev;
    if (name == ".debug_str" || name == ".zdebug_str" ||
        name == ".debug_str_offsets" || name == ".zdebug_str_offsets") {
        return elf_type_seed_kind_t::dwarf_strings;
    }
    if (name == ".debug_line" || name == ".zdebug_line" ||
        name == ".debug_line_str" || name == ".zdebug_line_str") {
        return elf_type_seed_kind_t::dwarf_line;
    }
    if (name == ".debug_ranges" || name == ".zdebug_ranges" ||
        name == ".debug_rnglists" || name == ".zdebug_rnglists") {
        return elf_type_seed_kind_t::dwarf_ranges;
    }
    if (name == ".debug_loc" || name == ".zdebug_loc" ||
        name == ".debug_loclists" || name == ".zdebug_loclists") {
        return elf_type_seed_kind_t::dwarf_locations;
    }
    if (name == ".debug_frame" || name == ".zdebug_frame")
        return elf_type_seed_kind_t::dwarf_frame;
    if (name == ".debug_sup" || name == ".zdebug_sup")
        return elf_type_seed_kind_t::dwarf_supplementary;
    if (name == ".gnu_debugdata")
        return elf_type_seed_kind_t::embedded_debug;
    if (name == ".gnu_debuglink")
        return elf_type_seed_kind_t::debug_link;
    if (name == ".gnu_debugaltlink")
        return elf_type_seed_kind_t::debug_altlink;
    if (name.rfind(".debug_", 0) == 0 || name.rfind(".zdebug_", 0) == 0)
        return elf_type_seed_kind_t::auxiliary_debug;
    return std::nullopt;
}

bool region_less(const elf_metadata_region_t& left, const elf_metadata_region_t& right) {
    return std::tie(left.file_offset, left.size, left.section_index, left.segment_index,
                    left.name, left.address, left.compressed) <
           std::tie(right.file_offset, right.size, right.section_index, right.segment_index,
                    right.name, right.address, right.compressed);
}

workspace_result_t<void> append_symbol_seed(
    elf_metadata_t& metadata, const elf_symbol_t& symbol, elf_symbol_seed_source_t source,
    const elf_metadata_reader_limits_t& limits, std::uint64_t& string_bytes) {
    if (symbol.table_symbol_index == 0 && symbol.name.empty())
        return workspace_result_t<void>::success();
    auto count = charge_count(metadata.symbol_seeds.size(), limits.max_symbol_seeds,
                              "ELF symbol seed count exceeds its budget");
    if (!count)
        return count;
    auto name = charge_string(string_bytes, symbol.name.size(), limits);
    if (!name)
        return name;
    elf_symbol_seed_t seed;
    seed.source = source;
    seed.table_section_index = symbol.table_section_index;
    seed.table_symbol_index = symbol.table_symbol_index;
    seed.section_index = symbol.section_index;
    seed.name = symbol.name;
    seed.size = symbol.size;
    seed.kind = symbol.kind;
    seed.binding = symbol.binding;
    seed.visibility = symbol.visibility;
    seed.address = symbol_address(metadata.image, symbol);
    seed.defined = seed.address.has_value();
    seed.imported = symbol.is_import;
    seed.exported = symbol.is_export;
    seed.weak = symbol.is_weak;
    seed.local = symbol.is_local;
    metadata.symbol_seeds.push_back(std::move(seed));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> append_type_seed(
    elf_metadata_t& metadata, elf_type_seed_kind_t kind, const elf_section_t& section,
    const elf_metadata_reader_limits_t& limits, std::uint64_t& string_bytes) {
    auto count = charge_count(metadata.type_seeds.size(), limits.max_type_seeds,
                              "ELF type seed count exceeds its budget");
    if (!count)
        return count;
    auto name = charge_string(string_bytes, section.name.size(), limits);
    if (!name)
        return name;
    elf_type_seed_t seed;
    seed.kind = kind;
    seed.region = make_section_region(metadata.image, section);
    metadata.type_seeds.push_back(std::move(seed));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> append_unwind_region(
    elf_metadata_t& metadata, elf_unwind_region_kind_t kind, elf_metadata_region_t region,
    const elf_metadata_reader_limits_t& limits, std::uint64_t& string_bytes) {
    auto count = charge_count(metadata.unwind_regions.size(), limits.max_unwind_regions,
                              "ELF unwind region count exceeds its budget");
    if (!count)
        return count;
    auto name = charge_string(string_bytes, region.name.size(), limits);
    if (!name)
        return name;
    metadata.unwind_regions.push_back({kind, std::move(region)});
    return workspace_result_t<void>::success();
}

workspace_result_t<void> append_exception_region(
    elf_metadata_t& metadata, elf_exception_region_kind_t kind, elf_metadata_region_t region,
    const elf_metadata_reader_limits_t& limits, std::uint64_t& string_bytes) {
    auto count = charge_count(metadata.exception_regions.size(), limits.max_exception_regions,
                              "ELF exception region count exceeds its budget");
    if (!count)
        return count;
    auto name = charge_string(string_bytes, region.name.size(), limits);
    if (!name)
        return name;
    metadata.exception_regions.push_back({kind, std::move(region)});
    return workspace_result_t<void>::success();
}

workspace_result_t<void> append_debug_link(
    elf_metadata_t& metadata, elf_debug_link_t link,
    const elf_metadata_reader_limits_t& limits, std::uint64_t& string_bytes) {
    auto count = charge_count(metadata.debug_links.size(), limits.max_debug_links,
                              "ELF debug-link count exceeds its budget");
    if (!count)
        return count;
    auto section = charge_string(string_bytes, link.section_name.size(), limits);
    if (!section)
        return section;
    auto path = charge_string(string_bytes, link.path.size(), limits);
    if (!path)
        return path;
    if (link.build_id_hex) {
        auto build_id = charge_string(string_bytes, link.build_id_hex->size(), limits);
        if (!build_id)
            return build_id;
    }
    metadata.debug_links.push_back(std::move(link));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> parse_debug_link_section(
    const byte_provider_t& provider, elf_metadata_t& metadata, const elf_section_t& section,
    const elf_metadata_reader_limits_t& limits, const cancellation_token_t& cancel,
    std::uint64_t& string_bytes) {
    if (section.is_nobits || section.size == 0 || section.size > limits.max_debug_link_bytes) {
        return workspace_result_t<void>::failure(reader_error(
            workspace_error_code_t::limit_exceeded,
            "ELF debug-link section exceeds its budget", section.offset, section.size));
    }
    auto range = validate_span(section.offset, section.size, provider.size(), "elf_reader");
    if (!range)
        return workspace_result_t<void>::failure(std::move(range.error()));
    auto bytes = provider.read_vector(section.offset, section.size, limits.max_debug_link_bytes,
                                      cancel);
    if (!bytes)
        return workspace_result_t<void>::failure(std::move(bytes.error()));
    const auto& data = bytes.value();
    const auto terminator = std::find(data.begin(), data.end(), static_cast<std::uint8_t>(0));
    if (terminator == data.begin() || terminator == data.end()) {
        return workspace_result_t<void>::failure(reader_error(
            workspace_error_code_t::malformed_image,
            "ELF debug-link path is not a terminated nonempty string",
            section.offset, section.size));
    }
    const auto path_size = static_cast<std::size_t>(terminator - data.begin());
    elf_debug_link_t link;
    link.section_index = section.index;
    link.section_name = section.name;
    link.path.assign(reinterpret_cast<const char*>(data.data()), path_size);
    link.file_offset = section.offset;
    link.size = section.size;
    if (section.name == ".gnu_debuglink") {
        std::size_t crc_offset = 0;
        if (!align_up_4(path_size + 1U, crc_offset) || crc_offset > data.size() ||
            data.size() - crc_offset != sizeof(std::uint32_t)) {
            return workspace_result_t<void>::failure(reader_error(
                workspace_error_code_t::malformed_image,
                "ELF GNU debug-link checksum layout is invalid",
                section.offset, section.size));
        }
        link.kind = elf_debug_link_kind_t::gnu_debuglink;
        link.crc32 = read_u32(data.data() + crc_offset, metadata.image.endian);
    } else {
        const auto build_id_offset = path_size + 1U;
        if (build_id_offset >= data.size()) {
            return workspace_result_t<void>::failure(reader_error(
                workspace_error_code_t::malformed_image,
                "ELF GNU debug-altlink has no build identifier",
                section.offset, section.size));
        }
        link.kind = elf_debug_link_kind_t::gnu_debugaltlink;
        link.build_id_hex = encode_hex(data.data() + build_id_offset,
                                       data.size() - build_id_offset);
    }
    return append_debug_link(metadata, std::move(link), limits, string_bytes);
}

workspace_result_t<void> build_metadata_records(
    const byte_provider_t& provider, elf_metadata_t& metadata,
    const elf_metadata_reader_limits_t& limits, const cancellation_token_t& cancel) {
    std::uint64_t string_bytes = 0;
    for (std::size_t index = 0; index < metadata.image.symtab_symbols.size(); ++index) {
        auto stopped = poll(cancel, index);
        if (!stopped)
            return stopped;
        auto appended = append_symbol_seed(metadata, metadata.image.symtab_symbols[index],
                                           elf_symbol_seed_source_t::symbol_table,
                                           limits, string_bytes);
        if (!appended)
            return appended;
    }
    for (std::size_t index = 0; index < metadata.image.dynsym_symbols.size(); ++index) {
        auto stopped = poll(cancel, index + metadata.image.symtab_symbols.size());
        if (!stopped)
            return stopped;
        auto appended = append_symbol_seed(metadata, metadata.image.dynsym_symbols[index],
                                           elf_symbol_seed_source_t::dynamic_symbol_table,
                                           limits, string_bytes);
        if (!appended)
            return appended;
    }
    for (std::size_t index = 0; index < metadata.image.sections.size(); ++index) {
        auto stopped = poll(cancel, index);
        if (!stopped)
            return stopped;
        const auto& section = metadata.image.sections[index];
        if (const auto kind = type_seed_kind(section.name)) {
            auto appended = append_type_seed(metadata, *kind, section, limits, string_bytes);
            if (!appended)
                return appended;
        }
        const auto region = make_section_region(metadata.image, section);
        if (section.name == ".eh_frame") {
            auto appended = append_unwind_region(metadata, elf_unwind_region_kind_t::eh_frame,
                                                  region, limits, string_bytes);
            if (!appended)
                return appended;
        } else if (section.name == ".eh_frame_hdr") {
            auto appended = append_unwind_region(metadata,
                                                  elf_unwind_region_kind_t::eh_frame_header,
                                                  region, limits, string_bytes);
            if (!appended)
                return appended;
        } else if (section.name == ".debug_frame" || section.name == ".zdebug_frame") {
            auto appended = append_unwind_region(metadata, elf_unwind_region_kind_t::debug_frame,
                                                  region, limits, string_bytes);
            if (!appended)
                return appended;
        } else if (section.name == ".ARM.exidx") {
            auto appended = append_unwind_region(metadata, elf_unwind_region_kind_t::arm_exidx,
                                                  region, limits, string_bytes);
            if (!appended)
                return appended;
            auto exception = append_exception_region(metadata,
                                                     elf_exception_region_kind_t::arm_exidx,
                                                     region, limits, string_bytes);
            if (!exception)
                return exception;
        }
        if (section.name == ".gcc_except_table") {
            auto appended = append_exception_region(
                metadata, elf_exception_region_kind_t::gcc_except_table,
                region, limits, string_bytes);
            if (!appended)
                return appended;
        } else if (section.name == ".ARM.extab") {
            auto appended = append_exception_region(
                metadata, elf_exception_region_kind_t::arm_extab,
                region, limits, string_bytes);
            if (!appended)
                return appended;
        } else if (section.name == ".exception_ranges") {
            auto appended = append_exception_region(
                metadata, elf_exception_region_kind_t::exception_ranges,
                region, limits, string_bytes);
            if (!appended)
                return appended;
        }
        if (section.name == ".gnu_debuglink" || section.name == ".gnu_debugaltlink") {
            auto link = parse_debug_link_section(provider, metadata, section, limits,
                                                 cancel, string_bytes);
            if (!link)
                return link;
        }
    }
    for (std::size_t index = 0; index < metadata.image.segments.size(); ++index) {
        auto stopped = poll(cancel, index + metadata.image.sections.size());
        if (!stopped)
            return stopped;
        const auto& segment = metadata.image.segments[index];
        if (!segment.is_gnu_eh_frame)
            continue;
        auto appended = append_unwind_region(
            metadata, elf_unwind_region_kind_t::gnu_eh_frame_segment,
            make_segment_region(metadata.image, segment), limits, string_bytes);
        if (!appended)
            return appended;
    }
    std::sort(metadata.symbol_seeds.begin(), metadata.symbol_seeds.end(),
              [](const elf_symbol_seed_t& left, const elf_symbol_seed_t& right) {
                  return std::tie(left.source, left.table_section_index,
                                  left.table_symbol_index, left.section_index, left.name,
                                  left.size, left.kind, left.binding, left.visibility,
                                  left.address, left.defined, left.imported, left.exported,
                                  left.weak, left.local) <
                         std::tie(right.source, right.table_section_index,
                                  right.table_symbol_index, right.section_index, right.name,
                                  right.size, right.kind, right.binding, right.visibility,
                                  right.address, right.defined, right.imported, right.exported,
                                  right.weak, right.local);
              });
    std::sort(metadata.type_seeds.begin(), metadata.type_seeds.end(),
              [](const elf_type_seed_t& left, const elf_type_seed_t& right) {
                  if (left.kind != right.kind)
                      return left.kind < right.kind;
                  return region_less(left.region, right.region);
              });
    std::sort(metadata.unwind_regions.begin(), metadata.unwind_regions.end(),
              [](const elf_unwind_region_t& left, const elf_unwind_region_t& right) {
                  if (left.kind != right.kind)
                      return left.kind < right.kind;
                  return region_less(left.region, right.region);
              });
    std::sort(metadata.exception_regions.begin(), metadata.exception_regions.end(),
              [](const elf_exception_region_t& left, const elf_exception_region_t& right) {
                  if (left.kind != right.kind)
                      return left.kind < right.kind;
                  return region_less(left.region, right.region);
              });
    std::sort(metadata.debug_links.begin(), metadata.debug_links.end(),
              [](const elf_debug_link_t& left, const elf_debug_link_t& right) {
                  return std::tie(left.kind, left.path, left.section_index, left.section_name,
                                  left.file_offset, left.size, left.crc32, left.build_id_hex) <
                         std::tie(right.kind, right.path, right.section_index, right.section_name,
                                  right.file_offset, right.size, right.crc32, right.build_id_hex);
              });
    return workspace_result_t<void>::success();
}

}

workspace_result_t<elf_metadata_t> read_elf_metadata(
    const byte_provider_t& provider, const elf_metadata_reader_limits_t& limits,
    const cancellation_token_t& cancel) {
    try {
        if (cancel.stop_requested()) {
            auto stopped = poll(cancel, 0);
            return workspace_result_t<elf_metadata_t>::failure(std::move(stopped.error()));
        }
        auto parsed = parse_elf_image(provider, limits.parser_limits, cancel);
        if (!parsed)
            return workspace_result_t<elf_metadata_t>::failure(std::move(parsed.error()));
        elf_metadata_t metadata;
        metadata.image = parsed.take_value();
        auto records = build_metadata_records(provider, metadata, limits, cancel);
        if (!records)
            return workspace_result_t<elf_metadata_t>::failure(std::move(records.error()));
        return workspace_result_t<elf_metadata_t>::success(std::move(metadata));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<elf_metadata_t>::failure(reader_error(
            workspace_error_code_t::limit_exceeded, "ELF metadata allocation failed"));
    } catch (const std::length_error&) {
        return workspace_result_t<elf_metadata_t>::failure(reader_error(
            workspace_error_code_t::limit_exceeded, "ELF metadata allocation failed"));
    }
}

workspace_result_t<elf_metadata_t> read_elf_metadata(
    const byte_provider_t& provider, const cancellation_token_t& cancel) {
    return read_elf_metadata(provider, elf_metadata_reader_limits_t{}, cancel);
}

}
