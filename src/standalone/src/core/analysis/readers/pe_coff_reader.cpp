#include "pe_coff_reader.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <string_view>
#include <tuple>
#include <utility>

namespace aida::analysis {
namespace {

constexpr std::uint32_t k_cli_directory_index = 14;
constexpr std::uint32_t k_cli_header_size = 72;
constexpr std::uint32_t k_cli_flag_il_only = 0x00000001U;
constexpr std::uint32_t k_cli_flag_32bit_required = 0x00000002U;
constexpr std::uint32_t k_cli_flag_strong_name_signed = 0x00000008U;
constexpr std::uint32_t k_cli_flag_native_entry_point = 0x00000010U;
constexpr std::uint32_t k_cli_flag_track_debug_data = 0x00010000U;
constexpr std::uint32_t k_cli_flag_32bit_preferred = 0x00020000U;
constexpr std::uint32_t k_cli_metadata_signature = 0x424a5342U;

workspace_error_t reader_error(workspace_error_code_t code, std::string message,
                               std::string phase, std::optional<std::uint64_t> offset = {},
                               std::optional<std::uint64_t> size = {}) {
    auto error = make_workspace_error(code, std::move(message), std::move(phase));
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t reader_stop_error(const cancellation_token_t& cancel) {
    auto error = reader_error(workspace_error_code_t::cancelled, "PE/COFF metadata read was cancelled",
                              "pe_coff_reader");
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    if (error.deadline)
        error.code = workspace_error_code_t::deadline_exceeded;
    return error;
}

bool valid_coff_limits(const coff_parse_limits_t& limits) noexcept {
    return limits.max_sections != 0 && limits.max_sections <= 65536U &&
           limits.max_symbols != 0 && limits.max_symbols <= (1U << 22U) &&
           limits.max_relocations != 0 && limits.max_relocations <= (1U << 24U) &&
           limits.max_archive_members != 0 && limits.max_archive_members <= (1U << 20U) &&
           limits.max_archive_symbols != 0 && limits.max_archive_symbols <= (1U << 22U) &&
           limits.max_member_size != 0 && limits.max_member_size <= (1ULL << 40U) &&
           limits.max_string_table_bytes != 0 &&
           limits.max_string_table_bytes <= 1024ULL * 1024ULL * 1024ULL &&
           limits.max_materialized_string_bytes != 0 &&
           limits.max_materialized_string_bytes <= 1024ULL * 1024ULL * 1024ULL &&
           limits.max_total_metadata_bytes != 0 &&
           limits.max_total_metadata_bytes <= 1024ULL * 1024ULL * 1024ULL &&
           limits.max_synthetic_image_size != 0 && limits.max_synthetic_image_size <= (1ULL << 40U) &&
           limits.max_name_bytes != 0 && limits.max_name_bytes <= (1U << 20U);
}

workspace_result_t<void> validate_reader_limits(const pe_coff_reader_limits_t& limits) {
    auto pe_validation = validate_pe_parser_profile(make_pe_parser_profile(limits.pe_limits));
    if (!pe_validation)
        return pe_validation;
    if (!valid_coff_limits(limits.coff_limits) || limits.max_cli_metadata_bytes < k_cli_header_size ||
        limits.max_cli_metadata_bytes > 1024ULL * 1024ULL * 1024ULL ||
        limits.max_type_seeds == 0 || limits.max_type_seeds > (1U << 20U) ||
        limits.max_layout_mappings == 0 || limits.max_layout_mappings > (1U << 20U) ||
        limits.max_layout_regions == 0 || limits.max_layout_regions > (1U << 20U)) {
        return workspace_result_t<void>::failure(
            reader_error(workspace_error_code_t::invalid_argument,
                         "PE/COFF metadata limits are outside supported safety bounds",
                         "pe_coff_reader.limits"));
    }
    return workspace_result_t<void>::success();
}

std::uint16_t read_u16(const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint16_t>(bytes[0]) |
           (static_cast<std::uint16_t>(bytes[1]) << 8U);
}

std::uint32_t read_u32(const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

workspace_result_t<void> validate_cli_range(const pe_image_t& image, std::uint32_t rva,
                                            std::uint32_t size, std::uint64_t limit,
                                            std::string_view field) {
    if (rva == 0 && size == 0)
        return workspace_result_t<void>::success();
    if (rva == 0 || size == 0 || size > limit)
        return workspace_result_t<void>::failure(
            reader_error(workspace_error_code_t::malformed_image,
                         "CLI metadata range is incomplete or exceeds its limit",
                         std::string("pe_coff_reader.cli.").append(field), rva, size));
    auto file_offset = image.rva_to_file_offset(rva, size);
    if (!file_offset)
        return workspace_result_t<void>::failure(file_offset.error());
    return workspace_result_t<void>::success();
}

workspace_result_t<std::optional<pe_coff_cli_metadata_t>> parse_cli_metadata(
    const byte_provider_t& provider, const pe_image_t& image, const pe_coff_reader_limits_t& limits,
    const cancellation_token_t& cancel) {
    const auto directory = std::find_if(image.directories().begin(), image.directories().end(),
        [](const pe_data_directory_t& value) { return value.index == k_cli_directory_index; });
    if (directory == image.directories().end())
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::success(std::nullopt);
    if (directory->size < k_cli_header_size || directory->size > limits.max_cli_metadata_bytes)
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(
            reader_error(workspace_error_code_t::malformed_image,
                         "CLI header directory is smaller than IMAGE_COR20_HEADER or exceeds its limit",
                         "pe_coff_reader.cli.header", directory->rva, directory->size));
    auto header_offset = image.rva_to_file_offset(directory->rva, k_cli_header_size);
    if (!header_offset)
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(header_offset.error());
    auto header = provider.read_vector(header_offset.value(), k_cli_header_size, k_cli_header_size, cancel);
    if (!header)
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(header.error());
    const auto* bytes = header.value().data();
    const std::uint32_t declared_size = read_u32(bytes);
    if (declared_size < k_cli_header_size || declared_size > directory->size)
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(
            reader_error(workspace_error_code_t::malformed_image,
                         "CLI header declared size is outside its directory",
                         "pe_coff_reader.cli.header", directory->rva, declared_size));

    pe_coff_cli_metadata_t result;
    result.header_rva = directory->rva;
    result.header_size = declared_size;
    result.runtime_major = read_u16(bytes + 4U);
    result.runtime_minor = read_u16(bytes + 6U);
    result.metadata_rva = read_u32(bytes + 8U);
    result.metadata_size = read_u32(bytes + 12U);
    result.flags = read_u32(bytes + 16U);
    result.entry_point = read_u32(bytes + 20U);
    result.resources_rva = read_u32(bytes + 24U);
    result.resources_size = read_u32(bytes + 28U);
    result.strong_name_rva = read_u32(bytes + 32U);
    result.strong_name_size = read_u32(bytes + 36U);
    result.vtable_fixups_rva = read_u32(bytes + 48U);
    result.vtable_fixups_size = read_u32(bytes + 52U);
    result.export_address_table_jumps_rva = read_u32(bytes + 56U);
    result.export_address_table_jumps_size = read_u32(bytes + 60U);
    result.managed_native_header_rva = read_u32(bytes + 64U);
    result.managed_native_header_size = read_u32(bytes + 68U);

    for (const auto& range : std::array<std::tuple<std::uint32_t, std::uint32_t, std::string_view>, 5>{{
             {result.metadata_rva, result.metadata_size, "metadata"},
             {result.resources_rva, result.resources_size, "resources"},
             {result.strong_name_rva, result.strong_name_size, "strong_name"},
             {result.vtable_fixups_rva, result.vtable_fixups_size, "vtable_fixups"},
             {result.export_address_table_jumps_rva, result.export_address_table_jumps_size,
              "export_address_table_jumps"}}}) {
        auto validation = validate_cli_range(image, std::get<0>(range), std::get<1>(range),
                                             limits.max_cli_metadata_bytes, std::get<2>(range));
        if (!validation)
            return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(
                validation.error());
    }
    auto native_validation = validate_cli_range(image, result.managed_native_header_rva,
                                                result.managed_native_header_size,
                                                limits.max_cli_metadata_bytes, "managed_native_header");
    if (!native_validation)
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(native_validation.error());
    if (result.metadata_rva == 0 || result.metadata_size == 0)
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(
            reader_error(workspace_error_code_t::malformed_image,
                         "CLI header does not contain a metadata root", "pe_coff_reader.cli.metadata",
                         result.header_rva, result.header_size));
    auto metadata_offset = image.rva_to_file_offset(result.metadata_rva, 4U);
    if (!metadata_offset)
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(metadata_offset.error());
    auto metadata_signature = provider.read_vector(metadata_offset.value(), 4U, 4U, cancel);
    if (!metadata_signature)
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(metadata_signature.error());
    if (read_u32(metadata_signature.value().data()) != k_cli_metadata_signature)
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(
            reader_error(workspace_error_code_t::malformed_image,
                         "CLI metadata root signature is invalid", "pe_coff_reader.cli.metadata",
                         result.metadata_rva, result.metadata_size));

    result.il_only = (result.flags & k_cli_flag_il_only) != 0;
    result.requires_32bit = (result.flags & k_cli_flag_32bit_required) != 0;
    result.preferred_32bit = (result.flags & k_cli_flag_32bit_preferred) != 0;
    result.strong_name_signed = (result.flags & k_cli_flag_strong_name_signed) != 0;
    result.native_entry_point = (result.flags & k_cli_flag_native_entry_point) != 0;
    result.track_debug_data = (result.flags & k_cli_flag_track_debug_data) != 0;
    if ((result.requires_32bit && result.preferred_32bit) ||
        (result.preferred_32bit && !result.il_only) ||
        (result.native_entry_point && result.entry_point == 0U) ||
        (!result.native_entry_point && result.entry_point != 0U &&
         (result.entry_point & 0xff000000U) != 0x06000000U)) {
        return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::failure(
            reader_error(workspace_error_code_t::malformed_image,
                         "CLI flags and entry-point encoding are inconsistent",
                         "pe_coff_reader.cli.flags", result.header_rva, result.header_size));
    }
    return workspace_result_t<std::optional<pe_coff_cli_metadata_t>>::success(std::move(result));
}

std::string lowercase_ascii(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const char character : value) {
        if (character >= 'A' && character <= 'Z')
            result.push_back(static_cast<char>(character - 'A' + 'a'));
        else
            result.push_back(character);
    }
    return result;
}

bool starts_with(std::string_view value, std::string_view prefix) noexcept {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

std::optional<pe_coff_type_seed_kind_t> classify_type_seed(std::string_view name) {
    const std::string lower = lowercase_ascii(name);
    if (starts_with(name, "??_7") || starts_with(lower, "_ztv") ||
        lower.find("vftable") != std::string::npos || lower.find("vtable") != std::string::npos)
        return pe_coff_type_seed_kind_t::vtable;
    if (starts_with(name, "??_r") || lower.find("rtti") != std::string::npos ||
        lower.find("completeobjectlocator") != std::string::npos)
        return pe_coff_type_seed_kind_t::rtti;
    if (starts_with(lower, "_zti") || lower.find("typedesc") != std::string::npos ||
        lower.find("typeinfo") != std::string::npos)
        return pe_coff_type_seed_kind_t::type_information;
    return std::nullopt;
}

workspace_result_t<void> append_type_seed(std::vector<pe_coff_type_seed_t>& seeds,
                                          const pe_coff_reader_limits_t& limits,
                                          pe_coff_type_seed_origin_t origin,
                                          std::optional<std::uint64_t> rva,
                                          const std::string& name) {
    const auto kind = classify_type_seed(name);
    if (!kind)
        return workspace_result_t<void>::success();
    if (seeds.size() >= limits.max_type_seeds)
        return workspace_result_t<void>::failure(
            reader_error(workspace_error_code_t::limit_exceeded,
                         "PE/COFF type-seed count exceeds its limit", "pe_coff_reader.type_seeds"));
    seeds.push_back({*kind, origin, rva, name});
    return workspace_result_t<void>::success();
}

workspace_result_t<void> add_pe_type_seeds(std::vector<pe_coff_type_seed_t>& seeds,
                                           const pe_image_t& image,
                                           const pe_coff_reader_limits_t& limits,
                                           const cancellation_token_t& cancel) {
    for (const auto& exported : image.exports()) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(reader_stop_error(cancel));
        if (!exported.name)
            continue;
        auto appended = append_type_seed(seeds, limits, pe_coff_type_seed_origin_t::pe_export,
                                         exported.rva, *exported.name);
        if (!appended)
            return appended;
    }
    for (const auto& imported : image.imports()) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(reader_stop_error(cancel));
        if (!imported.name)
            continue;
        auto appended = append_type_seed(seeds, limits, pe_coff_type_seed_origin_t::pe_import,
                                         imported.iat_rva, *imported.name);
        if (!appended)
            return appended;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> add_coff_type_seeds(std::vector<pe_coff_type_seed_t>& seeds,
                                             const coff_image_t& image,
                                             const pe_coff_reader_limits_t& limits,
                                             const cancellation_token_t& cancel) {
    for (const auto& symbol : image.symbols) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(reader_stop_error(cancel));
        auto appended = append_type_seed(seeds, limits, pe_coff_type_seed_origin_t::coff_symbol,
                                         symbol.normalized_address, symbol.name);
        if (!appended)
            return appended;
    }
    for (const auto& imported : image.import_objects) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(reader_stop_error(cancel));
        if (!imported.symbol_name)
            continue;
        auto appended = append_type_seed(seeds, limits, pe_coff_type_seed_origin_t::coff_symbol,
                                         std::nullopt, *imported.symbol_name);
        if (!appended)
            return appended;
    }
    for (const auto& symbol : image.archive_symbols) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(reader_stop_error(cancel));
        auto appended = append_type_seed(seeds, limits, pe_coff_type_seed_origin_t::coff_symbol,
                                         std::nullopt, symbol.name);
        if (!appended)
            return appended;
    }
    return workspace_result_t<void>::success();
}

void sort_type_seeds(std::vector<pe_coff_type_seed_t>& seeds) {
    std::sort(seeds.begin(), seeds.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.kind, lhs.origin, lhs.rva, lhs.name) <
               std::tie(rhs.kind, rhs.origin, rhs.rva, rhs.name);
    });
    seeds.erase(std::unique(seeds.begin(), seeds.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.kind == rhs.kind && lhs.origin == rhs.origin && lhs.rva == rhs.rva &&
               lhs.name == rhs.name;
    }), seeds.end());
}

workspace_result_t<image_layout_index_t> build_layout(const byte_provider_t& provider,
                                                       const workspace_image_t& image,
                                                       const pe_coff_reader_limits_t& limits,
                                                       const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<image_layout_index_t>::failure(reader_stop_error(cancel));
    if (image.address_width_bits != 32U && image.address_width_bits != 64U)
        return workspace_result_t<image_layout_index_t>::failure(
            reader_error(workspace_error_code_t::malformed_image,
                         "normalized image has an unsupported address width",
                         "pe_coff_reader.layout"));
    if (image.address_mappings.size() > limits.max_layout_mappings ||
        image.sections.size() > limits.max_layout_regions ||
        image.segments.size() > limits.max_layout_regions)
        return workspace_result_t<image_layout_index_t>::failure(
            reader_error(workspace_error_code_t::limit_exceeded,
                         "normalized image exceeds PE/COFF layout limits",
                         "pe_coff_reader.layout"));
    auto digest = provider.identity().content_sha256;
    if (!digest) {
        auto computed = provider.compute_content_sha256(cancel);
        if (!computed)
            return workspace_result_t<image_layout_index_t>::failure(computed.error());
        digest = computed.take_value();
    }

    image_layout_definition_t definition;
    definition.identity.content_id = *digest;
    definition.identity.format = image.format;
    definition.identity.endian = image.endian;
    definition.identity.address_width_bits = image.address_width_bits;
    definition.identity.image_base = image.image_base;
    definition.identity.provider_size = provider.size();
    definition.identity.member = provider.member_metadata();
    if (definition.identity.member)
        definition.members.push_back({0U, definition.identity.member->normalized_member_path, 0U,
                                      provider.size()});

    for (const auto& section : image.sections) {
        const std::uint64_t virtual_size = (std::max)(section.virtual_size, section.file_size);
        if (virtual_size == 0 && section.file_size == 0)
            continue;
        definition.sections.push_back({section.index, section.name, section.virtual_address,
                                       virtual_size, section.file_offset, section.file_size,
                                       section.permissions});
    }
    for (const auto& segment : image.segments) {
        const std::uint64_t virtual_size = (std::max)(segment.virtual_size, segment.file_size);
        if (virtual_size == 0 && segment.file_size == 0)
            continue;
        definition.segments.push_back({segment.index, segment.name, segment.virtual_address,
                                       virtual_size, segment.file_offset, segment.file_size,
                                       segment.permissions});
    }
    for (std::size_t index = 0; index < image.address_mappings.size(); ++index) {
        if (cancel.stop_requested())
            return workspace_result_t<image_layout_index_t>::failure(reader_stop_error(cancel));
        const auto& mapping = image.address_mappings[index];
        if (mapping.source_space != address_space_id_t::file_offset ||
            mapping.target_space != address_space_id_t::relative_virtual || mapping.size == 0)
            return workspace_result_t<image_layout_index_t>::failure(
                reader_error(workspace_error_code_t::malformed_image,
                             "normalized image has an unsupported address mapping",
                             "pe_coff_reader.layout", mapping.source_start, mapping.size));
        if (mapping.target_start > (std::numeric_limits<std::uint64_t>::max)() - image.image_base)
            return workspace_result_t<image_layout_index_t>::failure(
                reader_error(workspace_error_code_t::range_overflow,
                             "normalized image virtual address overflows", "pe_coff_reader.layout",
                             mapping.target_start, mapping.size));
        image_layout_mapping_t layout_mapping;
        layout_mapping.id = static_cast<std::uint32_t>(index);
        layout_mapping.rva = mapping.target_start;
        layout_mapping.virtual_address = image.image_base + mapping.target_start;
        layout_mapping.virtual_size = mapping.size;
        layout_mapping.file_offset = mapping.source_start;
        layout_mapping.file_size = mapping.size;
        layout_mapping.permissions = mapping.permissions;
        if (definition.identity.member)
            layout_mapping.member_id = 0U;
        definition.mappings.push_back(std::move(layout_mapping));
    }
    return image_layout_index_t::build(std::move(definition));
}

pe_coff_pe_metadata_t project_pe_metadata(const pe_image_t& image,
                                          std::optional<pe_coff_cli_metadata_t> cli) {
    pe_coff_pe_metadata_t result;
    result.artifact_kind = image.artifact_kind();
    result.machine = image.machine();
    result.subsystem = image.subsystem();
    result.characteristics = image.characteristics();
    result.dll_characteristics = image.dll_characteristics();
    result.timestamp = image.timestamp();
    result.directories = image.directories();
    result.sections = image.sections();
    result.entry_points = image.entry_points();
    result.imports = image.imports();
    result.exports = image.exports();
    result.relocations = image.relocations();
    result.tls_callbacks = image.tls_callbacks();
    result.runtime_functions = image.runtime_functions();
    result.unwind_records = image.unwind_records();
    result.load_config = image.load_config();
    result.codeview_records = image.codeview_records();
    result.resources = image.resources();
    result.cli = std::move(cli);
    return result;
}

pe_coff_coff_metadata_t project_coff_metadata(coff_image_t&& image) {
    pe_coff_coff_metadata_t result;
    result.artifact_kind = image.artifact_kind;
    result.machine = image.machine;
    result.characteristics = image.characteristics;
    result.timestamp = image.time_date_stamp;
    result.symbol_table_offset = image.symbol_table_offset;
    result.symbol_table_count = image.symbol_table_count;
    result.header_size = image.header_size;
    result.sections = std::move(image.sections);
    result.symbols = std::move(image.symbols);
    result.relocations = std::move(image.relocations);
    result.import_objects = std::move(image.import_objects);
    result.archive_members = std::move(image.archive_members);
    result.archive_symbols = std::move(image.archive_symbols);
    result.archive_has_long_name_table = image.archive_has_long_name_table;
    result.archive_has_first_linker_member = image.archive_has_first_linker_member;
    result.archive_has_second_linker_member = image.archive_has_second_linker_member;
    result.archive_has_64bit_symbol_table = image.archive_has_64bit_symbol_table;
    result.archive_has_mixed_machines = image.archive_has_mixed_machines;
    return result;
}

workspace_result_t<pe_coff_metadata_result_t> read_pe_metadata(
    const byte_provider_t& provider, const pe_coff_reader_limits_t& limits,
    const cancellation_token_t& cancel) {
    auto parsed = parse_pe_image(provider, limits.pe_limits, cancel);
    if (!parsed)
        return workspace_result_t<pe_coff_metadata_result_t>::failure(parsed.error());
    auto normalized = normalize_pe_image(*parsed.value(), provider, cancel);
    if (!normalized)
        return workspace_result_t<pe_coff_metadata_result_t>::failure(normalized.error());
    auto cli = parse_cli_metadata(provider, *parsed.value(), limits, cancel);
    if (!cli)
        return workspace_result_t<pe_coff_metadata_result_t>::failure(cli.error());
    pe_coff_normalized_record_t record;
    record.image = *normalized.value();
    record.pe = project_pe_metadata(*parsed.value(), cli.take_value());
    auto seeds = add_pe_type_seeds(record.type_seeds, *parsed.value(), limits, cancel);
    if (!seeds)
        return workspace_result_t<pe_coff_metadata_result_t>::failure(seeds.error());
    sort_type_seeds(record.type_seeds);
    auto layout = build_layout(provider, record.image, limits, cancel);
    if (!layout)
        return workspace_result_t<pe_coff_metadata_result_t>::failure(layout.error());
    return workspace_result_t<pe_coff_metadata_result_t>::success(
        {std::move(record), layout.take_value()});
}

workspace_result_t<pe_coff_metadata_result_t> read_coff_metadata(
    const byte_provider_t& provider, const pe_coff_reader_limits_t& limits,
    const cancellation_token_t& cancel) {
    auto parsed = parse_coff_image(provider, limits.coff_limits, cancel);
    if (!parsed)
        return workspace_result_t<pe_coff_metadata_result_t>::failure(parsed.error());
    coff_image_t coff = parsed.take_value();
    pe_coff_normalized_record_t record;
    record.image = std::move(coff.normalized);
    auto seeds = add_coff_type_seeds(record.type_seeds, coff, limits, cancel);
    if (!seeds)
        return workspace_result_t<pe_coff_metadata_result_t>::failure(seeds.error());
    sort_type_seeds(record.type_seeds);
    record.coff = project_coff_metadata(std::move(coff));
    auto layout = build_layout(provider, record.image, limits, cancel);
    if (!layout)
        return workspace_result_t<pe_coff_metadata_result_t>::failure(layout.error());
    return workspace_result_t<pe_coff_metadata_result_t>::success(
        {std::move(record), layout.take_value()});
}

}

workspace_result_t<pe_coff_metadata_result_t>
read_pe_coff_metadata(const byte_provider_t& provider, const pe_coff_reader_limits_t& limits,
                      const cancellation_token_t& cancel) {
    try {
        if (cancel.stop_requested())
            return workspace_result_t<pe_coff_metadata_result_t>::failure(reader_stop_error(cancel));
        auto validation = validate_reader_limits(limits);
        if (!validation)
            return workspace_result_t<pe_coff_metadata_result_t>::failure(validation.error());
        if (provider.size() < 2U)
            return workspace_result_t<pe_coff_metadata_result_t>::failure(
                reader_error(workspace_error_code_t::malformed_image,
                             "PE/COFF input is smaller than a format probe",
                             "pe_coff_reader.probe", 0U, provider.size()));
        std::array<std::uint8_t, 2> probe{};
        auto read = provider.read_exact(0U, probe.data(), probe.size(), cancel);
        if (!read)
            return workspace_result_t<pe_coff_metadata_result_t>::failure(read.error());
        if (probe[0] == static_cast<std::uint8_t>('M') &&
            probe[1] == static_cast<std::uint8_t>('Z'))
            return read_pe_metadata(provider, limits, cancel);
        return read_coff_metadata(provider, limits, cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<pe_coff_metadata_result_t>::failure(
            reader_error(workspace_error_code_t::limit_exceeded,
                         "PE/COFF metadata allocation failed", "pe_coff_reader"));
    } catch (const std::length_error&) {
        return workspace_result_t<pe_coff_metadata_result_t>::failure(
            reader_error(workspace_error_code_t::limit_exceeded,
                         "PE/COFF metadata length exceeds allocator bounds", "pe_coff_reader"));
    }
}

}
