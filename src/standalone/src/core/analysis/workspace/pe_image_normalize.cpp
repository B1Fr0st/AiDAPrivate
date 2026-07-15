#include "pe_image.hpp"

#include <new>
#include <utility>

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

namespace aida::analysis {
namespace {

workspace_error_t normalize_stop_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "PE parsing deadline exceeded", "pe_parse");
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "PE parsing cancelled", "pe_parse");
    error.cancellation = true;
    return error;
}

}

workspace_result_t<std::shared_ptr<const workspace_image_t>>
normalize_pe_image(const pe_image_t& image, const byte_provider_t& provider,
                   const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            normalize_stop_error(cancel));
    try {
        auto normalized = std::make_shared<workspace_image_t>();
        normalized->format = image.format();
        normalized->architecture = image.architecture();
        normalized->architecture_mode = image.architecture_mode();
        normalized->abi = image.abi();
        normalized->endian = image.endian();
        normalized->address_width_bits = static_cast<std::uint8_t>(
            image.format() == format_id_t::pe32_plus ? 64U : 32U);
        normalized->image_base = image.image_base();
        normalized->image_size = image.image_size();
        normalized->header_size = image.headers_size();
        normalized->format_name = image.format() == format_id_t::pe32_plus ? "pe32_plus" : "pe32";
        normalized->provider_size = provider.size();
        normalized->member = provider.member_metadata();

        const auto make_address = [&image](std::uint64_t rva) {
            return address_t{address_space_id_t::relative_virtual, rva,
                             image.architecture(), image.architecture_mode()};
        };
        const auto section_permissions = [](const pe_section_t& section) {
            std::uint32_t permissions = image_permission_none;
            if (section.readable)
                permissions |= image_permission_read;
            if (section.writable)
                permissions |= image_permission_write;
            if (section.executable)
                permissions |= image_permission_execute;
            if (section.discardable)
                permissions |= image_permission_discardable;
            return permissions;
        };

        if (image.headers_size() != 0) {
            image_address_mapping_t mapping;
            mapping.source_start = 0;
            mapping.target_start = 0;
            mapping.size = image.headers_size();
            mapping.permissions = image_permission_read;
            normalized->address_mappings.push_back(mapping);
        }
        for (const auto& section : image.sections()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                    normalize_stop_error(cancel));
            const std::uint64_t virtual_size = section.virtual_size;
            const std::uint64_t file_size = section.raw_size;
            if (virtual_size == 0 && file_size == 0)
                continue;
            image_section_t normalized_section;
            normalized_section.index = section.index;
            normalized_section.name = section.name;
            normalized_section.virtual_address = section.virtual_address;
            normalized_section.virtual_size = virtual_size;
            normalized_section.file_offset = file_size == 0 ? 0 : section.raw_offset;
            normalized_section.file_size = file_size;
            normalized_section.flags = section.characteristics;
            normalized_section.permissions = section_permissions(section);
            normalized->sections.push_back(normalized_section);

            image_segment_t normalized_segment;
            normalized_segment.index = section.index;
            normalized_segment.name = section.name;
            normalized_segment.virtual_address = section.virtual_address;
            normalized_segment.virtual_size = virtual_size;
            normalized_segment.file_offset = file_size == 0 ? 0 : section.raw_offset;
            normalized_segment.file_size = file_size;
            normalized_segment.flags = section.characteristics;
            normalized_segment.permissions = normalized_section.permissions;
            normalized->segments.push_back(std::move(normalized_segment));

            if (file_size != 0) {
                image_address_mapping_t mapping;
                mapping.source_start = section.raw_offset;
                mapping.target_start = section.virtual_address;
                mapping.size = file_size;
                mapping.permissions = normalized_section.permissions;
                normalized->address_mappings.push_back(mapping);
            }
        }
        for (const auto& entry : image.entry_points()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                    normalize_stop_error(cancel));
            normalized->entry_points.push_back(
                image_entry_point_t{make_address(entry.rva), entry.provenance});
        }
        for (const auto& imported : image.imports()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                    normalize_stop_error(cancel));
            image_import_t normalized_import;
            normalized_import.library = imported.library;
            normalized_import.name = imported.name;
            if (imported.ordinal)
                normalized_import.ordinal = *imported.ordinal;
            normalized_import.lookup_address = make_address(imported.lookup_rva);
            normalized_import.address = make_address(imported.iat_rva);
            normalized_import.delayed = imported.delayed;
            normalized->imports.push_back(normalized_import);

            image_symbol_t symbol;
            symbol.name = imported.library;
            symbol.name.push_back('!');
            if (imported.name)
                symbol.name.append(*imported.name);
            else if (imported.ordinal)
                symbol.name.append("#").append(std::to_string(*imported.ordinal));
            symbol.address = normalized_import.address;
            symbol.kind = image_symbol_kind_t::import_symbol;
            symbol.binding = image_symbol_binding_t::external;
            normalized->symbols.push_back(std::move(symbol));
        }
        for (const auto& exported : image.exports()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                    normalize_stop_error(cancel));
            image_export_t normalized_export;
            normalized_export.name = exported.name;
            normalized_export.ordinal = exported.ordinal;
            normalized_export.address = make_address(exported.rva);
            normalized_export.forwarder = exported.forwarder;
            normalized->exports.push_back(normalized_export);

            image_symbol_t symbol;
            symbol.ordinal = exported.ordinal;
            if (exported.name)
                symbol.name = *exported.name;
            symbol.address = normalized_export.address;
            symbol.kind = image_symbol_kind_t::export_symbol;
            symbol.binding = image_symbol_binding_t::global;
            symbol.defined = !exported.forwarder.has_value();
            symbol.forwarded = exported.forwarder.has_value();
            normalized->symbols.push_back(std::move(symbol));
        }
        for (const auto& relocation : image.relocations()) {
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                    normalize_stop_error(cancel));
            normalized->relocations.push_back(image_relocation_t{
                make_address(relocation.rva), relocation.type, std::nullopt});
        }
        auto validation = validate_workspace_image(*normalized);
        if (!validation)
            return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                validation.error());
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::success(
            std::static_pointer_cast<const workspace_image_t>(std::move(normalized)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "PE normalization allocation failed", "pe_normalize"));
    }
}

}

#endif
