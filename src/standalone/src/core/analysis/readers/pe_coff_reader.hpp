#pragma once

#include "../image_layout_index.hpp"
#include "../workspace/coff_image.hpp"
#include "../workspace/pe_image.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

enum class pe_coff_type_seed_kind_t : std::uint8_t {
    rtti = 0,
    vtable = 1,
    type_information = 2
};

enum class pe_coff_type_seed_origin_t : std::uint8_t {
    pe_export = 0,
    pe_import = 1,
    coff_symbol = 2
};

struct pe_coff_cli_metadata_t {
    std::uint32_t header_rva = 0;
    std::uint32_t header_size = 0;
    std::uint16_t runtime_major = 0;
    std::uint16_t runtime_minor = 0;
    std::uint32_t metadata_rva = 0;
    std::uint32_t metadata_size = 0;
    std::uint32_t flags = 0;
    std::uint32_t entry_point = 0;
    std::uint32_t resources_rva = 0;
    std::uint32_t resources_size = 0;
    std::uint32_t strong_name_rva = 0;
    std::uint32_t strong_name_size = 0;
    std::uint32_t vtable_fixups_rva = 0;
    std::uint32_t vtable_fixups_size = 0;
    std::uint32_t export_address_table_jumps_rva = 0;
    std::uint32_t export_address_table_jumps_size = 0;
    std::uint32_t managed_native_header_rva = 0;
    std::uint32_t managed_native_header_size = 0;
    bool il_only = false;
    bool requires_32bit = false;
    bool preferred_32bit = false;
    bool strong_name_signed = false;
    bool native_entry_point = false;
    bool track_debug_data = false;
};

struct pe_coff_type_seed_t {
    pe_coff_type_seed_kind_t kind = pe_coff_type_seed_kind_t::rtti;
    pe_coff_type_seed_origin_t origin = pe_coff_type_seed_origin_t::pe_export;
    std::optional<std::uint64_t> rva;
    std::string name;
};

struct pe_coff_pe_metadata_t {
    pe_artifact_kind_t artifact_kind = pe_artifact_kind_t::executable;
    std::uint16_t machine = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t characteristics = 0;
    std::uint16_t dll_characteristics = 0;
    std::uint32_t timestamp = 0;
    std::vector<pe_data_directory_t> directories;
    std::vector<pe_section_t> sections;
    std::vector<pe_entry_point_t> entry_points;
    std::vector<pe_import_t> imports;
    std::vector<pe_export_t> exports;
    std::vector<pe_relocation_t> relocations;
    std::vector<std::uint32_t> tls_callbacks;
    std::vector<pe_runtime_function_t> runtime_functions;
    std::vector<pe_unwind_record_t> unwind_records;
    std::optional<pe_load_config_t> load_config;
    std::vector<pe_codeview_t> codeview_records;
    std::vector<pe_resource_t> resources;
    std::optional<pe_coff_cli_metadata_t> cli;
};

struct pe_coff_coff_metadata_t {
    coff_artifact_kind_t artifact_kind = coff_artifact_kind_t::object;
    std::uint16_t machine = 0;
    std::uint16_t characteristics = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t symbol_table_offset = 0;
    std::uint32_t symbol_table_count = 0;
    std::uint64_t header_size = 0;
    std::vector<coff_section_t> sections;
    std::vector<coff_symbol_t> symbols;
    std::vector<coff_relocation_t> relocations;
    std::vector<coff_import_object_t> import_objects;
    std::vector<coff_archive_member_t> archive_members;
    std::vector<coff_archive_symbol_t> archive_symbols;
    bool archive_has_long_name_table = false;
    bool archive_has_first_linker_member = false;
    bool archive_has_second_linker_member = false;
    bool archive_has_64bit_symbol_table = false;
    bool archive_has_mixed_machines = false;
};

struct pe_coff_normalized_record_t {
    workspace_image_t image;
    std::optional<pe_coff_pe_metadata_t> pe;
    std::optional<pe_coff_coff_metadata_t> coff;
    std::vector<pe_coff_type_seed_t> type_seeds;
};

struct pe_coff_reader_limits_t {
    pe_parse_limits_t pe_limits;
    coff_parse_limits_t coff_limits;
    std::uint64_t max_cli_metadata_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint32_t max_type_seeds = 65536;
    std::uint32_t max_layout_mappings = 1U << 20;
    std::uint32_t max_layout_regions = 1U << 20;
};

struct pe_coff_metadata_result_t {
    pe_coff_normalized_record_t record;
    image_layout_index_t layout;
    std::shared_ptr<const pe_image_t> pe_adapter;
};

workspace_result_t<pe_coff_metadata_result_t>
read_pe_coff_metadata(const byte_provider_t& provider, const pe_coff_reader_limits_t& limits = {},
                      const cancellation_token_t& cancel = {});

}
