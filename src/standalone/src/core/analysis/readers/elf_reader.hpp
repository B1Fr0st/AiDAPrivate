#pragma once

#include "../workspace/elf_image.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

enum class elf_symbol_seed_source_t : std::uint8_t {
    symbol_table = 0,
    dynamic_symbol_table = 1
};

struct elf_symbol_seed_t {
    elf_symbol_seed_source_t source = elf_symbol_seed_source_t::symbol_table;
    std::uint32_t table_section_index = 0;
    std::uint32_t table_symbol_index = 0;
    std::uint32_t section_index = 0;
    std::string name;
    std::uint64_t size = 0;
    elf_symbol_kind_t kind = elf_symbol_kind_t::unknown;
    std::uint8_t binding = 0;
    std::uint8_t visibility = 0;
    std::optional<address_t> address;
    bool defined = false;
    bool imported = false;
    bool exported = false;
    bool weak = false;
    bool local = false;
};

enum class elf_type_seed_kind_t : std::uint8_t {
    dwarf_info = 0,
    dwarf_types = 1,
    dwarf_names = 2,
    dwarf_abbrev = 3,
    dwarf_strings = 4,
    dwarf_line = 5,
    dwarf_ranges = 6,
    dwarf_locations = 7,
    dwarf_frame = 8,
    dwarf_supplementary = 9,
    compressed_debug = 10,
    embedded_debug = 11,
    debug_link = 12,
    debug_altlink = 13,
    auxiliary_debug = 14
};

struct elf_metadata_region_t {
    std::uint32_t section_index = 0;
    std::optional<std::uint32_t> segment_index;
    std::string name;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::optional<address_t> address;
    bool compressed = false;
};

struct elf_type_seed_t {
    elf_type_seed_kind_t kind = elf_type_seed_kind_t::auxiliary_debug;
    elf_metadata_region_t region;
};

enum class elf_unwind_region_kind_t : std::uint8_t {
    eh_frame = 0,
    eh_frame_header = 1,
    gnu_eh_frame_segment = 2,
    debug_frame = 3,
    arm_exidx = 4
};

struct elf_unwind_region_t {
    elf_unwind_region_kind_t kind = elf_unwind_region_kind_t::eh_frame;
    elf_metadata_region_t region;
};

enum class elf_exception_region_kind_t : std::uint8_t {
    gcc_except_table = 0,
    arm_extab = 1,
    arm_exidx = 2,
    exception_ranges = 3
};

struct elf_exception_region_t {
    elf_exception_region_kind_t kind = elf_exception_region_kind_t::gcc_except_table;
    elf_metadata_region_t region;
};

enum class elf_debug_link_kind_t : std::uint8_t {
    gnu_debuglink = 0,
    gnu_debugaltlink = 1
};

struct elf_debug_link_t {
    elf_debug_link_kind_t kind = elf_debug_link_kind_t::gnu_debuglink;
    std::uint32_t section_index = 0;
    std::string section_name;
    std::string path;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::optional<std::uint32_t> crc32;
    std::optional<std::string> build_id_hex;
};

struct elf_metadata_reader_limits_t {
    elf_parse_limits_t parser_limits;
    std::uint32_t max_symbol_seeds = 1U << 20;
    std::uint32_t max_type_seeds = 1U << 16;
    std::uint32_t max_unwind_regions = 1U << 16;
    std::uint32_t max_exception_regions = 1U << 16;
    std::uint32_t max_debug_links = 1024;
    std::uint64_t max_debug_link_bytes = 1024ULL * 1024ULL;
    std::uint64_t max_materialized_string_bytes = 64ULL * 1024ULL * 1024ULL;
};

struct elf_metadata_t {
    elf_image_t image;
    std::vector<elf_symbol_seed_t> symbol_seeds;
    std::vector<elf_type_seed_t> type_seeds;
    std::vector<elf_unwind_region_t> unwind_regions;
    std::vector<elf_exception_region_t> exception_regions;
    std::vector<elf_debug_link_t> debug_links;
};

workspace_result_t<elf_metadata_t>
read_elf_metadata(const byte_provider_t& provider,
                  const elf_metadata_reader_limits_t& limits,
                  const cancellation_token_t& cancel = {});

workspace_result_t<elf_metadata_t>
read_elf_metadata(const byte_provider_t& provider,
                  const cancellation_token_t& cancel = {});

}
