#pragma once

#include "../workspace/byte_provider.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis::readers {

enum class macho_container_kind_t : std::uint8_t {
    thin = 0,
    fat = 1,
    archive = 2
};

enum class macho_file_kind_t : std::uint8_t {
    unknown = 0,
    object = 1,
    executable = 2,
    fixed_vm_library = 3,
    core = 4,
    preload = 5,
    dylib = 6,
    dylinker = 7,
    bundle = 8,
    dylib_stub = 9,
    dsym = 10,
    kext_bundle = 11,
    fileset = 12
};

enum class macho_bind_stream_kind_t : std::uint8_t {
    regular = 0,
    weak = 1,
    lazy = 2
};

struct macho_reader_limits_t {
    std::uint64_t max_input_bytes = 256ULL * 1024ULL * 1024ULL;
    std::uint64_t max_metadata_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_string_bytes = 8ULL * 1024ULL * 1024ULL;
    std::uint64_t max_linkedit_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint32_t max_archive_members = 65536;
    std::uint32_t max_fat_slices = 256;
    std::uint32_t max_load_commands = 65536;
    std::uint32_t max_segments = 65536;
    std::uint32_t max_sections = 1U << 20;
    std::uint32_t max_symbols = 1U << 20;
    std::uint32_t max_dylibs = 65536;
    std::uint32_t max_binds = 1U << 20;
    std::uint32_t max_rebases = 1U << 20;
    std::uint32_t max_exports = 1U << 20;
    std::uint32_t max_relocations = 1U << 22;
    std::uint32_t max_unwind_records = 1U << 20;
    std::uint32_t max_metadata_seeds = 1U << 20;
    std::uint32_t max_code_signature_slots = 65536;
    std::uint32_t max_export_depth = 128;
};

struct macho_slice_identity_t {
    std::uint64_t container_offset = 0;
    std::uint64_t size = 0;
    std::int32_t cpu_type = 0;
    std::int32_t cpu_subtype = 0;
    architecture_id_t architecture = architecture_id_t::unknown;
    endian_t endian = endian_t::little;
    bool is_64_bit = false;
    std::optional<std::uint32_t> archive_member_ordinal;

    std::string stable_key() const;
};

struct macho_load_command_metadata_t {
    std::uint32_t ordinal = 0;
    std::uint32_t command = 0;
    std::uint64_t offset = 0;
    std::uint32_t size = 0;
    std::string kind;
};

struct macho_section_metadata_t {
    std::uint32_t index = 0;
    std::string segment_name;
    std::string section_name;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::uint64_t file_offset = 0;
    std::uint32_t alignment = 0;
    std::uint32_t relocation_offset = 0;
    std::uint32_t relocation_count = 0;
    std::uint32_t flags = 0;
    std::uint32_t reserved1 = 0;
    std::uint32_t reserved2 = 0;
    std::uint32_t reserved3 = 0;
};

struct macho_segment_metadata_t {
    std::uint32_t index = 0;
    std::string name;
    std::uint64_t virtual_address = 0;
    std::uint64_t virtual_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::int32_t maximum_protection = 0;
    std::int32_t initial_protection = 0;
    std::uint32_t flags = 0;
    std::vector<macho_section_metadata_t> sections;
};

struct macho_dylib_metadata_t {
    std::uint32_t command = 0;
    std::string path;
    std::uint32_t timestamp = 0;
    std::uint32_t current_version = 0;
    std::uint32_t compatibility_version = 0;
};

struct macho_symbol_metadata_t {
    std::uint32_t index = 0;
    std::string name;
    std::uint64_t value = 0;
    std::uint8_t type = 0;
    std::uint8_t section = 0;
    std::uint16_t descriptor = 0;
};

struct macho_binding_metadata_t {
    macho_bind_stream_kind_t stream = macho_bind_stream_kind_t::regular;
    std::uint32_t segment_index = 0;
    std::uint64_t address = 0;
    std::uint8_t type = 0;
    std::int64_t library_ordinal = 0;
    std::string symbol;
    std::int64_t addend = 0;
    std::uint8_t flags = 0;
};

struct macho_rebase_metadata_t {
    std::uint32_t segment_index = 0;
    std::uint64_t address = 0;
    std::uint8_t type = 0;
};

struct macho_export_metadata_t {
    std::string name;
    std::uint64_t flags = 0;
    std::uint64_t address = 0;
    std::optional<std::uint64_t> other;
    std::optional<std::string> import_name;
};

struct macho_relocation_metadata_t {
    std::optional<std::uint32_t> section_index;
    std::uint64_t address = 0;
    std::uint32_t symbol_number = 0;
    std::uint8_t type = 0;
    std::uint8_t length = 0;
    bool pc_relative = false;
    bool external = false;
    bool scattered = false;
    std::optional<std::uint64_t> target_value;
};

struct macho_unwind_metadata_t {
    std::string kind;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::optional<std::uint64_t> function_address;
};

struct macho_exception_metadata_t {
    std::string kind;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
};

struct macho_metadata_seed_t {
    std::string kind;
    std::string segment_name;
    std::string section_name;
    std::uint64_t address = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
};

struct macho_code_signature_slot_t {
    std::uint32_t type = 0;
    std::uint32_t offset = 0;
    std::uint32_t magic = 0;
    std::uint32_t length = 0;
};

struct macho_code_signature_metadata_t {
    bool present = false;
    bool parsed = false;
    bool verified = false;
    bool trusted = false;
    std::uint64_t command_offset = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t data_size = 0;
    std::uint32_t superblob_magic = 0;
    std::uint32_t superblob_length = 0;
    std::vector<macho_code_signature_slot_t> slots;
};

struct macho_slice_metadata_t {
    macho_slice_identity_t identity;
    macho_file_kind_t file_kind = macho_file_kind_t::unknown;
    std::uint32_t file_type = 0;
    std::uint32_t flags = 0;
    std::uint64_t header_size = 0;
    std::vector<macho_load_command_metadata_t> load_commands;
    std::vector<macho_segment_metadata_t> segments;
    std::vector<macho_dylib_metadata_t> dylibs;
    std::vector<macho_symbol_metadata_t> symbols;
    std::vector<macho_binding_metadata_t> bindings;
    std::vector<macho_rebase_metadata_t> rebases;
    std::vector<macho_export_metadata_t> exports;
    std::vector<macho_relocation_metadata_t> relocations;
    std::vector<macho_unwind_metadata_t> unwind;
    std::vector<macho_exception_metadata_t> exceptions;
    std::vector<macho_metadata_seed_t> metadata_seeds;
    macho_code_signature_metadata_t code_signature;
};

struct macho_archive_member_metadata_t {
    std::uint32_t ordinal = 0;
    std::string name;
    std::uint64_t header_offset = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t data_size = 0;
    bool embedded = false;
    bool mach_metadata_available = false;
};

struct macho_metadata_document_t {
    macho_container_kind_t container_kind = macho_container_kind_t::thin;
    bool thin_archive = false;
    std::vector<macho_archive_member_metadata_t> archive_members;
    std::vector<macho_slice_metadata_t> slices;

    std::vector<std::string> differential_records() const;
};

workspace_result_t<macho_metadata_document_t> read_macho_metadata(
    const byte_provider_t& provider, const macho_reader_limits_t& limits = {},
    const cancellation_token_t& cancel = {});

workspace_result_t<macho_metadata_document_t> read_macho_metadata(
    const std::vector<std::uint8_t>& bytes, const macho_reader_limits_t& limits = {},
    const cancellation_token_t& cancel = {});

}
