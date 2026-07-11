#pragma once

#include "byte_provider.hpp"
#include "workspace_types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

inline constexpr std::uint16_t coff_machine_i386 = 0x014c;
inline constexpr std::uint16_t coff_machine_arm = 0x01c0;
inline constexpr std::uint16_t coff_machine_armnt = 0x01c4;
inline constexpr std::uint16_t coff_machine_mips16 = 0x0266;
inline constexpr std::uint16_t coff_machine_mipsfpu = 0x0366;
inline constexpr std::uint16_t coff_machine_mipsfpu16 = 0x0466;
inline constexpr std::uint16_t coff_machine_powerpc = 0x01f0;
inline constexpr std::uint16_t coff_machine_powerpcfp = 0x01f1;
inline constexpr std::uint16_t coff_machine_riscv32 = 0x5032;
inline constexpr std::uint16_t coff_machine_riscv64 = 0x5064;
inline constexpr std::uint16_t coff_machine_amd64 = 0x8664;
inline constexpr std::uint16_t coff_machine_arm64 = 0xaa64;
inline constexpr std::uint16_t coff_machine_arm64ec = 0xa641;

inline constexpr std::uint32_t coff_section_cnt_code = 0x00000020u;
inline constexpr std::uint32_t coff_section_cnt_initialized_data = 0x00000040u;
inline constexpr std::uint32_t coff_section_cnt_uninitialized_data = 0x00000080u;
inline constexpr std::uint32_t coff_section_lnk_nreloc_ovfl = 0x01000000u;
inline constexpr std::uint32_t coff_section_mem_discardable = 0x02000000u;
inline constexpr std::uint32_t coff_section_mem_execute = 0x20000000u;
inline constexpr std::uint32_t coff_section_mem_read = 0x40000000u;
inline constexpr std::uint32_t coff_section_mem_write = 0x80000000u;

inline constexpr std::uint8_t coff_storage_class_end_of_function = 0xff;
inline constexpr std::uint8_t coff_storage_class_null = 0;
inline constexpr std::uint8_t coff_storage_class_automatic = 1;
inline constexpr std::uint8_t coff_storage_class_external = 2;
inline constexpr std::uint8_t coff_storage_class_static = 3;
inline constexpr std::uint8_t coff_storage_class_register = 4;
inline constexpr std::uint8_t coff_storage_class_external_def = 5;
inline constexpr std::uint8_t coff_storage_class_label = 6;
inline constexpr std::uint8_t coff_storage_class_undefined_label = 7;
inline constexpr std::uint8_t coff_storage_class_member_of_struct = 8;
inline constexpr std::uint8_t coff_storage_class_argument = 9;
inline constexpr std::uint8_t coff_storage_class_struct_tag = 10;
inline constexpr std::uint8_t coff_storage_class_member_of_union = 11;
inline constexpr std::uint8_t coff_storage_class_union_tag = 12;
inline constexpr std::uint8_t coff_storage_class_type_definition = 13;
inline constexpr std::uint8_t coff_storage_class_undefined_static = 14;
inline constexpr std::uint8_t coff_storage_class_enum_tag = 15;
inline constexpr std::uint8_t coff_storage_class_member_of_enum = 16;
inline constexpr std::uint8_t coff_storage_class_register_param = 17;
inline constexpr std::uint8_t coff_storage_class_bit_field = 18;
inline constexpr std::uint8_t coff_storage_class_block = 100;
inline constexpr std::uint8_t coff_storage_class_function = 101;
inline constexpr std::uint8_t coff_storage_class_end_of_struct = 102;
inline constexpr std::uint8_t coff_storage_class_file = 103;
inline constexpr std::uint8_t coff_storage_class_section = 104;
inline constexpr std::uint8_t coff_storage_class_weak_external = 105;
inline constexpr std::uint8_t coff_storage_class_clr_token = 107;

#pragma pack(push, 1)

struct coff_file_header_t {
    std::uint16_t machine;
    std::uint16_t number_of_sections;
    std::uint32_t time_date_stamp;
    std::uint32_t pointer_to_symbol_table;
    std::uint32_t number_of_symbols;
    std::uint16_t size_of_optional_header;
    std::uint16_t characteristics;
};
static_assert(sizeof(coff_file_header_t) == 20);

struct coff_section_header_t {
    std::uint8_t name[8];
    std::uint32_t virtual_size;
    std::uint32_t virtual_address;
    std::uint32_t size_of_raw_data;
    std::uint32_t pointer_to_raw_data;
    std::uint32_t pointer_to_relocations;
    std::uint32_t pointer_to_linenumbers;
    std::uint16_t number_of_relocations;
    std::uint16_t number_of_linenumbers;
    std::uint32_t characteristics;
};
static_assert(sizeof(coff_section_header_t) == 40);

struct coff_symbol_t_disk {
    std::uint8_t name[8];
    std::uint32_t value;
    std::int16_t section_number;
    std::uint16_t type;
    std::uint8_t storage_class;
    std::uint8_t number_of_aux_symbols;
};
static_assert(sizeof(coff_symbol_t_disk) == 18);

struct coff_relocation_t_disk {
    std::uint32_t virtual_address;
    std::uint32_t symbol_table_index;
    std::uint16_t type;
};
static_assert(sizeof(coff_relocation_t_disk) == 10);

struct coff_import_object_header_t {
    std::uint16_t sig1;
    std::uint16_t sig2;
    std::uint16_t version;
    std::uint16_t machine;
    std::uint32_t time_date_stamp;
    std::uint32_t size_of_data;
    std::uint16_t ordinal_or_hint;
    std::uint16_t type_and_name_type;
};
static_assert(sizeof(coff_import_object_header_t) == 20);

struct coff_archive_member_header_t {
    char name[16];
    char date[12];
    char uid[6];
    char gid[6];
    char mode[8];
    char size[10];
    char end[2];
};
static_assert(sizeof(coff_archive_member_header_t) == 60);

#pragma pack(pop)

enum class coff_artifact_kind_t : std::uint8_t {
    object = 0,
    import_object = 1,
    archive = 2
};

enum class coff_archive_member_kind_t : std::uint8_t {
    object = 0,
    import_object = 1,
    linker_member = 2,
    long_name_table = 3,
    opaque = 4
};

enum class coff_archive_symbol_table_t : std::uint8_t {
    first_linker_member = 0,
    second_linker_member = 1,
    symbol_table_64 = 2,
    member_scan = 3
};

struct coff_parse_limits_t {
    std::uint32_t max_sections = 65536;
    std::uint32_t max_symbols = 1u << 20;
    std::uint32_t max_relocations = 1u << 22;
    std::uint32_t max_archive_members = 1u << 16;
    std::uint32_t max_archive_symbols = 1u << 20;
    std::uint64_t max_member_size = 1ULL << 32;
    std::uint64_t max_string_table_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_materialized_string_bytes = 128ULL * 1024ULL * 1024ULL;
    std::uint64_t max_total_metadata_bytes = 256ULL * 1024ULL * 1024ULL;
    std::uint64_t max_synthetic_image_size = 1ULL << 36;
    std::uint32_t max_name_bytes = 32768;

    friend bool operator==(const coff_parse_limits_t& lhs,
                           const coff_parse_limits_t& rhs) noexcept {
        return lhs.max_sections == rhs.max_sections && lhs.max_symbols == rhs.max_symbols &&
               lhs.max_relocations == rhs.max_relocations &&
               lhs.max_archive_members == rhs.max_archive_members &&
               lhs.max_archive_symbols == rhs.max_archive_symbols &&
               lhs.max_member_size == rhs.max_member_size &&
               lhs.max_string_table_bytes == rhs.max_string_table_bytes &&
               lhs.max_materialized_string_bytes == rhs.max_materialized_string_bytes &&
               lhs.max_total_metadata_bytes == rhs.max_total_metadata_bytes &&
               lhs.max_synthetic_image_size == rhs.max_synthetic_image_size &&
               lhs.max_name_bytes == rhs.max_name_bytes;
    }

    friend bool operator!=(const coff_parse_limits_t& lhs,
                           const coff_parse_limits_t& rhs) noexcept {
        return !(lhs == rhs);
    }
};

struct coff_section_t {
    std::uint32_t index = 0;
    std::string name;
    std::uint32_t source_virtual_address = 0;
    std::uint64_t normalized_virtual_address = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t relocation_offset = 0;
    std::uint32_t relocation_count = 0;
    std::uint32_t line_number_offset = 0;
    std::uint16_t line_number_count = 0;
    std::uint32_t characteristics = 0;
    bool has_raw_data = false;
};

struct coff_symbol_t {
    std::uint32_t table_index = 0;
    std::string name;
    std::uint32_t value = 0;
    std::int32_t section_number = 0;
    std::uint16_t type = 0;
    std::uint8_t storage_class = 0;
    std::uint8_t auxiliary_symbol_count = 0;
    std::optional<std::uint64_t> normalized_address;
    bool is_defined = false;
    bool is_external = false;
    bool is_weak = false;
    bool is_function = false;
    bool is_section_symbol = false;
};

struct coff_relocation_t {
    std::uint32_t section_index = 0;
    std::uint32_t virtual_address = 0;
    std::uint32_t symbol_table_index = 0;
    std::uint16_t type = 0;
    std::optional<std::uint64_t> normalized_address;
    std::optional<std::uint64_t> target_address;
};

struct coff_import_object_t {
    std::uint16_t version = 0;
    std::uint16_t machine = 0;
    std::uint32_t time_date_stamp = 0;
    std::uint16_t ordinal_or_hint = 0;
    std::uint8_t import_type = 0;
    std::uint8_t name_type = 0;
    std::optional<std::string> symbol_name;
    std::string library_name;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
};

struct coff_archive_member_t {
    std::uint32_t index = 0;
    coff_archive_member_kind_t kind = coff_archive_member_kind_t::opaque;
    std::string name;
    std::uint64_t header_offset = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t size = 0;
    std::uint64_t payload_offset = 0;
    std::uint64_t payload_size = 0;
    std::uint64_t timestamp = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::uint64_t mode = 0;
    std::optional<std::uint16_t> machine;
    std::uint32_t section_count = 0;
    std::uint32_t symbol_count = 0;
    std::uint32_t relocation_count = 0;
};

struct coff_archive_symbol_t {
    std::string name;
    std::uint32_t member_index = 0;
    std::uint64_t member_header_offset = 0;
    coff_archive_symbol_table_t table = coff_archive_symbol_table_t::first_linker_member;
};

struct coff_image_t {
    workspace_image_t normalized;
    coff_artifact_kind_t artifact_kind = coff_artifact_kind_t::object;
    std::uint16_t machine = 0;
    std::uint16_t characteristics = 0;
    std::uint32_t time_date_stamp = 0;
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

architecture_id_t coff_machine_to_architecture(std::uint16_t machine) noexcept;
architecture_mode_t coff_machine_to_mode(std::uint16_t machine) noexcept;
abi_id_t coff_machine_to_abi(std::uint16_t machine) noexcept;
const char* coff_machine_name(std::uint16_t machine) noexcept;

workspace_result_t<workspace_image_t>
parse_coff(const byte_provider_t& provider, const cancellation_token_t& cancel = {});

workspace_result_t<workspace_image_t>
parse_coff(const byte_provider_t& provider, const coff_parse_limits_t& limits,
           const cancellation_token_t& cancel = {});

workspace_result_t<coff_image_t>
parse_coff_image(const byte_provider_t& provider, const cancellation_token_t& cancel = {});

workspace_result_t<coff_image_t>
parse_coff_image(const byte_provider_t& provider, const coff_parse_limits_t& limits,
                 const cancellation_token_t& cancel = {});

workspace_result_t<bool>
is_coff_file(const byte_provider_t& provider, const cancellation_token_t& cancel = {});

}
