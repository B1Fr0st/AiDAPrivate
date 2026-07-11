#pragma once

#include "byte_provider.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

enum class dex_container_kind_t : std::uint8_t {
    unknown = 0,
    dex,
    compact_dex,
    oat,
    vdex
};

enum class dalvik_reference_kind_t : std::uint8_t {
    none = 0,
    string,
    type,
    field,
    method,
    proto,
    call_site,
    method_handle
};

struct dex_parse_limits_t {
    std::uint64_t max_file_size = 512ULL * 1024ULL * 1024ULL;
    std::uint64_t max_container_scan_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint32_t max_embedded_dex_files = 64;
    std::uint32_t max_map_items = 65536;
    std::uint32_t max_string_ids = 1U << 20;
    std::uint32_t max_type_ids = 1U << 20;
    std::uint32_t max_proto_ids = 1U << 20;
    std::uint32_t max_field_ids = 1U << 20;
    std::uint32_t max_method_ids = 1U << 20;
    std::uint32_t max_class_defs = 1U << 20;
    std::uint32_t max_parameters_per_proto = 65536;
    std::uint32_t max_class_data_items = 1U << 20;
    std::uint32_t max_code_units_per_method = 8U << 20;
    std::uint64_t max_total_code_units = 64ULL << 20;
    std::uint32_t max_instruction_records_per_method = 8U << 20;
    std::uint64_t max_total_instruction_records = 64ULL << 20;
    std::uint32_t max_try_items_per_method = 1U << 20;
    std::uint32_t max_catch_handlers_per_method = 1U << 20;
    std::uint32_t max_catch_pairs_per_handler = 65536;
    std::uint32_t max_debug_parameters = 65536;
    std::uint32_t max_debug_positions_per_method = 1U << 20;
    std::uint64_t max_total_debug_positions = 8ULL << 20;
    std::uint64_t max_string_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_single_string_bytes = 1ULL * 1024ULL * 1024ULL;
};

struct dex_compact_dex_features_t {
    std::uint32_t declared_header_size = 0;
    std::uint32_t feature_flags = 0;
    std::uint32_t unknown_feature_flags = 0;
    bool default_methods = false;
    bool compact_code_items = true;
    bool debug_info_offset_table = true;
};

struct dex_container_info_t {
    dex_container_kind_t kind = dex_container_kind_t::unknown;
    std::string version;
    std::uint64_t header_size = 0;
    std::optional<dex_compact_dex_features_t> compact_features;
    std::vector<std::uint64_t> embedded_dex_offsets;
};

struct dex_header_t {
    std::array<std::uint8_t, 8> magic{};
    std::uint32_t checksum = 0;
    std::array<std::uint8_t, 20> signature{};
    std::uint32_t file_size = 0;
    std::uint32_t header_size = 0;
    std::uint32_t endian_tag = 0;
    std::uint32_t link_size = 0;
    std::uint32_t link_offset = 0;
    std::uint32_t map_offset = 0;
    std::uint32_t string_ids_size = 0;
    std::uint32_t string_ids_offset = 0;
    std::uint32_t type_ids_size = 0;
    std::uint32_t type_ids_offset = 0;
    std::uint32_t proto_ids_size = 0;
    std::uint32_t proto_ids_offset = 0;
    std::uint32_t field_ids_size = 0;
    std::uint32_t field_ids_offset = 0;
    std::uint32_t method_ids_size = 0;
    std::uint32_t method_ids_offset = 0;
    std::uint32_t class_defs_size = 0;
    std::uint32_t class_defs_offset = 0;
    std::uint32_t data_size = 0;
    std::uint32_t data_offset = 0;
};

struct dex_map_item_t {
    std::uint16_t type = 0;
    std::uint32_t size = 0;
    std::uint32_t offset = 0;
};

struct dex_string_t {
    std::uint32_t index = 0;
    std::uint32_t data_offset = 0;
    std::uint32_t utf16_length = 0;
    std::string value;
};

struct dex_type_t {
    std::uint32_t index = 0;
    std::uint32_t descriptor_string_index = 0;
    std::string descriptor;
};

struct dex_proto_t {
    std::uint32_t index = 0;
    std::uint32_t shorty_string_index = 0;
    std::uint32_t return_type_index = 0;
    std::uint32_t parameters_offset = 0;
    std::string shorty;
    std::string descriptor;
    std::vector<std::uint16_t> parameter_type_indices;
};

struct dex_field_t {
    std::uint32_t index = 0;
    std::uint16_t class_type_index = 0;
    std::uint16_t type_index = 0;
    std::uint32_t name_string_index = 0;
    std::string class_descriptor;
    std::string type_descriptor;
    std::string name;
};

struct dex_method_t {
    std::uint32_t index = 0;
    std::uint16_t class_type_index = 0;
    std::uint16_t proto_index = 0;
    std::uint32_t name_string_index = 0;
    std::string class_descriptor;
    std::string name;
    std::string descriptor;
};

struct dalvik_instruction_t {
    std::uint32_t code_unit_offset = 0;
    std::uint64_t file_offset = 0;
    std::uint16_t opcode_unit = 0;
    std::uint8_t opcode = 0;
    std::uint16_t width_code_units = 0;
    const char* mnemonic = "invalid";
    bool payload = false;
    dalvik_reference_kind_t reference_kind = dalvik_reference_kind_t::none;
    std::optional<std::uint32_t> reference_index;
    std::optional<std::uint32_t> secondary_reference_index;
    std::optional<std::int64_t> literal;
    std::optional<std::int32_t> branch_target;
};

struct dex_catch_handler_t {
    std::uint32_t relative_offset = 0;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> typed_handlers;
    std::optional<std::uint32_t> catch_all_address;
};

struct dex_try_item_t {
    std::uint32_t start_address = 0;
    std::uint16_t instruction_count = 0;
    std::uint16_t handler_offset = 0;
};

struct dex_debug_position_t {
    std::uint32_t address = 0;
    std::int32_t line = 0;
    std::optional<std::uint32_t> source_file_string_index;
};

struct dex_debug_info_t {
    std::uint32_t offset = 0;
    std::uint32_t line_start = 0;
    std::vector<std::optional<std::uint32_t>> parameter_name_string_indices;
    std::vector<dex_debug_position_t> positions;
};

struct dex_code_item_t {
    std::uint32_t offset = 0;
    std::uint16_t registers_size = 0;
    std::uint16_t ins_size = 0;
    std::uint16_t outs_size = 0;
    std::uint16_t tries_size = 0;
    std::uint32_t debug_info_offset = 0;
    std::uint32_t instruction_count = 0;
    std::vector<dalvik_instruction_t> instructions;
    std::vector<dex_try_item_t> tries;
    std::vector<dex_catch_handler_t> catch_handlers;
    std::optional<dex_debug_info_t> debug_info;
};

struct dex_encoded_field_t {
    std::uint32_t field_index = 0;
    std::uint32_t access_flags = 0;
    bool is_static = false;
};

struct dex_encoded_method_t {
    std::uint32_t method_index = 0;
    std::uint32_t access_flags = 0;
    std::uint32_t code_offset = 0;
    bool is_direct = false;
    std::shared_ptr<const dex_code_item_t> code;
};

struct dex_class_def_t {
    std::uint32_t index = 0;
    std::uint32_t class_type_index = 0;
    std::uint32_t access_flags = 0;
    std::uint32_t superclass_type_index = 0xffffffffU;
    std::uint32_t interfaces_offset = 0;
    std::uint32_t source_file_string_index = 0xffffffffU;
    std::uint32_t annotations_offset = 0;
    std::uint32_t class_data_offset = 0;
    std::uint32_t static_values_offset = 0;
    std::string class_descriptor;
    std::optional<std::string> superclass_descriptor;
    std::optional<std::string> source_file;
    std::vector<std::uint16_t> interface_type_indices;
    std::vector<dex_encoded_field_t> static_fields;
    std::vector<dex_encoded_field_t> instance_fields;
    std::vector<dex_encoded_method_t> direct_methods;
    std::vector<dex_encoded_method_t> virtual_methods;
};

struct dex_managed_identity_t {
    dex_container_kind_t container_kind = dex_container_kind_t::unknown;
    std::string version;
    std::uint64_t dex_offset = 0;
    std::array<std::uint8_t, 20> dex_signature{};
    std::uint32_t dex_checksum = 0;
    std::vector<std::string> class_descriptors;
    std::vector<std::string> source_files;
};

struct dex_image_t {
    workspace_image_t normalized;
    dex_container_info_t container;
    dex_header_t header;
    dex_managed_identity_t managed_identity;
    std::uint64_t dex_offset = 0;
    std::vector<dex_map_item_t> map_items;
    std::vector<dex_string_t> strings;
    std::vector<dex_type_t> types;
    std::vector<dex_proto_t> protos;
    std::vector<dex_field_t> fields;
    std::vector<dex_method_t> methods;
    std::vector<dex_class_def_t> classes;
};

const char* dex_container_kind_name(dex_container_kind_t kind) noexcept;
const char* dalvik_opcode_mnemonic(std::uint8_t opcode) noexcept;

workspace_result_t<dex_container_info_t>
detect_dex_container(const byte_provider_t& provider, const cancellation_token_t& cancel = {});

workspace_result_t<bool>
is_dex_file(const byte_provider_t& provider, const cancellation_token_t& cancel = {});

workspace_result_t<bool>
is_oat_file(const byte_provider_t& provider, const cancellation_token_t& cancel = {});

workspace_result_t<bool>
is_vdex_file(const byte_provider_t& provider, const cancellation_token_t& cancel = {});

workspace_result_t<dex_image_t>
parse_dex_image(const byte_provider_t& provider, const dex_parse_limits_t& limits,
                const cancellation_token_t& cancel = {});

workspace_result_t<dex_image_t>
parse_dex_image(const byte_provider_t& provider, const cancellation_token_t& cancel = {});

workspace_result_t<workspace_image_t>
parse_dex(const byte_provider_t& provider, const dex_parse_limits_t& limits,
          const cancellation_token_t& cancel = {});

workspace_result_t<workspace_image_t>
parse_dex(const byte_provider_t& provider, const cancellation_token_t& cancel = {});

}
