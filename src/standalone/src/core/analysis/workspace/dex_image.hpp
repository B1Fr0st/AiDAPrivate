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
    std::uint32_t debug_info_offsets_position = 0;
    std::uint32_t debug_info_offsets_table_offset = 0;
    std::uint32_t debug_info_base = 0;
    std::uint32_t owned_data_begin = 0;
    std::uint32_t owned_data_end = 0;
    bool default_methods = false;
    bool compact_code_items = true;
    bool debug_info_offset_table = true;

    bool valid(std::uint32_t method_count, std::uint32_t data_size) const noexcept;
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
    std::uint32_t instructions_offset = 0;
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
    std::uint64_t payload_size = 0;
    std::vector<dex_map_item_t> map_items;
    std::vector<dex_string_t> strings;
    std::vector<dex_type_t> types;
    std::vector<dex_proto_t> protos;
    std::vector<dex_field_t> fields;
    std::vector<dex_method_t> methods;
    std::vector<dex_class_def_t> classes;
};

const char* dex_container_kind_name(dex_container_kind_t kind) noexcept;
inline const char* dalvik_opcode_mnemonic(std::uint8_t opcode) noexcept {
    switch (opcode) {
        case 0x00: return "nop"; case 0x01: return "move"; case 0x02: return "move/from16";
        case 0x03: return "move/16"; case 0x04: return "move-wide"; case 0x05: return "move-wide/from16";
        case 0x06: return "move-wide/16"; case 0x07: return "move-object"; case 0x08: return "move-object/from16";
        case 0x09: return "move-object/16"; case 0x0a: return "move-result"; case 0x0b: return "move-result-wide";
        case 0x0c: return "move-result-object"; case 0x0d: return "move-exception"; case 0x0e: return "return-void";
        case 0x0f: return "return"; case 0x10: return "return-wide"; case 0x11: return "return-object";
        case 0x12: return "const/4"; case 0x13: return "const/16"; case 0x14: return "const";
        case 0x15: return "const/high16"; case 0x16: return "const-wide/16"; case 0x17: return "const-wide/32";
        case 0x18: return "const-wide"; case 0x19: return "const-wide/high16"; case 0x1a: return "const-string";
        case 0x1b: return "const-string/jumbo"; case 0x1c: return "const-class"; case 0x1d: return "monitor-enter";
        case 0x1e: return "monitor-exit"; case 0x1f: return "check-cast"; case 0x20: return "instance-of";
        case 0x21: return "array-length"; case 0x22: return "new-instance"; case 0x23: return "new-array";
        case 0x24: return "filled-new-array"; case 0x25: return "filled-new-array/range"; case 0x26: return "fill-array-data";
        case 0x27: return "throw"; case 0x28: return "goto"; case 0x29: return "goto/16";
        case 0x2a: return "goto/32"; case 0x2b: return "packed-switch"; case 0x2c: return "sparse-switch";
        case 0x2d: return "cmpl-float"; case 0x2e: return "cmpg-float"; case 0x2f: return "cmpl-double";
        case 0x30: return "cmpg-double"; case 0x31: return "cmp-long"; case 0x32: return "if-eq";
        case 0x33: return "if-ne"; case 0x34: return "if-lt"; case 0x35: return "if-ge";
        case 0x36: return "if-gt"; case 0x37: return "if-le"; case 0x38: return "if-eqz";
        case 0x39: return "if-nez"; case 0x3a: return "if-ltz"; case 0x3b: return "if-gez";
        case 0x3c: return "if-gtz"; case 0x3d: return "if-lez";
        case 0x44: return "aget"; case 0x45: return "aget-wide"; case 0x46: return "aget-object";
        case 0x47: return "aget-boolean"; case 0x48: return "aget-byte"; case 0x49: return "aget-char";
        case 0x4a: return "aget-short"; case 0x4b: return "aput"; case 0x4c: return "aput-wide";
        case 0x4d: return "aput-object"; case 0x4e: return "aput-boolean"; case 0x4f: return "aput-byte";
        case 0x50: return "aput-char"; case 0x51: return "aput-short";
        case 0x52: return "iget"; case 0x53: return "iget-wide"; case 0x54: return "iget-object";
        case 0x55: return "iget-boolean"; case 0x56: return "iget-byte"; case 0x57: return "iget-char";
        case 0x58: return "iget-short"; case 0x59: return "iput"; case 0x5a: return "iput-wide";
        case 0x5b: return "iput-object"; case 0x5c: return "iput-boolean"; case 0x5d: return "iput-byte";
        case 0x5e: return "iput-char"; case 0x5f: return "iput-short";
        case 0x60: return "sget"; case 0x61: return "sget-wide"; case 0x62: return "sget-object";
        case 0x63: return "sget-boolean"; case 0x64: return "sget-byte"; case 0x65: return "sget-char";
        case 0x66: return "sget-short"; case 0x67: return "sput"; case 0x68: return "sput-wide";
        case 0x69: return "sput-object"; case 0x6a: return "sput-boolean"; case 0x6b: return "sput-byte";
        case 0x6c: return "sput-char"; case 0x6d: return "sput-short";
        case 0x6e: return "invoke-virtual"; case 0x6f: return "invoke-super"; case 0x70: return "invoke-direct";
        case 0x71: return "invoke-static"; case 0x72: return "invoke-interface";
        case 0x74: return "invoke-virtual/range"; case 0x75: return "invoke-super/range";
        case 0x76: return "invoke-direct/range"; case 0x77: return "invoke-static/range";
        case 0x78: return "invoke-interface/range";
        case 0x7b: return "neg-int"; case 0x7c: return "not-int"; case 0x7d: return "neg-long";
        case 0x7e: return "not-long"; case 0x7f: return "neg-float"; case 0x80: return "neg-double";
        case 0x81: return "int-to-long"; case 0x82: return "int-to-float"; case 0x83: return "int-to-double";
        case 0x84: return "long-to-int"; case 0x85: return "long-to-float"; case 0x86: return "long-to-double";
        case 0x87: return "float-to-int"; case 0x88: return "float-to-long"; case 0x89: return "float-to-double";
        case 0x8a: return "double-to-int"; case 0x8b: return "double-to-long"; case 0x8c: return "double-to-float";
        case 0x8d: return "int-to-byte"; case 0x8e: return "int-to-char"; case 0x8f: return "int-to-short";
        case 0x90: return "add-int"; case 0x91: return "sub-int"; case 0x92: return "mul-int";
        case 0x93: return "div-int"; case 0x94: return "rem-int"; case 0x95: return "and-int";
        case 0x96: return "or-int"; case 0x97: return "xor-int"; case 0x98: return "shl-int";
        case 0x99: return "shr-int"; case 0x9a: return "ushr-int"; case 0x9b: return "add-long";
        case 0x9c: return "sub-long"; case 0x9d: return "mul-long"; case 0x9e: return "div-long";
        case 0x9f: return "rem-long"; case 0xa0: return "and-long"; case 0xa1: return "or-long";
        case 0xa2: return "xor-long"; case 0xa3: return "shl-long"; case 0xa4: return "shr-long";
        case 0xa5: return "ushr-long"; case 0xa6: return "add-float"; case 0xa7: return "sub-float";
        case 0xa8: return "mul-float"; case 0xa9: return "div-float"; case 0xaa: return "rem-float";
        case 0xab: return "add-double"; case 0xac: return "sub-double"; case 0xad: return "mul-double";
        case 0xae: return "div-double"; case 0xaf: return "rem-double";
        case 0xb0: return "add-int/2addr"; case 0xb1: return "sub-int/2addr"; case 0xb2: return "mul-int/2addr";
        case 0xb3: return "div-int/2addr"; case 0xb4: return "rem-int/2addr"; case 0xb5: return "and-int/2addr";
        case 0xb6: return "or-int/2addr"; case 0xb7: return "xor-int/2addr"; case 0xb8: return "shl-int/2addr";
        case 0xb9: return "shr-int/2addr"; case 0xba: return "ushr-int/2addr"; case 0xbb: return "add-long/2addr";
        case 0xbc: return "sub-long/2addr"; case 0xbd: return "mul-long/2addr"; case 0xbe: return "div-long/2addr";
        case 0xbf: return "rem-long/2addr"; case 0xc0: return "and-long/2addr"; case 0xc1: return "or-long/2addr";
        case 0xc2: return "xor-long/2addr"; case 0xc3: return "shl-long/2addr"; case 0xc4: return "shr-long/2addr";
        case 0xc5: return "ushr-long/2addr"; case 0xc6: return "add-float/2addr"; case 0xc7: return "sub-float/2addr";
        case 0xc8: return "mul-float/2addr"; case 0xc9: return "div-float/2addr"; case 0xca: return "rem-float/2addr";
        case 0xcb: return "add-double/2addr"; case 0xcc: return "sub-double/2addr"; case 0xcd: return "mul-double/2addr";
        case 0xce: return "div-double/2addr"; case 0xcf: return "rem-double/2addr";
        case 0xd0: return "add-int/lit16"; case 0xd1: return "rsub-int"; case 0xd2: return "mul-int/lit16";
        case 0xd3: return "div-int/lit16"; case 0xd4: return "rem-int/lit16"; case 0xd5: return "and-int/lit16";
        case 0xd6: return "or-int/lit16"; case 0xd7: return "xor-int/lit16"; case 0xd8: return "add-int/lit8";
        case 0xd9: return "rsub-int/lit8"; case 0xda: return "mul-int/lit8"; case 0xdb: return "div-int/lit8";
        case 0xdc: return "rem-int/lit8"; case 0xdd: return "and-int/lit8"; case 0xde: return "or-int/lit8";
        case 0xdf: return "xor-int/lit8"; case 0xe0: return "shl-int/lit8"; case 0xe1: return "shr-int/lit8";
        case 0xe2: return "ushr-int/lit8"; case 0xfa: return "invoke-polymorphic";
        case 0xfb: return "invoke-polymorphic/range"; case 0xfc: return "invoke-custom";
        case 0xfd: return "invoke-custom/range"; case 0xfe: return "const-method-handle";
        case 0xff: return "const-method-type";
        default: return "reserved";
    }
}

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
