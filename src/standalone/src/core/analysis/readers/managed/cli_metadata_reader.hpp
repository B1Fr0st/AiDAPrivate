#pragma once

#include "managed_reader_contracts.hpp"

#include "../../workspace/byte_provider.hpp"
#include "../../workspace/pe_image.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis::readers::managed {

inline constexpr std::uint32_t cli_metadata_magic = 0x424A5342u;
inline constexpr std::uint16_t cli_metadata_major_version = 1;
inline constexpr std::uint16_t cli_metadata_minor_version = 1;
inline constexpr std::uint8_t cli_heap_sizes_large_strings = 0x01u;
inline constexpr std::uint8_t cli_heap_sizes_large_guid = 0x02u;
inline constexpr std::uint8_t cli_heap_sizes_large_blob = 0x04u;
inline constexpr std::uint8_t cli_method_head_tiny_format = 0x02u;
inline constexpr std::uint8_t cli_method_head_fat_format = 0x03u;
inline constexpr std::uint8_t cli_method_head_more_sects = 0x08u;
inline constexpr std::uint8_t cli_method_head_init_locals = 0x10u;
inline constexpr std::uint8_t cli_cor_section_eh_table = 0x01u;
inline constexpr std::uint8_t cli_cor_section_fat_format = 0x40u;
inline constexpr std::uint8_t cli_cor_section_more_sects = 0x80u;
inline constexpr std::uint32_t cli_pe_cli_directory_index = 14;
inline constexpr std::uint32_t cli_max_tables = 64;

enum class cli_table_id_t : std::uint8_t {
    module = 0x00,
    type_ref = 0x01,
    type_def = 0x02,
    field = 0x04,
    method_def = 0x06,
    param = 0x08,
    interface_impl = 0x09,
    member_ref = 0x0A,
    constant = 0x0B,
    custom_attribute = 0x0C,
    field_marshal = 0x0D,
    decl_security = 0x0E,
    class_layout = 0x0F,
    field_layout = 0x10,
    semantics = 0x11,
    impl_map = 0x12,
    field_rva = 0x13,
    assembly = 0x14,
    assembly_ref = 0x15,
    file = 0x16,
    exported_type = 0x17,
    manifest_resource = 0x18,
    nested_class = 0x19,
    generic_param = 0x1A,
    method_spec = 0x1B,
    generic_param_constraint = 0x1C
};

struct cli_stream_header_t {
    std::string name;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
};

struct cli_metadata_header_t {
    std::uint32_t magic = 0;
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    std::uint32_t version_length = 0;
    std::string version_string;
    std::uint16_t flags = 0;
    std::uint16_t stream_count = 0;
    std::vector<cli_stream_header_t> streams;
    std::uint64_t root_offset = 0;
    std::uint64_t root_size = 0;
};

struct cli_table_row_counts_t {
    std::array<std::uint32_t, cli_max_tables> counts{};
    std::uint64_t valid_mask = 0;
    std::uint64_t sorted_mask = 0;
    std::uint8_t heap_sizes = 0;
    std::uint16_t tables_major = 0;
    std::uint16_t tables_minor = 0;
    std::uint64_t table_data_offset = 0;
};

struct cli_module_row_t {
    std::uint16_t generation = 0;
    std::string name;
    std::uint32_t mvid_index = 0;
    std::uint32_t enc_id_index = 0;
    std::uint32_t enc_base_id_index = 0;
};

struct cli_type_ref_row_t {
    std::uint32_t resolution_scope_index = 0;
    std::uint8_t resolution_scope_tag = 0;
    std::string type_name;
    std::string type_namespace;
    std::string assembly_ref_name;
};

struct cli_type_def_row_t {
    std::uint32_t flags = 0;
    std::string type_name;
    std::string type_namespace;
    std::uint32_t extends_index = 0;
    std::uint8_t extends_tag = 0;
    std::uint32_t field_list_index = 0;
    std::uint32_t method_list_index = 0;
    std::string base_type_name;
    bool is_interface = false;
    bool is_abstract = false;
    bool is_sealed = false;
    bool is_nested = false;
};

struct cli_field_row_t {
    std::uint16_t flags = 0;
    std::string name;
    std::vector<std::uint8_t> signature_blob;
    std::uint32_t declaring_type_token = 0;
    bool is_static = false;
    bool is_literal = false;
    bool is_init_only = false;
};

struct cli_method_def_row_t {
    std::uint32_t rva = 0;
    std::uint16_t impl_flags = 0;
    std::uint16_t flags = 0;
    std::string name;
    std::vector<std::uint8_t> signature_blob;
    std::uint32_t param_list_index = 0;
    std::uint32_t declaring_type_token = 0;
    bool is_static = false;
    bool is_abstract = false;
    bool is_virtual = false;
    bool is_native = false;
    bool has_body = false;
};

struct cli_member_ref_row_t {
    std::uint8_t class_tag = 0;
    std::uint32_t class_index = 0;
    std::string name;
    std::vector<std::uint8_t> signature_blob;
    std::string declaring_type_name;
    managed_reference_kind_t reference_kind = managed_reference_kind_t::type_reference;
};

struct cli_assembly_row_t {
    std::uint32_t hash_alg_id = 0;
    std::uint32_t major_version = 0;
    std::uint32_t minor_version = 0;
    std::uint32_t build_number = 0;
    std::uint32_t revision_number = 0;
    std::uint32_t flags = 0;
    std::vector<std::uint8_t> public_key_blob;
    std::string name;
    std::string culture;
};

struct cli_assembly_ref_row_t {
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    std::uint16_t build_number = 0;
    std::uint16_t revision_number = 0;
    std::uint32_t flags = 0;
    std::vector<std::uint8_t> public_key_or_token_blob;
    std::string name;
    std::string culture;
    std::uint32_t hash_value_index = 0;
};

struct cli_nested_class_row_t {
    std::uint32_t nested_class_index = 0;
    std::uint32_t enclosing_class_index = 0;
};

struct cli_generic_param_row_t {
    std::uint16_t number = 0;
    std::uint16_t flags = 0;
    std::uint8_t owner_tag = 0;
    std::uint32_t owner_index = 0;
    std::string name;
};

struct cli_method_spec_row_t {
    std::uint8_t method_tag = 0;
    std::uint32_t method_index = 0;
    std::vector<std::uint8_t> instantiation_blob;
};

struct cli_custom_attribute_row_t {
    std::uint8_t parent_tag = 0;
    std::uint32_t parent_index = 0;
    std::uint8_t type_tag = 0;
    std::uint32_t type_index = 0;
    std::vector<std::uint8_t> value_blob;
    std::uint32_t parent_token = 0;
};

struct cli_manifest_resource_row_t {
    std::uint32_t offset = 0;
    std::uint32_t flags = 0;
    std::string name;
    std::uint8_t implementation_tag = 0;
    std::uint32_t implementation_index = 0;
};

struct cli_param_row_t {
    std::uint16_t flags = 0;
    std::uint16_t sequence = 0;
    std::string name;
};

struct cli_exception_clause_t {
    std::uint32_t flags = 0;
    std::uint32_t try_offset = 0;
    std::uint32_t try_length = 0;
    std::uint32_t handler_offset = 0;
    std::uint32_t handler_length = 0;
    std::uint32_t class_token_or_filter_offset = 0;
    bool is_finally = false;
    bool is_filter = false;
    bool is_catch_all = false;
    std::optional<std::string> catch_type_name;
    std::optional<std::uint32_t> catch_type_token;
};

struct cli_method_body_t {
    std::uint32_t method_token = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    bool is_fat = false;
    std::uint16_t max_stack = 0;
    std::uint32_t local_token = 0;
    std::vector<std::uint8_t> code_bytes;
    std::vector<std::uint8_t> local_signature_blob;
    std::vector<cli_exception_clause_t> exception_clauses;
};

struct cli_metadata_t {
    cli_metadata_header_t header;
    cli_table_row_counts_t table_counts;
    cli_module_row_t module;
    std::vector<cli_type_ref_row_t> type_refs;
    std::vector<cli_type_def_row_t> type_defs;
    std::vector<cli_field_row_t> fields;
    std::vector<cli_method_def_row_t> method_defs;
    std::vector<cli_member_ref_row_t> member_refs;
    std::vector<cli_param_row_t> params;
    std::optional<cli_assembly_row_t> assembly;
    std::vector<cli_assembly_ref_row_t> assembly_refs;
    std::vector<cli_nested_class_row_t> nested_classes;
    std::vector<cli_generic_param_row_t> generic_params;
    std::vector<cli_method_spec_row_t> method_specs;
    std::vector<cli_custom_attribute_row_t> custom_attributes;
    std::vector<cli_manifest_resource_row_t> manifest_resources;
    std::vector<cli_method_body_t> method_bodies;
    std::vector<std::string> string_heap;
    std::vector<std::vector<std::uint8_t>> blob_heap;
    std::vector<std::array<std::uint8_t, 16>> guid_heap;
    std::vector<std::uint8_t> tables_raw;
    std::uint64_t metadata_rva = 0;
    std::uint64_t metadata_size = 0;
    std::uint32_t resources_rva = 0;
    std::uint32_t resources_size = 0;
    std::uint64_t image_base = 0;
    std::uint32_t entry_point_token = 0;
    std::shared_ptr<const pe_image_t> pe_image;
};

struct cli_metadata_parse_limits_t {
    std::uint64_t max_metadata_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint32_t max_table_rows = 1U << 24;
    std::uint32_t max_streams = 16;
    std::uint32_t max_string_heap_bytes = 16ULL * 1024ULL * 1024ULL;
    std::uint32_t max_blob_heap_bytes = 32ULL * 1024ULL * 1024ULL;
    std::uint32_t max_guid_heap_entries = 1U << 16;
    std::uint32_t max_method_bodies = 1U << 20;
    std::uint64_t max_total_code_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint32_t max_exception_clauses_per_method = 1U << 16;
};

workspace_result_t<cli_metadata_t>
parse_cli_metadata(const byte_provider_t& provider,
                   const cli_metadata_parse_limits_t& limits = {},
                   const cancellation_token_t& cancel = {});

workspace_result_t<managed_artifact_t>
build_cli_artifact(const cli_metadata_t& metadata,
                   const byte_provider_t& provider,
                   const managed_reader_limits_t& limits = {},
                   const cancellation_token_t& cancel = {});

}
