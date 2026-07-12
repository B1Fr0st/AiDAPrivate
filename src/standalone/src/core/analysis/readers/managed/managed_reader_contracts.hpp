#pragma once

#include "../../workspace/byte_provider.hpp"
#include "../../workspace/workspace_types.hpp"
#include "../../workspace/compact_ir.hpp"
#include "../../decompiler/decompiler_contracts.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis::readers::managed {

inline constexpr std::uint32_t managed_reader_schema_version = 1;

enum class managed_artifact_kind_t : std::uint8_t {
    cli_metadata = 0,
    java_classfile = 1,
    dex = 2,
    oat = 3,
    vdex = 4,
    multidex_container = 5
};

enum class managed_token_type_t : std::uint8_t {
    unknown = 0,
    module = 0x1A,
    type_ref = 0x01,
    type_def = 0x02,
    field_def = 0x04,
    method_def = 0x06,
    param = 0x08,
    interface_impl = 0x09,
    member_ref = 0x0A,
    constant = 0x0B,
    custom_attribute = 0x0C,
    assembly = 0x14,
    assembly_ref = 0x15,
    file_table = 0x16,
    exported_type = 0x17,
    manifest_resource = 0x18,
    nested_class = 0x19,
    generic_param = 0x1A,
    method_spec = 0x1B,
    generic_param_constraint = 0x1C
};

struct cli_metadata_token_t {
    std::uint32_t token = 0;

    constexpr cli_metadata_token_t() noexcept = default;
    explicit constexpr cli_metadata_token_t(std::uint32_t value) noexcept : token(value) {}

    constexpr std::uint8_t table_code() const noexcept {
        return static_cast<std::uint8_t>(token >> 24);
    }
    constexpr std::uint32_t row_index() const noexcept {
        return token & 0x00FFFFFFu;
    }
    constexpr bool valid() const noexcept {
        return token != 0;
    }
    constexpr bool operator==(const cli_metadata_token_t& other) const noexcept {
        return token == other.token;
    }
    constexpr bool operator!=(const cli_metadata_token_t& other) const noexcept {
        return !(*this == other);
    }
    constexpr bool operator<(const cli_metadata_token_t& other) const noexcept {
        return token < other.token;
    }
};

struct managed_module_identity_t {
    sha256_digest_t artifact_hash{};
    std::string assembly_name;
    std::string module_name;
    std::string version;
    managed_artifact_kind_t kind = managed_artifact_kind_t::cli_metadata;
    std::uint64_t artifact_offset = 0;
    std::uint64_t artifact_size = 0;
    std::optional<std::uint32_t> runtime_major;
    std::optional<std::uint32_t> runtime_minor;
    std::optional<std::uint32_t> assembly_flags;
    std::optional<std::uint32_t> entry_point_token;

    bool valid() const noexcept {
        return !assembly_name.empty() && artifact_size != 0;
    }
};

struct managed_type_identity_t {
    std::string namespace_name;
    std::string type_name;
    std::string fully_qualified_name;
    std::uint32_t generic_arity = 0;
    std::uint32_t metadata_token = 0;
    std::string declaring_type_name;
    std::string signature;
    std::vector<std::string> interface_names;
    std::optional<std::string> base_type_name;
    std::uint32_t access_flags = 0;
    bool is_interface = false;
    bool is_abstract = false;
    bool is_final = false;
    bool is_nested = false;
    bool is_enum = false;
    bool is_annotation = false;
    std::vector<std::uint32_t> method_tokens;
    std::vector<std::uint32_t> field_tokens;

    bool valid() const noexcept {
        return !type_name.empty() && metadata_token != 0;
    }
};

struct managed_method_identity_t {
    std::string declaring_type_name;
    std::string method_name;
    std::string method_signature;
    std::uint32_t generic_arity = 0;
    std::uint32_t metadata_token = 0;
    std::uint32_t method_index = 0;
    std::uint64_t code_offset = 0;
    std::uint64_t code_size = 0;
    std::uint32_t access_flags = 0;
    bool is_abstract = false;
    bool is_native = false;
    bool is_static = false;
    bool is_virtual = false;
    bool is_direct = false;
    bool has_body = false;
    std::optional<std::uint16_t> max_stack;
    std::optional<std::uint16_t> local_token;
    std::vector<std::string> parameter_names;
    std::vector<std::string> parameter_types;

    bool valid() const noexcept {
        return !method_name.empty();
    }
};

struct managed_field_identity_t {
    std::string declaring_type_name;
    std::string field_name;
    std::string field_signature;
    std::uint32_t metadata_token = 0;
    std::uint32_t field_index = 0;
    std::uint32_t access_flags = 0;
    bool is_static = false;
    bool is_literal = false;
    bool is_init_only = false;

    bool valid() const noexcept {
        return !field_name.empty();
    }
};

enum class managed_reference_kind_t : std::uint8_t {
    type_reference = 0,
    method_reference = 1,
    field_reference = 2,
    assembly_reference = 3
};

struct managed_member_reference_t {
    managed_reference_kind_t kind = managed_reference_kind_t::type_reference;
    std::string declaring_type_name;
    std::string member_name;
    std::string member_signature;
    std::uint32_t reference_token = 0;
    std::uint32_t source_method_index = 0;
    std::uint64_t code_offset = 0;
    std::optional<std::string> assembly_reference_name;
};

struct managed_code_range_t {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint16_t max_stack = 0;
    std::uint16_t max_locals = 0;
    std::uint32_t method_token = 0;
    std::uint32_t local_token = 0;
    bool is_fat_format = false;
    std::vector<std::uint8_t> code_bytes;
    std::vector<std::uint8_t> local_signature_blob;
};

struct managed_exception_region_t {
    std::uint64_t start_offset = 0;
    std::uint64_t end_offset = 0;
    std::uint64_t handler_offset = 0;
    std::optional<std::string> catch_type_name;
    std::optional<std::uint32_t> catch_type_token;
    std::uint32_t method_token = 0;
    bool is_finally = false;
    bool is_filter = false;
    bool is_catch_all = false;
    std::optional<std::uint64_t> filter_offset;
};

struct managed_signature_t {
    std::string raw_signature;
    std::string return_type;
    std::vector<std::string> parameter_types;
    std::vector<std::string> type_parameters;
    std::uint32_t method_token = 0;
    managed_artifact_kind_t artifact_kind = managed_artifact_kind_t::cli_metadata;
};

struct managed_annotation_t {
    std::string annotation_type;
    std::vector<std::pair<std::string, std::string>> named_arguments;
    std::uint64_t offset = 0;
    std::uint32_t parent_token = 0;
    bool is_runtime_visible = false;
    bool is_runtime_invisible = false;
};

struct managed_resource_t {
    std::string name;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::optional<std::string> file_name;
    std::uint32_t flags = 0;
    std::optional<std::uint32_t> implementation_token;
};

struct managed_reader_limits_t {
    std::uint64_t max_metadata_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint32_t max_types = 1U << 20;
    std::uint32_t max_methods = 1U << 20;
    std::uint32_t max_fields = 1U << 20;
    std::uint32_t max_member_references = 1U << 20;
    std::uint32_t max_annotations = 1U << 20;
    std::uint32_t max_resources = 1U << 20;
    std::uint32_t max_exception_regions = 1U << 20;
    std::uint32_t max_code_ranges = 1U << 20;
    std::uint64_t max_code_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_string_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint32_t max_dex_files = 64;
    std::uint32_t max_constant_pool_entries = 65535;
    std::uint32_t max_table_rows = 1U << 24;
    std::uint32_t max_generic_params = 1U << 20;
};

struct managed_duplicate_identity_t {
    std::string identity_key;
    std::uint32_t first_token = 0;
    std::uint32_t second_token = 0;
    std::string description;
};

struct managed_artifact_t {
    managed_module_identity_t module_identity;
    managed_artifact_kind_t kind = managed_artifact_kind_t::cli_metadata;
    std::vector<managed_type_identity_t> types;
    std::vector<managed_method_identity_t> methods;
    std::vector<managed_field_identity_t> fields;
    std::vector<managed_member_reference_t> member_references;
    std::vector<managed_code_range_t> code_ranges;
    std::vector<managed_exception_region_t> exception_regions;
    std::vector<managed_signature_t> signatures;
    std::vector<managed_annotation_t> annotations;
    std::vector<managed_resource_t> resources;
    std::vector<managed_duplicate_identity_t> duplicate_identities;
    workspace_image_t normalized;
    std::uint32_t schema_version = managed_reader_schema_version;
    std::uint64_t total_code_bytes = 0;
    std::uint64_t total_string_bytes = 0;

    bool valid() const noexcept {
        return module_identity.valid() && schema_version == managed_reader_schema_version;
    }
};

struct managed_multidex_t {
    std::vector<managed_artifact_t> artifacts;
    std::string container_version;
    managed_artifact_kind_t container_kind = managed_artifact_kind_t::multidex_container;
    std::vector<std::string> dex_class_descriptors;
    std::vector<std::uint64_t> embedded_offsets;

    bool valid() const noexcept {
        return !artifacts.empty();
    }
};

const char* managed_artifact_kind_name(managed_artifact_kind_t kind) noexcept;
const char* managed_reference_kind_name(managed_reference_kind_t kind) noexcept;
const char* managed_token_type_name(managed_token_type_t type) noexcept;

std::string format_cli_token(std::uint32_t token) noexcept;

cli_decompiler_entity_identity_t
build_cli_entity_identity(const managed_artifact_t& artifact, std::uint32_t method_index);

jvm_decompiler_entity_identity_t
build_jvm_entity_identity(const managed_artifact_t& artifact, std::uint32_t method_index);

dalvik_decompiler_entity_identity_t
build_dalvik_entity_identity(const managed_artifact_t& artifact, std::uint32_t method_index);

decompiler_entity_key_t
build_cli_entity_key(const managed_artifact_t& artifact, std::uint32_t method_index);

decompiler_entity_key_t
build_jvm_entity_key(const managed_artifact_t& artifact, std::uint32_t method_index);

decompiler_entity_key_t
build_dalvik_entity_key(const managed_artifact_t& artifact, std::uint32_t method_index);

workspace_result_t<managed_artifact_t>
read_cli_metadata(const byte_provider_t& provider,
                  const managed_reader_limits_t& limits = {},
                  const cancellation_token_t& cancel = {});

workspace_result_t<managed_artifact_t>
read_classfile(const byte_provider_t& provider,
               const managed_reader_limits_t& limits = {},
               const cancellation_token_t& cancel = {});

workspace_result_t<managed_artifact_t>
read_dex(const byte_provider_t& provider,
         const managed_reader_limits_t& limits = {},
         const cancellation_token_t& cancel = {});

workspace_result_t<managed_multidex_t>
read_multidex_container(const byte_provider_t& provider,
                        const managed_reader_limits_t& limits = {},
                        const cancellation_token_t& cancel = {});

workspace_result_t<managed_artifact_t>
read_managed_artifact(const byte_provider_t& provider,
                      const managed_reader_limits_t& limits = {},
                      const cancellation_token_t& cancel = {});

}
