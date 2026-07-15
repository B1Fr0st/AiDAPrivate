#pragma once

#include "byte_provider.hpp"
#include "workspace_types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

class pe_parser_t;

enum class pe_artifact_kind_t : std::uint8_t {
    executable = 0,
    dynamic_library = 1,
    driver = 2
};

struct pe_parse_limits_t {
    std::uint32_t max_sections = 4096;
    std::uint32_t max_import_descriptors = 65536;
    std::uint32_t max_imports = 1U << 20;
    std::uint32_t max_exports = 1U << 20;
    std::uint32_t max_relocations = 1U << 22;
    std::uint32_t max_tls_callbacks = 65536;
    std::uint32_t max_runtime_functions = 1U << 22;
    std::uint64_t max_unwind_codes = 1ULL << 24;
    std::uint32_t max_unwind_chain_depth = 32;
    std::uint32_t max_language_scopes = 1U << 20;
    std::uint32_t max_load_config_entries = 1U << 22;
    std::uint32_t max_resources = 1U << 20;
    std::uint32_t max_resource_depth = 2;
    std::uint32_t max_string_bytes = 1U << 20;
    std::uint32_t max_dynamic_relocation_records = 1U << 20;
    std::uint64_t max_dynamic_relocation_bytes = 256ULL * 1024ULL * 1024ULL;
    std::uint64_t max_total_metadata_bytes = 256ULL * 1024ULL * 1024ULL;

    friend bool operator==(const pe_parse_limits_t& lhs,
                           const pe_parse_limits_t& rhs) noexcept {
        return lhs.max_sections == rhs.max_sections &&
               lhs.max_import_descriptors == rhs.max_import_descriptors &&
               lhs.max_imports == rhs.max_imports &&
               lhs.max_exports == rhs.max_exports &&
               lhs.max_relocations == rhs.max_relocations &&
               lhs.max_tls_callbacks == rhs.max_tls_callbacks &&
               lhs.max_runtime_functions == rhs.max_runtime_functions &&
               lhs.max_unwind_codes == rhs.max_unwind_codes &&
               lhs.max_unwind_chain_depth == rhs.max_unwind_chain_depth &&
               lhs.max_language_scopes == rhs.max_language_scopes &&
               lhs.max_load_config_entries == rhs.max_load_config_entries &&
               lhs.max_resources == rhs.max_resources &&
               lhs.max_resource_depth == rhs.max_resource_depth &&
               lhs.max_string_bytes == rhs.max_string_bytes &&
               lhs.max_dynamic_relocation_records == rhs.max_dynamic_relocation_records &&
               lhs.max_dynamic_relocation_bytes == rhs.max_dynamic_relocation_bytes &&
               lhs.max_total_metadata_bytes == rhs.max_total_metadata_bytes;
    }

    friend bool operator!=(const pe_parse_limits_t& lhs,
                           const pe_parse_limits_t& rhs) noexcept {
        return !(lhs == rhs);
    }
};

enum pe_parser_feature_flag_t : std::uint64_t {
    pe_feature_headers = 1ULL << 0,
    pe_feature_imports = 1ULL << 1,
    pe_feature_exports = 1ULL << 2,
    pe_feature_relocations = 1ULL << 3,
    pe_feature_tls = 1ULL << 4,
    pe_feature_x64_unwind = 1ULL << 5,
    pe_feature_c_specific_scopes = 1ULL << 6,
    pe_feature_load_config = 1ULL << 7,
    pe_feature_guard_stride_metadata = 1ULL << 8,
    pe_feature_dynamic_relocations = 1ULL << 9,
    pe_feature_codeview = 1ULL << 10,
    pe_feature_resources = 1ULL << 11
};

struct pe_parser_profile_t {
    static constexpr std::uint64_t schema_version = 2;
    static constexpr std::size_t canonical_byte_count = 160;

    std::uint64_t feature_mask = pe_feature_headers | pe_feature_imports |
        pe_feature_exports | pe_feature_relocations | pe_feature_tls |
        pe_feature_x64_unwind | pe_feature_c_specific_scopes |
        pe_feature_load_config | pe_feature_guard_stride_metadata |
        pe_feature_dynamic_relocations | pe_feature_codeview |
        pe_feature_resources;
    pe_parse_limits_t limits;

    std::array<std::uint8_t, canonical_byte_count> canonical_bytes() const noexcept;

    friend bool operator==(const pe_parser_profile_t& lhs,
                           const pe_parser_profile_t& rhs) noexcept {
        return lhs.feature_mask == rhs.feature_mask && lhs.limits == rhs.limits;
    }

    friend bool operator!=(const pe_parser_profile_t& lhs,
                           const pe_parser_profile_t& rhs) noexcept {
        return !(lhs == rhs);
    }
};

pe_parser_profile_t make_pe_parser_profile(const pe_parse_limits_t& limits) noexcept;
workspace_result_t<void> validate_pe_parser_profile(const pe_parser_profile_t& profile);

struct pe_data_directory_t {
    std::uint32_t index = 0;
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

struct pe_section_t {
    std::uint32_t index = 0;
    std::string name;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool discardable = false;
};

struct pe_entry_point_t {
    std::uint32_t rva = 0;
    std::string provenance;
};

struct pe_import_t {
    std::string library;
    std::optional<std::string> name;
    std::optional<std::uint16_t> hint;
    std::optional<std::uint16_t> ordinal;
    std::uint32_t lookup_rva = 0;
    std::uint32_t iat_rva = 0;
    bool delayed = false;
};

struct pe_export_t {
    std::optional<std::string> name;
    std::uint32_t ordinal = 0;
    std::uint32_t rva = 0;
    std::optional<std::string> forwarder;
};

struct pe_relocation_t {
    std::uint32_t rva = 0;
    std::uint16_t type = 0;
};

struct pe_runtime_function_t {
    std::uint32_t begin_rva = 0;
    std::uint32_t end_rva = 0;
    std::uint32_t unwind_rva = 0;
    std::uint32_t unwind_record_index = 0;
};

enum class pe_unwind_operation_t : std::uint8_t {
    push_nonvolatile = 0,
    allocate_large = 1,
    allocate_small = 2,
    set_frame_pointer = 3,
    save_nonvolatile = 4,
    save_nonvolatile_far = 5,
    epilogue = 6,
    spare = 7,
    save_xmm128 = 8,
    save_xmm128_far = 9,
    push_machine_frame = 10
};

struct pe_unwind_code_t {
    std::uint8_t code_offset = 0;
    pe_unwind_operation_t operation = pe_unwind_operation_t::push_nonvolatile;
    std::uint8_t operation_info = 0;
    std::uint8_t slot_count = 0;
    std::uint32_t stack_offset = 0;
    std::uint32_t epilogue_offset = 0;
    std::uint8_t epilogue_size = 0;
    bool epilogue_at_end = false;
    bool epilogue_padding = false;
};

enum class pe_unwind_language_data_kind_t : std::uint8_t {
    opaque = 0,
    c_specific_scope_table = 1
};

struct pe_unwind_scope_t {
    std::uint32_t begin_rva = 0;
    std::uint32_t end_rva = 0;
    std::uint32_t handler_rva = 0;
    std::uint32_t jump_target_rva = 0;
};

struct pe_unwind_record_t {
    std::uint32_t unwind_rva = 0;
    std::uint8_t version = 0;
    std::uint8_t flags = 0;
    std::uint8_t prolog_size = 0;
    std::uint8_t frame_register = 0;
    std::uint8_t frame_offset = 0;
    std::vector<pe_unwind_code_t> codes;
    std::optional<std::uint32_t> exception_handler_rva;
    std::optional<std::uint32_t> language_data_rva;
    std::uint32_t language_data_size = 0;
    pe_unwind_language_data_kind_t language_data_kind =
        pe_unwind_language_data_kind_t::opaque;
    std::vector<pe_unwind_scope_t> language_scopes;
    std::optional<pe_runtime_function_t> chained_function;
};

enum class pe_guard_function_flag_t : std::uint8_t {
    fid_suppressed = 0x01,
    export_suppressed = 0x02,
    language_exception_handler = 0x04,
    xfg = 0x08
};

struct pe_guard_function_entry_t {
    std::uint32_t rva = 0;
    std::uint8_t metadata_size = 0;
    std::array<std::uint8_t, 15> metadata{};

    std::uint8_t flags() const noexcept {
        return metadata_size == 0 ? 0 : metadata[0];
    }

    bool has_flag(pe_guard_function_flag_t flag) const noexcept {
        return (flags() & static_cast<std::uint8_t>(flag)) != 0;
    }
};

static_assert(sizeof(pe_guard_function_entry_t) == 20);

enum class pe_dynamic_relocation_kind_t : std::uint8_t {
    unknown = 0,
    guard_rf_prologue = 1,
    guard_rf_epilogue = 2,
    guard_import_control_transfer = 3,
    guard_indirect_control_transfer = 4,
    guard_switchtable_branch = 5,
    arm64x = 6,
    function_override = 7,
    arm64_kernel_import_call_transfer = 8
};

struct pe_dynamic_relocation_record_t {
    std::uint32_t record_rva = 0;
    std::uint32_t header_size = 0;
    std::uint32_t fixup_info_rva = 0;
    std::uint32_t fixup_info_size = 0;
    std::uint64_t symbol = 0;
    std::uint32_t symbol_group = 0;
    std::uint32_t flags = 0;
    pe_dynamic_relocation_kind_t kind = pe_dynamic_relocation_kind_t::unknown;
};

struct pe_dynamic_relocation_table_t {
    std::uint32_t table_rva = 0;
    std::uint32_t version = 0;
    std::uint32_t payload_size = 0;
    std::vector<pe_dynamic_relocation_record_t> records;
};

struct pe_load_config_t {
    std::uint32_t declared_size = 0;
    std::optional<std::uint32_t> security_cookie_rva;
    std::optional<std::uint32_t> seh_table_rva;
    std::uint64_t seh_handler_count = 0;
    std::optional<std::uint32_t> guard_check_rva;
    std::optional<std::uint32_t> guard_dispatch_rva;
    std::optional<std::uint32_t> guard_function_table_rva;
    std::uint64_t guard_function_count = 0;
    std::uint32_t guard_flags = 0;
    std::vector<std::uint32_t> seh_handler_rvas;
    std::vector<pe_guard_function_entry_t> guard_function_entries;
    std::optional<std::uint32_t> guard_address_taken_iat_table_rva;
    std::uint64_t guard_address_taken_iat_count = 0;
    std::vector<pe_guard_function_entry_t> guard_address_taken_iat_entries;
    std::optional<std::uint32_t> guard_long_jump_table_rva;
    std::uint64_t guard_long_jump_target_count = 0;
    std::vector<pe_guard_function_entry_t> guard_long_jump_targets;
    std::optional<std::uint32_t> guard_eh_continuation_table_rva;
    std::uint64_t guard_eh_continuation_count = 0;
    std::vector<pe_guard_function_entry_t> guard_eh_continuation_targets;
    std::optional<std::uint32_t> dynamic_value_reloc_table_rva;
    std::uint32_t dynamic_value_reloc_table_offset = 0;
    std::uint16_t dynamic_value_reloc_table_section = 0;
    std::optional<pe_dynamic_relocation_table_t> dynamic_relocations;
};

struct pe_codeview_t {
    std::array<std::uint8_t, 16> guid{};
    std::uint32_t age = 0;
    std::string pdb_path;
    std::uint32_t timestamp = 0;
};

struct pe_resource_t {
    std::string type;
    std::string name;
    std::uint16_t language = 0;
    std::uint32_t data_rva = 0;
    std::uint32_t size = 0;
    std::uint32_t code_page = 0;
};

class pe_image_t final {
public:
    format_id_t format() const noexcept { return format_; }
    architecture_id_t architecture() const noexcept { return architecture_; }
    architecture_mode_t architecture_mode() const noexcept { return mode_; }
    abi_id_t abi() const noexcept { return abi_; }
    endian_t endian() const noexcept { return endian_t::little; }
    pe_artifact_kind_t artifact_kind() const noexcept { return artifact_kind_; }
    std::uint64_t image_base() const noexcept { return image_base_; }
    std::uint32_t image_size() const noexcept { return image_size_; }
    std::uint32_t headers_size() const noexcept { return headers_size_; }
    std::uint32_t entry_rva() const noexcept { return entry_rva_; }
    std::uint16_t machine() const noexcept { return machine_; }
    std::uint16_t subsystem() const noexcept { return subsystem_; }
    std::uint16_t characteristics() const noexcept { return characteristics_; }
    std::uint16_t dll_characteristics() const noexcept { return dll_characteristics_; }
    std::uint32_t timestamp() const noexcept { return timestamp_; }
    const pe_parser_profile_t& parser_profile() const noexcept { return parser_profile_; }

    const std::vector<pe_data_directory_t>& directories() const noexcept { return directories_; }
    const std::vector<pe_section_t>& sections() const noexcept { return sections_; }
    const std::vector<pe_entry_point_t>& entry_points() const noexcept { return entry_points_; }
    const std::vector<pe_import_t>& imports() const noexcept { return imports_; }
    const std::vector<pe_export_t>& exports() const noexcept { return exports_; }
    const std::vector<pe_relocation_t>& relocations() const noexcept { return relocations_; }
    const std::vector<std::uint32_t>& tls_callbacks() const noexcept { return tls_callbacks_; }
    const std::vector<pe_runtime_function_t>& runtime_functions() const noexcept { return runtime_functions_; }
    const std::vector<pe_unwind_record_t>& unwind_records() const noexcept { return unwind_records_; }
    const std::optional<pe_load_config_t>& load_config() const noexcept { return load_config_; }
    const std::vector<pe_codeview_t>& codeview_records() const noexcept { return codeview_records_; }
    const std::vector<pe_resource_t>& resources() const noexcept { return resources_; }

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static std::shared_ptr<const pe_image_t> create_preview();
#endif

    workspace_result_t<std::uint64_t> rva_to_file_offset(std::uint64_t rva,
                                                        std::uint64_t size = 1) const;
    workspace_result_t<std::uint64_t> file_offset_to_rva(std::uint64_t offset,
                                                        std::uint64_t size = 1) const;
    workspace_result_t<std::uint64_t> rva_to_va(std::uint64_t rva) const;
    workspace_result_t<std::uint64_t> va_to_rva(std::uint64_t va) const;
    const pe_section_t* section_for_rva(std::uint64_t rva, std::uint64_t size = 1) const noexcept;
    const pe_section_t* section_for_file_offset(std::uint64_t offset,
                                                std::uint64_t size = 1) const noexcept;

private:
    format_id_t format_ = format_id_t::unknown;
    architecture_id_t architecture_ = architecture_id_t::unknown;
    architecture_mode_t mode_ = architecture_mode_t::unknown;
    abi_id_t abi_ = abi_id_t::unknown;
    pe_artifact_kind_t artifact_kind_ = pe_artifact_kind_t::executable;
    std::uint64_t image_base_ = 0;
    std::uint32_t image_size_ = 0;
    std::uint32_t headers_size_ = 0;
    std::uint32_t entry_rva_ = 0;
    std::uint16_t machine_ = 0;
    std::uint16_t subsystem_ = 0;
    std::uint16_t characteristics_ = 0;
    std::uint16_t dll_characteristics_ = 0;
    std::uint32_t timestamp_ = 0;
    pe_parser_profile_t parser_profile_;
    std::vector<pe_data_directory_t> directories_;
    std::vector<pe_section_t> sections_;
    std::vector<pe_entry_point_t> entry_points_;
    std::vector<pe_import_t> imports_;
    std::vector<pe_export_t> exports_;
    std::vector<pe_relocation_t> relocations_;
    std::vector<std::uint32_t> tls_callbacks_;
    std::vector<pe_runtime_function_t> runtime_functions_;
    std::vector<pe_unwind_record_t> unwind_records_;
    std::optional<pe_load_config_t> load_config_;
    std::vector<pe_codeview_t> codeview_records_;
    std::vector<pe_resource_t> resources_;

    friend workspace_result_t<std::shared_ptr<const pe_image_t>>
        parse_pe_image(const byte_provider_t&, const pe_parse_limits_t&,
                       const cancellation_token_t&);
    friend class pe_parser_t;
};

workspace_result_t<std::shared_ptr<const pe_image_t>>
parse_pe_image(const byte_provider_t& provider, const pe_parse_limits_t& limits = {},
               const cancellation_token_t& cancel = {});

workspace_result_t<std::shared_ptr<const workspace_image_t>>
normalize_pe_image(const pe_image_t& image, const byte_provider_t& provider,
                   const cancellation_token_t& cancel = {});

}
