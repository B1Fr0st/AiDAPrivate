#pragma once

#include "byte_provider.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

inline constexpr std::uint32_t classfile_magic = 0xCAFEBABEu;

inline constexpr std::uint16_t jvm_acc_public       = 0x0001u;
inline constexpr std::uint16_t jvm_acc_private      = 0x0002u;
inline constexpr std::uint16_t jvm_acc_protected    = 0x0004u;
inline constexpr std::uint16_t jvm_acc_static       = 0x0008u;
inline constexpr std::uint16_t jvm_acc_final        = 0x0010u;
inline constexpr std::uint16_t jvm_acc_super        = 0x0020u;
inline constexpr std::uint16_t jvm_acc_synchronized = 0x0020u;
inline constexpr std::uint16_t jvm_acc_volatile     = 0x0040u;
inline constexpr std::uint16_t jvm_acc_bridge       = 0x0040u;
inline constexpr std::uint16_t jvm_acc_transient    = 0x0080u;
inline constexpr std::uint16_t jvm_acc_varargs      = 0x0080u;
inline constexpr std::uint16_t jvm_acc_native       = 0x0100u;
inline constexpr std::uint16_t jvm_acc_interface    = 0x0200u;
inline constexpr std::uint16_t jvm_acc_abstract     = 0x0400u;
inline constexpr std::uint16_t jvm_acc_strict       = 0x0800u;
inline constexpr std::uint16_t jvm_acc_synthetic    = 0x1000u;
inline constexpr std::uint16_t jvm_acc_annotation   = 0x2000u;
inline constexpr std::uint16_t jvm_acc_enum         = 0x4000u;
inline constexpr std::uint16_t jvm_acc_module       = 0x8000u;

enum class jvm_constant_tag_t : std::uint8_t {
    invalid = 0,
    utf8 = 1,
    integer = 3,
    float_ = 4,
    long_ = 5,
    double_ = 6,
    class_ref = 7,
    string_ref = 8,
    fieldref = 9,
    methodref = 10,
    interface_methodref = 11,
    name_and_type = 12,
    method_handle = 15,
    method_type = 16,
    dynamic = 17,
    invoke_dynamic = 18,
    module_ref = 19,
    package_ref = 20
};

struct jvm_constant_pool_entry_t {
    jvm_constant_tag_t tag = jvm_constant_tag_t::invalid;
    std::uint16_t index = 0;
    std::uint64_t file_offset = 0;
    std::string utf8_value;
    std::uint32_t int_float_value = 0;
    std::uint64_t long_double_value = 0;
    std::uint16_t ref_index1 = 0;
    std::uint16_t ref_index2 = 0;
    std::uint8_t reference_kind = 0;
    std::uint16_t bootstrap_method_attr_index = 0;
    bool is_double_slot = false;
    bool valid = false;
};

struct jvm_attribute_t {
    std::string name;
    std::uint16_t name_index = 0;
    std::uint64_t offset = 0;
    std::uint32_t length = 0;
    std::vector<std::uint8_t> raw_data;
};

struct jvm_code_exception_t {
    std::uint16_t start_pc = 0;
    std::uint16_t end_pc = 0;
    std::uint16_t handler_pc = 0;
    std::uint16_t catch_type = 0;
    std::optional<std::string> catch_class_name;
};

struct jvm_line_number_t {
    std::uint16_t start_pc = 0;
    std::uint16_t line_number = 0;
};

struct jvm_local_variable_t {
    std::uint16_t start_pc = 0;
    std::uint16_t length = 0;
    std::uint16_t name_index = 0;
    std::uint16_t descriptor_index = 0;
    std::uint16_t index = 0;
    std::string name;
    std::string descriptor;
};

struct jvm_bytecode_instruction_t {
    std::uint64_t offset = 0;
    std::uint8_t opcode = 0;
    std::string mnemonic;
    std::uint32_t length = 0;
    std::vector<std::uint8_t> operands;
    std::optional<std::int32_t> branch_offset;
    std::optional<std::uint64_t> branch_target;
    std::optional<std::int32_t> switch_default_offset;
    std::optional<std::uint64_t> switch_default_target;
    std::vector<std::int32_t> switch_offsets;
    std::vector<std::uint64_t> switch_targets;
    std::optional<std::uint16_t> constant_pool_index;
    std::optional<std::uint8_t> local_variable_index;
    std::optional<std::uint16_t> wide_local_variable_index;
    std::optional<std::int8_t> increment;
    std::optional<std::int16_t> wide_increment;
    std::optional<std::uint8_t> array_type;
    std::optional<std::uint8_t> dimensions;
};

struct jvm_code_attribute_t {
    std::uint16_t max_stack = 0;
    std::uint16_t max_locals = 0;
    std::uint64_t code_offset = 0;
    std::uint32_t code_length = 0;
    std::vector<std::uint8_t> code;
    std::vector<jvm_code_exception_t> exceptions;
    std::vector<jvm_bytecode_instruction_t> instructions;
    std::vector<jvm_attribute_t> attributes;
    std::vector<jvm_line_number_t> line_numbers;
    std::vector<jvm_local_variable_t> local_variables;
};

struct jvm_field_t {
    std::uint16_t access_flags = 0;
    std::uint16_t name_index = 0;
    std::uint16_t descriptor_index = 0;
    std::string name;
    std::string descriptor;
    std::vector<jvm_attribute_t> attributes;
    bool is_public = false;
    bool is_private = false;
    bool is_protected = false;
    bool is_static = false;
    bool is_final = false;
    bool is_volatile = false;
    bool is_transient = false;
    bool is_synthetic = false;
    bool is_enum = false;
};

struct jvm_method_t {
    std::uint16_t access_flags = 0;
    std::uint16_t name_index = 0;
    std::uint16_t descriptor_index = 0;
    std::string name;
    std::string descriptor;
    std::vector<jvm_attribute_t> attributes;
    std::optional<jvm_code_attribute_t> code;
    std::vector<std::string> declared_exceptions;
    bool is_public = false;
    bool is_private = false;
    bool is_protected = false;
    bool is_static = false;
    bool is_final = false;
    bool is_synchronized = false;
    bool is_bridge = false;
    bool is_varargs = false;
    bool is_native = false;
    bool is_abstract = false;
    bool is_strict = false;
    bool is_synthetic = false;
};

struct jvm_inner_class_t {
    std::uint16_t inner_class_info_index = 0;
    std::uint16_t outer_class_info_index = 0;
    std::uint16_t inner_name_index = 0;
    std::uint16_t access_flags = 0;
    std::string inner_class_name;
    std::string outer_class_name;
    std::string inner_name;
};

struct jvm_bootstrap_method_t {
    std::uint16_t bootstrap_method_ref = 0;
    std::vector<std::uint16_t> bootstrap_arguments;
};

struct jvm_invokedynamic_reference_t {
    std::uint64_t code_offset = 0;
    std::uint16_t constant_pool_index = 0;
    std::uint16_t bootstrap_method_index = 0;
    std::string name;
    std::string descriptor;
};

struct classfile_parse_limits_t {
    std::uint64_t max_classfile_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint32_t max_constant_pool_entries = 65535;
    std::uint32_t max_fields = 65535;
    std::uint32_t max_methods = 65535;
    std::uint32_t max_interfaces = 65535;
    std::uint32_t max_attributes = 65535;
    std::uint64_t max_total_attributes = 262144;
    std::uint64_t max_total_attribute_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_total_code_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_bytecode_per_method = 16ULL * 1024ULL * 1024ULL;
    std::uint64_t max_attribute_size = 16ULL * 1024ULL * 1024ULL;
    std::uint64_t max_utf8_length = 65535;
    std::uint64_t max_exception_table_entries = 65535;
    std::uint64_t max_line_number_entries = 65535;
    std::uint64_t max_local_variable_entries = 65535;
    std::uint64_t max_inner_classes = 65535;
    std::uint64_t max_bootstrap_methods = 65535;
    std::uint64_t max_bootstrap_arguments = 65535;
    std::uint64_t max_instructions_per_method = 1ULL << 20;
    std::uint64_t max_switch_entries = 1ULL << 20;
};

struct classfile_image_t {
    workspace_image_t normalized;
    std::uint32_t magic = 0;
    std::uint16_t minor_version = 0;
    std::uint16_t major_version = 0;
    std::uint16_t access_flags = 0;
    std::uint16_t this_class = 0;
    std::uint16_t super_class = 0;
    std::string this_class_name;
    std::string super_class_name;
    std::vector<std::uint16_t> interfaces;
    std::vector<std::string> interface_names;
    std::vector<jvm_constant_pool_entry_t> constant_pool;
    std::vector<jvm_field_t> fields;
    std::vector<jvm_method_t> methods;
    std::vector<jvm_attribute_t> attributes;
    std::vector<jvm_line_number_t> line_number_table;
    std::vector<jvm_local_variable_t> local_variable_table;
    std::vector<jvm_inner_class_t> inner_classes;
    std::vector<jvm_bootstrap_method_t> bootstrap_methods;
    std::vector<jvm_invokedynamic_reference_t> invokedynamic_references;
    std::optional<std::string> source_file;
    std::optional<std::string> signature;
    bool is_interface = false;
    bool is_abstract = false;
    bool is_final = false;
    bool is_annotation = false;
    bool is_enum = false;
    bool is_module = false;
    bool is_synthetic = false;
    bool is_super = false;
    bool is_public = false;
};

workspace_result_t<std::shared_ptr<const workspace_image_t>>
parse_classfile(const byte_provider_t& provider,
                const cancellation_token_t& cancel = {});

workspace_result_t<std::shared_ptr<const workspace_image_t>>
parse_classfile(const byte_provider_t& provider,
                const classfile_parse_limits_t& limits,
                const cancellation_token_t& cancel = {});

workspace_result_t<classfile_image_t>
parse_classfile_image(const byte_provider_t& provider,
                      const cancellation_token_t& cancel = {});

workspace_result_t<classfile_image_t>
parse_classfile_image(const byte_provider_t& provider,
                      const classfile_parse_limits_t& limits,
                      const cancellation_token_t& cancel = {});

const char* jvm_constant_tag_name(jvm_constant_tag_t tag) noexcept;
const char* jvm_major_version_name(std::uint16_t major) noexcept;
const char* jvm_opcode_mnemonic(std::uint8_t opcode) noexcept;

}
