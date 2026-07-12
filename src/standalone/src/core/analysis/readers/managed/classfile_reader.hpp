#pragma once

#include "managed_reader_contracts.hpp"

#include "../../workspace/byte_provider.hpp"
#include "../../workspace/classfile_parser.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis::readers::managed {

struct classfile_parse_limits_t {
    classfile_parse_limits_t parser_limits;
    std::uint32_t max_types = 65535;
    std::uint32_t max_methods = 65535;
    std::uint32_t max_fields = 65535;
    std::uint32_t max_member_references = 1U << 20;
    std::uint32_t max_annotations = 1U << 20;
    std::uint32_t max_exception_regions = 1U << 20;
    std::uint32_t max_code_ranges = 65535;
    std::uint64_t max_code_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_string_bytes = 64ULL * 1024ULL * 1024ULL;
};

struct classfile_metadata_t {
    classfile_image_t image;
    std::vector<std::string> annotation_types;
    std::vector<std::pair<std::uint16_t, std::string>> constant_pool_refs;
    std::vector<std::string> interface_names_resolved;
    std::vector<jvm_code_exception_t> all_exception_regions;
    std::vector<jvm_bytecode_instruction_t> all_instructions;
    std::vector<std::uint16_t> member_reference_cp_indices;
};

workspace_result_t<classfile_metadata_t>
parse_classfile_metadata(const byte_provider_t& provider,
                         const classfile_parse_limits_t& limits = {},
                         const cancellation_token_t& cancel = {});

workspace_result_t<managed_artifact_t>
build_classfile_artifact(const classfile_metadata_t& metadata,
                         const byte_provider_t& provider,
                         const managed_reader_limits_t& limits = {},
                         const cancellation_token_t& cancel = {});

}
