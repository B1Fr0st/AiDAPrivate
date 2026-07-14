#pragma once

#include "managed_reader_contracts.hpp"

#include "../../workspace/byte_provider.hpp"
#include "../../workspace/dex_image.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis::readers::managed {

struct dex_parse_limits_t {
    ::aida::analysis::dex_parse_limits_t parser_limits;
    std::uint32_t max_types = 1U << 20;
    std::uint32_t max_methods = 1U << 20;
    std::uint32_t max_fields = 1U << 20;
    std::uint32_t max_member_references = 1U << 20;
    std::uint32_t max_annotations = 1U << 20;
    std::uint32_t max_exception_regions = 1U << 20;
    std::uint32_t max_code_ranges = 1U << 20;
    std::uint64_t max_code_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_string_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint32_t max_dex_files = 64;
};

struct dex_annotation_info_t {
    std::string type_descriptor;
    std::uint8_t visibility = 0;
};

struct dex_metadata_t {
    dex_image_t image;
    dex_container_info_t container;
    std::uint32_t dex_ordinal = 0;
    std::vector<dex_annotation_info_t> annotations;
    std::vector<std::pair<std::uint32_t, std::string>> method_references;
    std::vector<std::pair<std::uint32_t, std::string>> field_references;
    std::vector<std::pair<std::uint32_t, std::string>> type_references;
};

struct multidex_metadata_t {
    std::vector<dex_metadata_t> dex_entries;
    dex_container_info_t container;
    std::string container_version;
};

workspace_result_t<dex_metadata_t>
parse_dex_metadata(const byte_provider_t& provider,
                   const dex_parse_limits_t& limits = {},
                   const cancellation_token_t& cancel = {});

workspace_result_t<multidex_metadata_t>
parse_multidex_metadata(const byte_provider_t& provider,
                        const dex_parse_limits_t& limits = {},
                        const cancellation_token_t& cancel = {});

workspace_result_t<managed_artifact_t>
build_dex_artifact(const dex_metadata_t& metadata,
                   const byte_provider_t& provider,
                   const managed_reader_limits_t& limits = {},
                   const cancellation_token_t& cancel = {});

workspace_result_t<managed_multidex_t>
build_multidex_artifact(const multidex_metadata_t& metadata,
                        const byte_provider_t& provider,
                        const managed_reader_limits_t& limits = {},
                        const cancellation_token_t& cancel = {});

}
