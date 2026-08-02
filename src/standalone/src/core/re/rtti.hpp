#pragma once

#include "re_common.hpp"

#include "../analysis/workspace/byte_provider.hpp"
#include "../analysis/workspace/workspace_types.hpp"

namespace re::rtti
{
tool_result_t scan(const json& params);
tool_result_t find_type(const json& params);
tool_result_t list_hierarchy(const json& params);
tool_result_t find_constructor(const json& params);

struct base_class_record_t
{
    std::string name;
    std::string decorated_name;
    std::uint64_t type_descriptor_va = 0;
    std::uint64_t base_descriptor_va = 0;
    std::int32_t mdisp = 0;
    std::int32_t pdisp = 0;
    std::int32_t vdisp = 0;
    std::uint32_t attributes = 0;
};

struct static_rtti_limits_t
{
    std::uint32_t max_types = 65536;
    std::uint32_t max_vtables = 65536;
    std::uint32_t max_base_classes = 64;
    std::uint64_t max_section_bytes = 64ull << 20;
    bool deep_scan = false;
};

struct static_rtti_type_t
{
    std::string name;
    std::string decorated_name;
    std::uint64_t type_descriptor_rva = 0;
    std::uint64_t col_rva = 0;
    std::vector<base_class_record_t> bases;
    std::vector<std::uint64_t> vtable_rvas;
    int score = 0;
};

inline constexpr std::uint8_t k_static_rtti_completed = 0;
inline constexpr std::uint8_t k_static_rtti_no_rtti = 1;
inline constexpr std::uint8_t k_static_rtti_cancelled = 2;
inline constexpr std::uint8_t k_static_rtti_unsupported_format = 3;

struct static_rtti_result_t
{
    std::vector<static_rtti_type_t> types;
    std::uint64_t bytes_scanned = 0;
    std::uint8_t status = k_static_rtti_no_rtti;
    double elapsed_ms = 0.0;
};

aida::analysis::workspace_result_t<static_rtti_result_t> scan_static_image(
    const aida::analysis::workspace_image_t& image,
    const aida::analysis::byte_provider_t& provider,
    const static_rtti_limits_t& limits,
    const aida::analysis::cancellation_token_t& cancel);
}
