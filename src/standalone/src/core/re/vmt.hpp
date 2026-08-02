#pragma once

#include "re_common.hpp"
#include "rtti.hpp"

#include "../analysis/workspace/byte_provider.hpp"
#include "../analysis/workspace/workspace_types.hpp"

namespace re::vmt
{
tool_result_t read(const json& params);
tool_result_t hook_manage(const json& params);
tool_result_t copy(const json& params);
tool_result_t find_slot_by_signature(const json& params);
tool_result_t scan_objects(const json& params);

struct static_vfunc_slot_t
{
    std::uint64_t vtable_rva = 0;
    std::uint64_t slot_index = 0;
    std::uint64_t function_rva = 0;
    std::uint8_t confidence = 0;
};

inline constexpr std::uint8_t k_static_vtables_completed = 0;
inline constexpr std::uint8_t k_static_vtables_no_vtables = 1;
inline constexpr std::uint8_t k_static_vtables_cancelled = 2;

struct static_vtable_slots_result_t
{
    std::vector<static_vfunc_slot_t> slots;
    std::uint64_t vtables_validated = 0;
    std::uint8_t status = k_static_vtables_no_vtables;
    double elapsed_ms = 0.0;
};

inline constexpr std::uint64_t k_static_vtable_min_entries = 2;
inline constexpr std::uint64_t k_static_vtable_max_entries = 4096;

aida::analysis::workspace_result_t<static_vtable_slots_result_t> extract_slots_static(
    const aida::analysis::workspace_image_t& image,
    const aida::analysis::byte_provider_t& provider,
    const re::rtti::static_rtti_result_t& rtti,
    const std::vector<std::uint64_t>* function_starts_rva_sorted,
    const aida::analysis::cancellation_token_t& cancel);
}
