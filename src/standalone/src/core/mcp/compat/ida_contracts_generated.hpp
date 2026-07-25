#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace aida::standalone::mcp::compat {

enum class contract_effect_t : std::uint8_t {
    workspace_read,
    workspace_checkpoint,
    workspace_overlay_mutation,
    debugger_read,
    debugger_control,
    debugger_write,
    isolated_python,
    registry_read,
};

enum class contract_lock_t : std::uint8_t {
    workspace_shared,
    workspace_checkpoint,
    workspace_overlay_transaction,
    debugger_lane,
    python_worker,
    registry_read,
};

struct contract_descriptor_t {
    std::string_view name;
    std::string_view description;
    std::string_view input_schema_json;
    std::string_view output_schema_json;
    std::string_view annotations_json;
    std::string_view adapter_symbol;
    std::string_view source_path;
    std::uint32_t source_line;
    contract_effect_t effect;
    contract_lock_t lock;
    bool archive_backed;
    bool target_dependent;
    bool accepts_pid;
    bool accepts_bin_name;
    bool read_only;
    bool unsafe;
};

inline constexpr std::string_view k_pinned_archive_sha256 = "77FB255DEF04BA8ABD3D6BFA306916FA27597CF369D2863C4614ECFFEA288F0C";
inline constexpr std::string_view k_generated_contract_ledger_sha256 = "DD084F655A1EA9B81D173D8C4E4ABE040F218E25448C05EB2DA48441A09177A8";
inline constexpr std::string_view k_generated_effect_ledger_sha256 = "E8E4AECA80C597FAE5A9C33BCBE4BBA9B0BC0D0B67A5FBE50B338504AB06563C";
inline constexpr std::string_view k_generated_archive_manifest_sha256 = "98CD62E0F3BCB32C59D89679F5D49F03647631A7A2F884A548EDE6E7CBA42B5F";
inline constexpr std::size_t k_archive_tool_count = 88;
inline constexpr std::size_t k_compatibility_tool_count = 88;
inline constexpr std::size_t k_aida_extension_count = 4;
inline constexpr std::size_t k_union_tool_count = 92;
inline constexpr std::string_view k_aida_extension_names[] = {"analyze_funcs", "find_insns", "calculator", "calculate"};

const contract_descriptor_t* contracts() noexcept;
std::size_t contract_count() noexcept;
const contract_descriptor_t* find_contract(std::string_view name) noexcept;

}
