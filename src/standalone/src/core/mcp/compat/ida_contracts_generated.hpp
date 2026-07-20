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

inline constexpr std::string_view k_pinned_archive_sha256 = "3F7E7D9F534E3534C191D21251BBF0788DB14376C659488EA61681D48BC8D0F7";
inline constexpr std::string_view k_generated_contract_ledger_sha256 = "29E99FDDD813A18A84A1A736B47A1DBFEC95313A1692C1B906F9111537EB0E8A";
inline constexpr std::string_view k_generated_effect_ledger_sha256 = "A2495751CCC29407E8F7A1E4FEF6C1813DCA81B8D78431D60E4BCEDC3F31210C";
inline constexpr std::string_view k_generated_archive_manifest_sha256 = "A7D25BBE02F8C7BC59F3203C6DAA08FFC4A943321445901FC06C9AC91FDE025C";
inline constexpr std::size_t k_archive_tool_count = 88;
inline constexpr std::size_t k_compatibility_tool_count = 88;
inline constexpr std::size_t k_aida_extension_count = 4;
inline constexpr std::size_t k_union_tool_count = 92;
inline constexpr std::string_view k_aida_extension_names[] = {"analyze_funcs", "find_insns", "calculator", "calculate"};

const contract_descriptor_t* contracts() noexcept;
std::size_t contract_count() noexcept;
const contract_descriptor_t* find_contract(std::string_view name) noexcept;

}
