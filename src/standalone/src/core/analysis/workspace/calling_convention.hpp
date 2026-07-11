#pragma once

#include "analysis_workspace.hpp"
#include "compact_ir.hpp"
#include "workspace_types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace aida::analysis {

inline constexpr std::uint64_t calling_convention_rules_revision = 2;
inline constexpr std::uint64_t calling_convention_max_arguments = 256;
inline constexpr std::uint64_t calling_convention_max_stack_slots = 65536;
inline constexpr std::uint64_t calling_convention_max_evidence = 4096;
inline constexpr std::uint64_t calling_convention_max_conflicts = 256;
inline constexpr std::uint64_t calling_convention_max_instruction_visits = 262144;
inline constexpr std::uint32_t calling_convention_max_merge_iterations = 16;

enum class cc_abi_t : std::uint8_t {
    unknown = 0,
    x86_cdecl = 1,
    x86_stdcall = 2,
    x86_thiscall = 3,
    x86_fastcall = 4,
    x86_vectorcall = 5,
    system_v_x86 = 6,
    windows_x64 = 7,
    windows_x64_vectorcall = 8,
    system_v_x64 = 9,
    arm_aapcs = 10,
    aarch64_aapcs64 = 11,
    windows_arm64 = 12,
    windows_arm64ec = 13,
    mips_o32 = 14,
    mips_n64 = 15,
    ppc_sysv32 = 16,
    ppc_sysv64 = 17,
    riscv_ilp32 = 18,
    riscv_lp64 = 19,
    managed_jvm_identity = 20,
    managed_dalvik_identity = 21
};

enum class cc_inference_state_t : std::uint8_t {
    unknown = 0,
    abstained = 1,
    inferred = 2,
    conflicted = 3
};

enum class cc_value_state_t : std::uint8_t {
    unknown = 0,
    abstained = 1,
    inferred = 2,
    conflicted = 3
};

enum class cc_evidence_kind_t : std::uint8_t {
    unknown = 0,
    declared_abi = 1,
    managed_identity = 2,
    register_read_before_definition = 3,
    register_written = 4,
    stack_read = 5,
    stack_write = 6,
    stack_argument = 7,
    frame_pointer = 8,
    preserved_register_save = 9,
    preserved_register_restore = 10,
    return_register_write = 11,
    return_instruction = 12,
    callee_stack_cleanup = 13,
    variadic_indeterminate = 14,
    merge_consensus = 15,
    merge_conflict = 16
};

enum class cc_conflict_kind_t : std::uint8_t {
    unknown = 0,
    abi = 1,
    argument = 2,
    return_value = 3,
    register_effect = 4,
    cache_scope = 5,
    budget = 6
};

enum class argument_location_t : std::uint8_t {
    unknown = 0,
    register_arg = 1,
    stack_arg = 2,
    float_register = 3,
    vector_register = 4
};

enum class stack_slot_kind_t : std::uint8_t {
    unknown = 0,
    argument = 1,
    local = 2,
    spill = 3,
    saved_register = 4,
    outgoing_argument = 5
};

enum class register_effect_kind_t : std::uint8_t {
    unknown = 0,
    preserved = 1,
    clobbered = 2
};

struct calling_convention_cache_key_t {
    binary_id_t binary_id;
    address_t function;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    abi_id_t declared_abi = abi_id_t::unknown;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t rules_revision = calling_convention_rules_revision;

    std::uint64_t stable_hash() const noexcept;

    friend bool operator==(const calling_convention_cache_key_t& lhs,
                           const calling_convention_cache_key_t& rhs) noexcept {
        return lhs.binary_id == rhs.binary_id && lhs.function == rhs.function &&
               lhs.architecture == rhs.architecture &&
               lhs.architecture_mode == rhs.architecture_mode &&
               lhs.declared_abi == rhs.declared_abi && lhs.generation == rhs.generation &&
               lhs.analysis_revision == rhs.analysis_revision &&
               lhs.overlay_revision == rhs.overlay_revision &&
               lhs.rules_revision == rhs.rules_revision;
    }

    friend bool operator!=(const calling_convention_cache_key_t& lhs,
                           const calling_convention_cache_key_t& rhs) noexcept {
        return !(lhs == rhs);
    }
};

struct calling_convention_cache_key_hash_t {
    std::size_t operator()(const calling_convention_cache_key_t& key) const noexcept {
        return static_cast<std::size_t>(key.stable_hash());
    }
};

struct cc_evidence_t {
    cc_evidence_kind_t kind = cc_evidence_kind_t::unknown;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    address_t address;
    std::uint16_t reg = 0;
    std::int64_t stack_offset = 0;
    std::uint32_t subject = 0;
    std::uint8_t confidence = 0;
    bool positive = false;
};

struct cc_conflict_t {
    cc_conflict_kind_t kind = cc_conflict_kind_t::unknown;
    std::uint32_t subject = 0;
    std::uint16_t lhs_reg = 0;
    std::uint16_t rhs_reg = 0;
    std::int64_t lhs_stack_offset = 0;
    std::int64_t rhs_stack_offset = 0;
    std::uint8_t lhs_confidence = 0;
    std::uint8_t rhs_confidence = 0;
};

struct argument_info_t {
    std::uint32_t index = 0;
    std::uint32_t abi_slot = 0;
    std::uint16_t reg = 0;
    std::int64_t stack_offset = 0;
    std::uint16_t bit_width = 0;
    argument_location_t location = argument_location_t::unknown;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool index_is_logical = false;
    bool is_float = false;
    bool is_vector = false;
    bool used = false;
    bool conflicted = false;
};

struct preserved_register_t {
    std::uint16_t reg = 0;
    std::uint64_t save_rva = 0;
    std::uint64_t restore_rva = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool saved = false;
    bool restored = false;
};

struct register_effect_t {
    std::uint16_t reg = 0;
    register_effect_kind_t kind = register_effect_kind_t::unknown;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool observed = false;
    bool conflicted = false;
};

struct stack_slot_t {
    std::int64_t offset = 0;
    std::uint64_t size = 0;
    std::uint16_t base_reg = 0;
    std::uint16_t access_width_bits = 0;
    stack_slot_kind_t kind = stack_slot_kind_t::unknown;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool is_argument = false;
    bool is_spill = false;
    bool is_local = false;
    bool is_saved_register = false;
    bool read = false;
    bool written = false;
};

struct stack_frame_info_t {
    std::uint64_t frame_size = 0;
    std::uint64_t observed_stack_extent = 0;
    std::uint64_t prologue_end_rva = 0;
    std::uint64_t epilogue_start_rva = 0;
    std::uint16_t stack_pointer_reg = 0;
    std::uint16_t frame_pointer_reg = 0;
    bool frame_size_known = false;
    bool uses_frame_pointer = false;
    bool has_shadow_space = false;
    std::uint64_t shadow_space_size = 0;
    std::vector<stack_slot_t> slots;
    std::vector<preserved_register_t> preserved_registers;
};

struct cc_return_info_t {
    cc_value_state_t state = cc_value_state_t::unknown;
    std::vector<std::uint16_t> registers;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint16_t bit_width = 0;
    std::uint8_t confidence = 0;
    bool is_float = false;
    bool is_vector = false;
};

struct calling_convention_request_t {
    address_t function;
    std::optional<std::uint64_t> expected_generation;
    std::optional<std::uint64_t> expected_analysis_revision;
    std::optional<std::uint64_t> expected_overlay_revision;
    std::uint64_t max_instruction_visits = calling_convention_max_instruction_visits;
    std::uint64_t max_evidence = calling_convention_max_evidence;
    std::uint64_t max_stack_slots = calling_convention_max_stack_slots;
};

struct calling_convention_merge_options_t {
    std::uint32_t max_candidates = 64;
    std::uint32_t max_evidence = static_cast<std::uint32_t>(calling_convention_max_evidence);
    std::uint32_t max_iterations = calling_convention_max_merge_iterations;
    std::uint8_t winner_margin = 12;
};

struct cc_analysis_result_t {
    calling_convention_cache_key_t cache_key;
    cc_abi_t abi = cc_abi_t::unknown;
    cc_inference_state_t state = cc_inference_state_t::unknown;
    cc_value_state_t arguments_state = cc_value_state_t::unknown;
    cc_value_state_t variadic_state = cc_value_state_t::unknown;
    std::vector<argument_info_t> arguments;
    cc_return_info_t return_value;
    std::vector<register_effect_t> register_effects;
    std::uint16_t return_reg = 0;
    std::uint16_t return_bit_width = 0;
    bool return_is_float = false;
    bool is_variadic = false;
    bool is_noreturn = false;
    bool native_abi = false;
    stack_frame_info_t frame;
    std::vector<cc_evidence_t> evidence;
    std::vector<cc_conflict_t> conflicts;
    std::uint64_t function_rva = 0;
    std::uint64_t argument_count = 0;
    std::uint64_t instructions_analyzed = 0;
    std::uint32_t merge_iterations = 0;
    std::uint8_t confidence = 0;
    bool bounded = false;
    bool cancelled = false;
};

workspace_result_t<calling_convention_cache_key_t>
make_calling_convention_cache_key(const analysis_workspace_t& workspace,
                                  const calling_convention_request_t& request,
                                  const cancellation_token_t& cancel);

workspace_result_t<cc_analysis_result_t>
infer_calling_convention(const analysis_workspace_t& workspace,
                         const calling_convention_request_t& request,
                         const cancellation_token_t& cancel);

workspace_result_t<cc_analysis_result_t>
merge_calling_convention_results(const std::vector<cc_analysis_result_t>& candidates,
                                 const calling_convention_merge_options_t& options,
                                 const cancellation_token_t& cancel);

workspace_result_t<cc_analysis_result_t>
analyze_calling_convention(const analysis_workspace_t& workspace,
                           std::uint64_t function_rva,
                           const cancellation_token_t& cancel);

}
