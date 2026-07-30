#include "calling_convention.hpp"

#include "parallel_pass.hpp"

#include <Zydis/Zydis.h>

#include <capstone/arm.h>
#include <capstone/arm64.h>
#include <capstone/mips.h>
#include <capstone/ppc.h>
#include <capstone/riscv.h>

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace aida::analysis {
namespace {

constexpr std::uint8_t operand_read_access = 1U;
constexpr std::uint8_t operand_write_access = 2U;
constexpr std::size_t no_instruction_index = std::numeric_limits<std::size_t>::max();

struct function_instruction_t {
    const instruction_record_t* instruction = nullptr;
    entity_id_t block_id = 0;
};

struct function_view_t {
    const function_record_t* function = nullptr;
    std::vector<function_instruction_t> instructions;
};

struct abi_profile_t {
    cc_abi_t abi = cc_abi_t::unknown;
    std::vector<std::uint16_t> general_arguments;
    std::vector<std::uint16_t> floating_arguments;
    std::vector<std::uint16_t> vector_arguments;
    std::vector<std::uint16_t> general_returns;
    std::vector<std::uint16_t> floating_returns;
    std::vector<std::uint16_t> callee_saved;
    std::uint16_t stack_pointer = 0;
    std::uint16_t frame_pointer = 0;
    std::uint64_t word_size = 0;
    std::uint64_t return_address_size = 0;
    std::uint64_t shadow_space_size = 0;
    bool shared_register_slots = false;
};

struct register_observation_t {
    bool read = false;
    bool written = false;
    bool read_before_write = false;
    std::size_t first_read = no_instruction_index;
    std::size_t first_write = no_instruction_index;
    std::uint16_t bit_width = 0;
    address_t first_read_address;
    address_t first_write_address;
    fact_provenance_t read_provenance = fact_provenance_t::unknown;
    fact_provenance_t write_provenance = fact_provenance_t::unknown;
};

struct stack_key_t {
    std::uint16_t base_reg = 0;
    std::int64_t offset = 0;

    friend bool operator<(const stack_key_t& lhs, const stack_key_t& rhs) noexcept {
        return std::tie(lhs.base_reg, lhs.offset) < std::tie(rhs.base_reg, rhs.offset);
    }
};

struct stack_observation_t {
    bool read = false;
    bool written = false;
    bool argument_candidate = false;
    std::uint16_t access_width_bits = 0;
    address_t first_address;
    fact_provenance_t provenance = fact_provenance_t::unknown;
};

struct preservation_observation_t {
    bool saved = false;
    bool restored = false;
    address_t save_address;
    address_t restore_address;
    fact_provenance_t provenance = fact_provenance_t::unknown;
};

struct last_write_t {
    std::size_t instruction_index = no_instruction_index;
    entity_id_t block_id = 0;
    address_t address;
    std::uint16_t bit_width = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
};

struct profile_selection_t {
    cc_abi_t abi = cc_abi_t::unknown;
    std::uint8_t confidence = 0;
    bool inferred = false;
    bool conflicted = false;
};

struct argument_key_t {
    argument_location_t location = argument_location_t::unknown;
    std::uint16_t reg = 0;
    std::int64_t stack_offset = 0;
    std::uint32_t abi_slot = 0;

    friend bool operator<(const argument_key_t& lhs, const argument_key_t& rhs) noexcept {
        return std::tie(lhs.location, lhs.reg, lhs.stack_offset, lhs.abi_slot) <
               std::tie(rhs.location, rhs.reg, rhs.stack_offset, rhs.abi_slot);
    }
};

workspace_error_t stopped_error(const cancellation_token_t& cancel, const char* phase) {
    const bool deadline = cancel.deadline_exceeded();
    auto error = make_workspace_error(deadline ? workspace_error_code_t::deadline_exceeded
                                               : workspace_error_code_t::cancelled,
                                      deadline ? "calling convention inference deadline exceeded"
                                               : "calling convention inference cancelled",
                                      phase);
    error.deadline = deadline;
    error.cancellation = !deadline;
    return error;
}

bool cancelled(const cancellation_token_t& cancel) noexcept {
    return cancel.cancellation_requested() || cancel.stop_requested() || cancel.deadline_exceeded();
}

std::uint8_t bounded_confidence(std::uint64_t value) noexcept {
    return static_cast<std::uint8_t>((std::min)(value, std::uint64_t{100}));
}

bool operand_is_read(const operand_fact_t& operand) noexcept {
    return (operand.access & operand_read_access) != 0;
}

bool operand_is_written(const operand_fact_t& operand) noexcept {
    return (operand.access & operand_write_access) != 0;
}

std::uint64_t unsigned_magnitude(std::int64_t value) noexcept {
    if (value >= 0)
        return static_cast<std::uint64_t>(value);
    return static_cast<std::uint64_t>(-(value + 1)) + 1;
}

void hash_word(std::uint64_t& state, std::uint64_t value) noexcept {
    state ^= value;
    state *= 1099511628211ULL;
    state ^= state >> 32;
}

bool contains_register(const std::vector<std::uint16_t>& registers, std::uint16_t reg) {
    return std::find(registers.begin(), registers.end(), reg) != registers.end();
}

void append_evidence(cc_analysis_result_t& result, std::uint64_t max_evidence,
                     cc_evidence_t evidence) {
    if (result.evidence.size() >= max_evidence) {
        result.bounded = true;
        return;
    }
    result.evidence.push_back(std::move(evidence));
}

void append_conflict(cc_analysis_result_t& result, cc_conflict_t conflict) {
    if (result.conflicts.size() >= calling_convention_max_conflicts) {
        result.bounded = true;
        return;
    }
    result.conflicts.push_back(std::move(conflict));
}

std::uint16_t canonical_x86_register(std::uint16_t reg) noexcept {
    switch (static_cast<ZydisRegister>(reg)) {
    case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX:
    case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AH:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_RAX);
    case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX:
    case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BH:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_RBX);
    case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX:
    case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CH:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_RCX);
    case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX:
    case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DH:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_RDX);
    case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_SI:
    case ZYDIS_REGISTER_SIL:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_RSI);
    case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_DI:
    case ZYDIS_REGISTER_DIL:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_RDI);
    case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_BP:
    case ZYDIS_REGISTER_BPL:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_RBP);
    case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_SP:
    case ZYDIS_REGISTER_SPL:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_RSP);
    case ZYDIS_REGISTER_R8: case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R8W:
    case ZYDIS_REGISTER_R8B:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_R8);
    case ZYDIS_REGISTER_R9: case ZYDIS_REGISTER_R9D: case ZYDIS_REGISTER_R9W:
    case ZYDIS_REGISTER_R9B:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_R9);
    case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10W:
    case ZYDIS_REGISTER_R10B:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_R10);
    case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11W:
    case ZYDIS_REGISTER_R11B:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_R11);
    case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12W:
    case ZYDIS_REGISTER_R12B:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_R12);
    case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13W:
    case ZYDIS_REGISTER_R13B:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_R13);
    case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14W:
    case ZYDIS_REGISTER_R14B:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_R14);
    case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15W:
    case ZYDIS_REGISTER_R15B:
        return static_cast<std::uint16_t>(ZYDIS_REGISTER_R15);
    default:
        return reg;
    }
}

std::uint16_t canonical_aarch64_register(std::uint16_t reg) noexcept {
    const auto value = static_cast<unsigned int>(reg);
    const auto w0 = static_cast<unsigned int>(ARM64_REG_W0);
    const auto w28 = static_cast<unsigned int>(ARM64_REG_W28);
    if (value >= w0 && value <= w28)
        return static_cast<std::uint16_t>(static_cast<unsigned int>(ARM64_REG_X0) + value - w0);
    if (reg == static_cast<std::uint16_t>(ARM64_REG_W29))
        return static_cast<std::uint16_t>(ARM64_REG_FP);
    if (reg == static_cast<std::uint16_t>(ARM64_REG_W30))
        return static_cast<std::uint16_t>(ARM64_REG_LR);

    const auto map_vector_bank = [value](unsigned int first, unsigned int last,
                                         unsigned int target) -> std::uint16_t {
        if (value >= first && value <= last)
            return static_cast<std::uint16_t>(target + value - first);
        return 0;
    };
    for (const auto mapping : std::array<std::array<unsigned int, 3>, 6>{
             std::array<unsigned int, 3>{static_cast<unsigned int>(ARM64_REG_B0), static_cast<unsigned int>(ARM64_REG_B31), static_cast<unsigned int>(ARM64_REG_V0)},
             std::array<unsigned int, 3>{static_cast<unsigned int>(ARM64_REG_H0), static_cast<unsigned int>(ARM64_REG_H31), static_cast<unsigned int>(ARM64_REG_V0)},
             std::array<unsigned int, 3>{static_cast<unsigned int>(ARM64_REG_S0), static_cast<unsigned int>(ARM64_REG_S31), static_cast<unsigned int>(ARM64_REG_V0)},
             std::array<unsigned int, 3>{static_cast<unsigned int>(ARM64_REG_D0), static_cast<unsigned int>(ARM64_REG_D31), static_cast<unsigned int>(ARM64_REG_V0)},
             std::array<unsigned int, 3>{static_cast<unsigned int>(ARM64_REG_Q0), static_cast<unsigned int>(ARM64_REG_Q31), static_cast<unsigned int>(ARM64_REG_V0)},
             std::array<unsigned int, 3>{static_cast<unsigned int>(ARM64_REG_V0), static_cast<unsigned int>(ARM64_REG_V31), static_cast<unsigned int>(ARM64_REG_V0)}}) {
        const auto mapped = map_vector_bank(mapping[0], mapping[1], mapping[2]);
        if (mapped != 0)
            return mapped;
    }
    return reg;
}

std::uint16_t canonical_register(architecture_id_t architecture, std::uint16_t reg) noexcept {
    switch (architecture) {
    case architecture_id_t::x86:
    case architecture_id_t::x86_64:
        return canonical_x86_register(reg);
    case architecture_id_t::aarch64:
    case architecture_id_t::arm64ec:
        return canonical_aarch64_register(reg);
    default:
        return reg;
    }
}

abi_profile_t make_profile(cc_abi_t abi) {
    abi_profile_t profile;
    profile.abi = abi;
    switch (abi) {
    case cc_abi_t::x86_cdecl:
    case cc_abi_t::x86_stdcall:
    case cc_abi_t::system_v_x86:
        profile.general_returns = {static_cast<std::uint16_t>(ZYDIS_REGISTER_RAX), static_cast<std::uint16_t>(ZYDIS_REGISTER_RDX)};
        profile.floating_returns = {static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM0)};
        profile.callee_saved = {static_cast<std::uint16_t>(ZYDIS_REGISTER_RBX), static_cast<std::uint16_t>(ZYDIS_REGISTER_RSI), static_cast<std::uint16_t>(ZYDIS_REGISTER_RDI), static_cast<std::uint16_t>(ZYDIS_REGISTER_RBP)};
        profile.stack_pointer = static_cast<std::uint16_t>(ZYDIS_REGISTER_RSP);
        profile.frame_pointer = static_cast<std::uint16_t>(ZYDIS_REGISTER_RBP);
        profile.word_size = 4;
        profile.return_address_size = 4;
        break;
    case cc_abi_t::x86_thiscall:
        profile = make_profile(cc_abi_t::x86_cdecl);
        profile.abi = abi;
        profile.general_arguments = {static_cast<std::uint16_t>(ZYDIS_REGISTER_RCX)};
        break;
    case cc_abi_t::x86_fastcall:
        profile = make_profile(cc_abi_t::x86_cdecl);
        profile.abi = abi;
        profile.general_arguments = {static_cast<std::uint16_t>(ZYDIS_REGISTER_RCX), static_cast<std::uint16_t>(ZYDIS_REGISTER_RDX)};
        break;
    case cc_abi_t::x86_vectorcall:
        profile = make_profile(cc_abi_t::x86_fastcall);
        profile.abi = abi;
        profile.vector_arguments = {static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM0), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM1), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM2), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM3), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM4), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM5)};
        break;
    case cc_abi_t::windows_x64:
    case cc_abi_t::windows_x64_vectorcall:
        profile.general_arguments = {static_cast<std::uint16_t>(ZYDIS_REGISTER_RCX), static_cast<std::uint16_t>(ZYDIS_REGISTER_RDX), static_cast<std::uint16_t>(ZYDIS_REGISTER_R8), static_cast<std::uint16_t>(ZYDIS_REGISTER_R9)};
        profile.floating_arguments = {static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM0), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM1), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM2), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM3)};
        if (abi == cc_abi_t::windows_x64_vectorcall)
            profile.vector_arguments = {static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM0), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM1), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM2), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM3), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM4), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM5)};
        profile.general_returns = {static_cast<std::uint16_t>(ZYDIS_REGISTER_RAX), static_cast<std::uint16_t>(ZYDIS_REGISTER_RDX)};
        profile.floating_returns = {static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM0)};
        profile.callee_saved = {static_cast<std::uint16_t>(ZYDIS_REGISTER_RBX), static_cast<std::uint16_t>(ZYDIS_REGISTER_RBP), static_cast<std::uint16_t>(ZYDIS_REGISTER_RDI), static_cast<std::uint16_t>(ZYDIS_REGISTER_RSI), static_cast<std::uint16_t>(ZYDIS_REGISTER_R12), static_cast<std::uint16_t>(ZYDIS_REGISTER_R13), static_cast<std::uint16_t>(ZYDIS_REGISTER_R14), static_cast<std::uint16_t>(ZYDIS_REGISTER_R15), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM6), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM7), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM8), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM9), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM10), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM11), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM12), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM13), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM14), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM15)};
        profile.stack_pointer = static_cast<std::uint16_t>(ZYDIS_REGISTER_RSP);
        profile.frame_pointer = static_cast<std::uint16_t>(ZYDIS_REGISTER_RBP);
        profile.word_size = 8;
        profile.return_address_size = 8;
        profile.shadow_space_size = 32;
        profile.shared_register_slots = true;
        break;
    case cc_abi_t::system_v_x64:
        profile.general_arguments = {static_cast<std::uint16_t>(ZYDIS_REGISTER_RDI), static_cast<std::uint16_t>(ZYDIS_REGISTER_RSI), static_cast<std::uint16_t>(ZYDIS_REGISTER_RDX), static_cast<std::uint16_t>(ZYDIS_REGISTER_RCX), static_cast<std::uint16_t>(ZYDIS_REGISTER_R8), static_cast<std::uint16_t>(ZYDIS_REGISTER_R9)};
        profile.floating_arguments = {static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM0), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM1), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM2), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM3), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM4), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM5), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM6), static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM7)};
        profile.general_returns = {static_cast<std::uint16_t>(ZYDIS_REGISTER_RAX), static_cast<std::uint16_t>(ZYDIS_REGISTER_RDX)};
        profile.floating_returns = {static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM0)};
        profile.callee_saved = {static_cast<std::uint16_t>(ZYDIS_REGISTER_RBX), static_cast<std::uint16_t>(ZYDIS_REGISTER_RBP), static_cast<std::uint16_t>(ZYDIS_REGISTER_R12), static_cast<std::uint16_t>(ZYDIS_REGISTER_R13), static_cast<std::uint16_t>(ZYDIS_REGISTER_R14), static_cast<std::uint16_t>(ZYDIS_REGISTER_R15)};
        profile.stack_pointer = static_cast<std::uint16_t>(ZYDIS_REGISTER_RSP);
        profile.frame_pointer = static_cast<std::uint16_t>(ZYDIS_REGISTER_RBP);
        profile.word_size = 8;
        profile.return_address_size = 8;
        break;
    case cc_abi_t::arm_aapcs:
        profile.general_arguments = {static_cast<std::uint16_t>(ARM_REG_R0), static_cast<std::uint16_t>(ARM_REG_R1), static_cast<std::uint16_t>(ARM_REG_R2), static_cast<std::uint16_t>(ARM_REG_R3)};
        profile.general_returns = {static_cast<std::uint16_t>(ARM_REG_R0), static_cast<std::uint16_t>(ARM_REG_R1)};
        profile.callee_saved = {static_cast<std::uint16_t>(ARM_REG_R4), static_cast<std::uint16_t>(ARM_REG_R5), static_cast<std::uint16_t>(ARM_REG_R6), static_cast<std::uint16_t>(ARM_REG_R7), static_cast<std::uint16_t>(ARM_REG_R8), static_cast<std::uint16_t>(ARM_REG_R9), static_cast<std::uint16_t>(ARM_REG_R10), static_cast<std::uint16_t>(ARM_REG_R11)};
        profile.stack_pointer = static_cast<std::uint16_t>(ARM_REG_SP);
        profile.frame_pointer = static_cast<std::uint16_t>(ARM_REG_FP);
        profile.word_size = 4;
        break;
    case cc_abi_t::aarch64_aapcs64:
    case cc_abi_t::windows_arm64:
    case cc_abi_t::windows_arm64ec:
        profile.general_arguments = {static_cast<std::uint16_t>(ARM64_REG_X0), static_cast<std::uint16_t>(ARM64_REG_X1), static_cast<std::uint16_t>(ARM64_REG_X2), static_cast<std::uint16_t>(ARM64_REG_X3), static_cast<std::uint16_t>(ARM64_REG_X4), static_cast<std::uint16_t>(ARM64_REG_X5), static_cast<std::uint16_t>(ARM64_REG_X6), static_cast<std::uint16_t>(ARM64_REG_X7)};
        profile.floating_arguments = {static_cast<std::uint16_t>(ARM64_REG_V0), static_cast<std::uint16_t>(ARM64_REG_V1), static_cast<std::uint16_t>(ARM64_REG_V2), static_cast<std::uint16_t>(ARM64_REG_V3), static_cast<std::uint16_t>(ARM64_REG_V4), static_cast<std::uint16_t>(ARM64_REG_V5), static_cast<std::uint16_t>(ARM64_REG_V6), static_cast<std::uint16_t>(ARM64_REG_V7)};
        profile.general_returns = {static_cast<std::uint16_t>(ARM64_REG_X0), static_cast<std::uint16_t>(ARM64_REG_X1)};
        profile.floating_returns = {static_cast<std::uint16_t>(ARM64_REG_V0)};
        profile.callee_saved = {static_cast<std::uint16_t>(ARM64_REG_X19), static_cast<std::uint16_t>(ARM64_REG_X20), static_cast<std::uint16_t>(ARM64_REG_X21), static_cast<std::uint16_t>(ARM64_REG_X22), static_cast<std::uint16_t>(ARM64_REG_X23), static_cast<std::uint16_t>(ARM64_REG_X24), static_cast<std::uint16_t>(ARM64_REG_X25), static_cast<std::uint16_t>(ARM64_REG_X26), static_cast<std::uint16_t>(ARM64_REG_X27), static_cast<std::uint16_t>(ARM64_REG_X28), static_cast<std::uint16_t>(ARM64_REG_FP), static_cast<std::uint16_t>(ARM64_REG_V8), static_cast<std::uint16_t>(ARM64_REG_V9), static_cast<std::uint16_t>(ARM64_REG_V10), static_cast<std::uint16_t>(ARM64_REG_V11), static_cast<std::uint16_t>(ARM64_REG_V12), static_cast<std::uint16_t>(ARM64_REG_V13), static_cast<std::uint16_t>(ARM64_REG_V14), static_cast<std::uint16_t>(ARM64_REG_V15)};
        profile.stack_pointer = static_cast<std::uint16_t>(ARM64_REG_SP);
        profile.frame_pointer = static_cast<std::uint16_t>(ARM64_REG_FP);
        profile.word_size = 8;
        break;
    case cc_abi_t::mips_o32:
        profile.general_arguments = {static_cast<std::uint16_t>(MIPS_REG_A0), static_cast<std::uint16_t>(MIPS_REG_A1), static_cast<std::uint16_t>(MIPS_REG_A2), static_cast<std::uint16_t>(MIPS_REG_A3)};
        profile.general_returns = {static_cast<std::uint16_t>(MIPS_REG_V0), static_cast<std::uint16_t>(MIPS_REG_V1)};
        profile.callee_saved = {static_cast<std::uint16_t>(MIPS_REG_S0), static_cast<std::uint16_t>(MIPS_REG_S1), static_cast<std::uint16_t>(MIPS_REG_S2), static_cast<std::uint16_t>(MIPS_REG_S3), static_cast<std::uint16_t>(MIPS_REG_S4), static_cast<std::uint16_t>(MIPS_REG_S5), static_cast<std::uint16_t>(MIPS_REG_S6), static_cast<std::uint16_t>(MIPS_REG_S7), static_cast<std::uint16_t>(MIPS_REG_FP)};
        profile.stack_pointer = static_cast<std::uint16_t>(MIPS_REG_SP);
        profile.frame_pointer = static_cast<std::uint16_t>(MIPS_REG_FP);
        profile.word_size = 4;
        break;
    case cc_abi_t::mips_n64:
        profile = make_profile(cc_abi_t::mips_o32);
        profile.abi = abi;
        profile.general_arguments = {static_cast<std::uint16_t>(MIPS_REG_A0), static_cast<std::uint16_t>(MIPS_REG_A1), static_cast<std::uint16_t>(MIPS_REG_A2), static_cast<std::uint16_t>(MIPS_REG_A3), static_cast<std::uint16_t>(MIPS_REG_8), static_cast<std::uint16_t>(MIPS_REG_9), static_cast<std::uint16_t>(MIPS_REG_10), static_cast<std::uint16_t>(MIPS_REG_11)};
        profile.word_size = 8;
        break;
    case cc_abi_t::ppc_sysv32:
    case cc_abi_t::ppc_sysv64:
        profile.general_arguments = {static_cast<std::uint16_t>(PPC_REG_R3), static_cast<std::uint16_t>(PPC_REG_R4), static_cast<std::uint16_t>(PPC_REG_R5), static_cast<std::uint16_t>(PPC_REG_R6), static_cast<std::uint16_t>(PPC_REG_R7), static_cast<std::uint16_t>(PPC_REG_R8), static_cast<std::uint16_t>(PPC_REG_R9), static_cast<std::uint16_t>(PPC_REG_R10)};
        profile.floating_arguments = {static_cast<std::uint16_t>(PPC_REG_F1), static_cast<std::uint16_t>(PPC_REG_F2), static_cast<std::uint16_t>(PPC_REG_F3), static_cast<std::uint16_t>(PPC_REG_F4), static_cast<std::uint16_t>(PPC_REG_F5), static_cast<std::uint16_t>(PPC_REG_F6), static_cast<std::uint16_t>(PPC_REG_F7), static_cast<std::uint16_t>(PPC_REG_F8)};
        profile.general_returns = {static_cast<std::uint16_t>(PPC_REG_R3), static_cast<std::uint16_t>(PPC_REG_R4)};
        profile.floating_returns = {static_cast<std::uint16_t>(PPC_REG_F1)};
        profile.callee_saved = {static_cast<std::uint16_t>(PPC_REG_R14), static_cast<std::uint16_t>(PPC_REG_R15), static_cast<std::uint16_t>(PPC_REG_R16), static_cast<std::uint16_t>(PPC_REG_R17), static_cast<std::uint16_t>(PPC_REG_R18), static_cast<std::uint16_t>(PPC_REG_R19), static_cast<std::uint16_t>(PPC_REG_R20), static_cast<std::uint16_t>(PPC_REG_R21), static_cast<std::uint16_t>(PPC_REG_R22), static_cast<std::uint16_t>(PPC_REG_R23), static_cast<std::uint16_t>(PPC_REG_R24), static_cast<std::uint16_t>(PPC_REG_R25), static_cast<std::uint16_t>(PPC_REG_R26), static_cast<std::uint16_t>(PPC_REG_R27), static_cast<std::uint16_t>(PPC_REG_R28), static_cast<std::uint16_t>(PPC_REG_R29), static_cast<std::uint16_t>(PPC_REG_R30), static_cast<std::uint16_t>(PPC_REG_R31)};
        profile.stack_pointer = static_cast<std::uint16_t>(PPC_REG_R1);
        profile.word_size = abi == cc_abi_t::ppc_sysv64 ? 8 : 4;
        break;
    case cc_abi_t::riscv_ilp32:
    case cc_abi_t::riscv_lp64:
        profile.general_arguments = {static_cast<std::uint16_t>(RISCV_REG_A0), static_cast<std::uint16_t>(RISCV_REG_A1), static_cast<std::uint16_t>(RISCV_REG_A2), static_cast<std::uint16_t>(RISCV_REG_A3), static_cast<std::uint16_t>(RISCV_REG_A4), static_cast<std::uint16_t>(RISCV_REG_A5), static_cast<std::uint16_t>(RISCV_REG_A6), static_cast<std::uint16_t>(RISCV_REG_A7)};
        profile.general_returns = {static_cast<std::uint16_t>(RISCV_REG_A0), static_cast<std::uint16_t>(RISCV_REG_A1)};
        profile.callee_saved = {static_cast<std::uint16_t>(RISCV_REG_S0), static_cast<std::uint16_t>(RISCV_REG_S1), static_cast<std::uint16_t>(RISCV_REG_S2), static_cast<std::uint16_t>(RISCV_REG_S3), static_cast<std::uint16_t>(RISCV_REG_S4), static_cast<std::uint16_t>(RISCV_REG_S5), static_cast<std::uint16_t>(RISCV_REG_S6), static_cast<std::uint16_t>(RISCV_REG_S7), static_cast<std::uint16_t>(RISCV_REG_S8), static_cast<std::uint16_t>(RISCV_REG_S9), static_cast<std::uint16_t>(RISCV_REG_S10), static_cast<std::uint16_t>(RISCV_REG_S11)};
        profile.stack_pointer = static_cast<std::uint16_t>(RISCV_REG_SP);
        profile.frame_pointer = static_cast<std::uint16_t>(RISCV_REG_FP);
        profile.word_size = abi == cc_abi_t::riscv_lp64 ? 8 : 4;
        break;
    default:
        break;
    }
    return profile;
}

std::vector<cc_abi_t> candidate_abis(const workspace_identity_t& identity) {
    const auto architecture = identity.architecture();
    const auto abi = identity.abi();
    if (architecture == architecture_id_t::jvm_bytecode || abi == abi_id_t::jvm)
        return {cc_abi_t::managed_jvm_identity};
    if (architecture == architecture_id_t::dalvik_bytecode || abi == abi_id_t::dalvik)
        return {cc_abi_t::managed_dalvik_identity};

    if (architecture == architecture_id_t::x86) {
        if (identity.architecture_mode() != architecture_mode_t::x86_32)
            return {};
        if (abi == abi_id_t::windows_x86)
            return {cc_abi_t::x86_cdecl, cc_abi_t::x86_stdcall, cc_abi_t::x86_thiscall,
                    cc_abi_t::x86_fastcall, cc_abi_t::x86_vectorcall};
        if (abi == abi_id_t::linux_x86 || abi == abi_id_t::sysv || abi == abi_id_t::darwin ||
            abi == abi_id_t::android_x86)
            return {cc_abi_t::system_v_x86};
        return {};
    }
    if (architecture == architecture_id_t::x86_64) {
        if (abi == abi_id_t::windows_x64)
            return {cc_abi_t::windows_x64, cc_abi_t::windows_x64_vectorcall};
        if (abi == abi_id_t::linux_x64 || abi == abi_id_t::sysv || abi == abi_id_t::darwin ||
            abi == abi_id_t::darwin_x86_64 || abi == abi_id_t::android_x86_64)
            return {cc_abi_t::system_v_x64};
        return {};
    }
    if (architecture == architecture_id_t::arm) {
        if (abi == abi_id_t::linux_arm || abi == abi_id_t::android_arm)
            return {cc_abi_t::arm_aapcs};
        return {};
    }
    if (architecture == architecture_id_t::aarch64) {
        if (abi == abi_id_t::windows_arm64)
            return {cc_abi_t::windows_arm64};
        if (abi == abi_id_t::linux_aarch64 || abi == abi_id_t::darwin_aarch64 ||
            abi == abi_id_t::android_aarch64 || abi == abi_id_t::darwin)
            return {cc_abi_t::aarch64_aapcs64};
        return {};
    }
    if (architecture == architecture_id_t::arm64ec) {
        if (abi == abi_id_t::windows_arm64ec)
            return {cc_abi_t::windows_arm64ec};
        return {};
    }
    if (architecture == architecture_id_t::mips || architecture == architecture_id_t::mips64) {
        if (abi == abi_id_t::linux_mips)
            return identity.architecture_mode() == architecture_mode_t::mips64
                ? std::vector<cc_abi_t>{cc_abi_t::mips_n64}
                : std::vector<cc_abi_t>{cc_abi_t::mips_o32};
        return {};
    }
    if (architecture == architecture_id_t::ppc || architecture == architecture_id_t::ppc64) {
        if (abi == abi_id_t::linux_ppc || abi == abi_id_t::linux_ppc64)
            return architecture == architecture_id_t::ppc64
                ? std::vector<cc_abi_t>{cc_abi_t::ppc_sysv64}
                : std::vector<cc_abi_t>{cc_abi_t::ppc_sysv32};
        return {};
    }
    if (architecture == architecture_id_t::riscv || architecture == architecture_id_t::riscv32 ||
        architecture == architecture_id_t::riscv64) {
        if (abi == abi_id_t::linux_riscv)
            return identity.architecture_mode() == architecture_mode_t::riscv64
                ? std::vector<cc_abi_t>{cc_abi_t::riscv_lp64}
                : std::vector<cc_abi_t>{cc_abi_t::riscv_ilp32};
    }
    return {};
}

bool is_managed_abi(cc_abi_t abi) noexcept {
    return abi == cc_abi_t::managed_jvm_identity || abi == cc_abi_t::managed_dalvik_identity;
}

workspace_result_t<std::uint64_t> canonical_function_rva(
    const analysis_workspace_t& workspace, const calling_convention_request_t& request) {
    const auto& identity = workspace.identity();
    if (request.function.architecture != identity.architecture() ||
        request.function.mode != identity.architecture_mode()) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "function address architecture does not match workspace",
                                          "calling_convention.address");
        error.address = request.function;
        return workspace_result_t<std::uint64_t>::failure(std::move(error));
    }
    if (request.function.space == address_space_id_t::relative_virtual)
        return workspace_result_t<std::uint64_t>::success(request.function.value);
    if (request.function.space == address_space_id_t::virtual_address ||
        request.function.space == address_space_id_t::live_virtual) {
        const auto base = identity.image_base();
        if (request.function.value < base) {
            auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                              "function address precedes the workspace image base",
                                              "calling_convention.address");
            error.address = request.function;
            return workspace_result_t<std::uint64_t>::failure(std::move(error));
        }
        return workspace_result_t<std::uint64_t>::success(request.function.value - base);
    }
    auto error = make_workspace_error(workspace_error_code_t::unsupported_address_space,
                                      "calling convention inference requires an RVA or virtual address",
                                      "calling_convention.address");
    error.address = request.function;
    return workspace_result_t<std::uint64_t>::failure(std::move(error));
}

workspace_result_t<void> validate_request_budgets(
    const calling_convention_request_t& request) {
    if (request.max_instruction_visits == 0 || request.max_evidence == 0 ||
        request.max_stack_slots == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "calling convention request contains a zero budget", "calling_convention.request"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> check_request_revisions(
    const calling_convention_request_t& request, const analysis_snapshot_t& snapshot,
    const char* phase) {
    if ((request.expected_generation && *request.expected_generation != snapshot.generation) ||
        (request.expected_analysis_revision &&
         *request.expected_analysis_revision != snapshot.analysis_revision) ||
        (request.expected_overlay_revision && *request.expected_overlay_revision != snapshot.overlay_revision)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "calling convention request revisions do not match the snapshot", phase));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::shared_ptr<const analysis_snapshot_t>> acquire_snapshot(
    const analysis_workspace_t& workspace, const calling_convention_request_t& request,
    const cancellation_token_t& cancel, const char* phase) {
    if (cancelled(cancel))
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(stopped_error(cancel, phase));
    const auto workspace_cancel = workspace.cancellation_token();
    if (cancelled(workspace_cancel)) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            stopped_error(workspace_cancel, phase));
    }
    if (workspace.closing() || workspace.closed()) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "calling convention inference rejected a closing workspace", phase));
    }
    const auto snapshot = workspace.snapshot();
    if (!snapshot) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::analysis_in_progress,
                                 "calling convention inference requires a published analysis snapshot", phase));
    }
    if (snapshot->binary_id != workspace.identity().binary_id()) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "analysis snapshot identity does not match the workspace", phase));
    }
    const auto revisions = check_request_revisions(request, *snapshot, phase);
    if (!revisions) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            revisions.error());
    }
    return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::success(snapshot);
}

workspace_result_t<function_view_t> extract_function_view(const analysis_snapshot_t& snapshot,
                                                           std::uint64_t function_rva,
                                                           const workspace_identity_t& identity,
                                                           const cancellation_token_t& cancel) {
    function_view_t view;
    for (std::size_t index = 0; index < snapshot.functions.size(); ++index) {
        if ((index & 127U) == 0 && cancelled(cancel))
            return workspace_result_t<function_view_t>::failure(stopped_error(cancel, "calling_convention.function"));
        const auto& function = snapshot.functions[index];
        if (function.start.value == function_rva &&
            function.start.architecture == identity.architecture() &&
            function.start.mode == identity.architecture_mode()) {
            view.function = &function;
            break;
        }
    }
    if (!view.function) {
        return workspace_result_t<function_view_t>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "calling convention inference could not find the requested function", "calling_convention.function"));
    }

    std::map<std::size_t, entity_id_t> instruction_blocks;
    for (std::size_t block_index = 0; block_index < snapshot.blocks.size(); ++block_index) {
        if ((block_index & 127U) == 0 && cancelled(cancel))
            return workspace_result_t<function_view_t>::failure(stopped_error(cancel, "calling_convention.function"));
        const auto& block = snapshot.blocks[block_index];
        if (block.function_id != view.function->id)
            continue;
        const std::size_t first = block.first_instruction;
        const std::size_t count = block.instruction_count;
        if (first > snapshot.instructions.size() || count > snapshot.instructions.size() - first) {
            return workspace_result_t<function_view_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "function block instruction range exceeds the snapshot", "calling_convention.function"));
        }
        for (std::size_t index = first; index < first + count; ++index) {
            if (((index - first) & 127U) == 0 && cancelled(cancel)) {
                return workspace_result_t<function_view_t>::failure(
                    stopped_error(cancel, "calling_convention.function"));
            }
            instruction_blocks.emplace(index, block.id);
        }
    }
    if (instruction_blocks.empty()) {
        return workspace_result_t<function_view_t>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "requested function has no normalized instructions", "calling_convention.function"));
    }

    view.instructions.reserve(instruction_blocks.size());
    std::size_t record_index = 0;
    for (const auto& [index, block_id] : instruction_blocks) {
        if ((record_index++ & 127U) == 0 && cancelled(cancel)) {
            return workspace_result_t<function_view_t>::failure(
                stopped_error(cancel, "calling_convention.function"));
        }
        view.instructions.push_back(function_instruction_t{&snapshot.instructions[index], block_id});
    }
    std::stable_sort(view.instructions.begin(), view.instructions.end(),
                     [](const function_instruction_t& lhs, const function_instruction_t& rhs) {
                         if (lhs.instruction->address != rhs.instruction->address)
                             return lhs.instruction->address < rhs.instruction->address;
                         return lhs.instruction->id < rhs.instruction->id;
                     });
    return workspace_result_t<function_view_t>::success(std::move(view));
}

void observe_register(std::map<std::uint16_t, register_observation_t>& observations,
                      std::uint16_t reg, bool read, bool write, std::uint16_t bit_width,
                      std::size_t instruction_index, const instruction_record_t& instruction) {
    if (reg == 0)
        return;
    auto& observation = observations[reg];
    if (read) {
        if (!observation.read) {
            observation.first_read = instruction_index;
            observation.first_read_address = instruction.address;
            observation.read_provenance = instruction.provenance;
        }
        observation.read = true;
        if (!observation.written)
            observation.read_before_write = true;
    }
    if (write) {
        if (!observation.written) {
            observation.first_write = instruction_index;
            observation.first_write_address = instruction.address;
            observation.write_provenance = instruction.provenance;
        }
        observation.written = true;
    }
    observation.bit_width = (std::max)(observation.bit_width, bit_width);
}

profile_selection_t select_profile(const std::vector<cc_abi_t>& candidates,
                                   const std::map<std::uint16_t, register_observation_t>& observations,
                                   bool has_callee_cleanup) {
    profile_selection_t selection;
    if (candidates.empty())
        return selection;
    if (candidates.size() == 1 && !is_managed_abi(candidates.front())) {
        selection.abi = candidates.front();
        selection.inferred = true;
        selection.confidence = 72;
        return selection;
    }
    if (candidates.size() == 2 && candidates[0] == cc_abi_t::windows_x64 &&
        candidates[1] == cc_abi_t::windows_x64_vectorcall) {
        const auto used_vector_extension = [&observations](std::uint16_t reg) {
            const auto found = observations.find(reg);
            return found != observations.end() && found->second.read_before_write;
        };
        selection.abi = used_vector_extension(static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM4)) ||
                        used_vector_extension(static_cast<std::uint16_t>(ZYDIS_REGISTER_XMM5))
            ? cc_abi_t::windows_x64_vectorcall : cc_abi_t::windows_x64;
        selection.confidence = selection.abi == cc_abi_t::windows_x64_vectorcall ? 80 : 72;
        selection.inferred = true;
        return selection;
    }

    std::vector<std::pair<cc_abi_t, std::uint64_t>> scores;
    for (const auto candidate : candidates) {
        const auto profile = make_profile(candidate);
        std::uint64_t score = 0;
        const auto read_before_write = [&observations](std::uint16_t reg) {
            const auto found = observations.find(reg);
            return found != observations.end() && found->second.read_before_write;
        };
        switch (candidate) {
        case cc_abi_t::x86_stdcall:
            score = has_callee_cleanup ? 52 : 0;
            break;
        case cc_abi_t::x86_thiscall:
            score = read_before_write(static_cast<std::uint16_t>(ZYDIS_REGISTER_RCX)) ? 56 : 0;
            if (has_callee_cleanup)
                score += 12;
            break;
        case cc_abi_t::x86_fastcall:
            if (read_before_write(static_cast<std::uint16_t>(ZYDIS_REGISTER_RCX)) &&
                read_before_write(static_cast<std::uint16_t>(ZYDIS_REGISTER_RDX)))
                score = 68;
            else if (read_before_write(static_cast<std::uint16_t>(ZYDIS_REGISTER_RCX)) ||
                     read_before_write(static_cast<std::uint16_t>(ZYDIS_REGISTER_RDX)))
                score = 16;
            if (has_callee_cleanup)
                score += 10;
            break;
        case cc_abi_t::x86_vectorcall: {
            std::uint64_t vectors = 0;
            for (const auto reg : profile.vector_arguments)
                vectors += read_before_write(reg) ? 1 : 0;
            if (vectors != 0)
                score = 70 + (std::min)(vectors * 4, std::uint64_t{20});
            if (read_before_write(static_cast<std::uint16_t>(ZYDIS_REGISTER_RCX)) &&
                read_before_write(static_cast<std::uint16_t>(ZYDIS_REGISTER_RDX)))
                score += 8;
            if (has_callee_cleanup)
                score += 8;
            break;
        }
        default:
            break;
        }
        scores.emplace_back(candidate, score);
    }
    std::stable_sort(scores.begin(), scores.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.second != rhs.second)
            return lhs.second > rhs.second;
        return lhs.first < rhs.first;
    });
    if (scores.empty() || scores.front().second < 48)
        return selection;
    if (scores.size() > 1 && scores.front().second < scores[1].second + 12) {
        selection.conflicted = true;
        return selection;
    }
    selection.abi = scores.front().first;
    selection.confidence = bounded_confidence(scores.front().second);
    selection.inferred = true;
    return selection;
}

bool return_equivalent(const cc_return_info_t& lhs, const cc_return_info_t& rhs) {
    return lhs.state == rhs.state && lhs.registers == rhs.registers &&
           lhs.is_float == rhs.is_float && lhs.is_vector == rhs.is_vector;
}

bool arguments_equivalent(const std::vector<argument_info_t>& lhs,
                          const std::vector<argument_info_t>& rhs) {
    if (lhs.size() != rhs.size())
        return false;
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        const auto& left = lhs[index];
        const auto& right = rhs[index];
        if (left.index != right.index || left.abi_slot != right.abi_slot ||
            left.reg != right.reg || left.stack_offset != right.stack_offset ||
            left.bit_width != right.bit_width || left.location != right.location ||
            left.provenance != right.provenance || left.confidence != right.confidence ||
            left.index_is_logical != right.index_is_logical ||
            left.is_float != right.is_float || left.is_vector != right.is_vector ||
            left.used != right.used || left.conflicted != right.conflicted)
            return false;
    }
    return true;
}

std::uint64_t candidate_weight(const cc_analysis_result_t& candidate) {
    std::uint64_t provenance = 0;
    for (const auto& evidence : candidate.evidence)
        provenance = (std::max)(provenance, static_cast<std::uint64_t>(provenance_rank(evidence.provenance)));
    return static_cast<std::uint64_t>(candidate.confidence) * 16 + provenance +
           (candidate.state == cc_inference_state_t::inferred ? 32 : 0);
}

workspace_result_t<void> validate_current_scope(const analysis_workspace_t& workspace,
                                                const analysis_snapshot_t& snapshot,
                                                const cancellation_token_t& cancel) {
    if (cancelled(cancel))
        return workspace_result_t<void>::failure(stopped_error(cancel, "calling_convention.commit"));
    const auto workspace_cancel = workspace.cancellation_token();
    if (cancelled(workspace_cancel)) {
        return workspace_result_t<void>::failure(
            stopped_error(workspace_cancel, "calling_convention.commit"));
    }
    if (workspace.closing() || workspace.closed() || workspace.generation() != snapshot.generation ||
        workspace.analysis_revision() != snapshot.analysis_revision ||
        workspace.overlay_revision() != snapshot.overlay_revision) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "calling convention result became stale before completion", "calling_convention.commit"));
    }
    return workspace_result_t<void>::success();
}

void synchronize_legacy_return(cc_analysis_result_t& result) {
    result.return_reg = 0;
    result.return_bit_width = 0;
    result.return_is_float = false;
    if (result.return_value.state != cc_value_state_t::inferred ||
        result.return_value.registers.empty())
        return;
    result.return_reg = result.return_value.registers.front();
    result.return_bit_width = result.return_value.bit_width;
    result.return_is_float = result.return_value.is_float;
}

} 

std::uint64_t calling_convention_cache_key_t::stable_hash() const noexcept {
    std::uint64_t state = 1469598103934665603ULL;
    for (const auto byte : binary_id.bytes)
        hash_word(state, byte);
    hash_word(state, static_cast<std::uint64_t>(function.space));
    hash_word(state, function.value);
    hash_word(state, static_cast<std::uint64_t>(function.architecture));
    hash_word(state, static_cast<std::uint64_t>(function.mode));
    hash_word(state, static_cast<std::uint64_t>(architecture));
    hash_word(state, static_cast<std::uint64_t>(architecture_mode));
    hash_word(state, static_cast<std::uint64_t>(declared_abi));
    hash_word(state, generation);
    hash_word(state, analysis_revision);
    hash_word(state, overlay_revision);
    hash_word(state, rules_revision);
    return state;
}

workspace_result_t<calling_convention_cache_key_t>
make_calling_convention_cache_key(const analysis_workspace_t& workspace,
                                  const calling_convention_request_t& request,
                                  const cancellation_token_t& cancel) {
    const auto snapshot = acquire_snapshot(workspace, request, cancel, "calling_convention.cache_key");
    if (!snapshot)
        return workspace_result_t<calling_convention_cache_key_t>::failure(snapshot.error());
    const auto function_rva = canonical_function_rva(workspace, request);
    if (!function_rva)
        return workspace_result_t<calling_convention_cache_key_t>::failure(function_rva.error());
    const auto view = extract_function_view(*snapshot.value(), function_rva.value(), workspace.identity(), cancel);
    if (!view)
        return workspace_result_t<calling_convention_cache_key_t>::failure(view.error());
    const auto current = validate_current_scope(workspace, *snapshot.value(), cancel);
    if (!current)
        return workspace_result_t<calling_convention_cache_key_t>::failure(current.error());

    calling_convention_cache_key_t key;
    key.binary_id = workspace.identity().binary_id();
    key.function = request.function;
    key.architecture = workspace.identity().architecture();
    key.architecture_mode = workspace.identity().architecture_mode();
    key.declared_abi = workspace.identity().abi();
    key.generation = snapshot.value()->generation;
    key.analysis_revision = snapshot.value()->analysis_revision;
    key.overlay_revision = snapshot.value()->overlay_revision;
    return workspace_result_t<calling_convention_cache_key_t>::success(std::move(key));
}

namespace {

workspace_result_t<cc_analysis_result_t>
infer_with_snapshot(const analysis_workspace_t& workspace,
                    const std::shared_ptr<const analysis_snapshot_t>& snapshot,
                    const calling_convention_request_t& request,
                    const cancellation_token_t& cancel) {
    const auto function_rva = canonical_function_rva(workspace, request);
    if (!function_rva)
        return workspace_result_t<cc_analysis_result_t>::failure(function_rva.error());
    const auto view = extract_function_view(*snapshot, function_rva.value(), workspace.identity(), cancel);
    if (!view)
        return workspace_result_t<cc_analysis_result_t>::failure(view.error());
    const auto workspace_cancel = workspace.cancellation_token();

    cc_analysis_result_t result;
    result.function_rva = function_rva.value();
    result.cache_key.binary_id = workspace.identity().binary_id();
    result.cache_key.function = request.function;
    result.cache_key.architecture = workspace.identity().architecture();
    result.cache_key.architecture_mode = workspace.identity().architecture_mode();
    result.cache_key.declared_abi = workspace.identity().abi();
    result.cache_key.generation = snapshot->generation;
    result.cache_key.analysis_revision = snapshot->analysis_revision;
    result.cache_key.overlay_revision = snapshot->overlay_revision;

    const auto candidates = candidate_abis(workspace.identity());
    if (candidates.size() == 1 && is_managed_abi(candidates.front())) {
        result.abi = candidates.front();
        result.state = cc_inference_state_t::abstained;
        result.arguments_state = cc_value_state_t::abstained;
        result.variadic_state = cc_value_state_t::abstained;
        result.native_abi = false;
        append_evidence(result, request.max_evidence,
                        cc_evidence_t{cc_evidence_kind_t::managed_identity,
                                      fact_provenance_t::linear_validation,
                                      request.function, 0, 0, 0, 100, true});
        const auto current = validate_current_scope(workspace, *snapshot, cancel);
        if (!current)
            return workspace_result_t<cc_analysis_result_t>::failure(current.error());
        return workspace_result_t<cc_analysis_result_t>::success(std::move(result));
    }
    if (candidates.empty()) {
        result.state = cc_inference_state_t::abstained;
        result.arguments_state = cc_value_state_t::abstained;
        result.variadic_state = cc_value_state_t::abstained;
        const auto current = validate_current_scope(workspace, *snapshot, cancel);
        if (!current)
            return workspace_result_t<cc_analysis_result_t>::failure(current.error());
        return workspace_result_t<cc_analysis_result_t>::success(std::move(result));
    }

    std::vector<abi_profile_t> profiles;
    profiles.reserve(candidates.size());
    for (const auto candidate : candidates) {
        auto profile = make_profile(candidate);
        profiles.push_back(std::move(profile));
    }
    const auto& reference_profile = profiles.front();
    result.frame.stack_pointer_reg = reference_profile.stack_pointer;
    result.frame.frame_pointer_reg = reference_profile.frame_pointer;
    result.frame.has_shadow_space = reference_profile.shadow_space_size != 0;
    result.frame.shadow_space_size = reference_profile.shadow_space_size;

    std::map<std::uint16_t, register_observation_t> observations;
    std::map<stack_key_t, stack_observation_t> stack_observations;
    std::map<std::uint16_t, preservation_observation_t> preservation;
    std::map<std::uint16_t, last_write_t> last_writes;
    bool has_callee_cleanup = false;
    std::size_t first_return_index = no_instruction_index;
    const auto visit_limit = (std::min)(request.max_instruction_visits,
                                        static_cast<std::uint64_t>(view.value().instructions.size()));
    if (visit_limit < view.value().instructions.size())
        result.bounded = true;

    for (std::size_t instruction_index = 0; instruction_index < visit_limit; ++instruction_index) {
        if ((instruction_index & 63U) == 0) {
            if (cancelled(cancel)) {
                return workspace_result_t<cc_analysis_result_t>::failure(
                    stopped_error(cancel, "calling_convention.scan"));
            }
            if (cancelled(workspace_cancel)) {
                return workspace_result_t<cc_analysis_result_t>::failure(
                    stopped_error(workspace_cancel, "calling_convention.scan"));
            }
        }
        const auto& item = view.value().instructions[instruction_index];
        const auto& instruction = *item.instruction;
        const std::size_t operand_begin = instruction.operand_fact_begin;
        const std::size_t operand_count = instruction.operand_fact_count;
        if (operand_begin > snapshot->operand_facts.size() ||
            operand_count > snapshot->operand_facts.size() - operand_begin) {
            return workspace_result_t<cc_analysis_result_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "instruction operand range exceeds the snapshot", "calling_convention.scan"));
        }

        std::set<std::uint16_t> instruction_reads;
        std::set<std::uint16_t> instruction_writes;
        bool memory_read = false;
        bool memory_write = false;
        for (std::size_t operand_index = 0; operand_index < operand_count; ++operand_index) {
            const auto& operand = snapshot->operand_facts[operand_begin + operand_index];
            const auto bit_width = operand.access_width_bits != 0 ? operand.access_width_bits : operand.bit_width;
            if (operand.kind == operand_kind_t::reg) {
                const auto reg = canonical_register(workspace.identity().architecture(), operand.reg);
                if (operand_is_read(operand))
                    instruction_reads.insert(reg);
                if (operand_is_written(operand))
                    instruction_writes.insert(reg);
                observe_register(observations, reg, operand_is_read(operand), operand_is_written(operand),
                                 bit_width, instruction_index, instruction);
                continue;
            }
            if (operand.kind != operand_kind_t::memory)
                continue;

            const auto base = canonical_register(workspace.identity().architecture(), operand.base_reg);
            const auto index = canonical_register(workspace.identity().architecture(), operand.index_reg);
            if (base != 0) {
                instruction_reads.insert(base);
                observe_register(observations, base, true, false, operand.address_width_bits,
                                 instruction_index, instruction);
            }
            if (index != 0) {
                instruction_reads.insert(index);
                observe_register(observations, index, true, false, operand.address_width_bits,
                                 instruction_index, instruction);
            }
            const bool reads_memory = operand_is_read(operand);
            const bool writes_memory = operand_is_written(operand);
            memory_read = memory_read || reads_memory;
            memory_write = memory_write || writes_memory;
            const bool stack_based = reference_profile.stack_pointer != 0 &&
                base == reference_profile.stack_pointer;
            const bool frame_based = reference_profile.frame_pointer != 0 &&
                base == reference_profile.frame_pointer;
            if (!stack_based && !frame_based)
                continue;
            if (stack_observations.size() >= request.max_stack_slots &&
                stack_observations.find(stack_key_t{base, operand.displacement}) == stack_observations.end()) {
                result.bounded = true;
                continue;
            }
            auto& stack = stack_observations[stack_key_t{base, operand.displacement}];
            if (!stack.read && !stack.written)
                stack.first_address = instruction.address;
            stack.read = stack.read || reads_memory;
            stack.written = stack.written || writes_memory;
            stack.access_width_bits = (std::max)(stack.access_width_bits, bit_width);
            if (provenance_rank(instruction.provenance) >= provenance_rank(stack.provenance))
                stack.provenance = instruction.provenance;
            const auto frame_argument_offset = reference_profile.return_address_size +
                reference_profile.word_size + reference_profile.shadow_space_size;
            const bool frame_argument = frame_based && reads_memory && operand.displacement >=
                static_cast<std::int64_t>(frame_argument_offset);
            stack.argument_candidate = stack.argument_candidate || frame_argument;
            result.frame.observed_stack_extent = (std::max)(result.frame.observed_stack_extent,
                                                            unsigned_magnitude(operand.displacement));
            if (frame_based)
                result.frame.uses_frame_pointer = true;
        }

        for (const auto reg : instruction_reads) {
            if (!contains_register(reference_profile.callee_saved, reg) || !memory_write)
                continue;
            auto& observed = preservation[reg];
            if (!observed.saved) {
                observed.saved = true;
                observed.save_address = instruction.address;
                observed.provenance = instruction.provenance;
            }
        }
        for (const auto reg : instruction_writes) {
            if (!contains_register(reference_profile.callee_saved, reg) || !memory_read)
                continue;
            auto& observed = preservation[reg];
            if (!observed.restored) {
                observed.restored = true;
                observed.restore_address = instruction.address;
                if (provenance_rank(instruction.provenance) >= provenance_rank(observed.provenance))
                    observed.provenance = instruction.provenance;
            }
        }
        for (const auto reg : instruction_writes) {
            last_writes[reg] = last_write_t{instruction_index, item.block_id, instruction.address,
                                            observations[reg].bit_width, instruction.provenance};
        }

        if ((instruction.flow_flags & flow_return) == 0)
            continue;
        if (first_return_index == no_instruction_index) {
            first_return_index = instruction_index;
            result.frame.epilogue_start_rva = instruction.address.value;
        }
        for (std::size_t operand_index = 0; operand_index < operand_count; ++operand_index) {
            const auto& operand = snapshot->operand_facts[operand_begin + operand_index];
            if (operand.kind == operand_kind_t::immediate && operand.immediate != 0)
                has_callee_cleanup = true;
        }
        result.instructions_analyzed = instruction_index + 1;
    }
    result.instructions_analyzed = visit_limit;
    result.is_noreturn = view.value().function->noreturn;

    const auto selection = select_profile(candidates, observations, has_callee_cleanup);
    if (selection.conflicted) {
        result.state = cc_inference_state_t::conflicted;
        result.arguments_state = cc_value_state_t::conflicted;
        result.variadic_state = cc_value_state_t::abstained;
        append_conflict(result, cc_conflict_t{cc_conflict_kind_t::abi});
        append_evidence(result, request.max_evidence,
                        cc_evidence_t{cc_evidence_kind_t::merge_conflict,
                                      fact_provenance_t::unknown, request.function,
                                      0, 0, 0, 0, false});
    } else if (!selection.inferred) {
        result.state = cc_inference_state_t::abstained;
        result.arguments_state = cc_value_state_t::abstained;
        result.variadic_state = cc_value_state_t::abstained;
    } else {
        result.abi = selection.abi;
        result.state = cc_inference_state_t::inferred;
        result.native_abi = true;
        result.confidence = selection.confidence;
        const auto profile = make_profile(selection.abi);
        append_evidence(result, request.max_evidence,
                        cc_evidence_t{cc_evidence_kind_t::declared_abi,
                                      fact_provenance_t::linear_validation, request.function,
                                      0, 0, 0, selection.confidence, true});
        if (result.frame.uses_frame_pointer) {
            append_evidence(result, request.max_evidence,
                            cc_evidence_t{cc_evidence_kind_t::frame_pointer,
                                          fact_provenance_t::recursive_decode, request.function,
                                          profile.frame_pointer, 0, 0, 64, true});
        }
        if (first_return_index != no_instruction_index) {
            append_evidence(result, request.max_evidence,
                            cc_evidence_t{cc_evidence_kind_t::return_instruction,
                                          view.value().instructions[first_return_index].instruction->provenance,
                                          view.value().instructions[first_return_index].instruction->address,
                                          0, 0, 0, 72, true});
        }
        if (has_callee_cleanup) {
            append_evidence(result, request.max_evidence,
                            cc_evidence_t{cc_evidence_kind_t::callee_stack_cleanup,
                                          fact_provenance_t::recursive_decode, request.function,
                                          0, 0, 0, 56, true});
        }

        const auto emit_register_arguments = [&](const std::vector<std::uint16_t>& registers,
                                                 argument_location_t location,
                                                 bool is_float, bool is_vector) {
            for (std::size_t slot = 0; slot < registers.size(); ++slot) {
                const auto found = observations.find(registers[slot]);
                if (found == observations.end() || !found->second.read_before_write ||
                    result.arguments.size() >= calling_convention_max_arguments) {
                    if (result.arguments.size() >= calling_convention_max_arguments)
                        result.bounded = true;
                    continue;
                }
                argument_info_t argument;
                argument.index = static_cast<std::uint32_t>(result.arguments.size());
                argument.abi_slot = static_cast<std::uint32_t>(slot);
                argument.reg = registers[slot];
                argument.bit_width = found->second.bit_width;
                argument.location = location;
                argument.provenance = found->second.read_provenance;
                argument.confidence = bounded_confidence(48 + selection.confidence / 2);
                argument.is_float = is_float;
                argument.is_vector = is_vector;
                argument.used = true;
                result.arguments.push_back(argument);
                append_evidence(result, request.max_evidence,
                                cc_evidence_t{cc_evidence_kind_t::register_read_before_definition,
                                              found->second.read_provenance,
                                              found->second.first_read_address, registers[slot], 0,
                                              static_cast<std::uint32_t>(slot), argument.confidence, true});
            }
        };
        emit_register_arguments(profile.general_arguments, argument_location_t::register_arg, false, false);
        std::vector<std::uint16_t> floating_arguments;
        floating_arguments.reserve(profile.floating_arguments.size());
        for (const auto reg : profile.floating_arguments) {
            if (!contains_register(profile.vector_arguments, reg))
                floating_arguments.push_back(reg);
        }
        emit_register_arguments(floating_arguments, argument_location_t::float_register, true, false);
        emit_register_arguments(profile.vector_arguments, argument_location_t::vector_register, false, true);

        std::size_t stack_index = 0;
        for (const auto& [key, observed] : stack_observations) {
            if ((stack_index++ & 63U) == 0) {
                if (cancelled(cancel)) {
                    return workspace_result_t<cc_analysis_result_t>::failure(
                        stopped_error(cancel, "calling_convention.stack"));
                }
                if (cancelled(workspace_cancel)) {
                    return workspace_result_t<cc_analysis_result_t>::failure(
                        stopped_error(workspace_cancel, "calling_convention.stack"));
                }
            }
            if (result.frame.slots.size() >= calling_convention_max_stack_slots) {
                result.bounded = true;
                break;
            }
            stack_slot_t slot;
            slot.offset = key.offset;
            slot.base_reg = key.base_reg;
            slot.access_width_bits = observed.access_width_bits;
            slot.size = observed.access_width_bits == 0 ? 0 : (observed.access_width_bits + 7) / 8;
            slot.provenance = observed.provenance;
            slot.read = observed.read;
            slot.written = observed.written;
            slot.is_argument = observed.argument_candidate;
            slot.is_local = observed.written && !observed.argument_candidate;
            slot.is_spill = observed.read && observed.written && !observed.argument_candidate;
            if (slot.is_argument) {
                slot.kind = stack_slot_kind_t::argument;
                slot.confidence = 68;
            } else if (slot.is_spill) {
                slot.kind = stack_slot_kind_t::spill;
                slot.confidence = 52;
            } else if (slot.is_local) {
                slot.kind = stack_slot_kind_t::local;
                slot.confidence = 48;
            } else {
                slot.confidence = 32;
            }
            result.frame.slots.push_back(slot);
            if (slot.read) {
                append_evidence(result, request.max_evidence,
                                cc_evidence_t{cc_evidence_kind_t::stack_read, slot.provenance,
                                              observed.first_address, 0, slot.offset, 0,
                                              slot.confidence, true});
            }
            if (slot.written) {
                append_evidence(result, request.max_evidence,
                                cc_evidence_t{cc_evidence_kind_t::stack_write, slot.provenance,
                                              observed.first_address, 0, slot.offset, 0,
                                              slot.confidence, true});
            }
            if (!slot.is_argument || result.arguments.size() >= calling_convention_max_arguments)
                continue;
            argument_info_t argument;
            argument.index = static_cast<std::uint32_t>(result.arguments.size());
            argument.abi_slot = static_cast<std::uint32_t>(profile.general_arguments.size() +
                                                            result.arguments.size());
            argument.stack_offset = slot.offset;
            argument.bit_width = slot.access_width_bits;
            argument.location = argument_location_t::stack_arg;
            argument.provenance = slot.provenance;
            argument.confidence = slot.confidence;
            argument.used = true;
            result.arguments.push_back(argument);
            append_evidence(result, request.max_evidence,
                            cc_evidence_t{cc_evidence_kind_t::stack_argument, slot.provenance,
                                          observed.first_address, 0, slot.offset, argument.abi_slot,
                                          argument.confidence, true});
        }
        result.arguments_state = result.arguments.empty() ? cc_value_state_t::abstained
                                                           : cc_value_state_t::inferred;

        for (const auto& [reg, observed] : preservation) {
            if (!observed.saved && !observed.restored)
                continue;
            preserved_register_t preserved;
            preserved.reg = reg;
            preserved.saved = observed.saved;
            preserved.restored = observed.restored;
            preserved.save_rva = observed.save_address.value;
            preserved.restore_rva = observed.restore_address.value;
            preserved.provenance = observed.provenance;
            preserved.confidence = observed.saved && observed.restored ? 76 : 42;
            result.frame.preserved_registers.push_back(preserved);
            if (preserved.saved) {
                result.frame.prologue_end_rva = (std::max)(result.frame.prologue_end_rva,
                                                           preserved.save_rva);
                append_evidence(result, request.max_evidence,
                                cc_evidence_t{cc_evidence_kind_t::preserved_register_save,
                                              observed.provenance, observed.save_address, reg, 0, 0,
                                              preserved.confidence, true});
            }
            if (preserved.restored) {
                append_evidence(result, request.max_evidence,
                                cc_evidence_t{cc_evidence_kind_t::preserved_register_restore,
                                              observed.provenance, observed.restore_address, reg, 0, 0,
                                              preserved.confidence, true});
            }
        }

        std::set<std::uint16_t> preserved_registers;
        for (const auto& preserved : result.frame.preserved_registers)
            if (preserved.saved && preserved.restored)
                preserved_registers.insert(preserved.reg);
        for (const auto& [reg, observed] : observations) {
            if (!observed.written || reg == profile.stack_pointer || reg == profile.frame_pointer)
                continue;
            register_effect_t effect;
            effect.reg = reg;
            effect.observed = true;
            effect.provenance = observed.write_provenance;
            effect.confidence = bounded_confidence(42 + selection.confidence / 2);
            effect.kind = preserved_registers.count(reg) != 0
                ? register_effect_kind_t::preserved : register_effect_kind_t::clobbered;
            result.register_effects.push_back(effect);
            append_evidence(result, request.max_evidence,
                            cc_evidence_t{cc_evidence_kind_t::register_written,
                                          observed.write_provenance, observed.first_write_address, reg,
                                          0, 0, effect.confidence, true});
        }

        std::vector<std::uint16_t> observed_general_returns;
        std::vector<std::uint16_t> observed_floating_returns;
        bool return_scan_stopped = false;
        const auto collect_returns = [&](const std::vector<std::uint16_t>& registers, bool floating,
                                         std::vector<std::uint16_t>& output) {
            for (const auto reg : registers) {
                const auto found = last_writes.find(reg);
                bool near_return = false;
                for (std::size_t return_index = 0;
                     return_index < view.value().instructions.size(); ++return_index) {
                    if ((return_index & 63U) == 0 &&
                        (cancelled(cancel) || cancelled(workspace_cancel))) {
                        return_scan_stopped = true;
                        return;
                    }
                    const auto& item = view.value().instructions[return_index];
                    if ((item.instruction->flow_flags & flow_return) == 0 || found == last_writes.end())
                        continue;
                    if (found->second.block_id == item.block_id &&
                        found->second.instruction_index < return_index &&
                        return_index - found->second.instruction_index <= 16) {
                        near_return = true;
                        break;
                    }
                }
                if (!near_return)
                    continue;
                output.push_back(reg);
                append_evidence(result, request.max_evidence,
                                cc_evidence_t{cc_evidence_kind_t::return_register_write,
                                              found->second.provenance, found->second.address, reg, 0,
                                              floating ? 1U : 0U,
                                              bounded_confidence(50 + selection.confidence / 2), true});
            }
        };
        collect_returns(profile.general_returns, false, observed_general_returns);
        collect_returns(profile.floating_returns, true, observed_floating_returns);
        if (return_scan_stopped) {
            return workspace_result_t<cc_analysis_result_t>::failure(
                stopped_error(cancelled(cancel) ? cancel : workspace_cancel, "calling_convention.return"));
        }
        if (!observed_general_returns.empty() && !observed_floating_returns.empty()) {
            result.return_value.state = cc_value_state_t::conflicted;
            append_conflict(result, cc_conflict_t{cc_conflict_kind_t::return_value});
        } else if (!observed_general_returns.empty() || !observed_floating_returns.empty()) {
            const auto& registers = observed_general_returns.empty()
                ? observed_floating_returns : observed_general_returns;
            result.return_value.state = cc_value_state_t::inferred;
            result.return_value.registers = registers;
            result.return_value.is_float = observed_general_returns.empty();
            result.return_value.is_vector = false;
            result.return_value.provenance = fact_provenance_t::recursive_decode;
            result.return_value.confidence = bounded_confidence(50 + selection.confidence / 2);
            for (const auto reg : registers) {
                const auto found = observations.find(reg);
                if (found != observations.end())
                    result.return_value.bit_width = (std::max)(result.return_value.bit_width,
                                                               found->second.bit_width);
            }
        } else {
            result.return_value.state = cc_value_state_t::abstained;
        }

        result.variadic_state = cc_value_state_t::abstained;
        append_evidence(result, request.max_evidence,
                        cc_evidence_t{cc_evidence_kind_t::variadic_indeterminate,
                                      fact_provenance_t::unknown, request.function, 0, 0, 0, 0, false});
    }

    if (result.bounded && result.state == cc_inference_state_t::inferred) {
        result.arguments.clear();
        result.argument_count = 0;
        result.arguments_state = cc_value_state_t::abstained;
        result.return_value = {};
        result.return_value.state = cc_value_state_t::abstained;
    }
    result.argument_count = result.arguments.size();
    synchronize_legacy_return(result);
    const auto current = validate_current_scope(workspace, *snapshot, cancel);
    if (!current)
        return workspace_result_t<cc_analysis_result_t>::failure(current.error());
    return workspace_result_t<cc_analysis_result_t>::success(std::move(result));
}

workspace_result_t<cc_analysis_result_t>
run_cc_batch_item(const analysis_workspace_t& workspace,
    const std::shared_ptr<const analysis_snapshot_t>& snapshot,
    const calling_convention_request_t& request,
    const cancellation_token_t& cancel) {
    const auto budgets = validate_request_budgets(request);
    if (!budgets)
        return workspace_result_t<cc_analysis_result_t>::failure(budgets.error());
    if (cancelled(cancel))
        return workspace_result_t<cc_analysis_result_t>::failure(
            stopped_error(cancel, "calling_convention.infer"));
    const auto workspace_cancel = workspace.cancellation_token();
    if (cancelled(workspace_cancel)) {
        return workspace_result_t<cc_analysis_result_t>::failure(
            stopped_error(workspace_cancel, "calling_convention.infer"));
    }
    if (workspace.closing() || workspace.closed()) {
        return workspace_result_t<cc_analysis_result_t>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "calling convention inference rejected a closing workspace",
                                 "calling_convention.infer"));
    }
    const auto revisions = check_request_revisions(request, *snapshot, "calling_convention.infer");
    if (!revisions)
        return workspace_result_t<cc_analysis_result_t>::failure(revisions.error());
    return infer_with_snapshot(workspace, snapshot, request, cancel);
}

}

workspace_result_t<cc_analysis_result_t>
infer_calling_convention(const analysis_workspace_t& workspace,
                         const calling_convention_request_t& request,
                         const cancellation_token_t& cancel) {
    const auto budgets = validate_request_budgets(request);
    if (!budgets)
        return workspace_result_t<cc_analysis_result_t>::failure(budgets.error());
    const auto snapshot = acquire_snapshot(workspace, request, cancel, "calling_convention.infer");
    if (!snapshot)
        return workspace_result_t<cc_analysis_result_t>::failure(snapshot.error());
    return infer_with_snapshot(workspace, snapshot.value(), request, cancel);
}

workspace_result_t<std::vector<workspace_result_t<cc_analysis_result_t>>>
infer_calling_conventions_batch(const analysis_workspace_t& workspace,
    const std::vector<calling_convention_request_t>& requests,
    const calling_convention_batch_options_t& options,
    const cancellation_token_t& cancel) {
    using batch_output_t = std::vector<workspace_result_t<cc_analysis_result_t>>;
    if (options.worker_count > 256) {
        return workspace_result_t<batch_output_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "calling convention batch worker count is invalid", "calling_convention.batch"));
    }
    if (requests.empty())
        return workspace_result_t<batch_output_t>::success(batch_output_t{});
    if (cancelled(cancel)) {
        return workspace_result_t<batch_output_t>::failure(
            stopped_error(cancel, "calling_convention.infer"));
    }
    const auto workspace_cancel = workspace.cancellation_token();
    if (cancelled(workspace_cancel)) {
        return workspace_result_t<batch_output_t>::failure(
            stopped_error(workspace_cancel, "calling_convention.infer"));
    }
    if (workspace.closing() || workspace.closed()) {
        return workspace_result_t<batch_output_t>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "calling convention inference rejected a closing workspace",
                                 "calling_convention.infer"));
    }
    const auto pinned = workspace.snapshot();
    if (!pinned) {
        return workspace_result_t<batch_output_t>::failure(
            make_workspace_error(workspace_error_code_t::analysis_in_progress,
                                 "calling convention inference requires a published analysis snapshot",
                                 "calling_convention.infer"));
    }
    if (pinned->binary_id != workspace.identity().binary_id()) {
        return workspace_result_t<batch_output_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "analysis snapshot identity does not match the workspace",
                                 "calling_convention.infer"));
    }
    std::vector<std::optional<workspace_result_t<cc_analysis_result_t>>> slots(requests.size());
    const auto shards = parallel_shards(requests.size(), options.worker_count);
    const auto run = parallel_run_shards(shards,
        [&](std::size_t, parallel_shard_t shard) -> workspace_result_t<void> {
            for (std::size_t index = shard.begin; index != shard.end; ++index)
                slots[index].emplace(run_cc_batch_item(workspace, pinned, requests[index], cancel));
            return workspace_result_t<void>::success();
        }, cancel);
    if (!run)
        return workspace_result_t<batch_output_t>::failure(run.error());
    if (cancel.stop_requested()) {
        return workspace_result_t<batch_output_t>::failure(
            stopped_error(cancel, "calling_convention.infer"));
    }
    batch_output_t results;
    results.reserve(requests.size());
    for (auto& slot : slots)
        results.push_back(std::move(*slot));
    return workspace_result_t<batch_output_t>::success(std::move(results));
}

workspace_result_t<cc_analysis_result_t>
merge_calling_convention_results(const std::vector<cc_analysis_result_t>& candidates,
                                 const calling_convention_merge_options_t& options,
                                 const cancellation_token_t& cancel) {
    if (candidates.empty() || options.max_candidates == 0 || options.max_evidence == 0 ||
        options.max_iterations == 0) {
        return workspace_result_t<cc_analysis_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "calling convention merge requires nonzero candidates and budgets", "calling_convention.merge"));
    }
    if (cancelled(cancel))
        return workspace_result_t<cc_analysis_result_t>::failure(stopped_error(cancel, "calling_convention.merge"));

    const auto input_count = (std::min)(candidates.size(), static_cast<std::size_t>(options.max_candidates));
    const auto& scope = candidates.front().cache_key;
    for (std::size_t index = 0; index < input_count; ++index) {
        if ((index & 31U) == 0 && cancelled(cancel))
            return workspace_result_t<cc_analysis_result_t>::failure(stopped_error(cancel, "calling_convention.merge"));
        if (candidates[index].cache_key != scope) {
            return workspace_result_t<cc_analysis_result_t>::failure(make_workspace_error(
                workspace_error_code_t::revision_conflict,
                "calling convention merge candidates have different cache scopes", "calling_convention.merge"));
        }
    }

    std::vector<std::size_t> order(input_count);
    for (std::size_t index = 0; index < input_count; ++index)
        order[index] = index;
    std::stable_sort(order.begin(), order.end(), [&candidates](std::size_t lhs, std::size_t rhs) {
        const auto lhs_weight = candidate_weight(candidates[lhs]);
        const auto rhs_weight = candidate_weight(candidates[rhs]);
        if (lhs_weight != rhs_weight)
            return lhs_weight > rhs_weight;
        return candidates[lhs].abi < candidates[rhs].abi;
    });

    cc_analysis_result_t merged = candidates[order.front()];
    merged.merge_iterations = 0;
    if (candidates.size() > input_count)
        merged.bounded = true;
    if (merged.evidence.size() > options.max_evidence) {
        merged.evidence.resize(options.max_evidence);
        merged.bounded = true;
    }

    std::map<cc_abi_t, std::uint64_t> abi_weights;
    for (const auto index : order)
        abi_weights[candidates[index].abi] += candidate_weight(candidates[index]);
    std::vector<std::pair<cc_abi_t, std::uint64_t>> ranked_abis(abi_weights.begin(), abi_weights.end());
    std::stable_sort(ranked_abis.begin(), ranked_abis.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.second != rhs.second)
            return lhs.second > rhs.second;
        return lhs.first < rhs.first;
    });
    const bool ambiguous_abi = ranked_abis.size() > 1 &&
        ranked_abis[0].second < ranked_abis[1].second + static_cast<std::uint64_t>(options.winner_margin) * 16;
    if (ambiguous_abi) {
        merged.abi = cc_abi_t::unknown;
        merged.state = cc_inference_state_t::conflicted;
        merged.arguments.clear();
        merged.arguments_state = cc_value_state_t::conflicted;
        merged.return_value = {};
        merged.return_value.state = cc_value_state_t::conflicted;
        append_conflict(merged, cc_conflict_t{cc_conflict_kind_t::abi});
    } else if (!ranked_abis.empty()) {
        merged.abi = ranked_abis.front().first;
        if (merged.state != cc_inference_state_t::abstained)
            merged.state = cc_inference_state_t::inferred;
    }

    bool changed = true;
    for (std::uint32_t iteration = 0; iteration < options.max_iterations && changed; ++iteration) {
        if (cancelled(cancel))
            return workspace_result_t<cc_analysis_result_t>::failure(stopped_error(cancel, "calling_convention.merge"));
        changed = false;
        merged.merge_iterations = iteration + 1;
        if (merged.state == cc_inference_state_t::conflicted)
            break;

        std::map<argument_key_t, std::pair<argument_info_t, std::uint64_t>> votes;
        std::map<std::uint32_t, std::set<argument_key_t>> slots;
        std::uint64_t total_weight = 0;
        for (const auto index : order) {
            const auto& candidate = candidates[index];
            if (candidate.abi != merged.abi || candidate.state != cc_inference_state_t::inferred)
                continue;
            const auto weight = candidate_weight(candidate);
            total_weight += weight;
            for (const auto& argument : candidate.arguments) {
                const argument_key_t key{argument.location, argument.reg, argument.stack_offset,
                                         argument.abi_slot};
                auto& vote = votes[key];
                if (vote.second == 0 || argument.confidence > vote.first.confidence)
                    vote.first = argument;
                vote.second += weight;
                slots[argument.abi_slot].insert(key);
            }
        }
        std::vector<argument_info_t> consensus_arguments;
        for (const auto& [key, vote] : votes) {
            if (total_weight == 0 || vote.second * 2 < total_weight)
                continue;
            consensus_arguments.push_back(vote.first);
        }
        std::stable_sort(consensus_arguments.begin(), consensus_arguments.end(),
                         [](const argument_info_t& lhs, const argument_info_t& rhs) {
                             return std::tie(lhs.location, lhs.abi_slot, lhs.reg, lhs.stack_offset) <
                                    std::tie(rhs.location, rhs.abi_slot, rhs.reg, rhs.stack_offset);
                         });
        if (!arguments_equivalent(consensus_arguments, merged.arguments)) {
            merged.arguments = std::move(consensus_arguments);
            changed = true;
        }
        for (const auto& [slot, keys] : slots) {
            if (keys.size() <= 1)
                continue;
            append_conflict(merged, cc_conflict_t{cc_conflict_kind_t::argument, slot});
        }
        merged.arguments_state = merged.arguments.empty() ? cc_value_state_t::abstained
                                                           : cc_value_state_t::inferred;

        std::uint64_t matching_return_weight = 0;
        std::uint64_t return_weight = 0;
        for (const auto index : order) {
            const auto& candidate = candidates[index];
            if (candidate.abi != merged.abi || candidate.return_value.state != cc_value_state_t::inferred)
                continue;
            const auto weight = candidate_weight(candidate);
            return_weight += weight;
            if (return_equivalent(candidate.return_value, merged.return_value))
                matching_return_weight += weight;
        }
        if (return_weight != 0 && matching_return_weight * 2 < return_weight) {
            merged.return_value = {};
            merged.return_value.state = cc_value_state_t::conflicted;
            append_conflict(merged, cc_conflict_t{cc_conflict_kind_t::return_value});
            changed = true;
        }
    }
    if (changed) {
        merged.bounded = true;
        append_conflict(merged, cc_conflict_t{cc_conflict_kind_t::budget});
    }
    if (merged.state == cc_inference_state_t::inferred) {
        append_evidence(merged, options.max_evidence,
                        cc_evidence_t{cc_evidence_kind_t::merge_consensus,
                                      fact_provenance_t::unknown,
                                      merged.cache_key.function, 0, 0, 0,
                                      merged.confidence, true});
    }
    merged.argument_count = merged.arguments.size();
    synchronize_legacy_return(merged);
    return workspace_result_t<cc_analysis_result_t>::success(std::move(merged));
}

workspace_result_t<cc_analysis_result_t>
analyze_calling_convention(const analysis_workspace_t& workspace,
                           std::uint64_t function_rva,
                           const cancellation_token_t& cancel) {
    calling_convention_request_t request;
    request.function.space = address_space_id_t::relative_virtual;
    request.function.value = function_rva;
    request.function.architecture = workspace.identity().architecture();
    request.function.mode = workspace.identity().architecture_mode();
    return infer_calling_convention(workspace, request, cancel);
}

}
