#include "signature_operand_mask.hpp"

#include <Zydis/Zydis.h>
#include <capstone/capstone.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <initializer_list>
#include <limits>
#include <utility>

namespace aida::standalone::mcp::compat::handlers {
namespace {

static_assert(ZYDIS_VERSION == 0x0004000100000000ULL);
static_assert(CS_API_MAJOR == 5);
static_assert(CS_API_MINOR == 0);
static_assert(CS_VERSION_EXTRA == 9);

signature_mode_t effective_mode(const signature_instruction_t& instruction) noexcept {
    if (instruction.mode != signature_mode_t::unknown)
        return instruction.mode;
    switch (instruction.architecture) {
    case signature_architecture_t::x86: return signature_mode_t::x86_32;
    case signature_architecture_t::x64: return signature_mode_t::x86_64;
    case signature_architecture_t::arm: return signature_mode_t::arm_a32;
    case signature_architecture_t::thumb: return signature_mode_t::arm_thumb;
    case signature_architecture_t::aarch64: return signature_mode_t::aarch64;
    case signature_architecture_t::mips: return signature_mode_t::mips32;
    case signature_architecture_t::ppc: return signature_mode_t::ppc32;
    case signature_architecture_t::riscv: return signature_mode_t::riscv64;
    case signature_architecture_t::jvm: return signature_mode_t::jvm;
    case signature_architecture_t::dalvik: return signature_mode_t::dalvik;
    case signature_architecture_t::unknown: break;
    }
    return signature_mode_t::unknown;
}

void clear_byte(std::vector<std::uint8_t>& mask, std::size_t index) noexcept {
    if (index < mask.size())
        mask[index] = 0;
}

void clear_range(std::vector<std::uint8_t>& mask, std::size_t offset,
                 std::size_t size) noexcept {
    if (offset >= mask.size() || size == 0)
        return;
    const std::size_t bounded = (std::min)(size, mask.size() - offset);
    std::fill(mask.begin() + static_cast<std::ptrdiff_t>(offset),
              mask.begin() + static_cast<std::ptrdiff_t>(offset + bounded), 0);
}

std::size_t count_dynamic(const std::vector<std::uint8_t>& mask) noexcept {
    return static_cast<std::size_t>(std::count(mask.begin(), mask.end(), 0));
}

void clear_endian_low_half(std::vector<std::uint8_t>& mask,
                           signature_endian_t endian) noexcept {
    if (mask.size() != 4)
        return;
    if (endian == signature_endian_t::little) {
        clear_byte(mask, 0);
        clear_byte(mask, 1);
    } else {
        clear_byte(mask, 2);
        clear_byte(mask, 3);
    }
}

void clear_endian_indices(std::vector<std::uint8_t>& mask,
                          signature_endian_t endian,
                          std::initializer_list<std::size_t> little_indices) noexcept {
    for (const std::size_t index : little_indices) {
        clear_byte(mask, endian == signature_endian_t::little
            ? index : mask.size() - 1U - index);
    }
}

bool mask_x86(const signature_instruction_t& instruction,
              signature_mode_t mode,
              std::vector<std::uint8_t>& mask,
              std::string& error) noexcept {
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    if (mode == signature_mode_t::x86_64) {
        machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        stack_width = ZYDIS_STACK_WIDTH_64;
    } else if (mode == signature_mode_t::x86_32) {
        machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
        stack_width = ZYDIS_STACK_WIDTH_32;
    } else if (mode == signature_mode_t::x86_16) {
        machine_mode = ZYDIS_MACHINE_MODE_LEGACY_16;
        stack_width = ZYDIS_STACK_WIDTH_16;
    } else {
        error = "x86_mode_unavailable";
        return false;
    }
    ZydisDecoder decoder{};
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, machine_mode, stack_width))) {
        error = "zydis_decoder_init_failed";
        return false;
    }
    ZydisDecodedInstruction decoded{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            &decoder, instruction.bytes.data(), instruction.bytes.size(),
            &decoded, operands.data())) || decoded.length != instruction.bytes.size()) {
        error = "zydis_instruction_decode_failed";
        return false;
    }
    if (decoded.raw.disp.size != 0)
        clear_range(mask, decoded.raw.disp.offset, decoded.raw.disp.size / 8U);
    for (const auto& immediate : decoded.raw.imm) {
        if (immediate.size != 0)
            clear_range(mask, immediate.offset, immediate.size / 8U);
    }
    return true;
}

struct capstone_instruction_t final {
    csh handle = 0;
    cs_insn* instruction = nullptr;

    capstone_instruction_t() = default;
    capstone_instruction_t(const capstone_instruction_t&) = delete;
    capstone_instruction_t& operator=(const capstone_instruction_t&) = delete;
    ~capstone_instruction_t() {
        if (instruction != nullptr)
            cs_free(instruction, 1);
        if (handle != 0)
            cs_close(&handle);
    }
};

bool open_capstone(const signature_instruction_t& input,
                   signature_mode_t mode,
                   capstone_instruction_t& output,
    std::string& error) noexcept {
    cs_arch arch;
    cs_mode mode_flags = input.endian == signature_endian_t::big
        ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
    switch (mode) {
    case signature_mode_t::arm_a32:
        arch = CS_ARCH_ARM;
        mode_flags = static_cast<cs_mode>(mode_flags | CS_MODE_ARM);
        break;
    case signature_mode_t::arm_thumb:
        arch = CS_ARCH_ARM;
        mode_flags = static_cast<cs_mode>(mode_flags | CS_MODE_THUMB);
        break;
    case signature_mode_t::aarch64:
        arch = CS_ARCH_ARM64;
        break;
    case signature_mode_t::mips32:
        arch = CS_ARCH_MIPS;
        mode_flags = static_cast<cs_mode>(mode_flags | CS_MODE_MIPS32);
        break;
    case signature_mode_t::mips64:
        arch = CS_ARCH_MIPS;
        mode_flags = static_cast<cs_mode>(mode_flags | CS_MODE_MIPS64);
        break;
    case signature_mode_t::ppc32:
        arch = CS_ARCH_PPC;
        mode_flags = static_cast<cs_mode>(mode_flags | CS_MODE_32);
        break;
    case signature_mode_t::ppc64:
        arch = CS_ARCH_PPC;
        mode_flags = static_cast<cs_mode>(mode_flags | CS_MODE_64);
        break;
    case signature_mode_t::riscv32:
        arch = CS_ARCH_RISCV;
        mode_flags = static_cast<cs_mode>(
            mode_flags | CS_MODE_RISCV32 | CS_MODE_RISCVC);
        break;
    case signature_mode_t::riscv64:
        arch = CS_ARCH_RISCV;
        mode_flags = static_cast<cs_mode>(
            mode_flags | CS_MODE_RISCV64 | CS_MODE_RISCVC);
        break;
    default:
        error = "capstone_mode_unavailable";
        return false;
    }
    if (cs_open(arch, mode_flags, &output.handle) != CS_ERR_OK) {
        error = "capstone_open_failed";
        return false;
    }
    if (cs_option(output.handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        error = "capstone_detail_enable_failed";
        return false;
    }
    const std::size_t count = cs_disasm(
        output.handle, input.bytes.data(), input.bytes.size(), input.address, 1,
        &output.instruction);
    if (count != 1 || output.instruction == nullptr ||
        output.instruction->size != input.bytes.size() ||
        output.instruction->detail == nullptr) {
        error = "capstone_instruction_decode_failed";
        return false;
    }
    return true;
}

bool arm_has_dynamic_operand(const cs_arm& detail) noexcept {
    for (std::uint8_t index = 0; index < detail.op_count; ++index) {
        const auto& operand = detail.operands[index];
        if (operand.type == ARM_OP_IMM || operand.type == ARM_OP_CIMM ||
            operand.type == ARM_OP_PIMM || operand.type == ARM_OP_SETEND ||
            (operand.type == ARM_OP_MEM && operand.mem.disp != 0))
            return true;
    }
    return false;
}

bool arm64_has_dynamic_operand(const cs_arm64& detail) noexcept {
    for (std::uint8_t index = 0; index < detail.op_count; ++index) {
        const auto& operand = detail.operands[index];
        if (operand.type == ARM64_OP_IMM || operand.type == ARM64_OP_CIMM ||
            (operand.type == ARM64_OP_MEM && operand.mem.disp != 0))
            return true;
    }
    return false;
}

bool mips_has_dynamic_operand(const cs_mips& detail) noexcept {
    for (std::uint8_t index = 0; index < detail.op_count; ++index) {
        const auto& operand = detail.operands[index];
        if (operand.type == MIPS_OP_IMM ||
            (operand.type == MIPS_OP_MEM && operand.mem.disp != 0))
            return true;
    }
    return false;
}

bool ppc_has_dynamic_operand(const cs_ppc& detail) noexcept {
    for (std::uint8_t index = 0; index < detail.op_count; ++index) {
        const auto& operand = detail.operands[index];
        if (operand.type == PPC_OP_IMM ||
            (operand.type == PPC_OP_MEM && operand.mem.disp != 0))
            return true;
    }
    return false;
}

bool riscv_has_dynamic_operand(const cs_riscv& detail) noexcept {
    for (std::uint8_t index = 0; index < detail.op_count; ++index) {
        const auto& operand = detail.operands[index];
        if (operand.type == RISCV_OP_IMM ||
            (operand.type == RISCV_OP_MEM && operand.mem.disp != 0))
            return true;
    }
    return false;
}

bool capstone_group(const cs_insn& instruction, std::uint8_t group) noexcept {
    const auto* detail = instruction.detail;
    return detail != nullptr && std::find(
        detail->groups, detail->groups + detail->groups_count, group) !=
        detail->groups + detail->groups_count;
}

bool mask_arm_family(const signature_instruction_t& input,
                     signature_mode_t mode,
                     std::vector<std::uint8_t>& mask,
                     std::string& error) noexcept {
    capstone_instruction_t decoded;
    if (!open_capstone(input, mode, decoded, error))
        return false;
    if (mode == signature_mode_t::aarch64) {
        if (!arm64_has_dynamic_operand(decoded.instruction->detail->arm64))
            return true;
        if (capstone_group(*decoded.instruction, CS_GRP_JUMP) ||
            capstone_group(*decoded.instruction, CS_GRP_CALL)) {
            clear_range(mask, 0, mask.size());
            return true;
        }
        clear_endian_indices(mask, input.endian, {0, 1, 2});
        return true;
    }
    if (!arm_has_dynamic_operand(decoded.instruction->detail->arm))
        return true;
    if (mode == signature_mode_t::arm_thumb) {
        if (capstone_group(*decoded.instruction, CS_GRP_JUMP) ||
            capstone_group(*decoded.instruction, CS_GRP_CALL)) {
            clear_range(mask, 0, mask.size());
        } else if (mask.size() == 2) {
            clear_endian_indices(mask, input.endian, {0});
        } else {
            clear_endian_indices(mask, input.endian, {0, 2});
        }
        return true;
    }
    if (mask.size() != 4) {
        error = "arm_instruction_size_invalid";
        return false;
    }
    if (capstone_group(*decoded.instruction, CS_GRP_JUMP) ||
        capstone_group(*decoded.instruction, CS_GRP_CALL)) {
        clear_range(mask, 0, mask.size());
    } else {
        clear_endian_indices(mask, input.endian, {0, 1, 2});
    }
    return true;
}

bool mask_mips_ppc(const signature_instruction_t& input,
                   signature_mode_t mode,
                   std::vector<std::uint8_t>& mask,
                   std::string& error) noexcept {
    if (mask.size() != 4) {
        error = "fixed_width_instruction_size_invalid";
        return false;
    }
    capstone_instruction_t decoded;
    if (!open_capstone(input, mode, decoded, error))
        return false;
    const bool dynamic = mode == signature_mode_t::mips32 || mode == signature_mode_t::mips64
        ? mips_has_dynamic_operand(decoded.instruction->detail->mips)
        : ppc_has_dynamic_operand(decoded.instruction->detail->ppc);
    if (!dynamic)
        return true;
    if (capstone_group(*decoded.instruction, CS_GRP_JUMP) ||
        capstone_group(*decoded.instruction, CS_GRP_CALL)) {
        clear_range(mask, 0, mask.size());
    } else {
        clear_endian_low_half(mask, input.endian);
    }
    return true;
}

bool mask_riscv(const signature_instruction_t& input,
                signature_mode_t mode,
                std::vector<std::uint8_t>& mask,
                std::string& error) noexcept {
    if (mask.size() != 2 && mask.size() != 4) {
        error = "riscv_instruction_size_invalid";
        return false;
    }
    capstone_instruction_t decoded;
    if (!open_capstone(input, mode, decoded, error))
        return false;
    if (!riscv_has_dynamic_operand(decoded.instruction->detail->riscv))
        return true;
    if (mask.size() == 2) {
        clear_range(mask, 0, mask.size());
        return true;
    }
    const std::size_t opcode_index = input.endian == signature_endian_t::little ? 0 : 3;
    const std::uint8_t opcode = input.bytes[opcode_index] & 0x7fU;
    switch (opcode) {
    case 0x03:
    case 0x13:
    case 0x1b:
    case 0x67:
    case 0x73:
        clear_endian_indices(mask, input.endian, {2, 3});
        break;
    case 0x17:
    case 0x37:
    case 0x6f:
        clear_endian_indices(mask, input.endian, {1, 2, 3});
        break;
    case 0x23:
    case 0x63:
        clear_endian_indices(mask, input.endian, {0, 1, 3});
        break;
    default:
        clear_range(mask, 0, mask.size());
        break;
    }
    return true;
}

bool jvm_operandless(std::uint8_t opcode) noexcept {
    return opcode <= 0x0fU || (opcode >= 0x1aU && opcode <= 0x35U) ||
           (opcode >= 0x3bU && opcode <= 0x83U) ||
           (opcode >= 0x85U && opcode <= 0x98U) ||
           (opcode >= 0xacU && opcode <= 0xb1U) ||
           opcode == 0xbeU || opcode == 0xbfU || opcode == 0xc2U || opcode == 0xc3U;
}

bool mask_jvm(const signature_instruction_t& input,
              std::vector<std::uint8_t>& mask,
              std::string& error) noexcept {
    if (input.bytes.empty()) {
        error = "jvm_instruction_empty";
        return false;
    }
    const std::uint8_t opcode = input.bytes.front();
    if (input.bytes.size() == 1) {
        if (!jvm_operandless(opcode) && opcode != 0xcaU) {
            error = "jvm_truncated_operand_instruction";
            return false;
        }
        return true;
    }
    if (opcode == 0xc4U) {
        if (input.bytes.size() != 4 && input.bytes.size() != 6) {
            error = "jvm_wide_instruction_size_invalid";
            return false;
        }
        clear_range(mask, 2, input.bytes.size() - 2U);
    } else {
        clear_range(mask, 1, input.bytes.size() - 1U);
    }
    return true;
}

bool dalvik_operandless(std::uint8_t opcode) noexcept {
    return opcode == 0x00U || opcode == 0x0eU || opcode == 0x73U ||
           opcode == 0x79U || opcode == 0x7aU || opcode == 0xf1U;
}

bool mask_dalvik(const signature_instruction_t& input,
                 std::vector<std::uint8_t>& mask,
                 std::string& error) noexcept {
    if (input.bytes.size() < 2 || (input.bytes.size() & 1U) != 0) {
        error = "dalvik_instruction_size_invalid";
        return false;
    }
    const std::size_t opcode_index = input.endian == signature_endian_t::little ? 0 : 1;
    const std::uint8_t opcode = input.bytes[opcode_index];
    if (input.bytes.size() == 2 && dalvik_operandless(opcode))
        return true;
    for (std::size_t index = 0; index < input.bytes.size(); ++index) {
        if (index != opcode_index)
            clear_byte(mask, index);
    }
    return true;
}

}

signature_operand_mask_result_t build_signature_operand_mask(
    const signature_instruction_t& instruction) {
    signature_operand_mask_result_t result;
    if (instruction.bytes.empty() ||
        instruction.bytes.size() > (std::numeric_limits<std::uint8_t>::max)()) {
        result.error = "instruction_bytes_out_of_bounds";
        return result;
    }
    result.stable_mask.assign(instruction.bytes.size(), 0xffU);
    if (!instruction.stable_mask.empty()) {
        if (instruction.stable_mask.size() != instruction.bytes.size()) {
            result.error = "source_stable_mask_size_mismatch";
            result.stable_mask.clear();
            return result;
        }
        for (std::size_t index = 0; index < result.stable_mask.size(); ++index)
            result.stable_mask[index] = instruction.stable_mask[index] == 0xffU ? 0xffU : 0U;
    }

    bool decoded = instruction.stable_mask_authoritative &&
        !instruction.stable_mask.empty();
    if (!decoded) {
        const signature_mode_t mode = effective_mode(instruction);
        switch (mode) {
        case signature_mode_t::x86_16:
        case signature_mode_t::x86_32:
        case signature_mode_t::x86_64:
            decoded = mask_x86(instruction, mode, result.stable_mask, result.error);
            break;
        case signature_mode_t::arm_a32:
        case signature_mode_t::arm_thumb:
        case signature_mode_t::aarch64:
            decoded = mask_arm_family(instruction, mode, result.stable_mask, result.error);
            break;
        case signature_mode_t::mips32:
        case signature_mode_t::mips64:
        case signature_mode_t::ppc32:
        case signature_mode_t::ppc64:
            decoded = mask_mips_ppc(instruction, mode, result.stable_mask, result.error);
            break;
        case signature_mode_t::riscv32:
        case signature_mode_t::riscv64:
            decoded = mask_riscv(instruction, mode, result.stable_mask, result.error);
            break;
        case signature_mode_t::jvm:
            decoded = mask_jvm(instruction, result.stable_mask, result.error);
            break;
        case signature_mode_t::dalvik:
            decoded = mask_dalvik(instruction, result.stable_mask, result.error);
            break;
        case signature_mode_t::unknown:
            result.error = "instruction_architecture_mode_unavailable";
            break;
        }
    }
    if (!decoded) {
        result.stable_mask.clear();
        return result;
    }

    const std::size_t before_relocations = count_dynamic(result.stable_mask);
    for (const auto& relocation : instruction.relocation_ranges) {
        if (relocation.size == 0 || relocation.offset >= result.stable_mask.size() ||
            relocation.size > result.stable_mask.size() - relocation.offset) {
            result.error = "relocation_range_out_of_bounds";
            result.stable_mask.clear();
            return result;
        }
        clear_range(result.stable_mask, relocation.offset, relocation.size);
    }
    result.dynamic_byte_count = count_dynamic(result.stable_mask);
    result.relocation_byte_count = result.dynamic_byte_count - before_relocations;
    result.success = true;
    return result;
}

}
