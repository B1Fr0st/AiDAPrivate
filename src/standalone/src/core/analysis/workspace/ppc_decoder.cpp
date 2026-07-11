#include "ppc_decoder.hpp"

#include "checked_range.hpp"

#include <capstone/capstone.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace aida::analysis {
namespace {

constexpr const char* create_phase = "ppc_decoder.create";
constexpr const char* decode_phase = "ppc_decoder.decode";
constexpr std::uint64_t implementation_version = 0x0005000000090001ULL;
constexpr std::uint32_t ppc_opcode_branch = 18;
constexpr std::uint32_t ppc_opcode_conditional_branch = 16;
constexpr std::uint32_t ppc_opcode_extended = 19;
constexpr std::uint32_t ppc_opcode_system_call = 17;
constexpr std::uint32_t ppc_opcode_trap_doubleword_immediate = 2;
constexpr std::uint32_t ppc_opcode_trap_word_immediate = 3;
constexpr std::uint32_t ppc_opcode_integer = 31;
constexpr std::uint32_t ppc_xo_branch_to_link_register = 16;
constexpr std::uint32_t ppc_xo_branch_to_count_register = 528;
constexpr std::uint32_t ppc_xo_trap_word = 4;
constexpr std::uint32_t ppc_xo_trap_doubleword = 68;
constexpr std::uint32_t ppc_unconditional_branch_option = 20;

static_assert(CS_API_MAJOR == 5);
static_assert(CS_API_MINOR == 0);
static_assert(CS_VERSION_EXTRA == 9);
static_assert(PPC_INS_ENDING <= std::numeric_limits<std::uint16_t>::max());
static_assert(PPC_REG_ENDING <= std::numeric_limits<std::uint16_t>::max());
static_assert(std::is_trivially_copyable_v<instruction_record_t>);
static_assert(std::is_trivially_copyable_v<operand_fact_t>);
static_assert(std::is_trivially_copyable_v<target_fact_t>);

workspace_error_t stop_error(const cancellation_token_t& cancellation,
                             const char* phase) {
    if (cancellation.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "PowerPC decoder deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "PowerPC decoder operation cancelled", phase);
    error.cancellation = true;
    return error;
}

workspace_error_t request_error(workspace_error_code_t code,
                                const char* message,
                                const arch_decode_request_t& request,
                                const char* phase = decode_phase) {
    auto error = make_workspace_error(code, message, phase);
    error.address = request.address;
    error.offset = request.provider_offset;
    error.size = request.available_bytes;
    return error;
}

workspace_error_t capstone_error(const char* operation,
                                 cs_err status,
                                 const char* phase,
                                 const arch_decode_request_t* request = nullptr) {
    auto error = make_workspace_error(workspace_error_code_t::decode_failure,
                                      std::string("Capstone ") + operation + " failed",
                                      phase);
    error.provider_status = static_cast<std::int64_t>(status);
    if (request != nullptr) {
        error.address = request->address;
        error.offset = request->provider_offset;
        error.size = request->available_bytes;
    }
    return error;
}

entity_id_t stable_instruction_id(const address_t& address) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    const auto feed = [&hash](std::uint64_t value) {
        for (std::size_t index = 0; index < sizeof(value); ++index) {
            hash ^= static_cast<std::uint8_t>(value >> (index * 8));
            hash *= 1099511628211ULL;
        }
    };
    feed(static_cast<std::uint64_t>(address.space));
    feed(address.value);
    feed(static_cast<std::uint64_t>(address.architecture));
    feed(static_cast<std::uint64_t>(address.mode));
    return hash == 0 ? 1 : hash;
}

bool same_mode(cs_mode lhs, cs_mode rhs) noexcept {
    return static_cast<std::uint32_t>(lhs) == static_cast<std::uint32_t>(rhs);
}

workspace_result_t<cs_mode> capstone_mode_for(const arch_decoder_key_t& key) {
    const bool ppc32 = key.architecture == architecture_id_t::ppc &&
                       key.mode == architecture_mode_t::ppc32 &&
                       key.address_width_bits == 32;
    const bool ppc64 = key.architecture == architecture_id_t::ppc64 &&
                       key.mode == architecture_mode_t::ppc64 &&
                       key.address_width_bits == 64;
    if ((!ppc32 && !ppc64) || key.endian > endian_t::big) {
        return workspace_result_t<cs_mode>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "PowerPC decoder key is invalid", create_phase));
    }
    std::uint32_t mode = ppc64 ? static_cast<std::uint32_t>(CS_MODE_64) : 0;
    if (key.endian == endian_t::big)
        mode |= static_cast<std::uint32_t>(CS_MODE_BIG_ENDIAN);
    return workspace_result_t<cs_mode>::success(static_cast<cs_mode>(mode));
}

workspace_result_t<const std::uint8_t*> instruction_bytes(
    const byte_view_t& view,
    std::uint64_t view_provider_offset,
    const arch_decode_request_t& request) {
    if (view.data() == nullptr || request.available_bytes == 0 ||
        request.provider_offset < view_provider_offset) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::invalid_argument,
            "PowerPC decoder byte view is invalid", request));
    }
    std::uint64_t view_end = 0;
    if (!checked_add_u64(view_provider_offset,
                         static_cast<std::uint64_t>(view.size()), view_end)) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::range_overflow,
            "PowerPC decoder byte view range overflowed", request));
    }
    std::uint64_t instruction_end = 0;
    if (!checked_add_u64(request.provider_offset, request.available_bytes,
                         instruction_end)) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::range_overflow,
            "PowerPC decoder instruction range overflowed", request));
    }
    if (instruction_end > view_end) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::out_of_range,
            "PowerPC instruction exceeds the supplied byte view", request));
    }
    const std::uint64_t relative = request.provider_offset - view_provider_offset;
    if (relative > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::range_overflow,
            "PowerPC byte-view offset exceeds addressable memory", request));
    }
    return workspace_result_t<const std::uint8_t*>::success(
        view.data() + static_cast<std::size_t>(relative));
}

workspace_result_t<std::uint64_t> runtime_address_for(
    const arch_decoder_key_t& key,
    const arch_decode_request_t& request) {
    std::uint64_t runtime_address = request.address.value;
    switch (request.address.space) {
    case address_space_id_t::relative_virtual:
        if (!checked_add_u64(request.image_base, request.address.value, runtime_address)) {
            return workspace_result_t<std::uint64_t>::failure(request_error(
                workspace_error_code_t::range_overflow,
                "PowerPC instruction runtime address overflowed", request));
        }
        break;
    case address_space_id_t::file_offset:
        if (request.runtime_address == 0) {
            return workspace_result_t<std::uint64_t>::failure(request_error(
                workspace_error_code_t::invalid_argument,
                "PowerPC file-offset decoding requires a runtime address", request));
        }
        runtime_address = request.runtime_address;
        break;
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        break;
    }
    if (request.runtime_address != 0 && request.runtime_address != runtime_address) {
        return workspace_result_t<std::uint64_t>::failure(request_error(
            workspace_error_code_t::invalid_argument,
            "PowerPC decode runtime address conflicts with the typed address", request));
    }
    if (key.address_width_bits == 32 &&
        runtime_address > std::numeric_limits<std::uint32_t>::max()) {
        return workspace_result_t<std::uint64_t>::failure(request_error(
            workspace_error_code_t::invalid_argument,
            "PowerPC32 runtime address exceeds the active address width", request));
    }
    return workspace_result_t<std::uint64_t>::success(runtime_address);
}

bool add_signed_offset(std::uint64_t base,
                       std::int64_t offset,
                       std::uint64_t& output) noexcept {
    if (offset >= 0)
        return checked_add_u64(base, static_cast<std::uint64_t>(offset), output);
    const std::uint64_t magnitude =
        static_cast<std::uint64_t>(-(offset + 1)) + 1;
    return checked_sub_u64(base, magnitude, output);
}

std::int64_t sign_extend(std::uint64_t value, std::uint8_t bit_width) noexcept {
    const std::uint64_t sign = std::uint64_t{1} << (bit_width - 1);
    return static_cast<std::int64_t>((value ^ sign) - sign);
}

std::uint32_t instruction_word(const std::uint8_t* bytes,
                               endian_t endian) noexcept {
    if (endian == endian_t::big) {
        return (static_cast<std::uint32_t>(bytes[0]) << 24) |
               (static_cast<std::uint32_t>(bytes[1]) << 16) |
               (static_cast<std::uint32_t>(bytes[2]) << 8) |
               static_cast<std::uint32_t>(bytes[3]);
    }
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8) |
           (static_cast<std::uint32_t>(bytes[2]) << 16) |
           (static_cast<std::uint32_t>(bytes[3]) << 24);
}

std::uint32_t primary_opcode(std::uint32_t word) noexcept {
    return word >> 26;
}

std::uint32_t extended_opcode(std::uint32_t word) noexcept {
    return (word >> 1) & 0x3ffU;
}

std::uint32_t branch_option(std::uint32_t word) noexcept {
    return (word >> 21) & 0x1fU;
}

std::uint32_t branch_index(std::uint32_t word) noexcept {
    return (word >> 16) & 0x1fU;
}

bool branch_linked(std::uint32_t word) noexcept {
    return (word & 1U) != 0;
}

bool branch_is_conditional(std::uint32_t word) noexcept {
    const std::uint32_t opcode = primary_opcode(word);
    if (opcode == ppc_opcode_conditional_branch)
        return branch_option(word) != ppc_unconditional_branch_option;
    if (opcode != ppc_opcode_extended)
        return false;
    const std::uint32_t xo = extended_opcode(word);
    return (xo == ppc_xo_branch_to_link_register ||
            xo == ppc_xo_branch_to_count_register) &&
           branch_option(word) != ppc_unconditional_branch_option;
}

bool is_direct_branch_word(std::uint32_t word) noexcept {
    const std::uint32_t opcode = primary_opcode(word);
    return opcode == ppc_opcode_branch || opcode == ppc_opcode_conditional_branch;
}

bool is_indirect_branch_word(std::uint32_t word) noexcept {
    if (primary_opcode(word) != ppc_opcode_extended)
        return false;
    const std::uint32_t xo = extended_opcode(word);
    return xo == ppc_xo_branch_to_link_register ||
           xo == ppc_xo_branch_to_count_register;
}

bool is_link_register_return(std::uint32_t word, ppc_insn instruction) noexcept {
    return instruction == PPC_INS_BLR ||
           (primary_opcode(word) == ppc_opcode_extended &&
            extended_opcode(word) == ppc_xo_branch_to_link_register &&
            !branch_linked(word) &&
            branch_option(word) == ppc_unconditional_branch_option &&
            branch_index(word) == 0);
}

bool is_interrupt_return(ppc_insn instruction) noexcept {
    return instruction == PPC_INS_RFI || instruction == PPC_INS_RFID ||
           instruction == PPC_INS_RFCI || instruction == PPC_INS_HRFID;
}

bool is_trap_word(std::uint32_t word, ppc_insn instruction) noexcept {
    if (instruction == PPC_INS_TRAP)
        return true;
    const std::uint32_t opcode = primary_opcode(word);
    if (opcode == ppc_opcode_trap_doubleword_immediate ||
        opcode == ppc_opcode_trap_word_immediate)
        return true;
    if (opcode != ppc_opcode_integer)
        return false;
    const std::uint32_t xo = extended_opcode(word);
    return xo == ppc_xo_trap_word || xo == ppc_xo_trap_doubleword;
}

bool is_unconditional_trap(std::uint32_t word, ppc_insn instruction) noexcept {
    if (instruction == PPC_INS_TRAP)
        return true;
    if (primary_opcode(word) != ppc_opcode_integer ||
        (extended_opcode(word) != ppc_xo_trap_word &&
         extended_opcode(word) != ppc_xo_trap_doubleword)) {
        return false;
    }
    return branch_option(word) == 31 && branch_index(word) == 0 &&
           ((word >> 11) & 0x1fU) == 0;
}

bool is_system_call(std::uint32_t word, ppc_insn instruction) noexcept {
    return instruction == PPC_INS_SC || primary_opcode(word) == ppc_opcode_system_call;
}

bool runtime_in_image(const arch_decode_request_t& request,
                      std::uint64_t runtime_address) noexcept {
    if (request.image_size == 0 || runtime_address < request.image_base)
        return false;
    return runtime_address - request.image_base < request.image_size;
}

address_t compact_target_address(const arch_decode_request_t& request,
                                 std::uint64_t runtime_address) noexcept {
    address_t target = request.address;
    if (request.address.space == address_space_id_t::relative_virtual) {
        if (runtime_in_image(request, runtime_address)) {
            target.value = runtime_address - request.image_base;
        } else {
            target.space = address_space_id_t::virtual_address;
            target.value = runtime_address;
        }
    } else if (request.address.space == address_space_id_t::file_offset) {
        target.space = address_space_id_t::virtual_address;
        target.value = runtime_address;
    } else {
        target.value = runtime_address;
    }
    return target;
}

target_resolution_t target_resolution_for(const arch_decode_request_t& request,
                                          const address_t& target,
                                          std::uint64_t runtime_address,
                                          bool& external) noexcept {
    external = false;
    if (target.space == address_space_id_t::relative_virtual)
        return target_resolution_t::image_relative;
    if (request.image_size != 0 && !runtime_in_image(request, runtime_address)) {
        external = true;
        return target_resolution_t::external_virtual;
    }
    return target_resolution_t::image_virtual;
}

workspace_result_t<void> append_target(arch_decode_result_t& output,
                                       target_fact_t target,
                                       const arch_decode_request_t& request) {
    if (output.target_count >= output.targets.size()) {
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::limit_exceeded,
            "PowerPC instruction exceeds Compact IR target capacity", request));
    }
    output.targets[output.target_count++] = std::move(target);
    return workspace_result_t<void>::success();
}

struct direct_target_t {
    std::uint64_t runtime_address = 0;
};

workspace_result_t<std::optional<direct_target_t>> direct_target_for(
    const arch_decoder_key_t& key,
    std::uint32_t word,
    std::uint64_t runtime_address,
    const arch_decode_request_t& request) {
    const std::uint32_t opcode = primary_opcode(word);
    if (opcode != ppc_opcode_branch && opcode != ppc_opcode_conditional_branch) {
        return workspace_result_t<std::optional<direct_target_t>>::success(std::nullopt);
    }
    const bool absolute = (word & 2U) != 0;
    const std::uint64_t encoded_displacement = opcode == ppc_opcode_branch
        ? static_cast<std::uint64_t>(word & 0x03fffffcU)
        : static_cast<std::uint64_t>(word & 0x0000fffcU);
    const std::int64_t displacement = sign_extend(
        encoded_displacement, opcode == ppc_opcode_branch ? 26 : 16);
    direct_target_t target;
    if (absolute) {
        target.runtime_address = key.address_width_bits == 32
            ? static_cast<std::uint32_t>(displacement)
            : static_cast<std::uint64_t>(displacement);
        return workspace_result_t<std::optional<direct_target_t>>::success(target);
    }
    if (key.address_width_bits == 32) {
        target.runtime_address = static_cast<std::uint32_t>(runtime_address) +
                                 static_cast<std::uint32_t>(displacement);
        return workspace_result_t<std::optional<direct_target_t>>::success(target);
    }
    if (!add_signed_offset(runtime_address, displacement, target.runtime_address)) {
        return workspace_result_t<std::optional<direct_target_t>>::failure(request_error(
            workspace_error_code_t::range_overflow,
            "PowerPC direct branch target overflowed", request));
    }
    return workspace_result_t<std::optional<direct_target_t>>::success(target);
}

struct flow_info_t {
    std::uint32_t flags = flow_none;
    bool call = false;
    bool branch = false;
    bool direct = false;
};

flow_info_t classify_flow(csh handle,
                          const cs_insn& instruction,
                          std::uint32_t word) noexcept {
    const ppc_insn instruction_id = static_cast<ppc_insn>(instruction.id);
    const bool direct = is_direct_branch_word(word);
    const bool indirect = is_indirect_branch_word(word);
    const bool linked = (direct || indirect) && branch_linked(word);
    const bool group_jump = cs_insn_group(handle, &instruction, CS_GRP_JUMP);
    const bool group_call = cs_insn_group(handle, &instruction, CS_GRP_CALL);
    const bool group_return = cs_insn_group(handle, &instruction, CS_GRP_RET);
    const bool group_interrupt = cs_insn_group(handle, &instruction, CS_GRP_INT);
    const bool group_privileged = cs_insn_group(handle, &instruction, CS_GRP_PRIVILEGE);
    const bool interrupt_return = is_interrupt_return(instruction_id);
    const bool return_instruction = group_return || interrupt_return ||
                                    is_link_register_return(word, instruction_id);
    const bool system_call = is_system_call(word, instruction_id);
    const bool trap = is_trap_word(word, instruction_id);
    const bool call = !return_instruction && (linked || group_call);
    const bool branch = !return_instruction && !call && (direct || indirect || group_jump);
    const bool conditional = (call || branch) && branch_is_conditional(word);
    flow_info_t result;
    result.call = call;
    result.branch = branch;
    result.direct = direct && (call || branch);
    if (return_instruction) {
        result.flags = flow_return | flow_terminal | flow_indirect;
        if (interrupt_return)
            result.flags |= flow_interrupt;
    } else if (trap) {
        result.flags = flow_interrupt;
        if (is_unconditional_trap(word, instruction_id))
            result.flags |= flow_terminal;
        else
            result.flags |= flow_conditional | flow_fallthrough;
    } else if (system_call || group_interrupt) {
        result.flags = flow_interrupt | flow_fallthrough;
    } else if (call) {
        result.flags = flow_call | flow_fallthrough;
        if (conditional)
            result.flags |= flow_conditional;
    } else if (branch) {
        result.flags = flow_branch;
        if (conditional)
            result.flags |= flow_conditional | flow_fallthrough;
        else
            result.flags |= flow_terminal;
    } else {
        result.flags = flow_fallthrough;
    }
    if (group_privileged || interrupt_return)
        result.flags |= flow_privileged;
    return result;
}

class ppc_decoder_backend_t final : public arch_decoder_backend_t {
public:
    ppc_decoder_backend_t(arch_decoder_key_t key,
                          cs_mode capstone_mode,
                          csh handle,
                          cs_insn* instruction) noexcept
        : key_(key),
          capstone_mode_(capstone_mode),
          handle_(handle),
          instruction_(instruction) {}

    ~ppc_decoder_backend_t() override {
        if (instruction_ != nullptr)
            cs_free(instruction_, 1);
        if (handle_ != 0)
            cs_close(&handle_);
    }

    workspace_result_t<void> decode_one(
        const byte_view_t& view,
        std::uint64_t view_provider_offset,
        const arch_decode_request_t& request,
        arch_decode_result_t& output,
        const arch_decode_control_t& control) override {
        output = {};
        auto polled = control.poll();
        if (!polled)
            return polled;
        auto expected_mode = capstone_mode_for(key_);
        if (!expected_mode || !same_mode(expected_mode.value(), capstone_mode_)) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::integrity_failure,
                "PowerPC decoder worker mode transition is invalid", request));
        }
        if (request.address.architecture != key_.architecture ||
            request.address.mode != key_.mode || request.available_bytes != 4 ||
            instruction_ == nullptr || handle_ == 0) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::invalid_argument,
                "PowerPC decoder request is invalid", request));
        }
        auto data = instruction_bytes(view, view_provider_offset, request);
        if (!data)
            return workspace_result_t<void>::failure(data.error());
        auto runtime_address = runtime_address_for(key_, request);
        if (!runtime_address)
            return workspace_result_t<void>::failure(runtime_address.error());
        const std::uint32_t word = instruction_word(data.value(), key_.endian);
        const std::uint8_t* decode_bytes = data.value();
        std::size_t decode_size = request.available_bytes;
        std::uint64_t decode_address = runtime_address.value();
        if (!cs_disasm_iter(handle_, &decode_bytes, &decode_size, &decode_address,
                            instruction_)) {
            return workspace_result_t<void>::failure(capstone_error(
                "cs_disasm_iter", cs_errno(handle_), decode_phase, &request));
        }
        polled = control.poll();
        if (!polled)
            return polled;
        if (instruction_->detail == nullptr || instruction_->id == PPC_INS_INVALID ||
            instruction_->size != 4 || instruction_->address != runtime_address.value()) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::integrity_failure,
                "Capstone returned invalid PowerPC instruction metadata", request));
        }
        const cs_ppc& ppc = instruction_->detail->ppc;
        if (ppc.op_count > output.operands.size()) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::limit_exceeded,
                "PowerPC instruction exceeds Compact IR operand capacity", request));
        }
        cs_regs regs_read{};
        cs_regs regs_write{};
        std::uint8_t regs_read_count = 0;
        std::uint8_t regs_write_count = 0;
        const cs_err register_status = cs_regs_access(handle_, instruction_, regs_read,
                                                      &regs_read_count, regs_write,
                                                      &regs_write_count);
        if (register_status != CS_ERR_OK) {
            return workspace_result_t<void>::failure(capstone_error(
                "cs_regs_access", register_status, decode_phase, &request));
        }
        const auto register_access = [&](std::uint16_t reg) noexcept {
            std::uint8_t access = 0;
            for (std::uint8_t index = 0; index < regs_read_count; ++index) {
                if (regs_read[index] == reg) {
                    access |= CS_AC_READ;
                    break;
                }
            }
            for (std::uint8_t index = 0; index < regs_write_count; ++index) {
                if (regs_write[index] == reg) {
                    access |= CS_AC_WRITE;
                    break;
                }
            }
            return access;
        };
        const flow_info_t flow = classify_flow(handle_, *instruction_, word);
        auto direct_target = direct_target_for(key_, word, runtime_address.value(), request);
        if (!direct_target)
            return workspace_result_t<void>::failure(direct_target.error());
        output.instruction.id = stable_instruction_id(request.address);
        output.instruction.address = request.address;
        output.instruction.length = static_cast<std::uint8_t>(instruction_->size);
        output.instruction.mnemonic_id = static_cast<std::uint16_t>(instruction_->id);
        output.instruction.opcode_id = instruction_->id;
        output.instruction.flow_flags = flow.flags;
        output.instruction.provenance = request.provenance;
        output.instruction.confidence = request.confidence;
        output.instruction.coverage = coverage_reason_t::decoded;
        output.instruction.stable_source_id = request.stable_source_id;
        std::array<bool, static_cast<std::size_t>(PPC_REG_ENDING)> explicit_registers{};
        const auto mark_explicit = [&](ppc_reg reg) noexcept {
            const std::uint16_t value = static_cast<std::uint16_t>(reg);
            if (value < explicit_registers.size())
                explicit_registers[value] = true;
        };
        std::uint8_t direct_target_operand = 0xffU;
        for (std::uint8_t index = 0; index < ppc.op_count; ++index) {
            polled = control.poll();
            if (!polled)
                return polled;
            const auto& operand = ppc.operands[index];
            operand_fact_t fact;
            fact.instruction_id = output.instruction.id;
            fact.operand_index = index;
            fact.decoder_operand_id = index;
            fact.access_count = 1;
            fact.address_width_bits = key_.address_width_bits;
            switch (operand.type) {
            case PPC_OP_REG:
                fact.kind = operand_kind_t::reg;
                fact.reg = static_cast<std::uint16_t>(operand.reg);
                fact.access = register_access(fact.reg);
                fact.bit_width = key_.address_width_bits;
                fact.access_width_bits = key_.address_width_bits;
                mark_explicit(operand.reg);
                break;
            case PPC_OP_CRX:
                fact.kind = operand_kind_t::reg;
                fact.reg = static_cast<std::uint16_t>(operand.crx.reg);
                fact.access = register_access(fact.reg);
                fact.immediate = static_cast<std::uint64_t>(operand.crx.cond);
                fact.bit_width = 32;
                fact.access_width_bits = 32;
                mark_explicit(operand.crx.reg);
                break;
            case PPC_OP_IMM:
                fact.kind = operand_kind_t::immediate;
                fact.signed_value = operand.imm < 0;
                fact.immediate = static_cast<std::uint64_t>(operand.imm);
                fact.bit_width = key_.address_width_bits;
                fact.access_width_bits = key_.address_width_bits;
                break;
            case PPC_OP_MEM:
                fact.kind = operand_kind_t::memory;
                fact.base_reg = static_cast<std::uint16_t>(operand.mem.base);
                fact.displacement = operand.mem.disp;
                fact.has_displacement = fact.displacement != 0;
                if (operand.mem.base != PPC_REG_INVALID) {
                    fact.address_components |= address_component_base;
                    fact.access = register_access(fact.base_reg);
                    mark_explicit(operand.mem.base);
                }
                if (fact.has_displacement)
                    fact.address_components |= address_component_displacement;
                fact.address_expression = operand.mem.base == PPC_REG_INVALID
                    ? address_expression_kind_t::absolute
                    : address_expression_kind_t::base_displacement;
                fact.bit_width = key_.address_width_bits;
                fact.access_width_bits = key_.address_width_bits;
                break;
            default:
                return workspace_result_t<void>::failure(request_error(
                    workspace_error_code_t::integrity_failure,
                    "Capstone returned an unsupported PowerPC operand", request));
            }
            if (output.operand_count >= output.operands.size()) {
                return workspace_result_t<void>::failure(request_error(
                    workspace_error_code_t::limit_exceeded,
                    "PowerPC instruction exceeds Compact IR operand capacity", request));
            }
            const std::uint8_t compact_index = output.operand_count;
            output.operands[output.operand_count++] = fact;
            if (operand.type == PPC_OP_IMM && direct_target_operand == 0xffU)
                direct_target_operand = compact_index;
        }
        for (std::uint8_t index = 0; index < regs_read_count; ++index) {
            polled = control.poll();
            if (!polled)
                return polled;
            const std::uint16_t reg = regs_read[index];
            if (reg == PPC_REG_INVALID || reg >= explicit_registers.size())
                continue;
            if (explicit_registers[reg])
                continue;
            if (output.operand_count >= output.operands.size()) {
                return workspace_result_t<void>::failure(request_error(
                    workspace_error_code_t::limit_exceeded,
                    "PowerPC implicit registers exceed Compact IR operand capacity", request));
            }
            operand_fact_t fact;
            fact.instruction_id = output.instruction.id;
            fact.operand_index = output.operand_count;
            fact.decoder_operand_id = static_cast<std::uint8_t>(0x80U + output.operand_count);
            fact.kind = operand_kind_t::reg;
            fact.access = register_access(reg);
            fact.access_count = 1;
            fact.bit_width = key_.address_width_bits;
            fact.access_width_bits = key_.address_width_bits;
            fact.address_width_bits = key_.address_width_bits;
            fact.reg = reg;
            output.operands[output.operand_count++] = fact;
            explicit_registers[reg] = true;
        }
        for (std::uint8_t index = 0; index < regs_write_count; ++index) {
            polled = control.poll();
            if (!polled)
                return polled;
            const std::uint16_t reg = regs_write[index];
            if (reg == PPC_REG_INVALID || reg >= explicit_registers.size())
                continue;
            if (explicit_registers[reg])
                continue;
            if (output.operand_count >= output.operands.size()) {
                return workspace_result_t<void>::failure(request_error(
                    workspace_error_code_t::limit_exceeded,
                    "PowerPC implicit registers exceed Compact IR operand capacity", request));
            }
            operand_fact_t fact;
            fact.instruction_id = output.instruction.id;
            fact.operand_index = output.operand_count;
            fact.decoder_operand_id = static_cast<std::uint8_t>(0x80U + output.operand_count);
            fact.kind = operand_kind_t::reg;
            fact.access = register_access(reg);
            fact.access_count = 1;
            fact.bit_width = key_.address_width_bits;
            fact.access_width_bits = key_.address_width_bits;
            fact.address_width_bits = key_.address_width_bits;
            fact.reg = reg;
            output.operands[output.operand_count++] = fact;
            explicit_registers[reg] = true;
        }
        if (flow.direct) {
            if (!direct_target.value()) {
                return workspace_result_t<void>::failure(request_error(
                    workspace_error_code_t::integrity_failure,
                    "PowerPC direct control flow is missing a decoded target", request));
            }
            const std::uint64_t resolved = direct_target.value()->runtime_address;
            target_fact_t target;
            target.instruction_id = output.instruction.id;
            target.operand_index = direct_target_operand;
            target.target = compact_target_address(request, resolved);
            target.kind = flow.call ? target_kind_record_t::call
                                    : target_kind_record_t::branch;
            target.resolution = target_resolution_for(request, target.target, resolved,
                                                      target.is_external);
            target.direct = true;
            target.access_width_bits = key_.address_width_bits;
            auto appended = append_target(output, std::move(target), request);
            if (!appended)
                return appended;
            output.instruction.flow_flags |= flow_direct;
        } else if (flow.call || flow.branch) {
            output.instruction.flow_flags |= flow_indirect;
        }
        if ((output.instruction.flow_flags & flow_fallthrough) != 0) {
            std::uint64_t fallthrough_value = 0;
            if (!checked_add_u64(request.address.value, instruction_->size,
                                 fallthrough_value)) {
                return workspace_result_t<void>::failure(request_error(
                    workspace_error_code_t::range_overflow,
                    "PowerPC instruction fallthrough address overflowed", request));
            }
            if (key_.address_width_bits == 32 &&
                fallthrough_value > std::numeric_limits<std::uint32_t>::max()) {
                return workspace_result_t<void>::failure(request_error(
                    workspace_error_code_t::range_overflow,
                    "PowerPC32 instruction fallthrough exceeds the active address width", request));
            }
            target_fact_t target;
            target.instruction_id = output.instruction.id;
            target.target = request.address;
            target.target.value = fallthrough_value;
            target.kind = target_kind_record_t::fallthrough;
            target.resolution = request.address.space == address_space_id_t::relative_virtual
                ? target_resolution_t::image_relative
                : target_resolution_t::image_virtual;
            target.direct = true;
            auto appended = append_target(output, std::move(target), request);
            if (!appended)
                return appended;
        }
        output.instruction.operand_fact_count = output.operand_count;
        output.instruction.target_fact_count = output.target_count;
        return control.poll();
    }

    workspace_result_t<std::string> format_decoded(
        const arch_decode_result_t& decoded,
        const arch_decode_control_t& control) override {
        auto polled = control.poll();
        if (!polled)
            return workspace_result_t<std::string>::failure(polled.error());
        if (instruction_ == nullptr || handle_ == 0 || instruction_->detail == nullptr ||
            instruction_->id == PPC_INS_INVALID ||
            instruction_->size != decoded.instruction.length ||
            static_cast<std::uint16_t>(instruction_->id) != decoded.instruction.mnemonic_id ||
            static_cast<std::uint32_t>(instruction_->id) != decoded.instruction.opcode_id ||
            instruction_->detail->ppc.op_count != decoded.operand_count) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                              "PowerPC formatter state does not match compact IR",
                                              "arch_decoder.format");
            error.address = decoded.instruction.address;
            return workspace_result_t<std::string>::failure(std::move(error));
        }
        return combine_format_text(instruction_->mnemonic, sizeof(instruction_->mnemonic),
                                   instruction_->op_str, sizeof(instruction_->op_str));
    }

private:
    arch_decoder_key_t key_;
    cs_mode capstone_mode_ = CS_MODE_LITTLE_ENDIAN;
    csh handle_ = 0;
    cs_insn* instruction_ = nullptr;
};

workspace_result_t<std::unique_ptr<arch_decoder_backend_t>> create_ppc_backend(
    const arch_decoder_key_t& key,
    const cancellation_token_t& cancellation) {
    if (cancellation.stop_requested()) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            stop_error(cancellation, create_phase));
    }
    auto capstone_mode = capstone_mode_for(key);
    if (!capstone_mode) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            capstone_mode.error());
    }
    csh handle = 0;
    cs_err status = cs_open(CS_ARCH_PPC, capstone_mode.value(), &handle);
    if (status != CS_ERR_OK) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            capstone_error("cs_open", status, create_phase));
    }
    status = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (status != CS_ERR_OK) {
        cs_close(&handle);
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            capstone_error("cs_option detail", status, create_phase));
    }
    status = cs_option(handle, CS_OPT_MODE,
                       static_cast<std::size_t>(
                           static_cast<std::uint32_t>(capstone_mode.value())));
    if (status != CS_ERR_OK) {
        cs_close(&handle);
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            capstone_error("cs_option mode", status, create_phase));
    }
    if (cancellation.stop_requested()) {
        cs_close(&handle);
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            stop_error(cancellation, create_phase));
    }
    cs_insn* instruction = cs_malloc(handle);
    if (instruction == nullptr) {
        const cs_err error = cs_errno(handle);
        cs_close(&handle);
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            capstone_error("cs_malloc", error, create_phase));
    }
    std::unique_ptr<arch_decoder_backend_t> backend(
        new ppc_decoder_backend_t(key, capstone_mode.value(), handle, instruction));
    return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::success(
        std::move(backend));
}

arch_decoder_registration_t ppc_registration(architecture_id_t architecture,
                                             architecture_mode_t mode,
                                             endian_t endian,
                                             std::uint8_t address_width_bits) {
    arch_decoder_registration_t registration;
    registration.key.architecture = architecture;
    registration.key.mode = mode;
    registration.key.endian = endian;
    registration.key.abi = abi_id_t::unknown;
    registration.key.address_width_bits = address_width_bits;
    registration.limits.minimum_instruction_bytes = 4;
    registration.limits.maximum_instruction_bytes = 4;
    registration.limits.instruction_alignment = 4;
    registration.limits.maximum_operand_facts =
        static_cast<std::uint8_t>(arch_decode_result_t::operand_capacity);
    registration.limits.maximum_target_facts =
        static_cast<std::uint16_t>(arch_decode_result_t::target_capacity);
    registration.limits.maximum_delay_slots = 0;
    registration.implementation_id = "capstone.ppc";
    registration.implementation_version = implementation_version;
    registration.factory = &create_ppc_backend;
    return registration;
}

}

workspace_result_t<void> register_ppc_decoder_backends(
    arch_decoder_registry_t& registry) {
    const std::array<arch_decoder_registration_t, 4> registrations{{
        ppc_registration(architecture_id_t::ppc, architecture_mode_t::ppc32,
                         endian_t::little, 32),
        ppc_registration(architecture_id_t::ppc, architecture_mode_t::ppc32,
                         endian_t::big, 32),
        ppc_registration(architecture_id_t::ppc64, architecture_mode_t::ppc64,
                         endian_t::little, 64),
        ppc_registration(architecture_id_t::ppc64, architecture_mode_t::ppc64,
                         endian_t::big, 64)
    }};
    for (const auto& registration : registrations) {
        auto registered = registry.register_decoder(registration);
        if (!registered)
            return registered;
    }
    return workspace_result_t<void>::success();
}

}
