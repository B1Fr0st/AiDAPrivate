#include "arm_decoder.hpp"

#include "checked_range.hpp"

#include <capstone/capstone.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

namespace aida::analysis {
namespace {

constexpr const char* create_phase = "arm_decoder.create";
constexpr const char* decode_phase = "arm_decoder.decode";
constexpr std::uint64_t implementation_version = 0x0005000000090001ULL;

static_assert(CS_API_MAJOR == 5);
static_assert(CS_API_MINOR == 0);
static_assert(CS_VERSION_EXTRA == 9);
static_assert(ARM_INS_ENDING <= std::numeric_limits<std::uint16_t>::max());
static_assert(ARM_REG_ENDING <= std::numeric_limits<std::uint16_t>::max());
static_assert(std::is_trivially_copyable_v<instruction_record_t>);
static_assert(std::is_trivially_copyable_v<operand_fact_t>);
static_assert(std::is_trivially_copyable_v<target_fact_t>);

workspace_error_t stop_error(const cancellation_token_t& cancellation,
                             const char* phase) {
    if (cancellation.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "ARM decoder deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "ARM decoder operation cancelled", phase);
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
    if (key.architecture != architecture_id_t::arm ||
        (key.mode != architecture_mode_t::arm_a32 &&
         key.mode != architecture_mode_t::arm_thumb) ||
        key.address_width_bits != 32 || key.endian > endian_t::big) {
        return workspace_result_t<cs_mode>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "ARM decoder key is invalid", create_phase));
    }
    std::uint32_t mode = key.mode == architecture_mode_t::arm_thumb
        ? static_cast<std::uint32_t>(CS_MODE_THUMB)
        : static_cast<std::uint32_t>(CS_MODE_ARM);
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
            "ARM decoder byte view is invalid", request));
    }
    std::uint64_t view_end = 0;
    if (!checked_add_u64(view_provider_offset,
                         static_cast<std::uint64_t>(view.size()), view_end)) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::range_overflow,
            "ARM decoder byte view range overflowed", request));
    }
    std::uint64_t instruction_end = 0;
    if (!checked_add_u64(request.provider_offset, request.available_bytes,
                         instruction_end)) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::range_overflow,
            "ARM decoder instruction range overflowed", request));
    }
    if (instruction_end > view_end) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::out_of_range,
            "ARM decoder instruction exceeds the supplied byte view", request));
    }
    const std::uint64_t relative = request.provider_offset - view_provider_offset;
    if (relative > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::range_overflow,
            "ARM decoder byte-view offset exceeds addressable memory", request));
    }
    return workspace_result_t<const std::uint8_t*>::success(
        view.data() + static_cast<std::size_t>(relative));
}

workspace_result_t<std::uint64_t> runtime_address_for(
    const arch_decode_request_t& request) {
    std::uint64_t runtime_address = request.address.value;
    switch (request.address.space) {
    case address_space_id_t::relative_virtual:
        if (!checked_add_u64(request.image_base, request.address.value, runtime_address)) {
            return workspace_result_t<std::uint64_t>::failure(request_error(
                workspace_error_code_t::range_overflow,
                "ARM instruction runtime address overflowed", request));
        }
        break;
    case address_space_id_t::file_offset:
        if (request.runtime_address == 0) {
            return workspace_result_t<std::uint64_t>::failure(request_error(
                workspace_error_code_t::invalid_argument,
                "ARM file-offset decoding requires a runtime address", request));
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
            "ARM decode runtime address conflicts with the typed address", request));
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

workspace_result_t<std::uint64_t> program_counter_value(
    const arch_decoder_key_t& key,
    std::uint64_t runtime_address,
    const arch_decode_request_t& request) {
    std::uint64_t value = 0;
    if (key.mode == architecture_mode_t::arm_a32) {
        if (!checked_add_u64(runtime_address, 8, value)) {
            return workspace_result_t<std::uint64_t>::failure(request_error(
                workspace_error_code_t::range_overflow,
                "ARM program counter value overflowed", request));
        }
    } else {
        if (!checked_add_u64(runtime_address, 4, value)) {
            return workspace_result_t<std::uint64_t>::failure(request_error(
                workspace_error_code_t::range_overflow,
                "Thumb program counter value overflowed", request));
        }
        value &= ~std::uint64_t{3};
    }
    return workspace_result_t<std::uint64_t>::success(value);
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
            "ARM instruction exceeds Compact IR target capacity", request));
    }
    output.targets[output.target_count++] = std::move(target);
    return workspace_result_t<void>::success();
}

bool is_load_multiple(arm_insn instruction) noexcept {
    return instruction == ARM_INS_LDM || instruction == ARM_INS_LDMDA ||
           instruction == ARM_INS_LDMDB || instruction == ARM_INS_LDMIA ||
           instruction == ARM_INS_LDMIB;
}

bool is_exception_return(arm_insn instruction) noexcept {
    return instruction == ARM_INS_ERET || instruction == ARM_INS_RFEDA ||
           instruction == ARM_INS_RFEDB || instruction == ARM_INS_RFEIA ||
           instruction == ARM_INS_RFEIB;
}

bool is_terminal_interrupt(arm_insn instruction) noexcept {
    return instruction == ARM_INS_BKPT || instruction == ARM_INS_UDF;
}

bool is_explicit_interrupt(arm_insn instruction) noexcept {
    return instruction == ARM_INS_BKPT || instruction == ARM_INS_HVC ||
           instruction == ARM_INS_SMC || instruction == ARM_INS_SVC ||
           instruction == ARM_INS_UDF;
}

bool is_explicit_branch(arm_insn instruction) noexcept {
    return instruction == ARM_INS_B || instruction == ARM_INS_BX ||
           instruction == ARM_INS_BXJ || instruction == ARM_INS_BXNS ||
           instruction == ARM_INS_CBZ || instruction == ARM_INS_CBNZ ||
           instruction == ARM_INS_TBB || instruction == ARM_INS_TBH;
}

bool is_explicit_call(arm_insn instruction) noexcept {
    return instruction == ARM_INS_BL || instruction == ARM_INS_BLX ||
           instruction == ARM_INS_BLXNS;
}

struct flow_info_t {
    std::uint32_t flags = flow_none;
    bool call = false;
    bool branch = false;
};

flow_info_t classify_flow(csh handle,
                          const cs_insn& instruction,
                          const cs_arm& arm) noexcept {
    const arm_insn instruction_id = static_cast<arm_insn>(instruction.id);
    bool writes_pc = false;
    bool reads_lr = false;
    bool bx_lr = false;
    bool pc_in_register_list = false;
    for (std::uint8_t index = 0; index < arm.op_count; ++index) {
        const auto& operand = arm.operands[index];
        if (operand.type != ARM_OP_REG)
            continue;
        if (operand.reg == ARM_REG_PC) {
            pc_in_register_list = true;
            if ((operand.access & CS_AC_WRITE) != 0)
                writes_pc = true;
        }
        if (operand.reg == ARM_REG_LR) {
            if ((operand.access & CS_AC_READ) != 0)
                reads_lr = true;
            if (instruction_id == ARM_INS_BX && index == 0)
                bx_lr = true;
        }
    }
    const bool group_call = cs_insn_group(handle, &instruction, CS_GRP_CALL);
    const bool group_jump = cs_insn_group(handle, &instruction, CS_GRP_JUMP);
    const bool group_ret = cs_insn_group(handle, &instruction, CS_GRP_RET);
    const bool group_interrupt = cs_insn_group(handle, &instruction, CS_GRP_INT);
    const bool group_privileged = cs_insn_group(handle, &instruction, CS_GRP_PRIVILEGE);
    const bool register_list_return =
        pc_in_register_list && (instruction_id == ARM_INS_POP ||
                                is_load_multiple(instruction_id));
    const bool return_instruction = group_ret || bx_lr || register_list_return ||
        is_exception_return(instruction_id) || (writes_pc && reads_lr);
    const bool call = group_call || is_explicit_call(instruction_id);
    const bool branch = !return_instruction &&
        (group_jump || is_explicit_branch(instruction_id) || writes_pc);
    const bool conditional = branch &&
        (instruction_id == ARM_INS_CBZ || instruction_id == ARM_INS_CBNZ ||
         (arm.cc != ARM_CC_AL && arm.cc != ARM_CC_INVALID));
    const bool interrupt = group_interrupt || is_explicit_interrupt(instruction_id);
    flow_info_t result;
    result.call = call;
    result.branch = branch;
    if (return_instruction) {
        result.flags = flow_return | flow_terminal | flow_indirect;
    } else if (call) {
        result.flags = flow_call | flow_fallthrough;
    } else if (branch) {
        result.flags = flow_branch;
        if (conditional)
            result.flags |= flow_conditional | flow_fallthrough;
        else
            result.flags |= flow_terminal;
    } else if (interrupt) {
        result.flags = flow_interrupt;
        if (is_terminal_interrupt(instruction_id))
            result.flags |= flow_terminal;
        else
            result.flags |= flow_fallthrough;
    } else {
        result.flags = flow_fallthrough;
    }
    if (group_privileged || instruction_id == ARM_INS_ERET ||
        instruction_id == ARM_INS_HVC || instruction_id == ARM_INS_SMC) {
        result.flags |= flow_privileged;
    }
    return result;
}

class arm_decoder_backend_t final : public arch_decoder_backend_t {
public:
    arm_decoder_backend_t(arch_decoder_key_t key,
                          cs_mode capstone_mode,
                          csh handle,
                          cs_insn* instruction) noexcept
        : key_(key),
          capstone_mode_(capstone_mode),
          handle_(handle),
          instruction_(instruction) {}

    ~arm_decoder_backend_t() override {
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
                "ARM decoder worker mode transition is invalid", request));
        }
        if (request.address.architecture != architecture_id_t::arm ||
            request.address.mode != key_.mode || request.available_bytes == 0 ||
            request.available_bytes > 4 || instruction_ == nullptr || handle_ == 0) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::invalid_argument,
                "ARM decoder request is invalid", request));
        }
        const std::uint16_t minimum_size = key_.mode == architecture_mode_t::arm_thumb ? 2 : 4;
        if (request.available_bytes < minimum_size) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::invalid_argument,
                "ARM decoder input is shorter than the active instruction mode", request));
        }
        auto data = instruction_bytes(view, view_provider_offset, request);
        if (!data)
            return workspace_result_t<void>::failure(data.error());
        auto runtime_address = runtime_address_for(request);
        if (!runtime_address)
            return workspace_result_t<void>::failure(runtime_address.error());
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
        if (instruction_->detail == nullptr || instruction_->id == ARM_INS_INVALID ||
            instruction_->size < minimum_size || instruction_->size > request.available_bytes ||
            instruction_->size > 4 || instruction_->address != runtime_address.value()) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::integrity_failure,
                "Capstone returned invalid ARM instruction metadata", request));
        }
        const cs_arm& arm = instruction_->detail->arm;
        if (arm.op_count > output.operands.size()) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::limit_exceeded,
                "ARM instruction exceeds Compact IR operand capacity", request));
        }
        const flow_info_t flow = classify_flow(handle_, *instruction_, arm);
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
        bool direct_control_target = false;
        for (std::uint8_t index = 0; index < arm.op_count; ++index) {
            polled = control.poll();
            if (!polled)
                return polled;
            const auto& operand = arm.operands[index];
            operand_fact_t fact;
            fact.instruction_id = output.instruction.id;
            fact.operand_index = index;
            fact.decoder_operand_id = index;
            fact.access = operand.access;
            fact.access_count = 1;
            fact.address_width_bits = 32;
            switch (operand.type) {
            case ARM_OP_REG:
            case ARM_OP_SYSREG:
                fact.kind = operand_kind_t::reg;
                fact.reg = static_cast<std::uint16_t>(operand.reg);
                fact.bit_width = 32;
                fact.access_width_bits = 32;
                break;
            case ARM_OP_IMM:
            case ARM_OP_CIMM:
            case ARM_OP_PIMM:
                fact.kind = operand_kind_t::immediate;
                fact.signed_value = operand.imm < 0;
                fact.immediate = static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(operand.imm));
                fact.bit_width = 32;
                fact.access_width_bits = 32;
                break;
            case ARM_OP_FP:
                fact.kind = operand_kind_t::immediate;
                std::memcpy(&fact.immediate, &operand.fp, sizeof(operand.fp));
                fact.bit_width = 64;
                fact.access_width_bits = 64;
                break;
            case ARM_OP_SETEND:
                fact.kind = operand_kind_t::immediate;
                fact.immediate = static_cast<std::uint64_t>(operand.setend);
                fact.bit_width = 8;
                fact.access_width_bits = 8;
                break;
            case ARM_OP_MEM:
                fact.kind = operand_kind_t::memory;
                fact.base_reg = static_cast<std::uint16_t>(operand.mem.base);
                fact.index_reg = static_cast<std::uint16_t>(operand.mem.index);
                fact.displacement = operand.mem.disp;
                if (operand.subtracted && fact.displacement > 0)
                    fact.displacement = -fact.displacement;
                fact.has_displacement = fact.displacement != 0;
                if (operand.mem.base != ARM_REG_INVALID) {
                    fact.address_components |= address_component_base;
                    if (operand.mem.base == ARM_REG_PC)
                        fact.address_components |= address_component_instruction_pointer;
                }
                if (operand.mem.index != ARM_REG_INVALID)
                    fact.address_components |= address_component_index;
                if (operand.mem.scale > 0 &&
                    operand.mem.scale <= std::numeric_limits<std::uint8_t>::max()) {
                    fact.scale = static_cast<std::uint8_t>(operand.mem.scale);
                    fact.address_components |= address_component_scale;
                }
                if (fact.has_displacement)
                    fact.address_components |= address_component_displacement;
                if (operand.mem.base == ARM_REG_PC &&
                    operand.mem.index == ARM_REG_INVALID) {
                    fact.address_expression = address_expression_kind_t::instruction_relative;
                } else if (operand.mem.base == ARM_REG_INVALID &&
                           operand.mem.index == ARM_REG_INVALID) {
                    fact.address_expression = address_expression_kind_t::absolute;
                } else if (operand.mem.index != ARM_REG_INVALID) {
                    fact.address_expression = address_expression_kind_t::base_index_displacement;
                } else {
                    fact.address_expression = address_expression_kind_t::base_displacement;
                }
                break;
            default:
                fact.kind = operand_kind_t::none;
                break;
            }
            if (output.operand_count >= output.operands.size()) {
                return workspace_result_t<void>::failure(request_error(
                    workspace_error_code_t::limit_exceeded,
                    "ARM instruction exceeds Compact IR operand capacity", request));
            }
            const std::uint8_t compact_index = output.operand_count;
            output.operands[output.operand_count++] = fact;
            if (operand.type == ARM_OP_MEM && operand.mem.base == ARM_REG_PC &&
                operand.mem.index == ARM_REG_INVALID) {
                auto pc = program_counter_value(key_, runtime_address.value(), request);
                if (!pc)
                    return workspace_result_t<void>::failure(pc.error());
                std::uint64_t resolved = 0;
                if (!add_signed_offset(pc.value(), fact.displacement, resolved)) {
                    return workspace_result_t<void>::failure(request_error(
                        workspace_error_code_t::range_overflow,
                        "ARM PC-relative memory target overflowed", request));
                }
                auto& stored_fact = output.operands[compact_index];
                stored_fact.has_resolved_expression_value = true;
                stored_fact.resolved_expression_value = resolved;
                target_fact_t target;
                target.instruction_id = output.instruction.id;
                target.operand_index = compact_index;
                target.target = compact_target_address(request, resolved);
                target.kind = target_kind_record_t::data;
                target.resolution = target_resolution_for(request, target.target,
                                                          resolved, target.is_external);
                auto appended = append_target(output, std::move(target), request);
                if (!appended)
                    return appended;
            }
            if ((flow.call || flow.branch) &&
                (operand.type == ARM_OP_IMM || operand.type == ARM_OP_CIMM ||
                 operand.type == ARM_OP_PIMM)) {
                const std::uint64_t resolved = static_cast<std::uint32_t>(operand.imm);
                target_fact_t target;
                target.instruction_id = output.instruction.id;
                target.operand_index = compact_index;
                target.target = compact_target_address(request, resolved);
                target.kind = flow.call ? target_kind_record_t::call
                                        : target_kind_record_t::branch;
                target.resolution = target_resolution_for(request, target.target,
                                                          resolved, target.is_external);
                target.direct = true;
                target.access_width_bits = 32;
                auto appended = append_target(output, std::move(target), request);
                if (!appended)
                    return appended;
                direct_control_target = true;
            }
        }
        if (flow.call || flow.branch) {
            if (direct_control_target)
                output.instruction.flow_flags |= flow_direct;
            else
                output.instruction.flow_flags |= flow_indirect;
        }
        if ((output.instruction.flow_flags & flow_fallthrough) != 0) {
            std::uint64_t fallthrough_value = 0;
            if (!checked_add_u64(request.address.value, instruction_->size,
                                 fallthrough_value)) {
                return workspace_result_t<void>::failure(request_error(
                    workspace_error_code_t::range_overflow,
                    "ARM instruction fallthrough address overflowed", request));
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
            instruction_->id == ARM_INS_INVALID ||
            instruction_->size != decoded.instruction.length ||
            static_cast<std::uint16_t>(instruction_->id) != decoded.instruction.mnemonic_id ||
            static_cast<std::uint32_t>(instruction_->id) != decoded.instruction.opcode_id ||
            instruction_->detail->arm.op_count != decoded.operand_count) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                              "ARM formatter state does not match compact IR",
                                              "arch_decoder.format");
            error.address = decoded.instruction.address;
            return workspace_result_t<std::string>::failure(std::move(error));
        }
        return combine_format_text(instruction_->mnemonic, sizeof(instruction_->mnemonic),
                                   instruction_->op_str, sizeof(instruction_->op_str));
    }

private:
    arch_decoder_key_t key_;
    cs_mode capstone_mode_ = CS_MODE_ARM;
    csh handle_ = 0;
    cs_insn* instruction_ = nullptr;
};

workspace_result_t<std::unique_ptr<arch_decoder_backend_t>> create_arm_backend(
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
    cs_err status = cs_open(CS_ARCH_ARM, capstone_mode.value(), &handle);
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
        new arm_decoder_backend_t(key, capstone_mode.value(), handle, instruction));
    return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::success(
        std::move(backend));
}

arch_decoder_registration_t arm_registration(architecture_mode_t mode,
                                             endian_t endian) {
    arch_decoder_registration_t registration;
    registration.key.architecture = architecture_id_t::arm;
    registration.key.mode = mode;
    registration.key.endian = endian;
    registration.key.abi = abi_id_t::unknown;
    registration.key.address_width_bits = 32;
    registration.limits.minimum_instruction_bytes =
        mode == architecture_mode_t::arm_thumb ? 2 : 4;
    registration.limits.maximum_instruction_bytes = 4;
    registration.limits.instruction_alignment =
        mode == architecture_mode_t::arm_thumb ? 2 : 4;
    registration.limits.maximum_operand_facts =
        static_cast<std::uint8_t>(arch_decode_result_t::operand_capacity);
    registration.limits.maximum_target_facts =
        static_cast<std::uint16_t>(arch_decode_result_t::target_capacity);
    registration.limits.maximum_delay_slots = 0;
    registration.implementation_id = "capstone.arm";
    registration.implementation_version = implementation_version;
    registration.factory = &create_arm_backend;
    return registration;
}

}

workspace_result_t<void> register_arm_decoder_backends(
    arch_decoder_registry_t& registry) {
    const std::array<arch_decoder_registration_t, 4> registrations{{
        arm_registration(architecture_mode_t::arm_a32, endian_t::little),
        arm_registration(architecture_mode_t::arm_a32, endian_t::big),
        arm_registration(architecture_mode_t::arm_thumb, endian_t::little),
        arm_registration(architecture_mode_t::arm_thumb, endian_t::big)
    }};
    for (const auto& registration : registrations) {
        auto registered = registry.register_decoder(registration);
        if (!registered)
            return registered;
    }
    return workspace_result_t<void>::success();
}

}
