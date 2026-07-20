#include "mips_decoder.hpp"

#include "checked_range.hpp"

#include <capstone/capstone.h>
#include <capstone/mips.h>

#include <array>
#include <limits>
#include <memory>
#include <string>
#include <utility>

namespace aida::analysis {
namespace {

constexpr const char* profile_phase = "mips_decoder.profile";
constexpr const char* key_phase = "mips_decoder.key";
constexpr const char* registration_phase = "mips_decoder.register";
constexpr const char* creation_phase = "mips_decoder.create";
constexpr const char* decode_phase = "mips_decoder.decode";
constexpr const char* implementation_id = "capstone.mips";
constexpr std::uint64_t implementation_version = 0x0005000000090004ULL;
constexpr std::uint16_t mips_instruction_bytes = 4;
constexpr std::uint8_t mips_operand_capacity = 10;
constexpr std::uint16_t mips_target_capacity = 2;
constexpr std::uint8_t mips_delay_slot_capacity = 1;

static_assert(CS_API_MAJOR == mips_decoder_profile_t::capstone_api_major);
static_assert(CS_API_MINOR == mips_decoder_profile_t::capstone_api_minor);
static_assert(CS_VERSION_EXTRA == mips_decoder_profile_t::capstone_version_extra);
static_assert(MIPS_REG_ENDING <= std::numeric_limits<std::uint16_t>::max());
static_assert(MIPS_INS_ENDING <= std::numeric_limits<std::uint16_t>::max());
static_assert(sizeof(cs_mips{}.operands) / sizeof(cs_mips_op) == mips_operand_capacity);
static_assert(arch_decode_result_t::operand_capacity >= mips_operand_capacity);
static_assert(arch_decode_result_t::target_capacity >= mips_target_capacity);

workspace_error_t stop_error(const cancellation_token_t& cancellation,
                             const char* phase) {
    if (cancellation.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "MIPS decoder deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "MIPS decoder operation cancelled", phase);
    error.cancellation = true;
    return error;
}

workspace_error_t capstone_error(workspace_error_code_t code,
                                 const char* operation,
                                 cs_err status,
                                 const char* phase) {
    auto error = make_workspace_error(code, std::string(operation) + " failed", phase);
    error.provider_status = static_cast<std::int64_t>(status);
    return error;
}

entity_id_t stable_instruction_id(const address_t& address) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    const auto feed = [&hash](std::uint64_t value) {
        for (std::size_t index = 0; index < 8; ++index) {
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

bool is_mips32_key(const arch_decoder_key_t& key) noexcept {
    return key.architecture == architecture_id_t::mips &&
           key.mode == architecture_mode_t::mips32 &&
           key.address_width_bits == 32;
}

bool is_mips64_key(const arch_decoder_key_t& key) noexcept {
    return (key.architecture == architecture_id_t::mips ||
            key.architecture == architecture_id_t::mips64) &&
           key.mode == architecture_mode_t::mips64 &&
           key.address_width_bits == 64;
}

workspace_result_t<std::uint64_t> runtime_address(const arch_decode_request_t& request) {
    switch (request.address.space) {
    case address_space_id_t::relative_virtual: {
        std::uint64_t value = 0;
        if (!checked_add_u64(request.image_base, request.address.value, value)) {
            auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                              "MIPS runtime address overflowed", decode_phase);
            error.address = request.address;
            return workspace_result_t<std::uint64_t>::failure(std::move(error));
        }
        return workspace_result_t<std::uint64_t>::success(value);
    }
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        return workspace_result_t<std::uint64_t>::success(request.address.value);
    case address_space_id_t::file_offset:
        if (request.runtime_address == 0) {
            auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                              "MIPS file-offset decoding requires a runtime address",
                                              decode_phase);
            error.address = request.address;
            return workspace_result_t<std::uint64_t>::failure(std::move(error));
        }
        return workspace_result_t<std::uint64_t>::success(request.runtime_address);
    }
    auto error = make_workspace_error(workspace_error_code_t::unsupported_address_space,
                                      "MIPS decode address space is unsupported", decode_phase);
    error.address = request.address;
    return workspace_result_t<std::uint64_t>::failure(std::move(error));
}

address_t target_address(const arch_decode_request_t& request,
                         std::uint64_t absolute) noexcept {
    address_t target = request.address;
    if (request.address.space == address_space_id_t::relative_virtual) {
        std::uint64_t image_end = 0;
        const bool bounded_image = request.image_size != 0 &&
            checked_add_u64(request.image_base, request.image_size, image_end);
        if (absolute >= request.image_base &&
            (!bounded_image || absolute < image_end)) {
            target.value = absolute - request.image_base;
        } else {
            target.space = address_space_id_t::virtual_address;
            target.value = absolute;
        }
    } else if (request.address.space == address_space_id_t::file_offset) {
        target.space = address_space_id_t::virtual_address;
        target.value = absolute;
    } else {
        target.value = absolute;
    }
    return target;
}

target_resolution_t target_resolution(const arch_decode_request_t& request,
                                      const address_t& target,
                                      bool& external) noexcept {
    external = false;
    if (target.space == address_space_id_t::relative_virtual)
        return target_resolution_t::image_relative;
    if (request.image_size != 0) {
        external = true;
        return target_resolution_t::external_virtual;
    }
    return target_resolution_t::image_virtual;
}

bool in_group(csh handle, const cs_insn& instruction,
              unsigned int group) noexcept {
    return cs_insn_group(handle, &instruction, group);
}

bool is_delay_slotless_instruction(unsigned int instruction_id) noexcept {
    switch (instruction_id) {
    case MIPS_INS_BALC:
    case MIPS_INS_BC:
    case MIPS_INS_BC1EQZ:
    case MIPS_INS_BC1NEZ:
    case MIPS_INS_BC2EQZ:
    case MIPS_INS_BC2NEZ:
    case MIPS_INS_BEQC:
    case MIPS_INS_BEQZALC:
    case MIPS_INS_BEQZC:
    case MIPS_INS_BGEC:
    case MIPS_INS_BGEUC:
    case MIPS_INS_BGEZALC:
    case MIPS_INS_BGEZC:
    case MIPS_INS_BGTZALC:
    case MIPS_INS_BGTZC:
    case MIPS_INS_BLEZALC:
    case MIPS_INS_BLEZC:
    case MIPS_INS_BLTC:
    case MIPS_INS_BLTUC:
    case MIPS_INS_BLTZALC:
    case MIPS_INS_BLTZC:
    case MIPS_INS_BNEC:
    case MIPS_INS_BNEZALC:
    case MIPS_INS_BNEZC:
    case MIPS_INS_BNVC:
    case MIPS_INS_BOVC:
    case MIPS_INS_JALRC:
    case MIPS_INS_JIALC:
    case MIPS_INS_JIC:
    case MIPS_INS_JRC:
        return true;
    default:
        return false;
    }
}

bool is_interrupt_instruction(unsigned int instruction_id) noexcept {
    return instruction_id == MIPS_INS_BREAK ||
           instruction_id == MIPS_INS_BREAK16 ||
           instruction_id == MIPS_INS_SYSCALL;
}

struct flow_info_t {
    std::uint32_t flags = flow_none;
    target_kind_record_t target_kind = target_kind_record_t::branch;
    bool direct_target_supported = false;
    bool has_delay_slot = false;
};

flow_info_t describe_flow(csh handle, const cs_insn& instruction) noexcept {
    const bool is_call = in_group(handle, instruction, MIPS_GRP_CALL);
    const bool is_return = in_group(handle, instruction, MIPS_GRP_RET);
    const bool is_iret = in_group(handle, instruction, MIPS_GRP_IRET);
    const bool is_jump = in_group(handle, instruction, MIPS_GRP_JUMP);
    const bool is_relative_branch =
        in_group(handle, instruction, MIPS_GRP_BRANCH_RELATIVE);
    const bool is_interrupt = in_group(handle, instruction, MIPS_GRP_INT) ||
                              is_interrupt_instruction(instruction.id);
    const bool is_privileged = in_group(handle, instruction, MIPS_GRP_PRIVILEGE);

    flow_info_t flow;
    if (is_call) {
        flow.flags = flow_call | flow_fallthrough;
        flow.target_kind = target_kind_record_t::call;
        flow.direct_target_supported = true;
        if (is_relative_branch)
            flow.flags |= flow_branch | flow_conditional;
    } else if (is_return) {
        flow.flags = flow_return | flow_terminal | flow_indirect;
    } else if (is_iret) {
        flow.flags = flow_interrupt | flow_return | flow_terminal | flow_indirect;
    } else if (is_jump) {
        flow.flags = flow_branch;
        flow.direct_target_supported = true;
        if (is_relative_branch)
            flow.flags |= flow_conditional | flow_fallthrough;
        else
            flow.flags |= flow_terminal;
    } else if (is_interrupt) {
        flow.flags = flow_interrupt | flow_fallthrough;
    } else {
        flow.flags = flow_fallthrough;
    }
    if (is_privileged)
        flow.flags |= flow_privileged;
    flow.has_delay_slot = (is_call || is_return || is_jump) &&
                          !is_delay_slotless_instruction(instruction.id);
    return flow;
}

workspace_result_t<void> append_target(arch_decode_result_t& output,
                                       target_fact_t target) {
    if (output.target_count >= output.targets.size())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "MIPS target count exceeds inline Compact IR capacity",
                                 decode_phase));
    output.targets[output.target_count++] = std::move(target);
    return workspace_result_t<void>::success();
}

class mips_arch_decoder_backend_t final : public arch_decoder_backend_t {
public:
    mips_arch_decoder_backend_t(csh handle,
                                cs_insn* instruction,
                                arch_decoder_key_t key) noexcept
        : handle_(handle), instruction_(instruction), key_(key) {}

    ~mips_arch_decoder_backend_t() override {
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
        auto polled = control.poll();
        if (!polled)
            return polled;
        if (instruction_ == nullptr || handle_ == 0 || view.data() == nullptr) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                              "MIPS decoder worker is not initialized", decode_phase);
            error.address = request.address;
            return workspace_result_t<void>::failure(std::move(error));
        }
        if (request.provider_offset < view_provider_offset) {
            auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                              "MIPS decode offset precedes the supplied view",
                                              decode_phase);
            error.offset = request.provider_offset;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const std::uint64_t relative_offset = request.provider_offset - view_provider_offset;
        if (relative_offset > view.size() ||
            request.available_bytes > view.size() - relative_offset) {
            auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                              "MIPS decode bytes exceed the supplied view",
                                              decode_phase);
            error.offset = request.provider_offset;
            error.size = request.available_bytes;
            return workspace_result_t<void>::failure(std::move(error));
        }
        auto runtime = runtime_address(request);
        if (!runtime)
            return workspace_result_t<void>::failure(runtime.error());
        const auto* code = view.data() + static_cast<std::size_t>(relative_offset);
        std::size_t code_size = request.available_bytes;
        std::uint64_t decode_address = runtime.value();
        if (!cs_disasm_iter(handle_, &code, &code_size, &decode_address, instruction_)) {
            auto error = capstone_error(workspace_error_code_t::decode_failure,
                                        "Capstone MIPS disassembly", cs_errno(handle_),
                                        decode_phase);
            error.address = request.address;
            error.offset = request.provider_offset;
            error.size = request.available_bytes;
            return workspace_result_t<void>::failure(std::move(error));
        }
        polled = control.poll();
        if (!polled)
            return polled;
        if (instruction_->detail == nullptr || instruction_->id == MIPS_INS_INVALID ||
            instruction_->id >= MIPS_INS_ENDING ||
            instruction_->size != mips_instruction_bytes ||
            instruction_->size > request.available_bytes ||
            instruction_->address != runtime.value() ||
            code_size != request.available_bytes - instruction_->size) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                              "Capstone returned invalid MIPS instruction metadata",
                                              decode_phase);
            error.address = request.address;
            error.offset = request.provider_offset;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const cs_mips& decoded = instruction_->detail->mips;
        if (decoded.op_count > mips_operand_capacity ||
            decoded.op_count > output.operands.size()) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                              "Capstone MIPS operand count exceeds Compact IR capacity",
                                              decode_phase);
            error.address = request.address;
            return workspace_result_t<void>::failure(std::move(error));
        }

        output = {};
        output.instruction.id = stable_instruction_id(request.address);
        output.instruction.address = request.address;
        output.instruction.length = static_cast<std::uint8_t>(instruction_->size);
        output.instruction.mnemonic_id = static_cast<std::uint16_t>(instruction_->id);
        output.instruction.opcode_id = instruction_->id;
        output.instruction.provenance = request.provenance;
        output.instruction.confidence = request.confidence;
        output.instruction.coverage = coverage_reason_t::decoded;
        output.instruction.stable_source_id = request.stable_source_id;

        const flow_info_t flow = describe_flow(handle_, *instruction_);
        output.instruction.flow_flags = flow.flags;
        output.delay_slot_count = flow.has_delay_slot ? 1 : 0;
        const std::uint16_t register_width = key_.mode == architecture_mode_t::mips64 ? 64 : 32;
        std::int32_t direct_target_operand = -1;
        std::uint64_t direct_target_value = 0;
        for (std::uint8_t index = 0; index < decoded.op_count; ++index) {
            const cs_mips_op& operand = decoded.operands[index];
            operand_fact_t fact;
            fact.instruction_id = output.instruction.id;
            fact.operand_index = index;
            fact.decoder_operand_id = index;
            switch (operand.type) {
            case MIPS_OP_REG:
                if (operand.reg == MIPS_REG_INVALID || operand.reg >= MIPS_REG_ENDING) {
                    auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                                      "Capstone returned an invalid MIPS register",
                                                      decode_phase);
                    error.address = request.address;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                fact.kind = operand_kind_t::reg;
                fact.reg = static_cast<std::uint16_t>(operand.reg);
                fact.bit_width = register_width;
                fact.access_width_bits = register_width;
                break;
            case MIPS_OP_IMM:
                fact.kind = operand_kind_t::immediate;
                fact.signed_value = operand.imm < 0;
                fact.immediate = static_cast<std::uint64_t>(operand.imm);
                fact.relative = in_group(handle_, *instruction_, MIPS_GRP_BRANCH_RELATIVE);
                if (flow.direct_target_supported) {
                    direct_target_operand = index;
                    direct_target_value = static_cast<std::uint64_t>(operand.imm);
                }
                break;
            case MIPS_OP_MEM:
                if (operand.mem.base >= MIPS_REG_ENDING) {
                    auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                                      "Capstone returned an invalid MIPS memory base register",
                                                      decode_phase);
                    error.address = request.address;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                fact.kind = operand_kind_t::memory;
                fact.base_reg = static_cast<std::uint16_t>(operand.mem.base);
                fact.address_width_bits = register_width;
                fact.displacement = operand.mem.disp;
                fact.has_displacement = true;
                fact.address_components = address_component_displacement;
                if (operand.mem.base == MIPS_REG_INVALID) {
                    fact.address_expression = address_expression_kind_t::absolute;
                } else {
                    fact.address_expression = address_expression_kind_t::base_displacement;
                    fact.address_components |= address_component_base;
                }
                break;
            default: {
                auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                                  "Capstone returned an unsupported MIPS operand",
                                                  decode_phase);
                error.address = request.address;
                return workspace_result_t<void>::failure(std::move(error));
            }
            }
            output.operands[output.operand_count++] = fact;
        }

        if (flow.direct_target_supported) {
            if (direct_target_operand >= 0) {
                target_fact_t target;
                target.instruction_id = output.instruction.id;
                target.target = target_address(request, direct_target_value);
                target.kind = flow.target_kind;
                target.operand_index = static_cast<std::uint8_t>(direct_target_operand);
                target.direct = true;
                target.resolution = target_resolution(request, target.target, target.is_external);
                auto appended = append_target(output, std::move(target));
                if (!appended)
                    return appended;
                output.instruction.flow_flags |= flow_direct;
            } else {
                output.instruction.flow_flags |= flow_indirect;
            }
        }
        if ((output.instruction.flow_flags & flow_fallthrough) != 0) {
            const std::uint64_t stride =
                static_cast<std::uint64_t>(instruction_->size) * (1 + output.delay_slot_count);
            std::uint64_t next_address = 0;
            if (!checked_add_u64(request.address.value, stride, next_address)) {
                auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                                  "MIPS fallthrough address overflowed", decode_phase);
                error.address = request.address;
                return workspace_result_t<void>::failure(std::move(error));
            }
            target_fact_t fallthrough;
            fallthrough.instruction_id = output.instruction.id;
            fallthrough.target = request.address;
            fallthrough.target.value = next_address;
            fallthrough.kind = target_kind_record_t::fallthrough;
            fallthrough.resolution = request.address.space == address_space_id_t::relative_virtual
                ? target_resolution_t::image_relative : target_resolution_t::image_virtual;
            fallthrough.direct = true;
            auto appended = append_target(output, std::move(fallthrough));
            if (!appended)
                return appended;
        }
        output.instruction.operand_fact_count = output.operand_count;
        output.instruction.target_fact_count = output.target_count;
        return workspace_result_t<void>::success();
    }

    workspace_result_t<std::string> format_decoded(
        const arch_decode_result_t& decoded,
        const arch_decode_control_t& control) override {
        auto polled = control.poll();
        if (!polled)
            return workspace_result_t<std::string>::failure(polled.error());
        if (instruction_ == nullptr || handle_ == 0 || instruction_->detail == nullptr ||
            instruction_->id == MIPS_INS_INVALID || instruction_->id >= MIPS_INS_ENDING ||
            instruction_->size != decoded.instruction.length ||
            static_cast<std::uint16_t>(instruction_->id) != decoded.instruction.mnemonic_id ||
            static_cast<std::uint32_t>(instruction_->id) != decoded.instruction.opcode_id ||
            instruction_->detail->mips.op_count != decoded.operand_count) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                              "MIPS formatter state does not match compact IR",
                                              "arch_decoder.format");
            error.address = decoded.instruction.address;
            return workspace_result_t<std::string>::failure(std::move(error));
        }
        return combine_format_text(instruction_->mnemonic, sizeof(instruction_->mnemonic),
                                   instruction_->op_str, sizeof(instruction_->op_str));
    }

private:
    csh handle_ = 0;
    cs_insn* instruction_ = nullptr;
    arch_decoder_key_t key_;
};

workspace_result_t<std::unique_ptr<arch_decoder_backend_t>> create_mips_backend(
    const arch_decoder_key_t& key,
    const cancellation_token_t& cancellation) {
    if (cancellation.stop_requested())
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            stop_error(cancellation, creation_phase));
    if (!is_mips32_key(key) && !is_mips64_key(key)) {
        auto error = make_workspace_error(workspace_error_code_t::unsupported_format,
                                          "MIPS decoder key is unsupported", creation_phase);
        error.details.emplace_back("architecture",
                                   std::to_string(static_cast<std::uint8_t>(key.architecture)));
        error.details.emplace_back("mode",
                                   std::to_string(static_cast<std::uint8_t>(key.mode)));
        error.details.emplace_back("address_width_bits",
                                   std::to_string(key.address_width_bits));
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            std::move(error));
    }
    if (!cs_support(CS_ARCH_MIPS)) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_format,
                                 "Capstone does not provide MIPS support", creation_phase));
    }
    std::uint32_t mode_bits = is_mips64_key(key)
        ? static_cast<std::uint32_t>(CS_MODE_MIPS64)
        : static_cast<std::uint32_t>(CS_MODE_MIPS32);
    if (key.endian == endian_t::big)
        mode_bits |= static_cast<std::uint32_t>(CS_MODE_BIG_ENDIAN);
    csh handle = 0;
    const cs_err open_status = cs_open(CS_ARCH_MIPS, static_cast<cs_mode>(mode_bits), &handle);
    if (open_status != CS_ERR_OK) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            capstone_error(workspace_error_code_t::decode_failure, "cs_open", open_status,
                           creation_phase));
    }
    const cs_err detail_status = cs_option(handle, CS_OPT_DETAIL,
                                           static_cast<std::size_t>(CS_OPT_ON));
    if (detail_status != CS_ERR_OK) {
        cs_close(&handle);
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            capstone_error(workspace_error_code_t::decode_failure, "cs_option", detail_status,
                           creation_phase));
    }
    cs_insn* instruction = cs_malloc(handle);
    if (instruction == nullptr) {
        const cs_err status = cs_errno(handle);
        cs_close(&handle);
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            capstone_error(workspace_error_code_t::decode_failure, "cs_malloc", status,
                           creation_phase));
    }
    if (cancellation.stop_requested()) {
        cs_free(instruction, 1);
        cs_close(&handle);
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            stop_error(cancellation, creation_phase));
    }
    return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::success(
        std::unique_ptr<arch_decoder_backend_t>(
            new mips_arch_decoder_backend_t(handle, instruction, key)));
}

arch_decoder_registration_t make_registration(architecture_id_t architecture,
                                              architecture_mode_t mode,
                                              endian_t endian,
                                              std::uint8_t address_width_bits) {
    arch_decoder_registration_t registration;
    registration.key.architecture = architecture;
    registration.key.mode = mode;
    registration.key.endian = endian;
    registration.key.abi = abi_id_t::unknown;
    registration.key.address_width_bits = address_width_bits;
    registration.limits.minimum_instruction_bytes = mips_instruction_bytes;
    registration.limits.maximum_instruction_bytes = mips_instruction_bytes;
    registration.limits.instruction_alignment = mips_instruction_bytes;
    registration.limits.maximum_operand_facts = mips_operand_capacity;
    registration.limits.maximum_target_facts = mips_target_capacity;
    registration.limits.maximum_delay_slots = mips_delay_slot_capacity;
    registration.implementation_id = implementation_id;
    registration.implementation_version = implementation_version;
    registration.factory = create_mips_backend;
    return registration;
}

bool same_registration(const arch_decoder_registration_t& lhs,
                       const arch_decoder_registration_t& rhs) noexcept {
    return lhs.key == rhs.key &&
           lhs.limits.minimum_instruction_bytes == rhs.limits.minimum_instruction_bytes &&
           lhs.limits.maximum_instruction_bytes == rhs.limits.maximum_instruction_bytes &&
           lhs.limits.instruction_alignment == rhs.limits.instruction_alignment &&
           lhs.limits.maximum_operand_facts == rhs.limits.maximum_operand_facts &&
           lhs.limits.maximum_target_facts == rhs.limits.maximum_target_facts &&
           lhs.limits.maximum_delay_slots == rhs.limits.maximum_delay_slots &&
           lhs.implementation_id == rhs.implementation_id &&
           lhs.implementation_version == rhs.implementation_version &&
           lhs.factory == rhs.factory;
}

workspace_result_t<void> register_one(arch_decoder_registry_t& registry,
                                      const arch_decoder_registration_t& registration) {
    auto resolved = registry.resolve(registration.key);
    if (resolved) {
        if (same_registration(resolved.value(), registration))
            return workspace_result_t<void>::success();
        auto error = make_workspace_error(workspace_error_code_t::service_conflict,
                                          "MIPS decoder key is already owned by another backend",
                                          registration_phase);
        error.details.emplace_back("architecture",
                                   std::to_string(static_cast<std::uint8_t>(
                                       registration.key.architecture)));
        error.details.emplace_back("mode",
                                   std::to_string(static_cast<std::uint8_t>(registration.key.mode)));
        error.details.emplace_back("endian",
                                   std::to_string(static_cast<std::uint8_t>(registration.key.endian)));
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (resolved.error().code != workspace_error_code_t::unsupported_format)
        return workspace_result_t<void>::failure(resolved.error());
    auto registered = registry.register_decoder(registration);
    if (registered || registered.error().code != workspace_error_code_t::service_conflict)
        return registered;
    resolved = registry.resolve(registration.key);
    if (resolved && same_registration(resolved.value(), registration))
        return workspace_result_t<void>::success();
    return workspace_result_t<void>::failure(registered.error());
}

void write_u64_le(std::array<std::uint8_t, mips_decoder_profile_t::canonical_byte_count>& bytes,
                  std::size_t offset,
                  std::uint64_t value) noexcept {
    for (std::size_t index = 0; index < sizeof(value); ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8));
}

}

std::array<std::uint8_t, mips_decoder_profile_t::canonical_byte_count>
mips_decoder_profile_t::canonical_bytes() const noexcept {
    std::array<std::uint8_t, canonical_byte_count> bytes{};
    bytes[0] = 'M';
    bytes[1] = 'I';
    bytes[2] = 'P';
    bytes[3] = 'S';
    bytes[4] = static_cast<std::uint8_t>(mode);
    bytes[5] = static_cast<std::uint8_t>(endian);
    bytes[6] = micromips ? 1 : 0;
    bytes[7] = mips_instruction_bytes;
    write_u64_le(bytes, 8, schema_version);
    write_u64_le(bytes, 16, capstone_api_major);
    write_u64_le(bytes, 24, capstone_api_minor);
    write_u64_le(bytes, 32, capstone_version_extra);
    write_u64_le(bytes, 40, implementation_version);
    write_u64_le(bytes, 48, mips_operand_capacity);
    write_u64_le(bytes, 56, mips_target_capacity);
    return bytes;
}

workspace_result_t<mips_decoder_profile_t>
make_mips_decoder_profile(mips_mode_t mode, endian_t endian, bool micromips) {
    if ((mode != mips_mode_t::mips32 && mode != mips_mode_t::mips64) ||
        endian > endian_t::big) {
        return workspace_result_t<mips_decoder_profile_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "MIPS decoder profile is invalid", profile_phase));
    }
    if (micromips) {
        return workspace_result_t<mips_decoder_profile_t>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_format,
                                 "MicroMIPS cannot be selected through the architecture decoder key",
                                 profile_phase));
    }
    mips_decoder_profile_t profile;
    profile.mode = mode;
    profile.endian = endian;
    profile.micromips = micromips;
    return workspace_result_t<mips_decoder_profile_t>::success(profile);
}

workspace_result_t<arch_decoder_key_t>
make_mips_decoder_key(mips_mode_t mode, endian_t endian, abi_id_t abi) {
    auto profile = make_mips_decoder_profile(mode, endian);
    if (!profile)
        return workspace_result_t<arch_decoder_key_t>::failure(profile.error());
    if (abi > abi_id_t::dalvik) {
        return workspace_result_t<arch_decoder_key_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "MIPS decoder ABI is invalid", key_phase));
    }
    arch_decoder_key_t key;
    key.architecture = mode == mips_mode_t::mips64
        ? architecture_id_t::mips64 : architecture_id_t::mips;
    key.mode = mode == mips_mode_t::mips64
        ? architecture_mode_t::mips64 : architecture_mode_t::mips32;
    key.endian = endian;
    key.abi = abi;
    key.address_width_bits = mode == mips_mode_t::mips64 ? 64 : 32;
    auto valid = validate_arch_decoder_key(key);
    if (!valid)
        return workspace_result_t<arch_decoder_key_t>::failure(valid.error());
    return workspace_result_t<arch_decoder_key_t>::success(key);
}

workspace_result_t<void> register_mips_decoder(arch_decoder_registry_t& registry) {
    const std::array<arch_decoder_registration_t, 6> registrations{{
        make_registration(architecture_id_t::mips, architecture_mode_t::mips32,
                          endian_t::little, 32),
        make_registration(architecture_id_t::mips, architecture_mode_t::mips32,
                          endian_t::big, 32),
        make_registration(architecture_id_t::mips, architecture_mode_t::mips64,
                          endian_t::little, 64),
        make_registration(architecture_id_t::mips, architecture_mode_t::mips64,
                          endian_t::big, 64),
        make_registration(architecture_id_t::mips64, architecture_mode_t::mips64,
                          endian_t::little, 64),
        make_registration(architecture_id_t::mips64, architecture_mode_t::mips64,
                          endian_t::big, 64)
    }};
    for (const auto& registration : registrations) {
        auto registered = register_one(registry, registration);
        if (!registered)
            return registered;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> register_default_mips_decoder() {
    return register_mips_decoder(default_arch_decoder_registry());
}

}
