#include "riscv_decoder.hpp"

#include "checked_range.hpp"

#include <capstone/capstone.h>
#include <capstone/riscv.h>

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace aida::analysis {
namespace {

constexpr const char* profile_phase = "riscv_decoder.profile";
constexpr const char* registration_phase = "riscv_decoder.registration";
constexpr const char* factory_phase = "riscv_decoder.factory";
constexpr const char* decode_phase = "riscv_decoder.decode";
constexpr std::uint16_t minimum_instruction_size = 2;
constexpr std::uint16_t maximum_instruction_size = 4;
constexpr std::uint8_t maximum_operands = 8;
constexpr std::uint16_t maximum_targets = 3;

static_assert(CS_API_MAJOR == riscv_decoder_profile_t::capstone_api_major);
static_assert(CS_API_MINOR == riscv_decoder_profile_t::capstone_api_minor);
static_assert(CS_VERSION_EXTRA == riscv_decoder_profile_t::capstone_version_extra);
static_assert(CS_MODE_LITTLE_ENDIAN == 0);
static_assert(RISCV_REG_INVALID == 0);
static_assert(RISCV_REG_ENDING <= std::numeric_limits<std::uint16_t>::max());
static_assert(RISCV_INS_ENDING <= std::numeric_limits<std::uint16_t>::max());
static_assert(std::is_trivially_copyable_v<instruction_record_t>);
static_assert(std::is_trivially_copyable_v<operand_fact_t>);
static_assert(std::is_trivially_copyable_v<target_fact_t>);
static_assert(maximum_operands <= arch_decode_result_t::operand_capacity);
static_assert(maximum_targets <= arch_decode_result_t::target_capacity);

workspace_error_t stop_error(const cancellation_token_t& cancellation,
                             const char* phase) {
    if (cancellation.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "RISC-V decoder deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "RISC-V decoder operation cancelled", phase);
    error.cancellation = true;
    return error;
}

workspace_error_t request_error(workspace_error_code_t code,
                                const char* message,
                                const arch_decode_request_t& request) {
    auto error = make_workspace_error(code, message, decode_phase);
    error.address = request.address;
    error.offset = request.provider_offset;
    error.size = request.available_bytes;
    return error;
}

workspace_error_t capstone_error(const char* operation,
                                 cs_err status,
                                 const arch_decode_request_t& request) {
    auto error = request_error(workspace_error_code_t::decode_failure,
                               "Capstone rejected the RISC-V instruction", request);
    error.provider_status = static_cast<std::int64_t>(status);
    error.details.emplace_back("operation", operation);
    return error;
}

workspace_error_t factory_error(workspace_error_code_t code,
                                const char* message,
                                const arch_decoder_key_t& key) {
    auto error = make_workspace_error(code, message, factory_phase);
    error.details.emplace_back("architecture",
                               std::to_string(static_cast<std::uint8_t>(key.architecture)));
    error.details.emplace_back("mode",
                               std::to_string(static_cast<std::uint8_t>(key.mode)));
    error.details.emplace_back("endian",
                               std::to_string(static_cast<std::uint8_t>(key.endian)));
    error.details.emplace_back("address_width_bits",
                               std::to_string(key.address_width_bits));
    return error;
}

void write_u64(std::array<std::uint8_t, riscv_decoder_profile_t::canonical_byte_count>& bytes,
               std::size_t offset,
               std::uint64_t value) noexcept {
    for (std::size_t index = 0; index < sizeof(value); ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8));
}

bool is_riscv_mode(architecture_mode_t mode) noexcept {
    return mode == architecture_mode_t::riscv32 ||
           mode == architecture_mode_t::riscv64;
}

bool key_matches_mode(const arch_decoder_key_t& key) noexcept {
    if (!is_riscv_mode(key.mode) || key.endian > endian_t::big)
        return false;
    if (key.mode == architecture_mode_t::riscv32) {
        return key.address_width_bits == 32 &&
               (key.architecture == architecture_id_t::riscv ||
                key.architecture == architecture_id_t::riscv32);
    }
    return key.address_width_bits == 64 &&
           (key.architecture == architecture_id_t::riscv ||
            key.architecture == architecture_id_t::riscv64);
}

workspace_result_t<cs_mode> capstone_mode_for(const arch_decoder_key_t& key) {
    if (!key_matches_mode(key)) {
        return workspace_result_t<cs_mode>::failure(factory_error(
            workspace_error_code_t::invalid_argument,
            "RISC-V decoder factory received an incompatible key", key));
    }
    cs_mode mode = key.mode == architecture_mode_t::riscv32
        ? CS_MODE_RISCV32 : CS_MODE_RISCV64;
    mode = static_cast<cs_mode>(mode | CS_MODE_RISCVC);
    if (key.endian == endian_t::big)
        mode = static_cast<cs_mode>(mode | CS_MODE_BIG_ENDIAN);
    return workspace_result_t<cs_mode>::success(mode);
}

entity_id_t stable_instruction_id(const address_t& address) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    const auto feed = [&](std::uint64_t value) {
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

workspace_result_t<std::uint64_t> effective_runtime_address(
    const arch_decode_request_t& request) {
    switch (request.address.space) {
    case address_space_id_t::relative_virtual: {
        std::uint64_t runtime_address = 0;
        if (!checked_add_u64(request.image_base, request.address.value, runtime_address)) {
            return workspace_result_t<std::uint64_t>::failure(request_error(
                workspace_error_code_t::range_overflow,
                "RISC-V runtime address overflowed", request));
        }
        return workspace_result_t<std::uint64_t>::success(runtime_address);
    }
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        return workspace_result_t<std::uint64_t>::success(request.address.value);
    case address_space_id_t::file_offset:
        if (request.runtime_address == 0) {
            return workspace_result_t<std::uint64_t>::failure(request_error(
                workspace_error_code_t::invalid_argument,
                "RISC-V file-offset decoding requires a runtime address", request));
        }
        return workspace_result_t<std::uint64_t>::success(request.runtime_address);
    }
    return workspace_result_t<std::uint64_t>::failure(request_error(
        workspace_error_code_t::unsupported_address_space,
        "RISC-V decoder received an unsupported address space", request));
}

workspace_result_t<const std::uint8_t*> instruction_bytes(
    const byte_view_t& view,
    std::uint64_t view_provider_offset,
    const arch_decode_request_t& request) {
    if (request.available_bytes < minimum_instruction_size ||
        request.available_bytes > maximum_instruction_size) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::invalid_argument,
            "RISC-V decoder requires between two and four instruction bytes", request));
    }
    if ((request.address.value & 1U) != 0) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::invalid_argument,
            "RISC-V instruction address is not two-byte aligned", request));
    }
    if (view.size() != 0 && view.data() == nullptr) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::invalid_argument,
            "RISC-V decoder received an invalid byte view", request));
    }
    if (request.provider_offset < view_provider_offset) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::out_of_range,
            "RISC-V instruction precedes the leased byte view", request));
    }
    const std::uint64_t relative_offset = request.provider_offset - view_provider_offset;
    const std::uint64_t view_size = static_cast<std::uint64_t>(view.size());
    if (relative_offset > view_size ||
        request.available_bytes > view_size - relative_offset) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::out_of_range,
            "RISC-V instruction exceeds the leased byte view", request));
    }
    return workspace_result_t<const std::uint8_t*>::success(
        view.data() + static_cast<std::size_t>(relative_offset));
}

bool runtime_in_image(const arch_decode_request_t& request,
                      std::uint64_t runtime_address) noexcept {
    return request.image_size != 0 && runtime_address >= request.image_base &&
           runtime_address - request.image_base < request.image_size;
}

address_t target_address(const arch_decode_request_t& request,
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

target_resolution_t target_resolution(const arch_decode_request_t& request,
                                      const address_t& target,
                                      std::uint64_t runtime_address,
                                      bool& is_external) noexcept {
    is_external = false;
    if (target.space == address_space_id_t::relative_virtual)
        return target_resolution_t::image_relative;
    if (request.image_size != 0 && !runtime_in_image(request, runtime_address)) {
        is_external = true;
        return target_resolution_t::external_virtual;
    }
    return target_resolution_t::image_virtual;
}

bool add_signed_offset(std::uint64_t base,
                       std::int64_t displacement,
                       std::uint8_t address_width_bits,
                       std::uint64_t& output) noexcept {
    if (address_width_bits == 32) {
        const auto narrowed_base = static_cast<std::uint32_t>(base);
        const auto narrowed_displacement = static_cast<std::uint32_t>(displacement);
        output = static_cast<std::uint32_t>(narrowed_base + narrowed_displacement);
        return true;
    }
    if (displacement >= 0)
        return checked_add_u64(base, static_cast<std::uint64_t>(displacement), output);
    const std::uint64_t magnitude =
        static_cast<std::uint64_t>(-(displacement + 1)) + 1;
    return checked_sub_u64(base, magnitude, output);
}

std::uint64_t zero_base_address(std::int64_t displacement,
                                std::uint8_t address_width_bits) noexcept {
    if (address_width_bits == 32)
        return static_cast<std::uint32_t>(displacement);
    return static_cast<std::uint64_t>(displacement);
}

bool is_conditional_branch(unsigned int instruction_id) noexcept {
    switch (instruction_id) {
    case RISCV_INS_BEQ:
    case RISCV_INS_BNE:
    case RISCV_INS_BLT:
    case RISCV_INS_BGE:
    case RISCV_INS_BLTU:
    case RISCV_INS_BGEU:
    case RISCV_INS_C_BEQZ:
    case RISCV_INS_C_BNEZ:
        return true;
    default:
        return false;
    }
}

bool is_direct_control_instruction(unsigned int instruction_id) noexcept {
    return instruction_id == RISCV_INS_JAL || instruction_id == RISCV_INS_C_J ||
           instruction_id == RISCV_INS_C_JAL || is_conditional_branch(instruction_id);
}

bool is_interrupt_return(unsigned int instruction_id) noexcept {
    return instruction_id == RISCV_INS_MRET || instruction_id == RISCV_INS_SRET ||
           instruction_id == RISCV_INS_URET;
}

bool is_terminal_interrupt(unsigned int instruction_id) noexcept {
    return instruction_id == RISCV_INS_EBREAK ||
           instruction_id == RISCV_INS_C_EBREAK;
}

bool is_zero_register(unsigned int reg) noexcept {
    return reg == RISCV_REG_X0;
}

bool is_link_register(unsigned int reg) noexcept {
    return reg == RISCV_REG_X1 || reg == RISCV_REG_X5;
}

std::optional<std::uint8_t> register_operand_index(const cs_riscv& riscv,
                                                    std::uint8_t ordinal) noexcept {
    std::uint8_t seen = 0;
    for (std::uint8_t index = 0; index < riscv.op_count; ++index) {
        if (riscv.operands[index].type != RISCV_OP_REG)
            continue;
        if (seen == ordinal)
            return index;
        ++seen;
    }
    return std::nullopt;
}

std::optional<std::pair<std::uint8_t, std::int64_t>>
    direct_target_operand(const cs_riscv& riscv) noexcept {
    for (std::uint8_t index = 0; index < riscv.op_count; ++index) {
        if (riscv.operands[index].type == RISCV_OP_IMM)
            return std::make_pair(index, riscv.operands[index].imm);
    }
    return std::nullopt;
}

bool jal_is_call(const cs_riscv& riscv) noexcept {
    const auto destination = register_operand_index(riscv, 0);
    return !destination || !is_zero_register(riscv.operands[*destination].reg);
}

bool jalr_is_return(const cs_riscv& riscv) noexcept {
    const auto destination = register_operand_index(riscv, 0);
    const auto base = register_operand_index(riscv, 1);
    if (!destination || !base || !is_zero_register(riscv.operands[*destination].reg) ||
        !is_link_register(riscv.operands[*base].reg)) {
        return false;
    }
    const auto target = direct_target_operand(riscv);
    return target && target->second == 0;
}

bool compressed_jr_is_return(const cs_riscv& riscv) noexcept {
    const auto base = register_operand_index(riscv, 0);
    return base && is_link_register(riscv.operands[*base].reg);
}

struct flow_info_t {
    std::uint32_t flags = flow_none;
    bool call = false;
    bool branch = false;
    bool direct = false;
    bool indirect = false;
    bool return_instruction = false;
};

flow_info_t classify_flow(csh handle,
                          const cs_insn& instruction,
                          const cs_riscv& riscv) noexcept {
    const unsigned int instruction_id = instruction.id;
    const bool group_call = cs_insn_group(handle, &instruction, CS_GRP_CALL);
    const bool group_jump = cs_insn_group(handle, &instruction, CS_GRP_JUMP);
    const bool group_return = cs_insn_group(handle, &instruction, CS_GRP_RET);
    const bool group_interrupt = cs_insn_group(handle, &instruction, CS_GRP_INT);
    const bool group_privileged = cs_insn_group(handle, &instruction, CS_GRP_PRIVILEGE);
    const bool jal = instruction_id == RISCV_INS_JAL;
    const bool jalr = instruction_id == RISCV_INS_JALR;
    const bool compressed_jump = instruction_id == RISCV_INS_C_J;
    const bool compressed_call = instruction_id == RISCV_INS_C_JAL ||
                                 instruction_id == RISCV_INS_C_JALR;
    const bool compressed_jr = instruction_id == RISCV_INS_C_JR;
    const bool interrupt_return = is_interrupt_return(instruction_id) ||
                                  cs_insn_group(handle, &instruction, CS_GRP_IRET);
    const bool return_instruction = interrupt_return || group_return ||
        (jalr && jalr_is_return(riscv)) ||
        (compressed_jr && compressed_jr_is_return(riscv));
    const bool call = !return_instruction &&
        (compressed_call || (jal && jal_is_call(riscv)) ||
         (jalr && jal_is_call(riscv)) ||
         (group_call && !((jal || jalr) && !jal_is_call(riscv))));
    const bool branch = !return_instruction && !call &&
        (is_conditional_branch(instruction_id) || compressed_jump ||
         (jal && !jal_is_call(riscv)) || (jalr && !jal_is_call(riscv)) ||
         compressed_jr || group_jump);
    const bool direct = !return_instruction && is_direct_control_instruction(instruction_id);
    const bool indirect = return_instruction || ((branch || call) && !direct);
    const bool interrupt = group_interrupt || instruction_id == RISCV_INS_ECALL ||
                           is_terminal_interrupt(instruction_id);

    flow_info_t result;
    result.call = call;
    result.branch = branch;
    result.direct = direct;
    result.indirect = indirect;
    result.return_instruction = return_instruction;
    if (interrupt_return) {
        result.flags = flow_interrupt | flow_return | flow_terminal | flow_indirect;
    } else if (return_instruction) {
        result.flags = flow_return | flow_terminal | flow_indirect;
    } else if (call) {
        result.flags = flow_call | flow_fallthrough;
    } else if (branch) {
        result.flags = flow_branch;
        if (is_conditional_branch(instruction_id))
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
    if (group_privileged || interrupt_return)
        result.flags |= flow_privileged;
    return result;
}

std::uint16_t memory_width_bits(unsigned int instruction_id) noexcept {
    switch (instruction_id) {
    case RISCV_INS_LB:
    case RISCV_INS_LBU:
    case RISCV_INS_SB:
        return 8;
    case RISCV_INS_LH:
    case RISCV_INS_LHU:
    case RISCV_INS_SH:
        return 16;
    case RISCV_INS_LW:
    case RISCV_INS_LWU:
    case RISCV_INS_SW:
    case RISCV_INS_FLW:
    case RISCV_INS_FSW:
    case RISCV_INS_LR_W:
    case RISCV_INS_LR_W_AQ:
    case RISCV_INS_LR_W_AQ_RL:
    case RISCV_INS_LR_W_RL:
    case RISCV_INS_SC_W:
    case RISCV_INS_SC_W_AQ:
    case RISCV_INS_SC_W_AQ_RL:
    case RISCV_INS_SC_W_RL:
    case RISCV_INS_C_LW:
    case RISCV_INS_C_LWSP:
    case RISCV_INS_C_SW:
    case RISCV_INS_C_SWSP:
        return 32;
    case RISCV_INS_LD:
    case RISCV_INS_SD:
    case RISCV_INS_FLD:
    case RISCV_INS_FSD:
    case RISCV_INS_LR_D:
    case RISCV_INS_LR_D_AQ:
    case RISCV_INS_LR_D_AQ_RL:
    case RISCV_INS_LR_D_RL:
    case RISCV_INS_SC_D:
    case RISCV_INS_SC_D_AQ:
    case RISCV_INS_SC_D_AQ_RL:
    case RISCV_INS_SC_D_RL:
    case RISCV_INS_C_LD:
    case RISCV_INS_C_LDSP:
    case RISCV_INS_C_SD:
    case RISCV_INS_C_SDSP:
    case RISCV_INS_C_FLD:
    case RISCV_INS_C_FLDSP:
    case RISCV_INS_C_FSD:
    case RISCV_INS_C_FSDSP:
        return 64;
    default:
        break;
    }
    return 0;
}

std::uint8_t register_access(const cs_regs& reads,
                             std::uint8_t read_count,
                             const cs_regs& writes,
                             std::uint8_t write_count,
                             unsigned int reg) noexcept {
    std::uint8_t access = 0;
    for (std::uint8_t index = 0; index < read_count; ++index) {
        if (reads[index] == reg) {
            access |= CS_AC_READ;
            break;
        }
    }
    for (std::uint8_t index = 0; index < write_count; ++index) {
        if (writes[index] == reg) {
            access |= CS_AC_WRITE;
            break;
        }
    }
    return access;
}

workspace_result_t<void> append_target(arch_decode_result_t& output,
                                       target_fact_t target,
                                       const arch_decode_request_t& request) {
    if (output.target_count >= output.targets.size()) {
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::limit_exceeded,
            "RISC-V instruction exceeds Compact IR target capacity", request));
    }
    output.targets[output.target_count++] = std::move(target);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> append_resolved_target(
    arch_decode_result_t& output,
    entity_id_t instruction_id,
    std::uint8_t operand_index,
    std::uint64_t runtime_address,
    target_kind_record_t kind,
    std::uint16_t access_width_bits,
    const arch_decode_request_t& request) {
    target_fact_t target;
    target.instruction_id = instruction_id;
    target.operand_index = operand_index;
    target.target = target_address(request, runtime_address);
    target.kind = kind;
    target.resolution = target_resolution(request, target.target, runtime_address,
                                          target.is_external);
    target.access_width_bits = access_width_bits;
    target.direct = true;
    return append_target(output, std::move(target), request);
}

workspace_result_t<void> append_indirect_target(
    arch_decode_result_t& output,
    entity_id_t instruction_id,
    std::uint8_t operand_index,
    target_kind_record_t kind,
    const arch_decode_request_t& request) {
    target_fact_t target;
    target.instruction_id = instruction_id;
    target.operand_index = operand_index;
    target.kind = kind;
    target.resolution = target_resolution_t::unresolved_indirect;
    return append_target(output, std::move(target), request);
}

workspace_result_t<void> append_fallthrough_target(
    arch_decode_result_t& output,
    entity_id_t instruction_id,
    std::uint8_t instruction_length,
    const arch_decode_request_t& request) {
    std::uint64_t value = 0;
    if (!checked_add_u64(request.address.value, instruction_length, value)) {
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::range_overflow,
            "RISC-V fallthrough address overflowed", request));
    }
    target_fact_t target;
    target.instruction_id = instruction_id;
    target.target = request.address;
    target.target.value = value;
    target.kind = target_kind_record_t::fallthrough;
    target.resolution = request.address.space == address_space_id_t::relative_virtual
        ? target_resolution_t::image_relative : target_resolution_t::image_virtual;
    target.direct = true;
    return append_target(output, std::move(target), request);
}

struct riscv_decoder_impl_t {
    csh handle = 0;
    cs_insn* instruction = nullptr;

    ~riscv_decoder_impl_t() {
        if (instruction != nullptr)
            cs_free(instruction, 1);
        if (handle != 0)
            cs_close(&handle);
    }
};

class riscv_decoder_backend_t final : public arch_decoder_backend_t {
public:
    riscv_decoder_backend_t(arch_decoder_key_t key,
                            cs_mode capstone_mode,
                            std::unique_ptr<riscv_decoder_impl_t> impl) noexcept
        : key_(key), capstone_mode_(capstone_mode), impl_(std::move(impl)) {}

    ~riscv_decoder_backend_t() override = default;

    workspace_result_t<void> decode_one(
        const byte_view_t& view,
        std::uint64_t view_provider_offset,
        const arch_decode_request_t& request,
        arch_decode_result_t& output,
        const arch_decode_control_t& control) override;
    workspace_result_t<std::string> format_decoded(
        const arch_decode_result_t& decoded,
        const arch_decode_control_t& control) override;

private:
    arch_decoder_key_t key_;
    cs_mode capstone_mode_ = CS_MODE_RISCV32;
    std::unique_ptr<riscv_decoder_impl_t> impl_;
};

workspace_result_t<std::unique_ptr<arch_decoder_backend_t>> create_riscv_backend(
    const arch_decoder_key_t& key,
    const cancellation_token_t& cancellation) {
    if (cancellation.stop_requested()) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            stop_error(cancellation, factory_phase));
    }
    auto profile = make_riscv_decoder_profile(key.mode, key.endian);
    if (!profile) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            profile.error());
    }
    auto capstone_mode = capstone_mode_for(key);
    if (!capstone_mode) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            capstone_mode.error());
    }
    auto impl = std::make_unique<riscv_decoder_impl_t>();
    const cs_err open_status = cs_open(CS_ARCH_RISCV, capstone_mode.value(), &impl->handle);
    if (open_status != CS_ERR_OK) {
        auto error = factory_error(workspace_error_code_t::decode_failure,
                                   "Capstone failed to open a RISC-V decoder", key);
        error.provider_status = static_cast<std::int64_t>(open_status);
        error.details.emplace_back("operation", "cs_open");
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            std::move(error));
    }
    if (cancellation.stop_requested()) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            stop_error(cancellation, factory_phase));
    }
    const cs_err detail_status = cs_option(impl->handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (detail_status != CS_ERR_OK) {
        auto error = factory_error(workspace_error_code_t::decode_failure,
                                   "Capstone failed to enable RISC-V detail mode", key);
        error.provider_status = static_cast<std::int64_t>(detail_status);
        error.details.emplace_back("operation", "cs_option.detail");
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            std::move(error));
    }
    impl->instruction = cs_malloc(impl->handle);
    if (impl->instruction == nullptr) {
        const cs_err status = cs_errno(impl->handle);
        auto error = factory_error(workspace_error_code_t::decode_failure,
                                   "Capstone failed to allocate a RISC-V instruction", key);
        error.provider_status = static_cast<std::int64_t>(status);
        error.details.emplace_back("operation", "cs_malloc");
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            std::move(error));
    }
    if (cancellation.stop_requested()) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            stop_error(cancellation, factory_phase));
    }
    std::unique_ptr<arch_decoder_backend_t> backend(
        new riscv_decoder_backend_t(key, capstone_mode.value(), std::move(impl)));
    return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::success(
        std::move(backend));
}

arch_decoder_registration_t make_registration(architecture_id_t architecture,
                                              architecture_mode_t mode,
                                              endian_t endian) {
    arch_decoder_registration_t registration;
    registration.key.architecture = architecture;
    registration.key.mode = mode;
    registration.key.endian = endian;
    registration.key.abi = abi_id_t::unknown;
    registration.key.address_width_bits =
        mode == architecture_mode_t::riscv32 ? 32 : 64;
    registration.limits.minimum_instruction_bytes = minimum_instruction_size;
    registration.limits.maximum_instruction_bytes = maximum_instruction_size;
    registration.limits.instruction_alignment = minimum_instruction_size;
    registration.limits.maximum_operand_facts = maximum_operands;
    registration.limits.maximum_target_facts = maximum_targets;
    registration.limits.maximum_delay_slots = 0;
    registration.implementation_id = "capstone.riscv";
    registration.implementation_version =
        (riscv_decoder_profile_t::capstone_api_major << 32) |
        (riscv_decoder_profile_t::capstone_api_minor << 16) |
        riscv_decoder_profile_t::capstone_version_extra;
    registration.factory = &create_riscv_backend;
    return registration;
}

}

std::array<std::uint8_t, riscv_decoder_profile_t::canonical_byte_count>
    riscv_decoder_profile_t::canonical_bytes() const noexcept {
    std::array<std::uint8_t, canonical_byte_count> bytes{};
    write_u64(bytes, 0, schema_version);
    write_u64(bytes, 8, capstone_api_major);
    write_u64(bytes, 16, capstone_api_minor);
    write_u64(bytes, 24, capstone_version_extra);
    bytes[32] = static_cast<std::uint8_t>(mode);
    bytes[33] = static_cast<std::uint8_t>(endian);
    return bytes;
}

workspace_result_t<riscv_decoder_profile_t>
    make_riscv_decoder_profile(architecture_mode_t mode, endian_t endian) {
    if (!is_riscv_mode(mode) || endian > endian_t::big) {
        return workspace_result_t<riscv_decoder_profile_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "RISC-V decoder profile is invalid", profile_phase));
    }
    riscv_decoder_profile_t profile;
    profile.mode = mode;
    profile.endian = endian;
    return workspace_result_t<riscv_decoder_profile_t>::success(profile);
}

entity_id_t canonical_riscv_decode_claim_id(const address_t& address) noexcept {
    return stable_instruction_id(address);
}

workspace_result_t<void> register_riscv_decoder(arch_decoder_registry_t& registry) {
    const std::array<arch_decoder_registration_t, 8> registrations{{
        make_registration(architecture_id_t::riscv, architecture_mode_t::riscv32,
                          endian_t::little),
        make_registration(architecture_id_t::riscv, architecture_mode_t::riscv32,
                          endian_t::big),
        make_registration(architecture_id_t::riscv, architecture_mode_t::riscv64,
                          endian_t::little),
        make_registration(architecture_id_t::riscv, architecture_mode_t::riscv64,
                          endian_t::big),
        make_registration(architecture_id_t::riscv32, architecture_mode_t::riscv32,
                          endian_t::little),
        make_registration(architecture_id_t::riscv32, architecture_mode_t::riscv32,
                          endian_t::big),
        make_registration(architecture_id_t::riscv64, architecture_mode_t::riscv64,
                          endian_t::little),
        make_registration(architecture_id_t::riscv64, architecture_mode_t::riscv64,
                          endian_t::big)
    }};
    for (const auto& registration : registrations) {
        auto registered = registry.register_decoder(registration);
        if (!registered)
            return registered;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> register_riscv_decoder() {
    return register_riscv_decoder(default_arch_decoder_registry());
}

namespace {

workspace_result_t<void> riscv_decoder_backend_t::decode_one(
    const byte_view_t& view,
    std::uint64_t view_provider_offset,
    const arch_decode_request_t& request,
    arch_decode_result_t& output,
    const arch_decode_control_t& control) {
    output = {};
    auto polled = control.poll();
    if (!polled)
        return polled;
    auto expected_mode = capstone_mode_for(key_);
    if (!expected_mode || expected_mode.value() != capstone_mode_) {
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::integrity_failure,
            "RISC-V decoder worker mode transition is invalid", request));
    }
    if (!key_matches_mode(key_) || request.address.architecture != key_.architecture ||
        request.address.mode != key_.mode || impl_ == nullptr || impl_->handle == 0 ||
        impl_->instruction == nullptr) {
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::invalid_argument,
            "RISC-V decoder request is invalid", request));
    }
    auto data = instruction_bytes(view, view_provider_offset, request);
    if (!data)
        return workspace_result_t<void>::failure(data.error());
    auto runtime_address = effective_runtime_address(request);
    if (!runtime_address)
        return workspace_result_t<void>::failure(runtime_address.error());
    const std::uint8_t* decode_bytes = data.value();
    std::size_t decode_size = request.available_bytes;
    std::uint64_t decode_address = runtime_address.value();
    if (!cs_disasm_iter(impl_->handle, &decode_bytes, &decode_size, &decode_address,
                        impl_->instruction)) {
        return workspace_result_t<void>::failure(capstone_error(
            "cs_disasm_iter", cs_errno(impl_->handle), request));
    }
    polled = control.poll();
    if (!polled)
        return polled;
    const cs_insn& instruction = *impl_->instruction;
    if (instruction.detail == nullptr || instruction.id == RISCV_INS_INVALID ||
        (instruction.size != minimum_instruction_size &&
         instruction.size != maximum_instruction_size) ||
        instruction.size > request.available_bytes ||
        instruction.address != runtime_address.value()) {
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::integrity_failure,
            "Capstone returned invalid RISC-V instruction metadata", request));
    }
    const cs_riscv& riscv = instruction.detail->riscv;
    if (riscv.op_count > maximum_operands) {
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::limit_exceeded,
            "RISC-V instruction exceeds Compact IR operand capacity", request));
    }
    cs_regs reads{};
    cs_regs writes{};
    std::uint8_t read_count = 0;
    std::uint8_t write_count = 0;
    const cs_err register_status = cs_regs_access(impl_->handle, &instruction, reads,
                                                  &read_count, writes, &write_count);
    if (register_status != CS_ERR_OK) {
        return workspace_result_t<void>::failure(capstone_error(
            "cs_regs_access", register_status, request));
    }
    const flow_info_t flow = classify_flow(impl_->handle, instruction, riscv);
    output.instruction.id = stable_instruction_id(request.address);
    output.instruction.address = request.address;
    output.instruction.length = static_cast<std::uint8_t>(instruction.size);
    output.instruction.mnemonic_id = static_cast<std::uint16_t>(instruction.id);
    output.instruction.opcode_id = instruction.id;
    output.instruction.flow_flags = flow.flags;
    output.instruction.provenance = request.provenance;
    output.instruction.confidence = request.confidence;
    output.instruction.coverage = coverage_reason_t::decoded;
    output.instruction.stable_source_id = request.stable_source_id;

    const std::uint16_t width = key_.address_width_bits;
    const std::uint16_t memory_width = memory_width_bits(instruction.id);
    for (std::uint8_t index = 0; index < riscv.op_count; ++index) {
        polled = control.poll();
        if (!polled)
            return polled;
        const auto& operand = riscv.operands[index];
        operand_fact_t fact;
        fact.instruction_id = output.instruction.id;
        fact.operand_index = index;
        fact.decoder_operand_id = static_cast<std::uint8_t>(operand.type);
        fact.access_count = 1;
        fact.address_width_bits = width;
        switch (operand.type) {
        case RISCV_OP_REG:
            fact.kind = operand_kind_t::reg;
            fact.reg = static_cast<std::uint16_t>(operand.reg);
            fact.access = register_access(reads, read_count, writes, write_count,
                                          operand.reg);
            fact.bit_width = width;
            fact.access_width_bits = width;
            break;
        case RISCV_OP_IMM:
            fact.kind = operand_kind_t::immediate;
            fact.signed_value = operand.imm < 0;
            fact.immediate = static_cast<std::uint64_t>(operand.imm);
            fact.bit_width = width;
            fact.access_width_bits = width;
            break;
        case RISCV_OP_MEM:
            fact.kind = operand_kind_t::memory;
            fact.base_reg = static_cast<std::uint16_t>(operand.mem.base);
            fact.displacement = operand.mem.disp;
            fact.has_displacement = operand.mem.disp != 0;
            fact.bit_width = memory_width;
            fact.access_width_bits = memory_width;
            fact.access_width = memory_width == 0
                ? 0 : static_cast<std::uint8_t>(memory_width);
            if (operand.mem.base != RISCV_REG_INVALID)
                fact.address_components |= address_component_base;
            if (fact.has_displacement)
                fact.address_components |= address_component_displacement;
            fact.address_expression = operand.mem.base == RISCV_REG_INVALID
                ? address_expression_kind_t::absolute
                : address_expression_kind_t::base_displacement;
            break;
        default:
            fact.kind = operand_kind_t::none;
            break;
        }
        if (output.operand_count >= output.operands.size()) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::limit_exceeded,
                "RISC-V instruction exceeds Compact IR operand capacity", request));
        }
        const std::uint8_t compact_index = output.operand_count;
        output.operands[output.operand_count++] = fact;
        if (operand.type == RISCV_OP_MEM &&
            (operand.mem.base == RISCV_REG_INVALID ||
             operand.mem.base == RISCV_REG_X0)) {
            const std::uint64_t resolved = zero_base_address(operand.mem.disp,
                                                               key_.address_width_bits);
            auto& stored_fact = output.operands[compact_index];
            stored_fact.has_resolved_expression_value = true;
            stored_fact.resolved_expression_value = resolved;
            auto appended = append_resolved_target(
                output, output.instruction.id, compact_index, resolved,
                target_kind_record_t::data, memory_width, request);
            if (!appended)
                return appended;
        }
    }

    bool direct_control_target = false;
    if (flow.direct) {
        const auto target_operand = direct_target_operand(riscv);
        if (!target_operand) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::integrity_failure,
                "Capstone omitted the RISC-V direct control-flow immediate", request));
        }
        std::uint64_t resolved = 0;
        if (!add_signed_offset(runtime_address.value(), target_operand->second,
                               key_.address_width_bits, resolved)) {
            return workspace_result_t<void>::failure(request_error(
                workspace_error_code_t::range_overflow,
                "RISC-V direct control-flow target overflowed", request));
        }
        const target_kind_record_t kind = flow.call
            ? target_kind_record_t::call : target_kind_record_t::branch;
        auto appended = append_resolved_target(
            output, output.instruction.id, target_operand->first, resolved, kind,
            key_.address_width_bits, request);
        if (!appended)
            return appended;
        direct_control_target = true;
    } else if (flow.indirect) {
        std::optional<std::uint8_t> operand_index;
        if (instruction.id == RISCV_INS_JALR)
            operand_index = register_operand_index(riscv, 1);
        else if (instruction.id == RISCV_INS_C_JR ||
                 instruction.id == RISCV_INS_C_JALR) {
            operand_index = register_operand_index(riscv, 0);
        }
        if (operand_index) {
            const target_kind_record_t kind = flow.call
                ? target_kind_record_t::call : target_kind_record_t::branch;
            auto appended = append_indirect_target(output, output.instruction.id,
                                                   *operand_index, kind, request);
            if (!appended)
                return appended;
        }
    }
    if (flow.call || flow.branch) {
        if (direct_control_target)
            output.instruction.flow_flags |= flow_direct;
        else
            output.instruction.flow_flags |= flow_indirect;
    }
    if ((output.instruction.flow_flags & flow_fallthrough) != 0) {
        auto appended = append_fallthrough_target(output, output.instruction.id,
                                                  output.instruction.length, request);
        if (!appended)
            return appended;
    }
    output.instruction.operand_fact_count = output.operand_count;
    output.instruction.target_fact_count = output.target_count;
    return control.poll();
}

workspace_result_t<std::string> riscv_decoder_backend_t::format_decoded(
    const arch_decode_result_t& decoded,
    const arch_decode_control_t& control) {
    auto current = control.poll();
    if (!current)
        return workspace_result_t<std::string>::failure(current.error());
    if (!impl_ || impl_->handle == 0 || impl_->instruction == nullptr ||
        impl_->instruction->detail == nullptr ||
        impl_->instruction->id == RISCV_INS_INVALID ||
        impl_->instruction->size != decoded.instruction.length ||
        static_cast<std::uint16_t>(impl_->instruction->id) !=
            decoded.instruction.mnemonic_id ||
        static_cast<std::uint32_t>(impl_->instruction->id) !=
            decoded.instruction.opcode_id ||
        impl_->instruction->detail->riscv.op_count != decoded.operand_count) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "RISC-V formatter state does not match compact IR",
                                          "arch_decoder.format");
        error.address = decoded.instruction.address;
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    return combine_format_text(impl_->instruction->mnemonic,
                               sizeof(impl_->instruction->mnemonic),
                               impl_->instruction->op_str,
                               sizeof(impl_->instruction->op_str));
}

}

}
