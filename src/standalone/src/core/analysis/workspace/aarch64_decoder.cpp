#include "aarch64_decoder.hpp"

#include "checked_range.hpp"

#include <capstone/capstone.h>

#include <array>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

namespace aida::analysis {
namespace {

constexpr const char* profile_phase = "aarch64_decoder.profile";
constexpr const char* registration_phase = "aarch64_decoder.registration";
constexpr const char* factory_phase = "aarch64_decoder.factory";
constexpr const char* decode_phase = "aarch64_decoder.decode";
constexpr std::uint16_t instruction_size = 4;
constexpr std::uint8_t maximum_operands = 8;
constexpr std::uint16_t maximum_targets = 2;

static_assert(CS_API_MAJOR == aarch64_decoder_profile_t::capstone_api_major);
static_assert(CS_API_MINOR == aarch64_decoder_profile_t::capstone_api_minor);
static_assert(CS_VERSION_EXTRA == aarch64_decoder_profile_t::capstone_version_extra);
static_assert(CS_MODE_LITTLE_ENDIAN == 0);
static_assert(ARM64_REG_INVALID == 0);
static_assert(ARM64_REG_ENDING <= std::numeric_limits<std::uint16_t>::max());
static_assert(ARM64_INS_ENDING <= std::numeric_limits<std::uint16_t>::max());
static_assert(ARM64_OP_SME_INDEX <= std::numeric_limits<std::uint8_t>::max());
static_assert(sizeof(std::declval<cs_arm64_op>().access) <= sizeof(std::uint8_t));
static_assert(std::is_trivially_copyable_v<instruction_record_t>);
static_assert(std::is_trivially_copyable_v<operand_fact_t>);
static_assert(std::is_trivially_copyable_v<target_fact_t>);
static_assert(maximum_operands <= arch_decode_result_t::operand_capacity);
static_assert(maximum_targets <= arch_decode_result_t::target_capacity);

workspace_error_t stop_error(const cancellation_token_t& cancellation,
                             const char* phase) {
    if (cancellation.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "AArch64 decoder deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "AArch64 decoder operation cancelled", phase);
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
                               "Capstone rejected the AArch64 instruction", request);
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

void write_u64(std::array<std::uint8_t, aarch64_decoder_profile_t::canonical_byte_count>& bytes,
               std::size_t offset,
               std::uint64_t value) noexcept {
    for (std::size_t index = 0; index < sizeof(value); ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8));
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
        if (!checked_add_u64(request.image_base, request.address.value, runtime_address))
            return workspace_result_t<std::uint64_t>::failure(request_error(
                workspace_error_code_t::range_overflow,
                "AArch64 runtime address overflowed", request));
        return workspace_result_t<std::uint64_t>::success(runtime_address);
    }
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        return workspace_result_t<std::uint64_t>::success(request.address.value);
    case address_space_id_t::file_offset:
        if (request.runtime_address == 0)
            return workspace_result_t<std::uint64_t>::failure(request_error(
                workspace_error_code_t::invalid_argument,
                "AArch64 file-offset decoding requires a runtime address", request));
        return workspace_result_t<std::uint64_t>::success(request.runtime_address);
    }
    return workspace_result_t<std::uint64_t>::failure(request_error(
        workspace_error_code_t::unsupported_address_space,
        "AArch64 decoder received an unsupported address space", request));
}

workspace_result_t<const std::uint8_t*> instruction_bytes(
    const byte_view_t& view,
    std::uint64_t view_provider_offset,
    const arch_decode_request_t& request) {
    if (request.available_bytes != instruction_size)
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::invalid_argument,
            "AArch64 decoder requires exactly four instruction bytes", request));
    if (view.size() != 0 && view.data() == nullptr)
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::invalid_argument,
            "AArch64 decoder received an invalid byte view", request));
    if (request.provider_offset < view_provider_offset)
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::out_of_range,
            "AArch64 instruction precedes the leased byte view", request));
    const std::uint64_t relative_offset = request.provider_offset - view_provider_offset;
    const std::uint64_t view_size = static_cast<std::uint64_t>(view.size());
    if (relative_offset > view_size ||
        instruction_size > view_size - relative_offset) {
        return workspace_result_t<const std::uint8_t*>::failure(request_error(
            workspace_error_code_t::out_of_range,
            "AArch64 instruction exceeds the leased byte view", request));
    }
    return workspace_result_t<const std::uint8_t*>::success(
        view.data() + static_cast<std::size_t>(relative_offset));
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
                                      bool& is_external) noexcept {
    is_external = false;
    if (target.space == address_space_id_t::relative_virtual)
        return target_resolution_t::image_relative;
    if (request.image_size != 0) {
        is_external = true;
        return target_resolution_t::external_virtual;
    }
    return target_resolution_t::image_virtual;
}

bool is_conditional_branch(const cs_insn& instruction) noexcept {
    switch (instruction.id) {
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
        return true;
    default:
        break;
    }
    if (instruction.detail == nullptr)
        return false;
    const auto condition = instruction.detail->arm64.cc;
    return condition >= ARM64_CC_EQ && condition < ARM64_CC_AL;
}

bool is_pc_relative_data_instruction(unsigned int instruction_id) noexcept {
    return instruction_id == ARM64_INS_ADR || instruction_id == ARM64_INS_ADRP;
}

bool is_terminal_instruction(unsigned int instruction_id) noexcept {
    switch (instruction_id) {
    case ARM64_INS_BRK:
    case ARM64_INS_BRKA:
    case ARM64_INS_BRKAS:
    case ARM64_INS_BRKB:
    case ARM64_INS_BRKBS:
    case ARM64_INS_DCPS1:
    case ARM64_INS_DCPS2:
    case ARM64_INS_DCPS3:
    case ARM64_INS_HLT:
    case ARM64_INS_UDF:
        return true;
    default:
        return false;
    }
}

std::uint32_t flow_flags(csh handle, const cs_insn& instruction) noexcept {
    const bool is_interrupt_return = cs_insn_group(handle, &instruction, CS_GRP_IRET);
    const bool is_return = cs_insn_group(handle, &instruction, CS_GRP_RET);
    const bool is_call = cs_insn_group(handle, &instruction, CS_GRP_CALL);
    const bool is_branch = cs_insn_group(handle, &instruction, CS_GRP_JUMP);
    const bool is_interrupt = cs_insn_group(handle, &instruction, CS_GRP_INT);
    std::uint32_t flags = flow_none;
    if (is_interrupt_return) {
        flags = flow_interrupt | flow_return | flow_terminal | flow_indirect;
    } else if (is_return) {
        flags = flow_return | flow_terminal | flow_indirect;
    } else if (is_call) {
        flags = flow_call | flow_fallthrough;
    } else if (is_branch) {
        flags = flow_branch;
        if (is_conditional_branch(instruction))
            flags |= flow_conditional | flow_fallthrough;
        else
            flags |= flow_terminal;
    } else if (is_interrupt) {
        flags = flow_interrupt | flow_fallthrough;
    } else {
        flags = flow_fallthrough;
    }
    if (is_terminal_instruction(instruction.id))
        flags = flow_terminal | (flags & flow_privileged);
    if (cs_insn_group(handle, &instruction, CS_GRP_PRIVILEGE))
        flags |= flow_privileged;
    return flags;
}

void populate_operand_fact(const cs_arm64_op& operand,
                           std::uint8_t index,
                           entity_id_t instruction_id,
                           operand_fact_t& fact) noexcept {
    fact = {};
    fact.instruction_id = instruction_id;
    fact.operand_index = index;
    fact.decoder_operand_id = static_cast<std::uint8_t>(operand.type);
    fact.access = operand.access;
    switch (operand.type) {
    case ARM64_OP_REG:
    case ARM64_OP_REG_MRS:
    case ARM64_OP_REG_MSR:
        fact.kind = operand_kind_t::reg;
        fact.reg = static_cast<std::uint16_t>(operand.reg);
        break;
    case ARM64_OP_IMM:
    case ARM64_OP_CIMM:
        fact.kind = operand_kind_t::immediate;
        fact.signed_value = operand.imm < 0;
        fact.immediate = static_cast<std::uint64_t>(operand.imm);
        break;
    case ARM64_OP_MEM:
        fact.kind = operand_kind_t::memory;
        fact.base_reg = static_cast<std::uint16_t>(operand.mem.base);
        fact.index_reg = static_cast<std::uint16_t>(operand.mem.index);
        fact.displacement = operand.mem.disp;
        fact.has_displacement = operand.mem.disp != 0;
        fact.address_width_bits = 64;
        if (operand.mem.base != ARM64_REG_INVALID)
            fact.address_components |= address_component_base;
        if (operand.mem.index != ARM64_REG_INVALID) {
            fact.address_components |= address_component_index;
            if (operand.shift.type == ARM64_SFT_LSL && operand.shift.value < 8) {
                fact.scale = static_cast<std::uint8_t>(1U << operand.shift.value);
                fact.address_components |= address_component_scale;
            }
        }
        if (fact.has_displacement)
            fact.address_components |= address_component_displacement;
        if (operand.mem.base == ARM64_REG_INVALID &&
            operand.mem.index == ARM64_REG_INVALID) {
            fact.address_expression = address_expression_kind_t::absolute;
        } else if (operand.mem.index != ARM64_REG_INVALID) {
            fact.address_expression = address_expression_kind_t::base_index_displacement;
        } else {
            fact.address_expression = address_expression_kind_t::base_displacement;
        }
        break;
    default:
        fact.kind = operand_kind_t::none;
        break;
    }
}

workspace_result_t<void> append_operand(arch_decode_result_t& output,
                                        const operand_fact_t& fact,
                                        const arch_decode_request_t& request) {
    if (output.operand_count >= output.operands.size())
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::integrity_failure,
            "AArch64 operand count exceeds the Compact IR capacity", request));
    output.operands[output.operand_count++] = fact;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> append_target(arch_decode_result_t& output,
                                       const target_fact_t& fact,
                                       const arch_decode_request_t& request) {
    if (output.target_count >= output.targets.size())
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::integrity_failure,
            "AArch64 target count exceeds the Compact IR capacity", request));
    output.targets[output.target_count++] = fact;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> append_resolved_target(
    arch_decode_result_t& output,
    entity_id_t instruction_id,
    std::uint8_t operand_index,
    std::uint64_t absolute,
    target_kind_record_t kind,
    const arch_decode_request_t& request) {
    target_fact_t target;
    target.instruction_id = instruction_id;
    target.operand_index = operand_index;
    target.target = target_address(request, absolute);
    target.kind = kind;
    target.resolution = target_resolution(request, target.target, target.is_external);
    target.direct = true;
    return append_target(output, target, request);
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
    return append_target(output, target, request);
}

workspace_result_t<void> append_fallthrough_target(
    arch_decode_result_t& output,
    entity_id_t instruction_id,
    const arch_decode_request_t& request) {
    std::uint64_t value = 0;
    if (!checked_add_u64(request.address.value, instruction_size, value))
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::range_overflow,
            "AArch64 fallthrough address overflowed", request));
    target_fact_t target;
    target.instruction_id = instruction_id;
    target.target = request.address;
    target.target.value = value;
    target.kind = target_kind_record_t::fallthrough;
    target.resolution = request.address.space == address_space_id_t::relative_virtual
        ? target_resolution_t::image_relative : target_resolution_t::image_virtual;
    target.direct = true;
    return append_target(output, target, request);
}

struct aarch64_decoder_impl_t {
    csh handle = 0;
    cs_insn* instruction = nullptr;

    ~aarch64_decoder_impl_t() {
        if (instruction != nullptr)
            cs_free(instruction, 1);
        if (handle != 0)
            cs_close(&handle);
    }
};

class aarch64_decoder_backend_t final : public arch_decoder_backend_t {
public:
    explicit aarch64_decoder_backend_t(std::unique_ptr<aarch64_decoder_impl_t> impl)
        : impl_(std::move(impl)) {}

    ~aarch64_decoder_backend_t() override = default;

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
    std::unique_ptr<aarch64_decoder_impl_t> impl_;
};

workspace_result_t<std::unique_ptr<arch_decoder_backend_t>> create_aarch64_backend(
    const arch_decoder_key_t& key,
    const cancellation_token_t& cancellation) {
    if (cancellation.stop_requested())
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            stop_error(cancellation, factory_phase));
    if (key.architecture != architecture_id_t::aarch64 ||
        key.mode != architecture_mode_t::aarch64 ||
        key.address_width_bits != 64 || key.endian > endian_t::big) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            factory_error(workspace_error_code_t::invalid_argument,
                          "AArch64 decoder factory received an incompatible key", key));
    }
    auto profile = make_aarch64_decoder_profile(key.endian);
    if (!profile)
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            profile.error());
    const cs_mode mode = key.endian == endian_t::big
        ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
    auto impl = std::make_unique<aarch64_decoder_impl_t>();
    const cs_err open_status = cs_open(CS_ARCH_ARM64, mode, &impl->handle);
    if (open_status != CS_ERR_OK) {
        auto error = factory_error(workspace_error_code_t::decode_failure,
                                   "Capstone failed to open an AArch64 decoder", key);
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
                                   "Capstone failed to enable AArch64 detail mode", key);
        error.provider_status = static_cast<std::int64_t>(detail_status);
        error.details.emplace_back("operation", "cs_option.detail");
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            std::move(error));
    }
    impl->instruction = cs_malloc(impl->handle);
    if (impl->instruction == nullptr) {
        const cs_err status = cs_errno(impl->handle);
        auto error = factory_error(workspace_error_code_t::decode_failure,
                                   "Capstone failed to allocate an AArch64 instruction", key);
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
        new aarch64_decoder_backend_t(std::move(impl)));
    return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::success(
        std::move(backend));
}

arch_decoder_registration_t make_registration(endian_t endian) {
    arch_decoder_registration_t registration;
    registration.key.architecture = architecture_id_t::aarch64;
    registration.key.mode = architecture_mode_t::aarch64;
    registration.key.endian = endian;
    registration.key.abi = abi_id_t::unknown;
    registration.key.address_width_bits = 64;
    registration.limits.minimum_instruction_bytes = instruction_size;
    registration.limits.maximum_instruction_bytes = instruction_size;
    registration.limits.instruction_alignment = instruction_size;
    registration.limits.maximum_operand_facts = maximum_operands;
    registration.limits.maximum_target_facts = maximum_targets;
    registration.limits.maximum_delay_slots = 0;
    registration.implementation_id = "capstone.aarch64";
    registration.implementation_version =
        (aarch64_decoder_profile_t::capstone_api_major << 32) |
        (aarch64_decoder_profile_t::capstone_api_minor << 16) |
        aarch64_decoder_profile_t::capstone_version_extra;
    registration.factory = &create_aarch64_backend;
    return registration;
}

}

std::array<std::uint8_t, aarch64_decoder_profile_t::canonical_byte_count>
    aarch64_decoder_profile_t::canonical_bytes() const noexcept {
    std::array<std::uint8_t, canonical_byte_count> bytes{};
    write_u64(bytes, 0, schema_version);
    write_u64(bytes, 8, capstone_api_major);
    write_u64(bytes, 16, capstone_api_minor);
    write_u64(bytes, 24, capstone_version_extra);
    bytes[32] = static_cast<std::uint8_t>(endian);
    return bytes;
}

workspace_result_t<aarch64_decoder_profile_t>
    make_aarch64_decoder_profile(endian_t endian) {
    if (endian > endian_t::big)
        return workspace_result_t<aarch64_decoder_profile_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "AArch64 decoder endian is invalid", profile_phase));
    aarch64_decoder_profile_t profile;
    profile.endian = endian;
    return workspace_result_t<aarch64_decoder_profile_t>::success(profile);
}

entity_id_t canonical_aarch64_decode_claim_id(const address_t& address) noexcept {
    return stable_instruction_id(address);
}

workspace_result_t<void> register_aarch64_decoder(arch_decoder_registry_t& registry) {
    auto little = registry.register_decoder(make_registration(endian_t::little));
    if (!little)
        return little;
    return registry.register_decoder(make_registration(endian_t::big));
}

workspace_result_t<void> register_aarch64_decoder() {
    return register_aarch64_decoder(default_arch_decoder_registry());
}

namespace {

workspace_result_t<void> aarch64_decoder_backend_t::decode_one(
    const byte_view_t& view,
    std::uint64_t view_provider_offset,
    const arch_decode_request_t& request,
    arch_decode_result_t& output,
    const arch_decode_control_t& control) {
    output = {};
    auto current = control.poll();
    if (!current)
        return current;
    auto bytes = instruction_bytes(view, view_provider_offset, request);
    if (!bytes)
        return workspace_result_t<void>::failure(bytes.error());
    auto runtime_address = effective_runtime_address(request);
    if (!runtime_address)
        return workspace_result_t<void>::failure(runtime_address.error());
    const std::uint8_t* code = bytes.value();
    std::size_t remaining = instruction_size;
    std::uint64_t address = runtime_address.value();
    if (!cs_disasm_iter(impl_->handle, &code, &remaining, &address, impl_->instruction)) {
        return workspace_result_t<void>::failure(
            capstone_error("cs_disasm_iter", cs_errno(impl_->handle), request));
    }
    current = control.poll();
    if (!current)
        return current;
    const cs_insn& instruction = *impl_->instruction;
    if (instruction.id == ARM64_INS_INVALID || instruction.detail == nullptr ||
        instruction.address != runtime_address.value() ||
        instruction.size != instruction_size || remaining != 0 ||
        code != bytes.value() + instruction_size) {
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::integrity_failure,
            "Capstone returned an invalid AArch64 instruction shape", request));
    }
    const auto& detail = instruction.detail->arm64;
    if (detail.op_count > maximum_operands) {
        return workspace_result_t<void>::failure(request_error(
            workspace_error_code_t::integrity_failure,
            "Capstone returned too many AArch64 operands", request));
    }
    output.instruction.id = canonical_aarch64_decode_claim_id(request.address);
    output.instruction.address = request.address;
    output.instruction.length = instruction_size;
    output.instruction.mnemonic_id = static_cast<std::uint16_t>(instruction.id);
    output.instruction.opcode_id = instruction.id;
    output.instruction.flow_flags = flow_flags(impl_->handle, instruction);
    output.instruction.provenance = request.provenance;
    output.instruction.confidence = request.confidence;
    output.instruction.coverage = coverage_reason_t::decoded;
    output.instruction.stable_source_id = request.stable_source_id;
    const bool is_call = (output.instruction.flow_flags & flow_call) != 0;
    const bool is_branch = (output.instruction.flow_flags & flow_branch) != 0;
    const bool is_flow = is_call || is_branch;
    bool has_direct_flow_target = false;
    std::uint8_t indirect_operand_index = 0xFFU;
    for (std::uint8_t index = 0; index < detail.op_count; ++index) {
        current = control.poll();
        if (!current)
            return current;
        const auto& operand = detail.operands[index];
        operand_fact_t fact;
        populate_operand_fact(operand, index, output.instruction.id, fact);
        if ((is_flow || is_pc_relative_data_instruction(instruction.id)) &&
            operand.type == ARM64_OP_IMM) {
            fact.relative = true;
        }
        current = append_operand(output, fact, request);
        if (!current)
            return current;
        if (is_flow && operand.type == ARM64_OP_IMM && !has_direct_flow_target) {
            current = append_resolved_target(
                output, output.instruction.id, index,
                static_cast<std::uint64_t>(operand.imm),
                is_call ? target_kind_record_t::call : target_kind_record_t::branch,
                request);
            if (!current)
                return current;
            has_direct_flow_target = true;
        } else if (is_pc_relative_data_instruction(instruction.id) &&
                   operand.type == ARM64_OP_IMM) {
            current = append_resolved_target(
                output, output.instruction.id, index,
                static_cast<std::uint64_t>(operand.imm), target_kind_record_t::data, request);
            if (!current)
                return current;
        }
        if (is_flow && indirect_operand_index == 0xFFU &&
            (operand.type == ARM64_OP_REG || operand.type == ARM64_OP_REG_MRS ||
             operand.type == ARM64_OP_REG_MSR)) {
            indirect_operand_index = index;
        }
    }
    if (is_flow) {
        if (has_direct_flow_target) {
            output.instruction.flow_flags |= flow_direct;
        } else {
            output.instruction.flow_flags |= flow_indirect;
            current = append_indirect_target(
                output, output.instruction.id, indirect_operand_index,
                is_call ? target_kind_record_t::call : target_kind_record_t::branch, request);
            if (!current)
                return current;
        }
    }
    if ((output.instruction.flow_flags & flow_fallthrough) != 0) {
        current = append_fallthrough_target(output, output.instruction.id, request);
        if (!current)
            return current;
    }
    output.instruction.operand_fact_count = output.operand_count;
    output.instruction.target_fact_count = output.target_count;
    return control.poll();
}

workspace_result_t<std::string> aarch64_decoder_backend_t::format_decoded(
    const arch_decode_result_t& decoded,
    const arch_decode_control_t& control) {
    auto current = control.poll();
    if (!current)
        return workspace_result_t<std::string>::failure(current.error());
    if (!impl_ || impl_->handle == 0 || impl_->instruction == nullptr ||
        impl_->instruction->detail == nullptr ||
        impl_->instruction->id == ARM64_INS_INVALID ||
        impl_->instruction->size != decoded.instruction.length ||
        static_cast<std::uint16_t>(impl_->instruction->id) !=
            decoded.instruction.mnemonic_id ||
        static_cast<std::uint32_t>(impl_->instruction->id) !=
            decoded.instruction.opcode_id ||
        impl_->instruction->detail->arm64.op_count != decoded.operand_count) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "AArch64 formatter state does not match compact IR",
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
