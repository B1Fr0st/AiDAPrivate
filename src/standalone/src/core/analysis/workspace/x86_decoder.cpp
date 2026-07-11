#include "x86_decoder.hpp"

#include "checked_range.hpp"
#include "live_snapshot_provider.hpp"

#include <Zydis/Zydis.h>
#include <Zycore/Zycore.h>

#include <algorithm>
#include <array>
#include <limits>
#include <type_traits>
#include <utility>

namespace aida::analysis {
namespace {

static_assert(ZYDIS_VERSION == 0x0004000100000000ULL);
static_assert(ZYCORE_VERSION == 0x0001000500020000ULL);
static_assert(ZYDIS_MNEMONIC_MAX_VALUE <= std::numeric_limits<std::uint16_t>::max());
static_assert(ZYDIS_REGISTER_MAX_VALUE <= std::numeric_limits<std::uint16_t>::max());
static_assert(ZYDIS_REGISTER_NONE == 0);
static_assert(sizeof(ZydisOperandActions) <= sizeof(std::uint8_t));
static_assert(std::is_trivially_copyable_v<instruction_record_t>);
static_assert(std::is_trivially_copyable_v<operand_fact_t>);
static_assert(std::is_trivially_copyable_v<target_fact_t>);
static_assert(sizeof(instruction_record_t) <= 96);
static_assert(sizeof(operand_fact_t) <= 96);
static_assert(sizeof(target_fact_t) <= 64);
static_assert(x86_decode_result_t::operand_capacity == ZYDIS_MAX_OPERAND_COUNT);
static_assert(x86_decode_result_t::target_capacity >= ZYDIS_MAX_OPERAND_COUNT + 1);
static_assert(x86_decode_result_t::operand_capacity <= arch_decode_result_t::operand_capacity);
static_assert(x86_decode_result_t::target_capacity <= arch_decode_result_t::target_capacity);

constexpr const char* arch_create_phase = "x86_decoder.create";
constexpr const char* arch_decode_phase = "x86_decoder.decode";
constexpr const char* arch_format_phase = "x86_decoder.format";
constexpr std::uint64_t arch_implementation_version = 0x0004000100000002ULL;

workspace_error_t stop_error(const cancellation_token_t& cancel, const char* phase) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "decoder deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "decoder operation cancelled", phase);
    error.cancellation = true;
    return error;
}

workspace_error_t zydis_error(const char* operation, ZyanStatus status,
                              const address_t& address) {
    auto error = make_workspace_error(workspace_error_code_t::decode_failure,
                                      std::string(operation) + " failed", "x86_decode");
    error.address = address;
    error.provider_status = static_cast<std::int64_t>(status);
    return error;
}

entity_id_t stable_instruction_id(const address_t& address) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    auto feed = [&](std::uint64_t value) {
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

bool is_flow_category(ZydisInstructionCategory category) noexcept {
    return category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_COND_BR ||
           category == ZYDIS_CATEGORY_UNCOND_BR;
}

address_t target_address(const x86_decode_request_t& request,
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

std::uint32_t flow_flags(const ZydisDecodedInstruction& instruction) noexcept {
    std::uint32_t flags = flow_none;
    switch (instruction.meta.category) {
    case ZYDIS_CATEGORY_CALL:
        flags |= flow_call | flow_fallthrough;
        break;
    case ZYDIS_CATEGORY_COND_BR:
        flags |= flow_branch | flow_conditional | flow_fallthrough;
        break;
    case ZYDIS_CATEGORY_UNCOND_BR:
        flags |= flow_branch | flow_terminal;
        break;
    case ZYDIS_CATEGORY_RET:
        flags |= flow_return | flow_terminal | flow_indirect;
        break;
    case ZYDIS_CATEGORY_INTERRUPT:
    case ZYDIS_CATEGORY_SYSCALL:
        flags |= flow_interrupt | flow_fallthrough;
        break;
    case ZYDIS_CATEGORY_SYSRET:
        flags |= flow_interrupt | flow_return | flow_terminal;
        break;
    default:
        flags |= flow_fallthrough;
        break;
    }
    if (instruction.mnemonic == ZYDIS_MNEMONIC_HLT ||
        instruction.mnemonic == ZYDIS_MNEMONIC_UD0 ||
        instruction.mnemonic == ZYDIS_MNEMONIC_UD1 ||
        instruction.mnemonic == ZYDIS_MNEMONIC_UD2)
        flags = flow_terminal;
    if ((instruction.attributes & ZYDIS_ATTRIB_IS_PRIVILEGED) != 0)
        flags |= flow_privileged;
    return flags;
}

workspace_result_t<std::uint64_t> instruction_provider_offset(
    const byte_provider_t& provider, const pe_image_t& image,
    const instruction_record_t& instruction) {
    switch (instruction.address.space) {
    case address_space_id_t::file_offset:
        return workspace_result_t<std::uint64_t>::success(instruction.address.value);
    case address_space_id_t::relative_virtual:
        return image.rva_to_file_offset(instruction.address.value, instruction.length);
    case address_space_id_t::virtual_address: {
        auto rva = image.va_to_rva(instruction.address.value);
        if (!rva)
            return workspace_result_t<std::uint64_t>::failure(rva.error());
        return image.rva_to_file_offset(rva.value(), instruction.length);
    }
    case address_space_id_t::live_virtual: {
        const auto* snapshot = dynamic_cast<const live_snapshot_provider_t*>(&provider);
        if (!snapshot || instruction.address.value < snapshot->metadata().capture_address)
            return workspace_result_t<std::uint64_t>::failure(
                make_workspace_error(workspace_error_code_t::unsupported_address_space,
                                     "live instruction is not backed by this snapshot",
                                     "x86_format"));
        const std::uint64_t offset = instruction.address.value -
                                     snapshot->metadata().capture_address;
        auto range = validate_span(offset, instruction.length, provider.size(), "x86_format");
        if (!range)
            return workspace_result_t<std::uint64_t>::failure(range.error());
        return workspace_result_t<std::uint64_t>::success(offset);
    }
    }
    return workspace_result_t<std::uint64_t>::failure(
        make_workspace_error(workspace_error_code_t::unsupported_address_space,
                             "instruction address space is unsupported", "x86_format"));
}

workspace_result_t<const std::uint8_t*> contained_view_data(
    const byte_view_t& view, std::uint64_t view_provider_offset,
    std::uint64_t requested_provider_offset, std::uint64_t requested_size,
    const char* phase) {
    if (requested_size == 0 || (view.size() != 0 && view.data() == nullptr))
        return workspace_result_t<const std::uint8_t*>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "byte view is invalid", phase));
    std::uint64_t view_end = 0;
    if (!checked_add_u64(view_provider_offset, static_cast<std::uint64_t>(view.size()),
                         view_end)) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "byte view provider range overflowed", phase);
        error.offset = view_provider_offset;
        error.size = view.size();
        return workspace_result_t<const std::uint8_t*>::failure(std::move(error));
    }
    std::uint64_t requested_end = 0;
    if (!checked_add_u64(requested_provider_offset, requested_size, requested_end)) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "instruction provider range overflowed", phase);
        error.offset = requested_provider_offset;
        error.size = requested_size;
        return workspace_result_t<const std::uint8_t*>::failure(std::move(error));
    }
    if (requested_provider_offset < view_provider_offset || requested_end > view_end) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "instruction bytes are outside the supplied view", phase);
        error.offset = requested_provider_offset;
        error.size = requested_size;
        error.details.emplace_back("view_offset", std::to_string(view_provider_offset));
        error.details.emplace_back("view_size", std::to_string(view.size()));
        return workspace_result_t<const std::uint8_t*>::failure(std::move(error));
    }
    const auto relative = requested_provider_offset - view_provider_offset;
    if (relative > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
        return workspace_result_t<const std::uint8_t*>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "instruction view offset exceeds addressable memory", phase));
    return workspace_result_t<const std::uint8_t*>::success(
        view.data() + static_cast<std::size_t>(relative));
}

bool request_matches_mode(const address_t& address, architecture_mode_t mode) noexcept {
    return address.mode == mode &&
           ((mode == architecture_mode_t::x86_64 &&
             address.architecture == architecture_id_t::x86_64) ||
            (mode != architecture_mode_t::x86_64 &&
             address.architecture == architecture_id_t::x86));
}

std::uint32_t decoded_opcode_id(const ZydisDecodedInstruction& decoded) noexcept {
    return (static_cast<std::uint32_t>(decoded.encoding) << 16) |
           (static_cast<std::uint32_t>(decoded.opcode_map) << 8) | decoded.opcode;
}

bool resolvable_memory_operand(const ZydisDecodedOperand& operand) noexcept {
    return operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
           (operand.mem.base == ZYDIS_REGISTER_RIP ||
            operand.mem.base == ZYDIS_REGISTER_EIP ||
            operand.mem.base == ZYDIS_REGISTER_IP ||
            (operand.mem.base == ZYDIS_REGISTER_NONE &&
             operand.mem.index == ZYDIS_REGISTER_NONE));
}

workspace_error_t arch_request_error(workspace_error_code_t code,
                                     const char* message,
                                     const arch_decode_request_t& request,
                                     const char* phase = arch_decode_phase) {
    auto error = make_workspace_error(code, message, phase);
    error.address = request.address;
    error.offset = request.provider_offset;
    error.size = request.available_bytes;
    return error;
}

workspace_result_t<architecture_mode_t> x86_mode_for(
    const arch_decoder_key_t& key) {
    const bool x86_16 = key.architecture == architecture_id_t::x86 &&
                        key.mode == architecture_mode_t::x86_16 &&
                        key.address_width_bits == 16;
    const bool x86_32 = key.architecture == architecture_id_t::x86 &&
                        key.mode == architecture_mode_t::x86_32 &&
                        key.address_width_bits == 32;
    const bool x86_64 = key.architecture == architecture_id_t::x86_64 &&
                        key.mode == architecture_mode_t::x86_64 &&
                        key.address_width_bits == 64;
    if ((!x86_16 && !x86_32 && !x86_64) || key.endian != endian_t::little) {
        return workspace_result_t<architecture_mode_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "x86 decoder key requires a matching little-endian mode",
                                 arch_create_phase));
    }
    return workspace_result_t<architecture_mode_t>::success(key.mode);
}

workspace_result_t<std::uint64_t> runtime_address_for(
    const arch_decode_request_t& request) {
    std::uint64_t runtime_address = request.address.value;
    switch (request.address.space) {
    case address_space_id_t::relative_virtual:
        if (!checked_add_u64(request.image_base, request.address.value, runtime_address)) {
            return workspace_result_t<std::uint64_t>::failure(arch_request_error(
                workspace_error_code_t::range_overflow,
                "x86 instruction runtime address overflowed", request));
        }
        break;
    case address_space_id_t::file_offset:
        if (request.runtime_address == 0) {
            return workspace_result_t<std::uint64_t>::failure(arch_request_error(
                workspace_error_code_t::invalid_argument,
                "x86 file-offset decoding requires a runtime address", request));
        }
        runtime_address = request.runtime_address;
        break;
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        break;
    default:
        return workspace_result_t<std::uint64_t>::failure(arch_request_error(
            workspace_error_code_t::unsupported_address_space,
            "x86 instruction address space is unsupported", request));
    }
    if (request.runtime_address != 0 && request.runtime_address != runtime_address) {
        return workspace_result_t<std::uint64_t>::failure(arch_request_error(
            workspace_error_code_t::invalid_argument,
            "x86 runtime address conflicts with the typed address", request));
    }
    return workspace_result_t<std::uint64_t>::success(runtime_address);
}

bool same_format_instruction(const instruction_record_t& lhs,
                             const instruction_record_t& rhs) noexcept {
    return lhs.id == rhs.id && lhs.address == rhs.address &&
           lhs.length == rhs.length && lhs.mnemonic_id == rhs.mnemonic_id &&
           lhs.opcode_id == rhs.opcode_id && lhs.flow_flags == rhs.flow_flags &&
           lhs.operand_fact_begin == rhs.operand_fact_begin &&
           lhs.operand_fact_count == rhs.operand_fact_count &&
           lhs.target_fact_begin == rhs.target_fact_begin &&
           lhs.target_fact_count == rhs.target_fact_count &&
           lhs.provenance == rhs.provenance && lhs.confidence == rhs.confidence &&
           lhs.coverage == rhs.coverage &&
           lhs.stable_source_id == rhs.stable_source_id;
}

}

std::array<std::uint8_t, x86_decoder_profile_t::canonical_byte_count>
x86_decoder_profile_t::canonical_bytes() const noexcept {
    std::array<std::uint8_t, canonical_byte_count> bytes{};
    const auto write_u64 = [&bytes](std::size_t offset, std::uint64_t value) {
        for (std::size_t index = 0; index < sizeof(value); ++index)
            bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8));
    };
    write_u64(0, schema_version);
    write_u64(8, zydis_version);
    write_u64(16, zycore_version);
    write_u64(24, static_cast<std::uint64_t>(mode));
    write_u64(32, feature_mask);
    return bytes;
}

workspace_result_t<x86_decoder_profile_t>
make_x86_decoder_profile(architecture_mode_t mode) {
    if (mode != architecture_mode_t::x86_16 &&
        mode != architecture_mode_t::x86_32 &&
        mode != architecture_mode_t::x86_64) {
        return workspace_result_t<x86_decoder_profile_t>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_pe_arch,
                                 "x86 decoder mode is unsupported", arch_create_phase));
    }
    x86_decoder_profile_t profile;
    profile.mode = mode;
    return workspace_result_t<x86_decoder_profile_t>::success(std::move(profile));
}

entity_id_t canonical_x86_decode_claim_id(const address_t& address) noexcept {
    return stable_instruction_id(address);
}

struct worker_owned_x86_decoder_t::impl_t {
    architecture_mode_t mode = architecture_mode_t::unknown;
    x86_decoder_profile_t profile;
    ZydisDecoder decoder{};
    ZydisFormatter formatter{};
    std::vector<char> format_buffer;
};

workspace_result_t<std::unique_ptr<worker_owned_x86_decoder_t>>
worker_owned_x86_decoder_t::create(architecture_mode_t mode) {
    auto profile = make_x86_decoder_profile(mode);
    if (!profile)
        return workspace_result_t<std::unique_ptr<worker_owned_x86_decoder_t>>::failure(
            profile.error());
    ZydisMachineMode machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    ZydisStackWidth stack_width = ZYDIS_STACK_WIDTH_64;
    if (mode == architecture_mode_t::x86_16) {
        machine_mode = ZYDIS_MACHINE_MODE_LEGACY_16;
        stack_width = ZYDIS_STACK_WIDTH_16;
    } else if (mode == architecture_mode_t::x86_32) {
        machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
        stack_width = ZYDIS_STACK_WIDTH_32;
    } else if (mode != architecture_mode_t::x86_64) {
        return workspace_result_t<std::unique_ptr<worker_owned_x86_decoder_t>>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_pe_arch,
                                 "x86 decoder mode is unsupported", "x86_decode"));
    }
    auto impl = std::make_unique<impl_t>();
    impl->mode = mode;
    impl->profile = profile.take_value();
    ZyanStatus status = ZydisDecoderInit(&impl->decoder, machine_mode, stack_width);
    if (!ZYAN_SUCCESS(status))
        return workspace_result_t<std::unique_ptr<worker_owned_x86_decoder_t>>::failure(
            zydis_error("ZydisDecoderInit", status,
                        address_t{address_space_id_t::relative_virtual, 0,
                                  mode == architecture_mode_t::x86_64
                                      ? architecture_id_t::x86_64 : architecture_id_t::x86,
                                  mode}));
    status = ZydisFormatterInit(&impl->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    if (!ZYAN_SUCCESS(status))
        return workspace_result_t<std::unique_ptr<worker_owned_x86_decoder_t>>::failure(
            zydis_error("ZydisFormatterInit", status,
                        address_t{address_space_id_t::relative_virtual, 0,
                                  mode == architecture_mode_t::x86_64
                                      ? architecture_id_t::x86_64 : architecture_id_t::x86,
                                  mode}));
    return workspace_result_t<std::unique_ptr<worker_owned_x86_decoder_t>>::success(
        std::unique_ptr<worker_owned_x86_decoder_t>(
            new worker_owned_x86_decoder_t(std::move(impl))));
}

worker_owned_x86_decoder_t::worker_owned_x86_decoder_t(std::unique_ptr<impl_t> impl)
    : impl_(std::move(impl)) {}

worker_owned_x86_decoder_t::~worker_owned_x86_decoder_t() = default;
worker_owned_x86_decoder_t::worker_owned_x86_decoder_t(worker_owned_x86_decoder_t&&) noexcept = default;
worker_owned_x86_decoder_t& worker_owned_x86_decoder_t::operator=(worker_owned_x86_decoder_t&&) noexcept = default;

architecture_mode_t worker_owned_x86_decoder_t::mode() const noexcept {
    return impl_->mode;
}

const x86_decoder_profile_t& worker_owned_x86_decoder_t::profile() const noexcept {
    return impl_->profile;
}

workspace_result_t<void> worker_owned_x86_decoder_t::decode_one(
    const byte_view_t& view, std::uint64_t view_provider_offset,
    const x86_decode_request_t& request, x86_decode_result_t& output,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(stop_error(cancel, "x86_decode"));
    if (!request_matches_mode(request.address, impl_->mode))
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_pe_arch,
                                 "decode request architecture does not match the worker",
                                 "x86_decode"));
    if (request.available_bytes == 0 || request.available_bytes > 15)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "x86 decode byte count must be between 1 and 15",
                                 "x86_decode"));
    if (request.confidence > 100)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "x86 decode confidence exceeds 100", "x86_decode"));
    if (request.provenance > fact_provenance_t::decompiler_feedback)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "x86 decode provenance is invalid", "x86_decode"));
    const std::uint64_t available = request.available_bytes;
    auto data_result = contained_view_data(view, view_provider_offset,
                                           request.provider_offset, available,
                                           "x86_decode");
    if (!data_result)
        return workspace_result_t<void>::failure(data_result.error());
    ZydisDecodedInstruction decoded{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    const ZyanStatus status = ZydisDecoderDecodeFull(&impl_->decoder,
                                                     data_result.value(), available,
                                                     &decoded, operands.data());
    if (!ZYAN_SUCCESS(status))
        return workspace_result_t<void>::failure(
            zydis_error("ZydisDecoderDecodeFull", status, request.address));
    if (decoded.length == 0 || decoded.length > available)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "Zydis returned an invalid instruction length", "x86_decode"));
    std::uint64_t expected_runtime_address = 0;
    if (request.address.space == address_space_id_t::relative_virtual) {
        if (!checked_add_u64(request.image_base, request.address.value,
                             expected_runtime_address))
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "instruction runtime address overflowed", "x86_decode"));
    } else if (request.address.space == address_space_id_t::virtual_address ||
               request.address.space == address_space_id_t::live_virtual) {
        expected_runtime_address = request.address.value;
    } else if (request.address.space == address_space_id_t::file_offset) {
        if (request.runtime_address == 0)
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "file-offset decoding requires a runtime address",
                                     "x86_decode"));
        expected_runtime_address = request.runtime_address;
    } else {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_address_space,
                                 "decode address space is unsupported", "x86_decode"));
    }
    if (request.runtime_address != 0 &&
        request.runtime_address != expected_runtime_address)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decode runtime address conflicts with the typed address",
                                 "x86_decode"));
    const std::uint64_t runtime_address = expected_runtime_address;
    output.instruction = {};
    output.operand_count = 0;
    output.target_count = 0;
    output.instruction.id = stable_instruction_id(request.address);
    output.instruction.address = request.address;
    output.instruction.length = decoded.length;
    output.instruction.mnemonic_id = static_cast<std::uint16_t>(decoded.mnemonic);
    output.instruction.opcode_id = decoded_opcode_id(decoded);
    output.instruction.flow_flags = flow_flags(decoded);
    output.instruction.provenance = request.provenance;
    output.instruction.confidence = request.confidence;
    output.instruction.coverage = coverage_reason_t::decoded;
    output.instruction.stable_source_id = request.stable_source_id;
    bool direct_flow_target = false;
    for (std::uint8_t index = 0; index < decoded.operand_count; ++index) {
        const auto& operand = operands[index];
        operand_fact_t fact;
        fact.instruction_id = output.instruction.id;
        fact.operand_index = index;
        fact.access = static_cast<std::uint8_t>(operand.actions);
        fact.bit_width = operand.size;
        fact.access_width_bits = operand.size;
        switch (operand.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            fact.kind = operand_kind_t::reg;
            fact.reg = static_cast<std::uint16_t>(operand.reg.value);
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            fact.kind = operand_kind_t::memory;
            fact.segment_reg = static_cast<std::uint16_t>(operand.mem.segment);
            fact.base_reg = static_cast<std::uint16_t>(operand.mem.base);
            fact.index_reg = static_cast<std::uint16_t>(operand.mem.index);
            fact.scale = operand.mem.scale;
            fact.displacement = operand.mem.disp.value;
            fact.access_width = static_cast<std::uint8_t>(operand.size);
            if (operand.mem.segment == ZYDIS_REGISTER_FS ||
                operand.mem.segment == ZYDIS_REGISTER_GS) {
                fact.address_expression = address_expression_kind_t::segment_relative;
                fact.address_resolution = target_resolution_t::segment_relative;
            } else if (operand.mem.base == ZYDIS_REGISTER_RIP ||
                       operand.mem.base == ZYDIS_REGISTER_EIP ||
                       operand.mem.base == ZYDIS_REGISTER_IP) {
                fact.address_expression = address_expression_kind_t::instruction_relative;
            } else if (operand.mem.base == ZYDIS_REGISTER_NONE &&
                       operand.mem.index == ZYDIS_REGISTER_NONE) {
                fact.address_expression = address_expression_kind_t::absolute;
            } else if (operand.mem.index != ZYDIS_REGISTER_NONE) {
                fact.address_expression = address_expression_kind_t::base_index_displacement;
            } else {
                fact.address_expression = address_expression_kind_t::base_displacement;
            }
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            fact.kind = operand_kind_t::immediate;
            fact.relative = operand.imm.is_relative != ZYAN_FALSE;
            fact.signed_value = operand.imm.is_signed != ZYAN_FALSE;
            fact.immediate = operand.imm.value.u;
            break;
        case ZYDIS_OPERAND_TYPE_POINTER:
            fact.kind = operand_kind_t::pointer;
            fact.immediate = (static_cast<std::uint64_t>(operand.ptr.segment) << 32) |
                             operand.ptr.offset;
            break;
        default:
            fact.kind = operand_kind_t::none;
            break;
        }
        if (output.operand_count >= output.operands.size())
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "Zydis operand count exceeds the inline result capacity",
                                     "x86_decode"));
        output.operands[output.operand_count++] = fact;
        if ((operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative) ||
            resolvable_memory_operand(operand)) {
            ZyanU64 absolute = 0;
            const ZyanStatus address_status = ZydisCalcAbsoluteAddress(
                &decoded, &operand, runtime_address, &absolute);
            if (ZYAN_SUCCESS(address_status)) {
                target_fact_t target;
                target.instruction_id = output.instruction.id;
                target.target = target_address(request, absolute);
                target.access_width_bits = operand.size;
                if (fact.address_resolution == target_resolution_t::segment_relative) {
                    target.resolution = target_resolution_t::segment_relative;
                } else if (target.target.space == address_space_id_t::relative_virtual) {
                    target.resolution = target_resolution_t::image_relative;
                } else if (request.image_size != 0) {
                    target.resolution = target_resolution_t::external_virtual;
                    target.is_external = true;
                } else {
                    target.resolution = target_resolution_t::image_virtual;
                }
                target.direct = operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
                if (is_flow_category(decoded.meta.category) &&
                    operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    target.kind = decoded.meta.category == ZYDIS_CATEGORY_CALL
                                      ? target_kind_record_t::call
                                      : target_kind_record_t::branch;
                    direct_flow_target = true;
                } else {
                    target.kind = target_kind_record_t::data;
                }
                if (output.target_count >= output.targets.size())
                    return workspace_result_t<void>::failure(
                        make_workspace_error(workspace_error_code_t::integrity_failure,
                                             "decoded target count exceeds the inline result capacity",
                                             "x86_decode"));
                output.targets[output.target_count++] = target;
            }
        }
    }
    if (is_flow_category(decoded.meta.category)) {
        if (direct_flow_target)
            output.instruction.flow_flags |= flow_direct;
        else
            output.instruction.flow_flags |= flow_indirect;
    }
    if ((output.instruction.flow_flags & flow_fallthrough) != 0) {
        std::uint64_t fallthrough_value = 0;
        if (!checked_add_u64(request.address.value, decoded.length, fallthrough_value))
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "instruction fallthrough address overflowed",
                                     "x86_decode"));
        target_fact_t fallthrough;
        fallthrough.instruction_id = output.instruction.id;
        fallthrough.target = request.address;
        fallthrough.target.value = fallthrough_value;
        fallthrough.kind = target_kind_record_t::fallthrough;
        fallthrough.resolution = request.address.space == address_space_id_t::relative_virtual
            ? target_resolution_t::image_relative : target_resolution_t::image_virtual;
        fallthrough.direct = true;
        if (output.target_count >= output.targets.size())
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "decoded target count exceeds the inline result capacity",
                                     "x86_decode"));
        output.targets[output.target_count++] = fallthrough;
    }
    output.instruction.operand_fact_count = output.operand_count;
    output.instruction.target_fact_count = output.target_count;
    return workspace_result_t<void>::success();
}

workspace_result_t<x86_decode_result_t> worker_owned_x86_decoder_t::decode_one(
    const byte_view_t& view, std::uint64_t view_provider_offset,
    const x86_decode_request_t& request,
    const cancellation_token_t& cancel) {
    x86_decode_result_t result;
    auto decoded = decode_one(view, view_provider_offset, request, result, cancel);
    if (!decoded)
        return workspace_result_t<x86_decode_result_t>::failure(decoded.error());
    return workspace_result_t<x86_decode_result_t>::success(std::move(result));
}

workspace_result_t<x86_decode_result_t> worker_owned_x86_decoder_t::decode_one(
    const byte_provider_t& provider, const x86_decode_request_t& request,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<x86_decode_result_t>::failure(stop_error(cancel, "x86_decode"));
    if (request.available_bytes == 0 || request.available_bytes > 15)
        return workspace_result_t<x86_decode_result_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "x86 decode byte count must be between 1 and 15",
                                 "x86_decode"));
    auto lease_result = provider.lease(request.provider_offset,
                                       request.available_bytes, cancel);
    if (!lease_result)
        return workspace_result_t<x86_decode_result_t>::failure(lease_result.error());
    return decode_one(lease_result.value(), request.provider_offset, request, cancel);
}

workspace_result_t<std::string> worker_owned_x86_decoder_t::format_one(
    const std::uint8_t* bytes, std::size_t byte_count,
    std::uint64_t runtime_address,
    const instruction_record_t& instruction,
    const instruction_format_options_t& options,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<std::string>::failure(stop_error(cancel, "x86_format"));
    if (!request_matches_mode(instruction.address, impl_->mode) || instruction.length == 0 ||
        instruction.length > 15 || options.maximum_text_bytes < 32 ||
        options.maximum_text_bytes > 64ULL * 1024ULL || bytes == nullptr ||
        byte_count != instruction.length)
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "instruction formatting request is invalid", "x86_format"));
    if ((instruction.address.space == address_space_id_t::virtual_address ||
         instruction.address.space == address_space_id_t::live_virtual) &&
        runtime_address != instruction.address.value) {
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "formatted runtime address conflicts with the typed address",
                                 "x86_format"));
    }
    if (instruction.address.space == address_space_id_t::file_offset && runtime_address == 0) {
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "file-offset formatting requires a runtime address",
                                 "x86_format"));
    }
    if (instruction.address.space != address_space_id_t::relative_virtual &&
        instruction.address.space != address_space_id_t::file_offset &&
        instruction.address.space != address_space_id_t::virtual_address &&
        instruction.address.space != address_space_id_t::live_virtual) {
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_address_space,
                                 "instruction address space is unsupported", "x86_format"));
    }
    ZydisDecodedInstruction decoded{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    ZyanStatus status = ZydisDecoderDecodeFull(&impl_->decoder, bytes,
                                               instruction.length, &decoded,
                                               operands.data());
    if (!ZYAN_SUCCESS(status))
        return workspace_result_t<std::string>::failure(
            zydis_error("ZydisDecoderDecodeFull", status, instruction.address));
    if (decoded.length != instruction.length || decoded.mnemonic != instruction.mnemonic_id ||
        decoded_opcode_id(decoded) != instruction.opcode_id ||
        decoded.operand_count != instruction.operand_fact_count)
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::file_changed,
                                 "instruction bytes no longer match compact IR", "x86_format"));
    const ZyanUPointer uppercase = options.uppercase ? ZYAN_TRUE : ZYAN_FALSE;
    const ZyanUPointer relative = options.show_relative_addresses ? ZYAN_TRUE : ZYAN_FALSE;
    const std::array<std::pair<ZydisFormatterProperty, ZyanUPointer>, 9> properties{{
        {ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, options.force_segment ? ZYAN_TRUE : ZYAN_FALSE},
        {ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_BRANCHES, relative},
        {ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL, relative},
        {ZYDIS_FORMATTER_PROP_UPPERCASE_PREFIXES, uppercase},
        {ZYDIS_FORMATTER_PROP_UPPERCASE_MNEMONIC, uppercase},
        {ZYDIS_FORMATTER_PROP_UPPERCASE_REGISTERS, uppercase},
        {ZYDIS_FORMATTER_PROP_UPPERCASE_TYPECASTS, uppercase},
        {ZYDIS_FORMATTER_PROP_UPPERCASE_DECORATORS, uppercase},
        {ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, uppercase}
    }};
    for (const auto& property : properties) {
        status = ZydisFormatterSetProperty(&impl_->formatter, property.first, property.second);
        if (!ZYAN_SUCCESS(status))
            return workspace_result_t<std::string>::failure(
                zydis_error("ZydisFormatterSetProperty", status, instruction.address));
    }
    impl_->format_buffer.resize(options.maximum_text_bytes);
    status = ZydisFormatterFormatInstruction(
        &impl_->formatter, &decoded, operands.data(), decoded.operand_count_visible,
        impl_->format_buffer.data(), impl_->format_buffer.size(), runtime_address, nullptr);
    if (!ZYAN_SUCCESS(status))
        return workspace_result_t<std::string>::failure(
            zydis_error("ZydisFormatterFormatInstruction", status, instruction.address));
    const auto terminator = std::find(impl_->format_buffer.begin(),
                                      impl_->format_buffer.end(), '\0');
    if (terminator == impl_->format_buffer.end())
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "formatted instruction exceeded its output limit", "x86_format"));
    return workspace_result_t<std::string>::success(
        std::string(impl_->format_buffer.data(),
                    static_cast<std::size_t>(terminator - impl_->format_buffer.begin())));
}

workspace_result_t<std::string> worker_owned_x86_decoder_t::format_one(
    const byte_view_t& view, std::uint64_t view_provider_offset,
    const byte_provider_t& provider, const pe_image_t& image,
    const instruction_record_t& instruction,
    const instruction_format_options_t& options,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<std::string>::failure(stop_error(cancel, "x86_format"));
    auto offset_result = instruction_provider_offset(provider, image, instruction);
    if (!offset_result)
        return workspace_result_t<std::string>::failure(offset_result.error());
    auto data_result = contained_view_data(view, view_provider_offset,
                                           offset_result.value(), instruction.length,
                                           "x86_format");
    if (!data_result)
        return workspace_result_t<std::string>::failure(data_result.error());
    std::uint64_t runtime_address = instruction.address.value;
    if (instruction.address.space == address_space_id_t::relative_virtual) {
        auto va_result = image.rva_to_va(instruction.address.value);
        if (!va_result)
            return workspace_result_t<std::string>::failure(va_result.error());
        runtime_address = va_result.value();
    } else if (instruction.address.space == address_space_id_t::file_offset) {
        auto rva_result = image.file_offset_to_rva(instruction.address.value,
                                                   instruction.length);
        if (!rva_result)
            return workspace_result_t<std::string>::failure(rva_result.error());
        auto va_result = image.rva_to_va(rva_result.value());
        if (!va_result)
            return workspace_result_t<std::string>::failure(va_result.error());
        runtime_address = va_result.value();
    } else if (instruction.address.space != address_space_id_t::virtual_address &&
               instruction.address.space != address_space_id_t::live_virtual) {
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_address_space,
                                 "instruction address space is unsupported", "x86_format"));
    }
    return format_one(data_result.value(), instruction.length, runtime_address,
                      instruction, options, cancel);
}

workspace_result_t<std::string> worker_owned_x86_decoder_t::format_one(
    const byte_provider_t& provider, const pe_image_t& image,
    const instruction_record_t& instruction,
    const instruction_format_options_t& options,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<std::string>::failure(stop_error(cancel, "x86_format"));
    if (instruction.length == 0 || instruction.length > 15)
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "instruction formatting request is invalid", "x86_format"));
    auto offset_result = instruction_provider_offset(provider, image, instruction);
    if (!offset_result)
        return workspace_result_t<std::string>::failure(offset_result.error());
    auto lease_result = provider.lease(offset_result.value(), instruction.length, cancel);
    if (!lease_result)
        return workspace_result_t<std::string>::failure(lease_result.error());
    return format_one(lease_result.value(), offset_result.value(), provider, image,
                      instruction, options, cancel);
}

namespace {

class x86_decoder_backend_t final : public arch_decoder_backend_t {
public:
    x86_decoder_backend_t(arch_decoder_key_t key,
                          std::unique_ptr<worker_owned_x86_decoder_t> decoder)
        : key_(key), decoder_(std::move(decoder)) {}

    workspace_result_t<void> decode_one(
        const byte_view_t& view,
        std::uint64_t view_provider_offset,
        const arch_decode_request_t& request,
        arch_decode_result_t& output,
        const arch_decode_control_t& control) override {
        output = {};
        format_ready_ = false;
        auto polled = control.poll();
        if (!polled)
            return polled;
        auto mode = x86_mode_for(key_);
        if (!mode) {
            return workspace_result_t<void>::failure(arch_request_error(
                workspace_error_code_t::integrity_failure,
                "x86 decoder worker key is invalid", request));
        }
        if (decoder_ == nullptr || mode.value() != decoder_->mode() ||
            request.address.architecture != key_.architecture ||
            request.address.mode != key_.mode || request.available_bytes == 0 ||
            request.available_bytes > 15) {
            return workspace_result_t<void>::failure(arch_request_error(
                workspace_error_code_t::invalid_argument,
                "x86 decoder request is incompatible with the worker", request));
        }
        auto runtime_address = runtime_address_for(request);
        if (!runtime_address)
            return workspace_result_t<void>::failure(runtime_address.error());
        x86_decode_request_t native_request;
        native_request.address = request.address;
        native_request.provider_offset = request.provider_offset;
        native_request.runtime_address = request.runtime_address;
        native_request.image_base = request.image_base;
        native_request.image_size = request.image_size;
        native_request.available_bytes = static_cast<std::uint8_t>(request.available_bytes);
        native_request.provenance = request.provenance;
        native_request.confidence = request.confidence;
        native_request.stable_source_id = request.stable_source_id;
        x86_decode_result_t decoded;
        auto native = decoder_->decode_one(view, view_provider_offset, native_request,
                                           decoded, control.cancellation());
        if (!native)
            return native;
        polled = control.poll();
        if (!polled)
            return polled;
        if (decoded.operand_count > decoded.operands.size() ||
            decoded.target_count > decoded.targets.size() ||
            decoded.operand_count > output.operands.size() ||
            decoded.target_count > output.targets.size() ||
            decoded.instruction.length == 0 || decoded.instruction.length > 15) {
            return workspace_result_t<void>::failure(arch_request_error(
                workspace_error_code_t::integrity_failure,
                "x86 decoder returned Compact IR outside the registered bounds", request));
        }
        auto bytes = contained_view_data(view, view_provider_offset, request.provider_offset,
                                         decoded.instruction.length, arch_decode_phase);
        if (!bytes)
            return workspace_result_t<void>::failure(bytes.error());
        output.instruction = decoded.instruction;
        output.operand_count = decoded.operand_count;
        output.target_count = decoded.target_count;
        std::copy_n(decoded.operands.begin(), decoded.operand_count, output.operands.begin());
        std::copy_n(decoded.targets.begin(), decoded.target_count, output.targets.begin());
        format_instruction_ = output.instruction;
        format_runtime_address_ = runtime_address.value();
        format_byte_count_ = decoded.instruction.length;
        std::copy_n(bytes.value(), format_byte_count_, format_bytes_.begin());
        format_ready_ = true;
        return control.poll();
    }

protected:
    workspace_result_t<std::string> format_decoded(
        const arch_decode_result_t& decoded,
        const arch_decode_control_t& control) override {
        auto polled = control.poll();
        if (!polled)
            return workspace_result_t<std::string>::failure(polled.error());
        if (!format_ready_ || format_byte_count_ == 0 ||
            format_byte_count_ != decoded.instruction.length ||
            !same_format_instruction(format_instruction_, decoded.instruction)) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                              "x86 formatter state does not match compact IR",
                                              arch_format_phase);
            error.address = decoded.instruction.address;
            return workspace_result_t<std::string>::failure(std::move(error));
        }
        instruction_format_options_t options;
        options.maximum_text_bytes = arch_format_options_t::hard_maximum_text_bytes;
        auto formatted = decoder_->format_one(format_bytes_.data(), format_byte_count_,
                                              format_runtime_address_, decoded.instruction,
                                              options, control.cancellation());
        if (!formatted)
            return formatted;
        polled = control.poll();
        if (!polled)
            return workspace_result_t<std::string>::failure(polled.error());
        return formatted;
    }

private:
    arch_decoder_key_t key_;
    std::unique_ptr<worker_owned_x86_decoder_t> decoder_;
    std::array<std::uint8_t, 15> format_bytes_{};
    instruction_record_t format_instruction_;
    std::uint64_t format_runtime_address_ = 0;
    std::uint8_t format_byte_count_ = 0;
    bool format_ready_ = false;
};

workspace_result_t<std::unique_ptr<arch_decoder_backend_t>> create_x86_backend(
    const arch_decoder_key_t& key,
    const cancellation_token_t& cancellation) {
    if (cancellation.stop_requested()) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            stop_error(cancellation, arch_create_phase));
    }
    auto mode = x86_mode_for(key);
    if (!mode) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            mode.error());
    }
    auto decoder = worker_owned_x86_decoder_t::create(mode.value());
    if (!decoder) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            decoder.error());
    }
    if (cancellation.stop_requested()) {
        return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::failure(
            stop_error(cancellation, arch_create_phase));
    }
    std::unique_ptr<arch_decoder_backend_t> backend(
        new x86_decoder_backend_t(key, decoder.take_value()));
    return workspace_result_t<std::unique_ptr<arch_decoder_backend_t>>::success(
        std::move(backend));
}

arch_decoder_registration_t x86_registration(architecture_mode_t mode) {
    arch_decoder_registration_t registration;
    registration.key.architecture = mode == architecture_mode_t::x86_64
        ? architecture_id_t::x86_64 : architecture_id_t::x86;
    registration.key.mode = mode;
    registration.key.endian = endian_t::little;
    registration.key.abi = abi_id_t::unknown;
    registration.key.address_width_bits = mode == architecture_mode_t::x86_16
        ? 16 : (mode == architecture_mode_t::x86_32 ? 32 : 64);
    registration.limits.minimum_instruction_bytes = 1;
    registration.limits.maximum_instruction_bytes = 15;
    registration.limits.instruction_alignment = 1;
    registration.limits.maximum_operand_facts =
        static_cast<std::uint8_t>(x86_decode_result_t::operand_capacity);
    registration.limits.maximum_target_facts =
        static_cast<std::uint16_t>(x86_decode_result_t::target_capacity);
    registration.limits.maximum_delay_slots = 0;
    registration.implementation_id = mode == architecture_mode_t::x86_64
        ? "zydis.x86_64" : "zydis.x86";
    registration.implementation_version = arch_implementation_version;
    registration.factory = &create_x86_backend;
    return registration;
}

}

workspace_result_t<void> register_x86_decoder_backends(
    arch_decoder_registry_t& registry) {
    const std::array<arch_decoder_registration_t, 3> registrations{{
        x86_registration(architecture_mode_t::x86_16),
        x86_registration(architecture_mode_t::x86_32),
        x86_registration(architecture_mode_t::x86_64)
    }};
    for (const auto& registration : registrations) {
        auto registered = registry.register_decoder(registration);
        if (!registered)
            return registered;
    }
    return workspace_result_t<void>::success();
}

}
