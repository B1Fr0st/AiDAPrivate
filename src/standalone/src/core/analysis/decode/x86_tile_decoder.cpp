#include "x86_tile_decoder.hpp"

#include "../workspace/checked_range.hpp"

#include <Zydis/Zydis.h>
#include <Zycore/Zycore.h>

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <string>
#include <utility>

namespace aida::analysis::decode {
namespace {

static_assert(ZYDIS_VERSION == 0x0004000100000000ULL);
static_assert(ZYCORE_VERSION == 0x0001000500020000ULL);
static_assert(ZYDIS_MAX_OPERAND_COUNT == 10);
static_assert(ZYDIS_MNEMONIC_MAX_VALUE <= std::numeric_limits<std::uint16_t>::max());
static_assert(ZYDIS_REGISTER_MAX_VALUE <= std::numeric_limits<std::uint16_t>::max());
static_assert(sizeof(ZydisOperandActions) <= sizeof(std::uint8_t));

constexpr const char* tile_phase = "x86_tile_decode";
constexpr std::uint64_t instruction_domain = 0x78493634696E7374ULL;
constexpr std::uint64_t operand_domain = 0x784936346F706E64ULL;
constexpr std::uint64_t expression_domain = 0x7849363465787072ULL;
constexpr std::size_t initial_instruction_reserve = 4096;
constexpr std::size_t initial_operands_per_instruction = 3;
constexpr std::size_t initial_targets_per_instruction = 2;
constexpr std::size_t initial_coverage_reserve = 1024;

class active_decode_guard_t final {
public:
    explicit active_decode_guard_t(std::atomic_flag& flag) noexcept : flag_(flag) {}
    ~active_decode_guard_t() { flag_.clear(std::memory_order_release); }

    active_decode_guard_t(const active_decode_guard_t&) = delete;
    active_decode_guard_t& operator=(const active_decode_guard_t&) = delete;

private:
    std::atomic_flag& flag_;
};

workspace_error_t make_tile_error(workspace_error_code_t code, std::string message,
                                  const x86_tile_decode_request_t& request) {
    auto error = make_workspace_error(code, std::move(message), tile_phase);
    error.address = request.start_address;
    error.offset = request.provider_offset;
    error.size = request.byte_count;
    return error;
}

workspace_error_t stop_error(const cancellation_token_t& cancel,
                             const x86_tile_decode_request_t& request) {
    auto error = make_tile_error(cancel.deadline_exceeded()
                                     ? workspace_error_code_t::deadline_exceeded
                                     : workspace_error_code_t::cancelled,
                                 cancel.deadline_exceeded()
                                     ? "x86 tile decode deadline exceeded"
                                     : "x86 tile decode cancelled",
                                 request);
    error.cancellation = !cancel.deadline_exceeded();
    error.deadline = cancel.deadline_exceeded();
    return error;
}

workspace_error_t limit_error(const char* resource, std::uint64_t limit,
                              std::uint64_t used, std::uint64_t requested,
                              const x86_tile_decode_request_t& request) {
    auto error = make_tile_error(workspace_error_code_t::limit_exceeded,
                                 "x86 tile decode resource limit exceeded", request);
    error.details.emplace_back("resource", resource);
    error.details.emplace_back("limit", std::to_string(limit));
    error.details.emplace_back("used", std::to_string(used));
    error.details.emplace_back("requested", std::to_string(requested));
    return error;
}

bool mode_matches_address(architecture_mode_t mode, const address_t& address) noexcept {
    if (mode == architecture_mode_t::x86_64)
        return address.architecture == architecture_id_t::x86_64 &&
               address.mode == architecture_mode_t::x86_64;
    return (mode == architecture_mode_t::x86_16 || mode == architecture_mode_t::x86_32) &&
           address.architecture == architecture_id_t::x86 && address.mode == mode;
}

workspace_result_t<void> validate_limits(const x86_tile_decode_limits_t& limits,
                                         const x86_tile_decode_request_t& request) {
    const bool invalid = limits.maximum_window_bytes == 0 ||
                         limits.maximum_window_bytes > x86_tile_decode_limits_t::hard_maximum_window_bytes ||
                         limits.maximum_decode_attempts == 0 ||
                         limits.maximum_decode_attempts > x86_tile_decode_limits_t::hard_maximum_decode_attempts ||
                         limits.maximum_instructions == 0 ||
                         limits.maximum_instructions > x86_tile_decode_limits_t::hard_maximum_instructions ||
                         limits.maximum_operand_facts == 0 ||
                         limits.maximum_operand_facts > x86_tile_decode_limits_t::hard_maximum_operand_facts ||
                         limits.maximum_target_facts == 0 ||
                         limits.maximum_target_facts > x86_tile_decode_limits_t::hard_maximum_target_facts ||
                         limits.maximum_invalid_bytes == 0 ||
                         limits.maximum_invalid_bytes > x86_tile_decode_limits_t::hard_maximum_invalid_bytes ||
                         limits.maximum_coverage_spans == 0 ||
                         limits.maximum_coverage_spans > x86_tile_decode_limits_t::hard_maximum_coverage_spans ||
                         limits.maximum_decode_attempts > limits.maximum_window_bytes ||
                         limits.maximum_invalid_bytes > limits.maximum_window_bytes ||
                         limits.maximum_coverage_spans > limits.maximum_invalid_bytes ||
                         limits.maximum_operand_facts > limits.maximum_instructions * ZYDIS_MAX_OPERAND_COUNT ||
                         limits.maximum_target_facts > limits.maximum_instructions *
                                                       (ZYDIS_MAX_OPERAND_COUNT + 1ULL);
    if (invalid) {
        return workspace_result_t<void>::failure(make_tile_error(
            workspace_error_code_t::invalid_argument,
            "x86 tile decode limits are invalid", request));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::uint64_t> runtime_start_for(
    const x86_tile_decode_request_t& request) {
    std::uint64_t runtime = 0;
    switch (request.start_address.space) {
    case address_space_id_t::relative_virtual:
        if (!checked_add_u64(request.image_base, request.start_address.value, runtime)) {
            return workspace_result_t<std::uint64_t>::failure(make_tile_error(
                workspace_error_code_t::range_overflow,
                "x86 tile runtime address overflowed", request));
        }
        break;
    case address_space_id_t::file_offset:
        if (request.runtime_address == 0) {
            return workspace_result_t<std::uint64_t>::failure(make_tile_error(
                workspace_error_code_t::invalid_argument,
                "x86 file-offset tile requires a runtime address", request));
        }
        runtime = request.runtime_address;
        break;
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        runtime = request.start_address.value;
        break;
    default:
        return workspace_result_t<std::uint64_t>::failure(make_tile_error(
            workspace_error_code_t::unsupported_address_space,
            "x86 tile address space is unsupported", request));
    }
    if (request.runtime_address != 0 && request.runtime_address != runtime) {
        return workspace_result_t<std::uint64_t>::failure(make_tile_error(
            workspace_error_code_t::invalid_argument,
            "x86 tile runtime address conflicts with its typed address", request));
    }
    return workspace_result_t<std::uint64_t>::success(runtime);
}

entity_id_t stable_entity_id(std::uint64_t domain, std::uint64_t first,
                             std::uint64_t second) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    const auto feed = [&hash](std::uint64_t value) {
        for (std::size_t index = 0; index < sizeof(value); ++index) {
            hash ^= static_cast<std::uint8_t>(value >> (index * 8));
            hash *= 1099511628211ULL;
        }
    };
    feed(domain);
    feed(first);
    feed(second);
    return hash == 0 ? 1 : hash;
}

entity_id_t stable_instruction_id(const address_t& address) noexcept {
    return stable_entity_id(instruction_domain,
                            (static_cast<std::uint64_t>(address.space) << 56) |
                                (static_cast<std::uint64_t>(address.architecture) << 48) |
                                (static_cast<std::uint64_t>(address.mode) << 40),
                            address.value);
}

bool flow_category(const ZydisInstructionCategory category) noexcept {
    return category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_COND_BR ||
           category == ZYDIS_CATEGORY_UNCOND_BR;
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
        instruction.mnemonic == ZYDIS_MNEMONIC_UD2) {
        flags = flow_terminal;
    }
    if ((instruction.attributes & ZYDIS_ATTRIB_IS_PRIVILEGED) != 0)
        flags |= flow_privileged;
    return flags;
}

address_t relocatable_target_address(const x86_tile_decode_request_t& request,
                                     std::uint64_t absolute) noexcept {
    address_t target = request.start_address;
    if (request.start_address.space == address_space_id_t::relative_virtual) {
        std::uint64_t image_end = 0;
        const bool bounded_image = request.image_size != 0 &&
                                   checked_add_u64(request.image_base, request.image_size,
                                                   image_end);
        if (absolute >= request.image_base && (!bounded_image || absolute < image_end)) {
            target.value = absolute - request.image_base;
        } else {
            target.space = address_space_id_t::virtual_address;
            target.value = absolute;
        }
    } else if (request.start_address.space == address_space_id_t::file_offset) {
        target.space = address_space_id_t::virtual_address;
        target.value = absolute;
    } else {
        target.value = absolute;
    }
    return target;
}

std::uint32_t opcode_id(const ZydisDecodedInstruction& instruction) noexcept {
    return (static_cast<std::uint32_t>(instruction.encoding) << 16) |
           (static_cast<std::uint32_t>(instruction.opcode_map) << 8) |
           instruction.opcode;
}

bool resolvable_memory_operand(const ZydisDecodedOperand& operand) noexcept {
    return operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
           (operand.mem.base == ZYDIS_REGISTER_RIP ||
            operand.mem.base == ZYDIS_REGISTER_EIP ||
            operand.mem.base == ZYDIS_REGISTER_IP ||
            (operand.mem.base == ZYDIS_REGISTER_NONE &&
             operand.mem.index == ZYDIS_REGISTER_NONE));
}

workspace_result_t<void> append_target(x86_tile_decode_result_t& output,
                                       const target_fact_t& target,
                                       const x86_tile_decode_request_t& request) {
    if (output.target_facts.size() >= request.limits.maximum_target_facts) {
        return workspace_result_t<void>::failure(limit_error(
            "target_facts", request.limits.maximum_target_facts,
            output.target_facts.size(), 1, request));
    }
    output.target_facts.push_back(target);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> append_decoded_instruction(
    x86_tile_decode_result_t& output, const x86_tile_decode_request_t& request,
    const address_t& address, std::uint64_t runtime_address,
    const ZydisDecodedInstruction& decoded,
    const std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT>& decoded_operands) {
    if (output.instructions.size() >= request.limits.maximum_instructions) {
        return workspace_result_t<void>::failure(limit_error(
            "instructions", request.limits.maximum_instructions,
            output.instructions.size(), 1, request));
    }
    if (decoded.operand_count > ZYDIS_MAX_OPERAND_COUNT || decoded.length == 0 ||
        decoded.length > 15 || output.operand_facts.size() >
        std::numeric_limits<std::uint32_t>::max() || output.target_facts.size() >
        std::numeric_limits<std::uint32_t>::max()) {
        return workspace_result_t<void>::failure(make_tile_error(
            workspace_error_code_t::integrity_failure,
            "Zydis returned an invalid x86 tile record", request));
    }

    instruction_record_t instruction{};
    instruction.id = stable_instruction_id(address);
    instruction.address = address;
    instruction.length = decoded.length;
    instruction.mnemonic_id = static_cast<std::uint16_t>(decoded.mnemonic);
    instruction.opcode_id = opcode_id(decoded);
    instruction.flow_flags = flow_flags(decoded);
    instruction.operand_fact_begin = static_cast<std::uint32_t>(output.operand_facts.size());
    instruction.target_fact_begin = static_cast<std::uint32_t>(output.target_facts.size());
    instruction.provenance = request.provenance;
    instruction.confidence = request.confidence;
    instruction.coverage = coverage_reason_t::decoded;
    instruction.stable_source_id = request.stable_source_id;

    bool direct_flow_target = false;
    for (std::uint8_t index = 0; index < decoded.operand_count; ++index) {
        if (output.operand_facts.size() >= request.limits.maximum_operand_facts) {
            return workspace_result_t<void>::failure(limit_error(
                "operand_facts", request.limits.maximum_operand_facts,
                output.operand_facts.size(), 1, request));
        }

        const auto& operand = decoded_operands[index];
        operand_fact_t fact{};
        fact.id = stable_entity_id(operand_domain, instruction.id, operand.id);
        fact.instruction_id = instruction.id;
        fact.operand_index = index;
        fact.decoder_operand_id = operand.id;
        fact.access = static_cast<std::uint8_t>(operand.actions);
        fact.visibility = static_cast<std::uint8_t>(operand.visibility);
        fact.encoding = static_cast<std::uint8_t>(operand.encoding);
        fact.bit_width = operand.size;
        fact.access_width = static_cast<std::uint8_t>((std::min)(
            static_cast<std::uint16_t>(operand.size / 8),
            static_cast<std::uint16_t>(std::numeric_limits<std::uint8_t>::max())));
        fact.access_width_bits = operand.size;
        fact.access_count = operand.element_count;
        fact.element_width_bits = static_cast<std::uint16_t>(operand.element_size);
        fact.element_count = operand.element_count;
        fact.address_width_bits = decoded.address_width;

        switch (operand.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            fact.kind = operand_kind_t::reg;
            fact.reg = static_cast<std::uint16_t>(operand.reg.value);
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            fact.kind = operand_kind_t::memory;
            fact.memory_type = static_cast<std::uint8_t>(operand.mem.type);
            fact.segment_reg = static_cast<std::uint16_t>(operand.mem.segment);
            fact.base_reg = static_cast<std::uint16_t>(operand.mem.base);
            fact.index_reg = static_cast<std::uint16_t>(operand.mem.index);
            fact.scale = operand.mem.scale;
            fact.has_displacement = operand.mem.disp.has_displacement != ZYAN_FALSE;
            fact.displacement = operand.mem.disp.value;
            if (operand.mem.segment != ZYDIS_REGISTER_NONE)
                fact.address_components |= address_component_segment;
            if (operand.mem.base != ZYDIS_REGISTER_NONE)
                fact.address_components |= address_component_base;
            if (operand.mem.index != ZYDIS_REGISTER_NONE) {
                fact.address_components |= address_component_index;
                if (operand.mem.scale != 0)
                    fact.address_components |= address_component_scale;
            }
            if (fact.has_displacement)
                fact.address_components |= address_component_displacement;
            if (operand.mem.segment == ZYDIS_REGISTER_FS ||
                operand.mem.segment == ZYDIS_REGISTER_GS) {
                fact.address_expression = address_expression_kind_t::segment_relative;
                fact.address_resolution = target_resolution_t::segment_relative;
            } else if (operand.mem.base == ZYDIS_REGISTER_RIP ||
                       operand.mem.base == ZYDIS_REGISTER_EIP ||
                       operand.mem.base == ZYDIS_REGISTER_IP) {
                fact.address_expression = address_expression_kind_t::instruction_relative;
                fact.address_components |= address_component_instruction_pointer;
            } else if (operand.mem.base == ZYDIS_REGISTER_NONE &&
                       operand.mem.index == ZYDIS_REGISTER_NONE) {
                fact.address_expression = address_expression_kind_t::absolute;
            } else if (operand.mem.index != ZYDIS_REGISTER_NONE) {
                fact.address_expression = address_expression_kind_t::base_index_displacement;
            } else {
                fact.address_expression = address_expression_kind_t::base_displacement;
            }
            fact.address_expression_id = stable_entity_id(
                expression_domain, instruction.id, operand.id);
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

        output.operand_facts.push_back(fact);
        auto& normalized = output.operand_facts.back();
        if ((operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
             operand.imm.is_relative != ZYAN_FALSE) ||
            resolvable_memory_operand(operand)) {
            ZyanU64 absolute = 0;
            const ZyanStatus address_status = ZydisCalcAbsoluteAddress(
                &decoded, &operand, runtime_address, &absolute);
            if (ZYAN_SUCCESS(address_status)) {
                normalized.has_resolved_expression_value = true;
                normalized.resolved_expression_value = absolute;
                target_fact_t target{};
                target.instruction_id = instruction.id;
                target.operand_fact_id = normalized.id;
                target.address_expression_id = normalized.address_expression_id;
                target.target = relocatable_target_address(request, absolute);
                target.operand_index = index;
                target.access_width_bits = operand.size;
                target.access_count = operand.element_count;
                if (normalized.address_resolution == target_resolution_t::segment_relative) {
                    target.resolution = target_resolution_t::segment_relative;
                } else if (target.target.space == address_space_id_t::relative_virtual) {
                    target.resolution = target_resolution_t::image_relative;
                } else if (request.image_size != 0) {
                    target.resolution = target_resolution_t::external_virtual;
                    target.is_external = true;
                } else {
                    target.resolution = target_resolution_t::image_virtual;
                }
                normalized.address_resolution = target.resolution;
                target.direct = operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
                if (flow_category(decoded.meta.category) &&
                    operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    target.kind = decoded.meta.category == ZYDIS_CATEGORY_CALL
                                      ? target_kind_record_t::call
                                      : target_kind_record_t::branch;
                    direct_flow_target = true;
                } else {
                    target.kind = target_kind_record_t::data;
                }
                auto appended = append_target(output, target, request);
                if (!appended)
                    return appended;
            }
        }
    }

    if (flow_category(decoded.meta.category)) {
        if (direct_flow_target)
            instruction.flow_flags |= flow_direct;
        else
            instruction.flow_flags |= flow_indirect;
    }
    if ((instruction.flow_flags & flow_fallthrough) != 0) {
        std::uint64_t fallthrough_value = 0;
        if (!checked_add_u64(address.value, decoded.length, fallthrough_value)) {
            return workspace_result_t<void>::failure(make_tile_error(
                workspace_error_code_t::range_overflow,
                "x86 tile fallthrough address overflowed", request));
        }
        target_fact_t fallthrough{};
        fallthrough.instruction_id = instruction.id;
        fallthrough.target = address;
        fallthrough.target.value = fallthrough_value;
        fallthrough.kind = target_kind_record_t::fallthrough;
        fallthrough.resolution = address.space == address_space_id_t::relative_virtual
            ? target_resolution_t::image_relative : target_resolution_t::image_virtual;
        fallthrough.direct = true;
        auto appended = append_target(output, fallthrough, request);
        if (!appended)
            return appended;
    }

    const std::uint64_t operand_count = output.operand_facts.size() -
                                        instruction.operand_fact_begin;
    const std::uint64_t target_count = output.target_facts.size() -
                                       instruction.target_fact_begin;
    if (operand_count > std::numeric_limits<std::uint16_t>::max() ||
        target_count > std::numeric_limits<std::uint16_t>::max()) {
        return workspace_result_t<void>::failure(make_tile_error(
            workspace_error_code_t::integrity_failure,
            "x86 tile record count exceeded compact IR capacity", request));
    }
    instruction.operand_fact_count = static_cast<std::uint16_t>(operand_count);
    instruction.target_fact_count = static_cast<std::uint16_t>(target_count);
    output.instructions.push_back(instruction);
    return workspace_result_t<void>::success();
}

}

struct worker_owned_x86_tile_decoder_t::impl_t {
    architecture_mode_t mode = architecture_mode_t::unknown;
    ZydisDecoder decoder{};
};

workspace_result_t<std::unique_ptr<worker_owned_x86_tile_decoder_t>>
worker_owned_x86_tile_decoder_t::create(architecture_mode_t mode) {
    ZydisMachineMode machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    ZydisStackWidth stack_width = ZYDIS_STACK_WIDTH_64;
    if (mode == architecture_mode_t::x86_16) {
        machine_mode = ZYDIS_MACHINE_MODE_LEGACY_16;
        stack_width = ZYDIS_STACK_WIDTH_16;
    } else if (mode == architecture_mode_t::x86_32) {
        machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
        stack_width = ZYDIS_STACK_WIDTH_32;
    } else if (mode != architecture_mode_t::x86_64) {
        return workspace_result_t<std::unique_ptr<worker_owned_x86_tile_decoder_t>>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_pe_arch,
                                 "x86 tile decoder mode is unsupported", tile_phase));
    }
    try {
        auto impl = std::make_unique<impl_t>();
        impl->mode = mode;
        const ZyanStatus status = ZydisDecoderInit(&impl->decoder, machine_mode, stack_width);
        if (!ZYAN_SUCCESS(status)) {
            auto error = make_workspace_error(workspace_error_code_t::decode_failure,
                                              "ZydisDecoderInit failed", tile_phase);
            error.provider_status = static_cast<std::int64_t>(status);
            return workspace_result_t<std::unique_ptr<worker_owned_x86_tile_decoder_t>>::failure(
                std::move(error));
        }
        return workspace_result_t<std::unique_ptr<worker_owned_x86_tile_decoder_t>>::success(
            std::unique_ptr<worker_owned_x86_tile_decoder_t>(
                new worker_owned_x86_tile_decoder_t(std::move(impl))));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::unique_ptr<worker_owned_x86_tile_decoder_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "x86 tile decoder allocation failed", tile_phase));
    }
}

worker_owned_x86_tile_decoder_t::worker_owned_x86_tile_decoder_t(
    std::unique_ptr<impl_t> impl)
    : impl_(std::move(impl)) {}

worker_owned_x86_tile_decoder_t::~worker_owned_x86_tile_decoder_t() = default;

architecture_mode_t worker_owned_x86_tile_decoder_t::mode() const noexcept {
    return impl_->mode;
}

workspace_result_t<x86_tile_decode_result_t>
worker_owned_x86_tile_decoder_t::decode_tile(
    const provider_snapshot_t& snapshot, const x86_tile_decode_request_t& request,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested()) {
        return workspace_result_t<x86_tile_decode_result_t>::failure(stop_error(cancel, request));
    }
    if (active_.test_and_set(std::memory_order_acquire)) {
        return workspace_result_t<x86_tile_decode_result_t>::failure(make_tile_error(
            workspace_error_code_t::analysis_in_progress,
            "x86 tile decoder is already active on another worker operation", request));
    }
    active_decode_guard_t active_guard(active_);
    if (request.byte_count == 0 || request.confidence > 100 ||
        request.provenance > fact_provenance_t::decompiler_feedback ||
        !mode_matches_address(impl_->mode, request.start_address)) {
        return workspace_result_t<x86_tile_decode_result_t>::failure(make_tile_error(
            workspace_error_code_t::invalid_argument,
            "x86 tile decode request is invalid for this worker", request));
    }
    auto limits = validate_limits(request.limits, request);
    if (!limits)
        return workspace_result_t<x86_tile_decode_result_t>::failure(limits.error());
    if (request.byte_count > request.limits.maximum_window_bytes) {
        return workspace_result_t<x86_tile_decode_result_t>::failure(limit_error(
            "window_bytes", request.limits.maximum_window_bytes, 0, request.byte_count, request));
    }
    if (request.provider_offset > snapshot.size() ||
        request.byte_count > snapshot.size() - request.provider_offset) {
        return workspace_result_t<x86_tile_decode_result_t>::failure(make_tile_error(
            workspace_error_code_t::out_of_range,
            "x86 tile window exceeds its provider snapshot", request));
    }
    if (request.start_address.space == address_space_id_t::relative_virtual &&
        request.image_size != 0 &&
        (request.start_address.value > request.image_size ||
         request.byte_count > request.image_size - request.start_address.value)) {
        return workspace_result_t<x86_tile_decode_result_t>::failure(make_tile_error(
            workspace_error_code_t::out_of_range,
            "x86 tile range exceeds the relocatable image", request));
    }
    auto runtime_start = runtime_start_for(request);
    if (!runtime_start)
        return workspace_result_t<x86_tile_decode_result_t>::failure(runtime_start.error());
    auto source_valid = snapshot.validate_source();
    if (!source_valid)
        return workspace_result_t<x86_tile_decode_result_t>::failure(source_valid.error());
    if (cancel.stop_requested()) {
        return workspace_result_t<x86_tile_decode_result_t>::failure(stop_error(cancel, request));
    }
    const std::uint64_t contiguous = snapshot.maximum_contiguous_lease(request.provider_offset);
    if (contiguous < request.byte_count) {
        return workspace_result_t<x86_tile_decode_result_t>::failure(limit_error(
            "snapshot_contiguous_window", contiguous, 0, request.byte_count, request));
    }
    auto window = snapshot.lease(request.provider_offset, request.byte_count, cancel);
    if (!window)
        return workspace_result_t<x86_tile_decode_result_t>::failure(window.error());
    if (window.value().size() != request.byte_count || window.value().data() == nullptr) {
        return workspace_result_t<x86_tile_decode_result_t>::failure(make_tile_error(
            workspace_error_code_t::integrity_failure,
            "provider snapshot returned an invalid x86 tile window", request));
    }

    try {
        x86_tile_decode_result_t output;
        output.mode = impl_->mode;
        output.start_address = request.start_address;
        output.provider_offset = request.provider_offset;
        output.byte_count = request.byte_count;
        output.usage.input_bytes = request.byte_count;
        output.usage.snapshot_window_leases = 1;
        output.usage.snapshot_window_bytes = request.byte_count;
        const auto window_size = static_cast<std::size_t>(request.byte_count);
        const auto instruction_reserve = (std::min)({window_size,
            static_cast<std::size_t>(request.limits.maximum_instructions),
            initial_instruction_reserve});
        output.instructions.reserve(instruction_reserve);
        output.operand_facts.reserve((std::min)(
            instruction_reserve * initial_operands_per_instruction,
            static_cast<std::size_t>(request.limits.maximum_operand_facts)));
        output.target_facts.reserve((std::min)(
            instruction_reserve * initial_targets_per_instruction,
            static_cast<std::size_t>(request.limits.maximum_target_facts)));
        output.coverage.reserve((std::min)({window_size,
            static_cast<std::size_t>(request.limits.maximum_coverage_spans),
            initial_coverage_reserve}));

        bool invalid_run = false;
        address_t invalid_start{};
        std::uint64_t invalid_size = 0;
        const auto flush_invalid_run = [&]() -> workspace_result_t<void> {
            if (!invalid_run)
                return workspace_result_t<void>::success();
            if (output.coverage.size() >= request.limits.maximum_coverage_spans) {
                return workspace_result_t<void>::failure(limit_error(
                    "coverage_spans", request.limits.maximum_coverage_spans,
                    output.coverage.size(), 1, request));
            }
            coverage_span_t span{};
            span.start = invalid_start;
            span.size = invalid_size;
            span.reason = coverage_reason_t::undecodable;
            span.provenance = request.provenance;
            span.confidence = request.confidence;
            span.detail_code = static_cast<std::uint32_t>(workspace_error_code_t::decode_failure);
            output.coverage.push_back(span);
            output.usage.coverage_spans = output.coverage.size();
            invalid_run = false;
            invalid_size = 0;
            return workspace_result_t<void>::success();
        };

        while (output.usage.bytes_consumed < request.byte_count) {
            if (cancel.stop_requested()) {
                return workspace_result_t<x86_tile_decode_result_t>::failure(stop_error(cancel, request));
            }
            if (output.usage.decode_attempts >= request.limits.maximum_decode_attempts) {
                return workspace_result_t<x86_tile_decode_result_t>::failure(limit_error(
                    "decode_attempts", request.limits.maximum_decode_attempts,
                    output.usage.decode_attempts, 1, request));
            }
            const std::uint64_t consumed = output.usage.bytes_consumed;
            std::uint64_t provider_offset = 0;
            std::uint64_t address_value = 0;
            std::uint64_t runtime_address = 0;
            if (!checked_add_u64(request.provider_offset, consumed, provider_offset) ||
                !checked_add_u64(request.start_address.value, consumed, address_value) ||
                !checked_add_u64(runtime_start.value(), consumed, runtime_address)) {
                return workspace_result_t<x86_tile_decode_result_t>::failure(make_tile_error(
                    workspace_error_code_t::range_overflow,
                    "x86 tile address progression overflowed", request));
            }
            address_t address = request.start_address;
            address.value = address_value;
            const std::uint64_t remaining = request.byte_count - consumed;
            const std::uint64_t available = (std::min)(remaining, 15ULL);
            ZydisDecodedInstruction decoded{};
            std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
            const auto* bytes = window.value().data() + static_cast<std::size_t>(consumed);
            const ZyanStatus status = ZydisDecoderDecodeFull(
                &impl_->decoder, bytes, static_cast<ZyanUSize>(available),
                &decoded, operands.data());
            ++output.usage.decode_attempts;
            if (!ZYAN_SUCCESS(status)) {
                if (output.usage.invalid_bytes >= request.limits.maximum_invalid_bytes) {
                    return workspace_result_t<x86_tile_decode_result_t>::failure(limit_error(
                        "invalid_bytes", request.limits.maximum_invalid_bytes,
                        output.usage.invalid_bytes, 1, request));
                }
                if (!invalid_run) {
                    invalid_run = true;
                    invalid_start = address;
                }
                ++invalid_size;
                ++output.usage.invalid_bytes;
                ++output.usage.bytes_consumed;
                continue;
            }
            if (decoded.length == 0 || decoded.length > available) {
                return workspace_result_t<x86_tile_decode_result_t>::failure(make_tile_error(
                    workspace_error_code_t::integrity_failure,
                    "Zydis returned an invalid x86 tile instruction length", request));
            }
            auto flushed = flush_invalid_run();
            if (!flushed)
                return workspace_result_t<x86_tile_decode_result_t>::failure(flushed.error());
            auto appended = append_decoded_instruction(output, request, address,
                                                       runtime_address, decoded, operands);
            if (!appended)
                return workspace_result_t<x86_tile_decode_result_t>::failure(appended.error());
            output.usage.bytes_consumed += decoded.length;
            output.usage.decoded_bytes += decoded.length;
            output.usage.instructions = output.instructions.size();
            output.usage.operand_facts = output.operand_facts.size();
            output.usage.target_facts = output.target_facts.size();
        }
        auto flushed = flush_invalid_run();
        if (!flushed)
            return workspace_result_t<x86_tile_decode_result_t>::failure(flushed.error());
        output.usage.instructions = output.instructions.size();
        output.usage.operand_facts = output.operand_facts.size();
        output.usage.target_facts = output.target_facts.size();
        output.usage.coverage_spans = output.coverage.size();
        return workspace_result_t<x86_tile_decode_result_t>::success(std::move(output));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<x86_tile_decode_result_t>::failure(make_tile_error(
            workspace_error_code_t::provider_unavailable,
            "x86 tile decode output allocation failed", request));
    }
}

}
