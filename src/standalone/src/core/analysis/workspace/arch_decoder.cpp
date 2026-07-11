#include "arch_decoder.hpp"
#include "aarch64_decoder.hpp"
#include "arm_decoder.hpp"
#include "mips_decoder.hpp"
#include "ppc_decoder.hpp"
#include "riscv_decoder.hpp"
#include "x86_decoder.hpp"

#include <algorithm>
#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <tuple>
#include <utility>

namespace aida::analysis {
namespace {

constexpr const char* key_phase = "arch_decoder.key";
constexpr const char* limits_phase = "arch_decoder.limits";
constexpr const char* budget_phase = "arch_decoder.budget";
constexpr const char* registration_phase = "arch_decoder.register";
constexpr const char* resolution_phase = "arch_decoder.resolve";
constexpr const char* creation_phase = "arch_decoder.create";
constexpr const char* decode_phase = "arch_decoder.decode";
constexpr const char* format_phase = "arch_decoder.format";

bool initialize_default_arch_decoder_registry(arch_decoder_registry_t& registry) {
    using enrollment_t = workspace_result_t<void> (*)(arch_decoder_registry_t&);
    constexpr std::array<enrollment_t, 6> enrollments{{
        &register_x86_decoder_backends,
        &register_arm_decoder_backends,
        &register_aarch64_decoder,
        &register_mips_decoder,
        &register_ppc_decoder_backends,
        &register_riscv_decoder
    }};
    try {
        for (const auto enroll : enrollments) {
            auto enrolled = enroll(registry);
            if (!enrolled)
                std::terminate();
        }
    } catch (...) {
        std::terminate();
    }
    return true;
}

workspace_error_t stop_error(const cancellation_token_t& cancellation,
                             const char* phase) {
    if (cancellation.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "architecture decoder deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "architecture decoder operation cancelled", phase);
    error.cancellation = true;
    return error;
}

workspace_error_t key_error(workspace_error_code_t code,
                            std::string message,
                            const char* phase,
                            const arch_decoder_key_t& key) {
    auto error = make_workspace_error(code, std::move(message), phase);
    error.details.emplace_back("architecture",
                               std::to_string(static_cast<std::uint8_t>(key.architecture)));
    error.details.emplace_back("mode",
                               std::to_string(static_cast<std::uint8_t>(key.mode)));
    error.details.emplace_back("endian",
                               std::to_string(static_cast<std::uint8_t>(key.endian)));
    error.details.emplace_back("abi",
                               std::to_string(static_cast<std::uint8_t>(key.abi)));
    error.details.emplace_back("address_width_bits",
                               std::to_string(key.address_width_bits));
    return error;
}

workspace_error_t limit_error(const char* resource,
                              std::uint64_t limit,
                              std::uint64_t used,
                              std::uint64_t requested,
                              const char* phase = decode_phase) {
    auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                      "architecture decoder budget exhausted", phase);
    error.details.emplace_back("resource", resource);
    error.details.emplace_back("limit", std::to_string(limit));
    error.details.emplace_back("used", std::to_string(used));
    error.details.emplace_back("requested", std::to_string(requested));
    return error;
}

bool exceeds(std::uint64_t current,
             std::uint64_t increment,
             std::uint64_t limit) noexcept {
    return current > limit || increment > limit - current;
}

bool valid_implementation_id(const std::string& value) noexcept {
    if (value.empty() || value.size() > 64)
        return false;
    for (const unsigned char ch : value) {
        const bool alpha = (ch >= 'a' && ch <= 'z') ||
                           (ch >= 'A' && ch <= 'Z');
        const bool digit = ch >= '0' && ch <= '9';
        if (!alpha && !digit && ch != '.' && ch != '_' && ch != '-')
            return false;
    }
    return true;
}

bool same_decode_domain(const arch_decoder_key_t& lhs,
                        const arch_decoder_key_t& rhs) noexcept {
    return lhs.architecture == rhs.architecture &&
           lhs.mode == rhs.mode &&
           lhs.endian == rhs.endian &&
           lhs.address_width_bits == rhs.address_width_bits;
}

workspace_error_t normalize_backend_error(workspace_error_t error,
                                          const arch_decode_request_t& request) {
    if (error.code == workspace_error_code_t::none)
        error.code = workspace_error_code_t::decode_failure;
    if (error.message.empty())
        error.message = "architecture decoder backend rejected the instruction";
    if (error.phase.empty())
        error.phase = decode_phase;
    if (!error.offset)
        error.offset = request.provider_offset;
    if (!error.address)
        error.address = request.address;
    return error;
}

workspace_error_t normalize_format_backend_error(workspace_error_t error,
                                                 const arch_decode_request_t& request) {
    if (error.code == workspace_error_code_t::none)
        error.code = workspace_error_code_t::decode_failure;
    if (error.message.empty())
        error.message = "architecture formatter backend rejected the instruction";
    if (error.phase.empty())
        error.phase = format_phase;
    if (!error.offset)
        error.offset = request.provider_offset;
    if (!error.address)
        error.address = request.address;
    return error;
}

bool same_operand_fact(const operand_fact_t& lhs,
                       const operand_fact_t& rhs) noexcept {
    return lhs.id == rhs.id &&
           lhs.instruction_id == rhs.instruction_id &&
           lhs.address_expression_id == rhs.address_expression_id &&
           lhs.operand_index == rhs.operand_index &&
           lhs.decoder_operand_id == rhs.decoder_operand_id &&
           lhs.kind == rhs.kind &&
           lhs.access == rhs.access &&
           lhs.visibility == rhs.visibility &&
           lhs.encoding == rhs.encoding &&
           lhs.memory_type == rhs.memory_type &&
           lhs.access_width == rhs.access_width &&
           lhs.bit_width == rhs.bit_width &&
           lhs.access_width_bits == rhs.access_width_bits &&
           lhs.access_count == rhs.access_count &&
           lhs.element_width_bits == rhs.element_width_bits &&
           lhs.element_count == rhs.element_count &&
           lhs.address_width_bits == rhs.address_width_bits &&
           lhs.reg == rhs.reg &&
           lhs.segment_reg == rhs.segment_reg &&
           lhs.base_reg == rhs.base_reg &&
           lhs.index_reg == rhs.index_reg &&
           lhs.scale == rhs.scale &&
           lhs.relative == rhs.relative &&
           lhs.signed_value == rhs.signed_value &&
           lhs.has_displacement == rhs.has_displacement &&
           lhs.has_resolved_expression_value == rhs.has_resolved_expression_value &&
           lhs.displacement == rhs.displacement &&
           lhs.immediate == rhs.immediate &&
           lhs.resolved_expression_value == rhs.resolved_expression_value &&
           lhs.address_components == rhs.address_components &&
           lhs.address_expression == rhs.address_expression &&
           lhs.address_resolution == rhs.address_resolution;
}

bool same_target_fact(const target_fact_t& lhs,
                      const target_fact_t& rhs) noexcept {
    return lhs.instruction_id == rhs.instruction_id &&
           lhs.operand_fact_id == rhs.operand_fact_id &&
           lhs.address_expression_id == rhs.address_expression_id &&
           lhs.target == rhs.target &&
           lhs.kind == rhs.kind &&
           lhs.resolution == rhs.resolution &&
           lhs.operand_index == rhs.operand_index &&
           lhs.access_width_bits == rhs.access_width_bits &&
           lhs.access_count == rhs.access_count &&
           lhs.direct == rhs.direct &&
           lhs.is_external == rhs.is_external;
}

bool same_instruction_record(const instruction_record_t& lhs,
                             const instruction_record_t& rhs) noexcept {
    return lhs.id == rhs.id &&
           lhs.address == rhs.address &&
           lhs.length == rhs.length &&
           lhs.mnemonic_id == rhs.mnemonic_id &&
           lhs.opcode_id == rhs.opcode_id &&
           lhs.flow_flags == rhs.flow_flags &&
           lhs.operand_fact_begin == rhs.operand_fact_begin &&
           lhs.operand_fact_count == rhs.operand_fact_count &&
           lhs.target_fact_begin == rhs.target_fact_begin &&
           lhs.target_fact_count == rhs.target_fact_count &&
           lhs.provenance == rhs.provenance &&
           lhs.confidence == rhs.confidence &&
           lhs.coverage == rhs.coverage &&
           lhs.stable_source_id == rhs.stable_source_id;
}

bool same_decode_result(const arch_decode_result_t& lhs,
                        const arch_decode_result_t& rhs) noexcept {
    if (!same_instruction_record(lhs.instruction, rhs.instruction) ||
        lhs.operand_count != rhs.operand_count ||
        lhs.target_count != rhs.target_count ||
        lhs.delay_slot_count != rhs.delay_slot_count)
        return false;
    for (std::uint8_t index = 0; index < lhs.operand_count; ++index) {
        if (!same_operand_fact(lhs.operands[index], rhs.operands[index]))
            return false;
    }
    for (std::uint16_t index = 0; index < lhs.target_count; ++index) {
        if (!same_target_fact(lhs.targets[index], rhs.targets[index]))
            return false;
    }
    return true;
}

workspace_result_t<void> validate_request(
    const arch_decoder_key_t& key,
    const arch_decoder_limits_t& limits,
    const byte_view_t& view,
    std::uint64_t view_provider_offset,
    const arch_decode_request_t& request) {
    if (request.address.architecture != key.architecture ||
        request.address.mode != key.mode) {
        auto error = key_error(workspace_error_code_t::invalid_argument,
                               "decode address architecture does not match the decoder worker",
                               decode_phase, key);
        error.address = request.address;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (request.available_bytes < limits.minimum_instruction_bytes ||
        request.available_bytes > limits.maximum_instruction_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "decode byte count is outside decoder limits",
                                          decode_phase);
        error.offset = request.provider_offset;
        error.size = request.available_bytes;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (request.confidence > 100 ||
        request.provenance > fact_provenance_t::decompiler_feedback) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "decode provenance or confidence is invalid",
                                          decode_phase);
        error.address = request.address;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (request.address.space > address_space_id_t::live_virtual) {
        auto error = make_workspace_error(workspace_error_code_t::unsupported_address_space,
                                          "decode address space is invalid",
                                          decode_phase);
        error.address = request.address;
        return workspace_result_t<void>::failure(std::move(error));
    }
    std::uint64_t expected_runtime_address = request.address.value;
    if (request.address.space == address_space_id_t::relative_virtual) {
        if (request.address.value >
            (std::numeric_limits<std::uint64_t>::max)() - request.image_base) {
            auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                              "decode runtime address overflowed",
                                              decode_phase);
            error.address = request.address;
            return workspace_result_t<void>::failure(std::move(error));
        }
        expected_runtime_address = request.image_base + request.address.value;
    } else if (request.address.space == address_space_id_t::file_offset) {
        if (request.runtime_address == 0) {
            auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                              "file-offset decoding requires a runtime address",
                                              decode_phase);
            error.address = request.address;
            return workspace_result_t<void>::failure(std::move(error));
        }
        expected_runtime_address = request.runtime_address;
    }
    if (request.runtime_address != 0 &&
        request.runtime_address != expected_runtime_address) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "decode runtime address conflicts with the typed address",
                                          decode_phase);
        error.address = request.address;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (limits.instruction_alignment > 1 &&
        request.address.value % limits.instruction_alignment != 0) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "decode address violates instruction alignment",
                                          decode_phase);
        error.address = request.address;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (request.provider_offset < view_provider_offset) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "decode offset precedes the leased byte view",
                                          decode_phase);
        error.offset = request.provider_offset;
        return workspace_result_t<void>::failure(std::move(error));
    }
    const std::uint64_t relative_offset = request.provider_offset - view_provider_offset;
    if (relative_offset > view.size() ||
        request.available_bytes > view.size() - relative_offset) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "decode bytes exceed the leased byte view",
                                          decode_phase);
        error.offset = request.provider_offset;
        error.size = request.available_bytes;
        return workspace_result_t<void>::failure(std::move(error));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_result(
    const arch_decoder_key_t& key,
    const arch_decoder_limits_t& limits,
    const arch_decode_request_t& request,
    const arch_decode_result_t& output) {
    const auto& instruction = output.instruction;
    constexpr std::uint32_t valid_flow_flags =
        flow_fallthrough | flow_direct | flow_indirect | flow_call |
        flow_branch | flow_conditional | flow_return | flow_interrupt |
        flow_terminal | flow_privileged;
    if (instruction.id == 0 || instruction.address != request.address ||
        instruction.length < limits.minimum_instruction_bytes ||
        instruction.length > limits.maximum_instruction_bytes ||
        instruction.length > request.available_bytes ||
        instruction.length % limits.instruction_alignment != 0 ||
        instruction.provenance != request.provenance ||
        instruction.confidence != request.confidence ||
        instruction.coverage != coverage_reason_t::decoded ||
        instruction.stable_source_id != request.stable_source_id ||
        (instruction.flow_flags & ~valid_flow_flags) != 0 ||
        instruction.operand_fact_begin != 0 ||
        instruction.target_fact_begin != 0 ||
        instruction.operand_fact_count != output.operand_count ||
        instruction.target_fact_count != output.target_count) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "decoder returned an invalid Compact IR instruction",
                                          decode_phase);
        error.address = request.address;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (output.operand_count > limits.maximum_operand_facts ||
        output.operand_count > output.operands.size() ||
        output.target_count > limits.maximum_target_facts ||
        output.target_count > output.targets.size() ||
        output.delay_slot_count > limits.maximum_delay_slots) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "decoder output exceeds its registered Compact IR limits",
                                          decode_phase);
        error.address = request.address;
        return workspace_result_t<void>::failure(std::move(error));
    }
    for (std::size_t index = 0; index < output.operand_count; ++index) {
        const auto& operand = output.operands[index];
        constexpr std::uint16_t valid_address_components =
            address_component_segment | address_component_base |
            address_component_index | address_component_scale |
            address_component_displacement | address_component_instruction_pointer;
        const bool valid_address_width =
            operand.address_width_bits == 0 || operand.address_width_bits == 8 ||
            operand.address_width_bits == 16 || operand.address_width_bits == 32 ||
            operand.address_width_bits == 64;
        if (operand.instruction_id != instruction.id ||
            operand.operand_index != index ||
            operand.kind > operand_kind_t::pointer ||
            operand.address_expression > address_expression_kind_t::segment_relative ||
            operand.address_resolution > target_resolution_t::unresolved_indirect ||
            (operand.address_components & ~valid_address_components) != 0 ||
            !valid_address_width) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                              "decoder returned an invalid Compact IR operand",
                                              decode_phase);
            error.address = request.address;
            error.details.emplace_back("operand_index", std::to_string(index));
            return workspace_result_t<void>::failure(std::move(error));
        }
    }
    for (std::size_t index = 0; index < output.target_count; ++index) {
        const auto& target = output.targets[index];
        const bool unresolved =
            target.resolution == target_resolution_t::unresolved_indirect;
        const bool valid_target_address = unresolved ||
            (target.target.space <= address_space_id_t::live_virtual &&
             target.target.architecture == key.architecture &&
             target.target.mode == key.mode);
        const bool valid_external = target.is_external ==
            (target.resolution == target_resolution_t::external_virtual);
        if (target.instruction_id != instruction.id ||
            target.kind > target_kind_record_t::fallthrough ||
            target.resolution > target_resolution_t::unresolved_indirect ||
            (target.operand_index != 0xFFU &&
             target.operand_index >= output.operand_count) ||
            (unresolved && target.direct) ||
            !valid_target_address || !valid_external) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                              "decoder returned an invalid Compact IR target",
                                              decode_phase);
            error.address = request.address;
            error.details.emplace_back("target_index", std::to_string(index));
            return workspace_result_t<void>::failure(std::move(error));
        }
    }
    return workspace_result_t<void>::success();
}

}

bool operator==(const arch_decoder_key_t& lhs,
                const arch_decoder_key_t& rhs) noexcept {
    return lhs.architecture == rhs.architecture &&
           lhs.mode == rhs.mode &&
           lhs.endian == rhs.endian &&
           lhs.abi == rhs.abi &&
           lhs.address_width_bits == rhs.address_width_bits;
}

bool operator!=(const arch_decoder_key_t& lhs,
                const arch_decoder_key_t& rhs) noexcept {
    return !(lhs == rhs);
}

bool operator<(const arch_decoder_key_t& lhs,
               const arch_decoder_key_t& rhs) noexcept {
    return std::tie(lhs.architecture, lhs.mode, lhs.endian, lhs.abi,
                    lhs.address_width_bits) <
           std::tie(rhs.architecture, rhs.mode, rhs.endian, rhs.abi,
                    rhs.address_width_bits);
}

arch_decoder_key_t make_arch_decoder_key(const workspace_image_t& image) noexcept {
    arch_decoder_key_t key;
    key.architecture = image.architecture;
    key.mode = image.architecture_mode;
    key.endian = image.endian;
    key.abi = image.abi;
    key.address_width_bits = image.address_width_bits;
    return key;
}

workspace_result_t<void> validate_arch_decoder_key(const arch_decoder_key_t& key) {
    const bool valid_width = key.address_width_bits == 8 ||
                             key.address_width_bits == 16 ||
                             key.address_width_bits == 32 ||
                             key.address_width_bits == 64;
    if (!workspace_architecture_mode_matches(key.architecture, key.mode) ||
        key.endian > endian_t::big || key.abi > abi_id_t::dalvik || !valid_width) {
        return workspace_result_t<void>::failure(
            key_error(workspace_error_code_t::invalid_argument,
                      "architecture decoder key is invalid", key_phase, key));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_arch_decoder_limits(
    const arch_decoder_limits_t& limits) {
    const bool power_of_two_alignment = limits.instruction_alignment != 0 &&
        (limits.instruction_alignment & (limits.instruction_alignment - 1)) == 0;
    if (limits.minimum_instruction_bytes == 0 ||
        limits.minimum_instruction_bytes > limits.maximum_instruction_bytes ||
        limits.maximum_instruction_bytes > arch_decode_result_t::instruction_byte_capacity ||
        !power_of_two_alignment ||
        limits.minimum_instruction_bytes % limits.instruction_alignment != 0 ||
        limits.maximum_instruction_bytes % limits.instruction_alignment != 0 ||
        limits.maximum_operand_facts > arch_decode_result_t::operand_capacity ||
        limits.maximum_target_facts > arch_decode_result_t::target_capacity ||
        limits.maximum_delay_slots > 2) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "architecture decoder limits are invalid", limits_phase));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_arch_format_options(
    const arch_format_options_t& options) {
    if (options.maximum_text_bytes == 0 ||
        options.maximum_text_bytes > arch_format_options_t::hard_maximum_text_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "architecture formatter options are invalid", format_phase));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_arch_decode_budget(
    const arch_decode_budget_t& budget) {
    if (budget.max_decode_attempts == 0 ||
        budget.max_decode_attempts > arch_decode_budget_t::hard_max_decode_attempts ||
        budget.max_input_bytes == 0 ||
        budget.max_input_bytes > arch_decode_budget_t::hard_max_input_bytes ||
        budget.max_instructions == 0 ||
        budget.max_instructions > arch_decode_budget_t::hard_max_instructions ||
        budget.max_instructions > budget.max_decode_attempts ||
        budget.max_operand_facts > arch_decode_budget_t::hard_max_operand_facts ||
        budget.max_target_facts > arch_decode_budget_t::hard_max_target_facts ||
        budget.max_format_attempts == 0 ||
        budget.max_format_attempts > arch_decode_budget_t::hard_max_format_attempts ||
        budget.max_format_input_bytes == 0 ||
        budget.max_format_input_bytes > arch_decode_budget_t::hard_max_format_input_bytes ||
        budget.max_formatted_instructions == 0 ||
        budget.max_formatted_instructions >
            arch_decode_budget_t::hard_max_formatted_instructions ||
        budget.max_formatted_instructions > budget.max_format_attempts ||
        budget.max_formatted_text_bytes == 0 ||
        budget.max_formatted_text_bytes >
            arch_decode_budget_t::hard_max_formatted_text_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "architecture decode budget is invalid", budget_phase));
    }
    return workspace_result_t<void>::success();
}

arch_decode_control_t::arch_decode_control_t(
    const cancellation_token_t& cancellation,
    const arch_decode_budget_t& budget,
    arch_decode_usage_t& usage,
    const char* phase) noexcept
    : cancellation_(&cancellation), budget_(&budget), usage_(&usage), phase_(phase) {}

const cancellation_token_t& arch_decode_control_t::cancellation() const noexcept {
    return *cancellation_;
}

const arch_decode_budget_t& arch_decode_control_t::budget() const noexcept {
    return *budget_;
}

const arch_decode_usage_t& arch_decode_control_t::usage() const noexcept {
    return *usage_;
}

workspace_result_t<void> arch_decode_control_t::poll() const {
    if (usage_->cancellation_polls != (std::numeric_limits<std::uint64_t>::max)())
        ++usage_->cancellation_polls;
    if (cancellation_->stop_requested())
        return workspace_result_t<void>::failure(stop_error(*cancellation_, phase_));
    return workspace_result_t<void>::success();
}

workspace_result_t<std::string> arch_decoder_backend_t::combine_format_text(
    const char* mnemonic,
    std::size_t mnemonic_capacity,
    const char* operands,
    std::size_t operands_capacity) {
    if (mnemonic == nullptr || operands == nullptr || mnemonic_capacity == 0 ||
        operands_capacity == 0) {
        return workspace_result_t<std::string>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "architecture formatter returned invalid text storage", format_phase));
    }
    const auto* mnemonic_end = static_cast<const char*>(
        std::memchr(mnemonic, '\0', mnemonic_capacity));
    const auto* operands_end = static_cast<const char*>(
        std::memchr(operands, '\0', operands_capacity));
    if (mnemonic_end == nullptr || operands_end == nullptr || mnemonic_end == mnemonic) {
        return workspace_result_t<std::string>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "architecture formatter returned unterminated text", format_phase));
    }
    const std::size_t mnemonic_size =
        static_cast<std::size_t>(mnemonic_end - mnemonic);
    const std::size_t operands_size =
        static_cast<std::size_t>(operands_end - operands);
    std::string text;
    text.reserve(mnemonic_size + (operands_size == 0 ? 0 : operands_size + 1));
    text.append(mnemonic, mnemonic_size);
    if (operands_size != 0) {
        text.push_back(' ');
        text.append(operands, operands_size);
    }
    return workspace_result_t<std::string>::success(std::move(text));
}

worker_owned_arch_decoder_t::worker_owned_arch_decoder_t(
    arch_decoder_key_t key,
    arch_decoder_registration_t registration,
    arch_decode_budget_t budget,
    cancellation_token_t cancellation,
    std::unique_ptr<arch_decoder_backend_t> backend)
    : key_(key),
      registration_(std::move(registration)),
      budget_(budget),
      cancellation_(std::move(cancellation)),
      backend_(std::move(backend)),
      owner_thread_(std::this_thread::get_id()) {}

worker_owned_arch_decoder_t::~worker_owned_arch_decoder_t() = default;

const arch_decoder_key_t& worker_owned_arch_decoder_t::key() const noexcept {
    return key_;
}

const arch_decoder_registration_t&
worker_owned_arch_decoder_t::registration() const noexcept {
    return registration_;
}

const arch_decode_budget_t& worker_owned_arch_decoder_t::budget() const noexcept {
    return budget_;
}

const arch_decode_usage_t& worker_owned_arch_decoder_t::usage() const noexcept {
    return usage_;
}

std::thread::id worker_owned_arch_decoder_t::owner_thread() const noexcept {
    return owner_thread_;
}

workspace_result_t<void> worker_owned_arch_decoder_t::verify_owner() const {
    if (std::this_thread::get_id() == owner_thread_)
        return workspace_result_t<void>::success();
    auto error = make_workspace_error(workspace_error_code_t::service_conflict,
                                      "decoder worker used from a non-owner thread",
                                      decode_phase);
    error.details.emplace_back("implementation_id", registration_.implementation_id);
    return workspace_result_t<void>::failure(std::move(error));
}

workspace_result_t<void> worker_owned_arch_decoder_t::poll() {
    auto owner = verify_owner();
    if (!owner)
        return owner;
    const arch_decode_control_t control(cancellation_, budget_, usage_, decode_phase);
    return control.poll();
}

workspace_result_t<void> worker_owned_arch_decoder_t::decode_one(
    const byte_view_t& view,
    std::uint64_t view_provider_offset,
    const arch_decode_request_t& request,
    arch_decode_result_t& output) {
    output = {};
    auto owner = verify_owner();
    if (!owner)
        return owner;
    const arch_decode_control_t control(cancellation_, budget_, usage_, decode_phase);
    auto current = control.poll();
    if (!current)
        return current;
    if (exceeds(usage_.decode_attempts, 1, budget_.max_decode_attempts))
        return workspace_result_t<void>::failure(
            limit_error("decode_attempts", budget_.max_decode_attempts,
                        usage_.decode_attempts, 1));
    ++usage_.decode_attempts;
    current = validate_request(key_, registration_.limits, view,
                               view_provider_offset, request);
    if (!current)
        return current;
    if (exceeds(usage_.input_bytes, request.available_bytes,
                budget_.max_input_bytes)) {
        return workspace_result_t<void>::failure(
            limit_error("input_bytes", budget_.max_input_bytes,
                        usage_.input_bytes, request.available_bytes));
    }
    usage_.input_bytes += request.available_bytes;
    try {
        current = backend_->decode_one(view, view_provider_offset, request,
                                       output, control);
    } catch (...) {
        auto error = make_workspace_error(workspace_error_code_t::decode_failure,
                                          "architecture decoder backend raised an exception",
                                          decode_phase);
        error.offset = request.provider_offset;
        error.address = request.address;
        output = {};
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (!current) {
        auto error = normalize_backend_error(current.error(), request);
        output = {};
        return workspace_result_t<void>::failure(std::move(error));
    }
    current = control.poll();
    if (!current) {
        output = {};
        return current;
    }
    current = validate_result(key_, registration_.limits, request, output);
    if (!current) {
        output = {};
        return current;
    }
    if (exceeds(usage_.instructions, 1, budget_.max_instructions)) {
        output = {};
        return workspace_result_t<void>::failure(
            limit_error("instructions", budget_.max_instructions,
                        usage_.instructions, 1));
    }
    if (exceeds(usage_.operand_facts, output.operand_count,
                budget_.max_operand_facts)) {
        const auto requested = output.operand_count;
        output = {};
        return workspace_result_t<void>::failure(
            limit_error("operand_facts", budget_.max_operand_facts,
                        usage_.operand_facts, requested));
    }
    if (exceeds(usage_.target_facts, output.target_count,
                budget_.max_target_facts)) {
        const auto requested = output.target_count;
        output = {};
        return workspace_result_t<void>::failure(
            limit_error("target_facts", budget_.max_target_facts,
                        usage_.target_facts, requested));
    }
    ++usage_.instructions;
    usage_.decoded_bytes += output.instruction.length;
    usage_.operand_facts += output.operand_count;
    usage_.target_facts += output.target_count;
    return workspace_result_t<void>::success();
}

workspace_result_t<arch_decode_result_t> worker_owned_arch_decoder_t::decode_one(
    const byte_view_t& view,
    std::uint64_t view_provider_offset,
    const arch_decode_request_t& request) {
    arch_decode_result_t output;
    auto decoded = decode_one(view, view_provider_offset, request, output);
    if (!decoded)
        return workspace_result_t<arch_decode_result_t>::failure(decoded.error());
    return workspace_result_t<arch_decode_result_t>::success(std::move(output));
}

workspace_result_t<arch_decode_result_t> worker_owned_arch_decoder_t::decode_one(
    const byte_provider_t& provider,
    const arch_decode_request_t& request) {
    auto owner = verify_owner();
    if (!owner)
        return workspace_result_t<arch_decode_result_t>::failure(owner.error());
    auto polled = poll();
    if (!polled)
        return workspace_result_t<arch_decode_result_t>::failure(polled.error());
    if (request.available_bytes < registration_.limits.minimum_instruction_bytes ||
        request.available_bytes > registration_.limits.maximum_instruction_bytes) {
        return workspace_result_t<arch_decode_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "decode byte count is outside decoder limits", decode_phase));
    }
    auto leased = provider.lease(request.provider_offset,
                                 request.available_bytes, cancellation_);
    if (!leased)
        return workspace_result_t<arch_decode_result_t>::failure(leased.error());
    return decode_one(leased.value(), request.provider_offset, request);
}

workspace_result_t<std::string> worker_owned_arch_decoder_t::format_one(
    const byte_view_t& view,
    std::uint64_t view_provider_offset,
    const arch_decode_request_t& request,
    const arch_decode_result_t& decoded,
    const arch_format_options_t& options) {
    auto owner = verify_owner();
    if (!owner)
        return workspace_result_t<std::string>::failure(owner.error());
    const arch_decode_control_t control(cancellation_, budget_, usage_, format_phase);
    auto current = control.poll();
    if (!current)
        return workspace_result_t<std::string>::failure(current.error());
    if (exceeds(usage_.format_attempts, 1, budget_.max_format_attempts)) {
        return workspace_result_t<std::string>::failure(
            limit_error("format_attempts", budget_.max_format_attempts,
                        usage_.format_attempts, 1, format_phase));
    }
    ++usage_.format_attempts;
    current = validate_arch_format_options(options);
    if (!current)
        return workspace_result_t<std::string>::failure(current.error());
    if (decoded.instruction.length == 0 ||
        decoded.instruction.length > registration_.limits.maximum_instruction_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "formatted instruction facts have an invalid length",
                                          format_phase);
        error.address = decoded.instruction.address;
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    arch_decode_request_t format_request = request;
    format_request.available_bytes = decoded.instruction.length;
    current = validate_request(key_, registration_.limits, view, view_provider_offset,
                               format_request);
    if (!current)
        return workspace_result_t<std::string>::failure(current.error());
    current = validate_result(key_, registration_.limits, format_request, decoded);
    if (!current)
        return workspace_result_t<std::string>::failure(current.error());
    if (exceeds(usage_.format_input_bytes, format_request.available_bytes,
                budget_.max_format_input_bytes)) {
        return workspace_result_t<std::string>::failure(
            limit_error("format_input_bytes", budget_.max_format_input_bytes,
                        usage_.format_input_bytes, format_request.available_bytes,
                        format_phase));
    }
    usage_.format_input_bytes += format_request.available_bytes;
    arch_decode_result_t canonical;
    workspace_result_t<std::string> formatted =
        workspace_result_t<std::string>::failure(make_workspace_error(
            workspace_error_code_t::decode_failure,
            "architecture formatter backend did not produce text", format_phase));
    try {
        current = backend_->decode_one(view, view_provider_offset, format_request,
                                       canonical, control);
        if (!current) {
            return workspace_result_t<std::string>::failure(
                normalize_format_backend_error(current.error(), format_request));
        }
        current = control.poll();
        if (!current)
            return workspace_result_t<std::string>::failure(current.error());
        current = validate_result(key_, registration_.limits, format_request, canonical);
        if (!current)
            return workspace_result_t<std::string>::failure(current.error());
        if (!same_decode_result(canonical, decoded)) {
            auto error = make_workspace_error(workspace_error_code_t::file_changed,
                                              "instruction bytes no longer match compact IR",
                                              format_phase);
            error.offset = format_request.provider_offset;
            error.address = format_request.address;
            return workspace_result_t<std::string>::failure(std::move(error));
        }
        formatted = backend_->format_decoded(canonical, control);
    } catch (...) {
        auto error = make_workspace_error(workspace_error_code_t::decode_failure,
                                          "architecture formatter backend raised an exception",
                                          format_phase);
        error.offset = format_request.provider_offset;
        error.address = format_request.address;
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    if (!formatted) {
        return workspace_result_t<std::string>::failure(
            normalize_format_backend_error(formatted.error(), format_request));
    }
    current = control.poll();
    if (!current)
        return workspace_result_t<std::string>::failure(current.error());
    std::string text = formatted.take_value();
    if (text.empty()) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "architecture formatter returned empty text", format_phase);
        error.offset = format_request.provider_offset;
        error.address = format_request.address;
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    if (text.size() > options.maximum_text_bytes) {
        return workspace_result_t<std::string>::failure(
            limit_error("format_text_bytes", options.maximum_text_bytes, 0, text.size(),
                        format_phase));
    }
    if (exceeds(usage_.formatted_text_bytes, text.size(),
                budget_.max_formatted_text_bytes)) {
        return workspace_result_t<std::string>::failure(
            limit_error("formatted_text_bytes", budget_.max_formatted_text_bytes,
                        usage_.formatted_text_bytes, text.size(), format_phase));
    }
    if (exceeds(usage_.formatted_instructions, 1,
                budget_.max_formatted_instructions)) {
        return workspace_result_t<std::string>::failure(
            limit_error("formatted_instructions", budget_.max_formatted_instructions,
                        usage_.formatted_instructions, 1, format_phase));
    }
    if (options.uppercase) {
        for (char& character : text) {
            if (character >= 'a' && character <= 'z')
                character = static_cast<char>(character - 'a' + 'A');
        }
    }
    ++usage_.formatted_instructions;
    usage_.formatted_text_bytes += text.size();
    return workspace_result_t<std::string>::success(std::move(text));
}

workspace_result_t<std::string> worker_owned_arch_decoder_t::format_one(
    const byte_provider_t& provider,
    const arch_decode_request_t& request,
    const arch_decode_result_t& decoded,
    const arch_format_options_t& options) {
    auto owner = verify_owner();
    if (!owner)
        return workspace_result_t<std::string>::failure(owner.error());
    if (decoded.instruction.length == 0 ||
        decoded.instruction.length > registration_.limits.maximum_instruction_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "formatted instruction facts have an invalid length",
                                          format_phase);
        error.address = decoded.instruction.address;
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    auto leased = provider.lease(request.provider_offset, decoded.instruction.length,
                                 cancellation_);
    if (!leased)
        return workspace_result_t<std::string>::failure(leased.error());
    return format_one(leased.value(), request.provider_offset, request, decoded, options);
}

struct arch_decoder_registry_t::impl_t {
    mutable std::mutex mutex;
    std::array<arch_decoder_registration_t, registration_capacity> registrations{};
    std::size_t count = 0;
};

arch_decoder_registry_t::arch_decoder_registry_t()
    : impl_(std::make_unique<impl_t>()) {}

arch_decoder_registry_t::~arch_decoder_registry_t() = default;

workspace_result_t<void> arch_decoder_registry_t::register_decoder(
    const arch_decoder_registration_t& registration) {
    auto valid_key = validate_arch_decoder_key(registration.key);
    if (!valid_key)
        return valid_key;
    auto valid_limits = validate_arch_decoder_limits(registration.limits);
    if (!valid_limits)
        return valid_limits;
    if (!valid_implementation_id(registration.implementation_id) ||
        registration.implementation_version == 0 || registration.factory == nullptr) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "architecture decoder registration is invalid", registration_phase));
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->count == impl_->registrations.size()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "architecture decoder registration capacity exhausted",
            registration_phase));
    }
    for (std::size_t index = 0; index < impl_->count; ++index) {
        if (impl_->registrations[index].key == registration.key) {
            auto error = key_error(workspace_error_code_t::service_conflict,
                                   "architecture decoder key is already registered",
                                   registration_phase, registration.key);
            return workspace_result_t<void>::failure(std::move(error));
        }
    }
    impl_->registrations[impl_->count++] = registration;
    std::sort(impl_->registrations.begin(),
              impl_->registrations.begin() + impl_->count,
              [](const arch_decoder_registration_t& lhs,
                 const arch_decoder_registration_t& rhs) {
                  if (lhs.key != rhs.key)
                      return lhs.key < rhs.key;
                  if (lhs.implementation_id != rhs.implementation_id)
                      return lhs.implementation_id < rhs.implementation_id;
                  return lhs.implementation_version < rhs.implementation_version;
              });
    return workspace_result_t<void>::success();
}

workspace_result_t<arch_decoder_registration_t> arch_decoder_registry_t::resolve(
    const arch_decoder_key_t& key) const {
    auto valid_key = validate_arch_decoder_key(key);
    if (!valid_key)
        return workspace_result_t<arch_decoder_registration_t>::failure(valid_key.error());
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const arch_decoder_registration_t* wildcard = nullptr;
    for (std::size_t index = 0; index < impl_->count; ++index) {
        const auto& candidate = impl_->registrations[index];
        if (!same_decode_domain(candidate.key, key))
            continue;
        if (candidate.key.abi == key.abi)
            return workspace_result_t<arch_decoder_registration_t>::success(candidate);
        if (candidate.key.abi == abi_id_t::unknown)
            wildcard = &candidate;
    }
    if (wildcard != nullptr)
        return workspace_result_t<arch_decoder_registration_t>::success(*wildcard);
    return workspace_result_t<arch_decoder_registration_t>::failure(
        key_error(workspace_error_code_t::unsupported_format,
                  "no architecture decoder is registered for the requested configuration",
                  resolution_phase, key));
}

workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>>
arch_decoder_registry_t::create_worker(
    const arch_decoder_key_t& key,
    const arch_decode_budget_t& budget,
    const cancellation_token_t& cancellation) const {
    auto valid_budget = validate_arch_decode_budget(budget);
    if (!valid_budget) {
        return workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>>::failure(
            valid_budget.error());
    }
    if (cancellation.stop_requested()) {
        return workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>>::failure(
            stop_error(cancellation, creation_phase));
    }
    auto resolved = resolve(key);
    if (!resolved) {
        return workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>>::failure(
            resolved.error());
    }
    auto registration = resolved.take_value();
    if (budget.max_input_bytes < registration.limits.minimum_instruction_bytes) {
        return workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "decode budget cannot hold one minimum-size instruction",
                                 creation_phase));
    }
    try {
        auto backend = registration.factory(key, cancellation);
        if (!backend) {
            auto error = backend.error();
            if (error.code == workspace_error_code_t::none)
                error.code = workspace_error_code_t::decode_failure;
            if (error.message.empty())
                error.message = "architecture decoder factory rejected the worker";
            if (error.phase.empty())
                error.phase = creation_phase;
            return workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>>::failure(
                std::move(error));
        }
        auto backend_instance = backend.take_value();
        if (!backend_instance) {
            return workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "architecture decoder factory returned a null backend",
                                     creation_phase));
        }
        if (cancellation.stop_requested()) {
            return workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>>::failure(
                stop_error(cancellation, creation_phase));
        }
        std::unique_ptr<worker_owned_arch_decoder_t> worker(
            new worker_owned_arch_decoder_t(key, std::move(registration), budget,
                                            cancellation, std::move(backend_instance)));
        return workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>>::success(
            std::move(worker));
    } catch (...) {
        return workspace_result_t<std::unique_ptr<worker_owned_arch_decoder_t>>::failure(
            make_workspace_error(workspace_error_code_t::decode_failure,
                                 "architecture decoder factory raised an exception",
                                 creation_phase));
    }
}

std::size_t arch_decoder_registry_t::registered_count() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->count;
}

arch_decoder_registry_t& default_arch_decoder_registry() {
    static arch_decoder_registry_t registry;
    static const bool initialized = initialize_default_arch_decoder_registry(registry);
    (void)initialized;
    return registry;
}

}
