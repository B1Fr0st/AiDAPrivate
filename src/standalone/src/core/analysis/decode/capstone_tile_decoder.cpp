#include "capstone_tile_decoder.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <string>
#include <utility>

namespace aida::analysis::decode {
namespace {

constexpr const char* kPhase = "capstone_tile_decoder";

std::uint64_t mix(std::uint64_t value) noexcept
{
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31U;
    return value;
}

std::uint64_t combine(std::uint64_t seed, std::uint64_t value) noexcept
{
    return mix(seed ^ (mix(value) + 0x9e3779b97f4a7c15ULL + (seed << 6U) + (seed >> 2U)));
}

bool exceeds(std::uint64_t current, std::uint64_t requested, std::uint64_t limit) noexcept
{
    return current > limit || requested > limit - current;
}

bool add(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& output) noexcept
{
    if (lhs > (std::numeric_limits<std::uint64_t>::max)() - rhs)
        return false;
    output = lhs + rhs;
    return true;
}

workspace_error_t error(workspace_error_code_t code, std::string message,
                        const capstone_tile_identity_t* identity = nullptr,
                        std::uint64_t offset = 0)
{
    auto result = make_workspace_error(code, std::move(message), kPhase);
    if (identity != nullptr) {
        result.offset = offset;
        address_t address = identity->start;
        if (offset >= identity->provider_offset) {
            const std::uint64_t delta = offset - identity->provider_offset;
            std::uint64_t next_address = 0;
            if (add(address.value, delta, next_address))
                address.value = next_address;
        }
        result.address = address;
    }
    return result;
}

workspace_result_t<void> stopped(const cancellation_token_t& cancellation)
{
    auto result = make_workspace_error(
        cancellation.deadline_exceeded()
            ? workspace_error_code_t::deadline_exceeded
            : workspace_error_code_t::cancelled,
        "Capstone tile decode cancelled", kPhase);
    result.deadline = cancellation.deadline_exceeded();
    result.cancellation = !result.deadline;
    return workspace_result_t<void>::failure(std::move(result));
}

bool is_capstone_tile_architecture(const arch_decoder_key_t& key) noexcept
{
    switch (key.architecture) {
    case architecture_id_t::arm:
        return key.address_width_bits == 32 &&
               (key.mode == architecture_mode_t::arm_a32 ||
                key.mode == architecture_mode_t::arm_thumb);
    case architecture_id_t::aarch64:
        return key.address_width_bits == 64 && key.mode == architecture_mode_t::aarch64;
    case architecture_id_t::mips:
        return (key.address_width_bits == 32 && key.mode == architecture_mode_t::mips32) ||
               (key.address_width_bits == 64 && key.mode == architecture_mode_t::mips64);
    case architecture_id_t::mips64:
        return key.address_width_bits == 64 && key.mode == architecture_mode_t::mips64;
    case architecture_id_t::ppc:
        return key.address_width_bits == 32 && key.mode == architecture_mode_t::ppc32;
    case architecture_id_t::ppc64:
        return key.address_width_bits == 64 && key.mode == architecture_mode_t::ppc64;
    case architecture_id_t::riscv:
        return (key.address_width_bits == 32 && key.mode == architecture_mode_t::riscv32) ||
               (key.address_width_bits == 64 && key.mode == architecture_mode_t::riscv64);
    case architecture_id_t::riscv32:
        return key.address_width_bits == 32 && key.mode == architecture_mode_t::riscv32;
    case architecture_id_t::riscv64:
        return key.address_width_bits == 64 && key.mode == architecture_mode_t::riscv64;
    default:
        return false;
    }
}

workspace_result_t<void> validate_identity(const capstone_tile_identity_t& identity,
                                           const arch_decoder_key_t& key,
                                           const arch_decoder_registration_t& registration,
                                           const capstone_tile_decode_limits_t& limits,
                                           const provider_snapshot_t& snapshot)
{
    if (identity.decoder_key != key || identity.start.architecture != key.architecture ||
        identity.start.mode != key.mode || identity.start.space > address_space_id_t::live_virtual ||
        identity.provenance > fact_provenance_t::decompiler_feedback || identity.confidence > 100) {
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::invalid_argument,
            "Capstone tile identity does not match its worker configuration", &identity,
            identity.provider_offset));
    }
    if (identity.snapshot_generation != snapshot.generation()) {
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::stale_generation,
            "Capstone tile identity references a stale provider snapshot", &identity,
            identity.provider_offset));
    }
    if (identity.byte_count == 0 || identity.byte_count > limits.maximum_tile_bytes ||
        identity.byte_count > snapshot.size() ||
        identity.provider_offset > snapshot.size() - identity.byte_count) {
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::out_of_range,
            "Capstone tile range is outside the provider or configured tile budget", &identity,
            identity.provider_offset));
    }
    const std::uint64_t contiguous = snapshot.maximum_contiguous_lease(identity.provider_offset);
    if (contiguous < identity.byte_count) {
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::out_of_range,
            "Capstone tile range crosses a provider lease boundary", &identity,
            identity.provider_offset));
    }
    if (registration.limits.instruction_alignment > 1 &&
        identity.start.value % registration.limits.instruction_alignment != 0) {
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::invalid_argument,
            "Capstone tile start violates the architecture instruction alignment", &identity,
            identity.provider_offset));
    }
    std::uint64_t expected_runtime = identity.start.value;
    if (identity.start.space == address_space_id_t::relative_virtual) {
        if (identity.image_size == 0 || identity.start.value > identity.image_size ||
            identity.byte_count > identity.image_size - identity.start.value ||
            !add(identity.image_base, identity.start.value, expected_runtime) ||
            identity.runtime_address != expected_runtime) {
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::invalid_argument,
                "relative Capstone tile identity has an invalid image or runtime range", &identity,
                identity.provider_offset));
        }
    } else if (identity.start.space == address_space_id_t::virtual_address ||
               identity.start.space == address_space_id_t::live_virtual) {
        if (identity.runtime_address != identity.start.value ||
            identity.start.value < identity.image_base || identity.image_size == 0 ||
            identity.start.value - identity.image_base > identity.image_size ||
            identity.byte_count > identity.image_size -
                (identity.start.value - identity.image_base)) {
            return workspace_result_t<void>::failure(error(
                workspace_error_code_t::invalid_argument,
                "virtual Capstone tile identity has an invalid image or runtime range", &identity,
                identity.provider_offset));
        }
    } else if (identity.runtime_address == 0) {
        return workspace_result_t<void>::failure(error(
            workspace_error_code_t::invalid_argument,
            "file-offset Capstone tile identity requires an explicit runtime address", &identity,
            identity.provider_offset));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<arch_decode_request_t> make_request(const capstone_tile_identity_t& identity,
                                                        std::uint64_t relative_offset,
                                                        std::uint16_t available_bytes)
{
    arch_decode_request_t request;
    request.address = identity.start;
    if (!add(identity.start.value, relative_offset, request.address.value) ||
        !add(identity.provider_offset, relative_offset, request.provider_offset) ||
        !add(identity.runtime_address, relative_offset, request.runtime_address)) {
        return workspace_result_t<arch_decode_request_t>::failure(error(
            workspace_error_code_t::range_overflow,
            "Capstone tile instruction identity overflowed", &identity,
            identity.provider_offset));
    }
    request.image_base = identity.image_base;
    request.image_size = identity.image_size;
    request.available_bytes = available_bytes;
    request.provenance = identity.provenance;
    request.confidence = identity.confidence;
    request.stable_source_id = combine(capstone_tile_identity_hash(identity), relative_offset);
    return workspace_result_t<arch_decode_request_t>::success(std::move(request));
}

coverage_span_t coverage(const arch_decode_request_t& request, std::uint64_t size,
                         coverage_reason_t reason, std::uint8_t confidence,
                         workspace_error_code_t detail) noexcept
{
    coverage_span_t span;
    span.start = request.address;
    span.size = size;
    span.reason = reason;
    span.provenance = request.provenance;
    span.confidence = confidence;
    span.detail_code = static_cast<std::uint32_t>(detail);
    return span;
}

}

workspace_result_t<void> validate_capstone_tile_decode_limits(
    const capstone_tile_decode_limits_t& limits)
{
    if (limits.maximum_tile_bytes == 0 ||
        limits.maximum_tile_bytes > capstone_tile_decode_limits_t::hard_maximum_tile_bytes ||
        limits.maximum_instruction_records == 0 ||
        limits.maximum_instruction_records >
            capstone_tile_decode_limits_t::hard_maximum_instruction_records ||
        limits.maximum_operand_facts == 0 ||
        limits.maximum_operand_facts > capstone_tile_decode_limits_t::hard_maximum_operand_facts ||
        limits.maximum_target_facts == 0 ||
        limits.maximum_target_facts > capstone_tile_decode_limits_t::hard_maximum_target_facts ||
        limits.maximum_coverage_spans == 0 ||
        limits.maximum_coverage_spans > limits.maximum_instruction_records ||
        limits.maximum_operand_facts > limits.maximum_instruction_records *
            arch_decode_result_t::operand_capacity ||
        limits.maximum_target_facts > limits.maximum_instruction_records *
            arch_decode_result_t::target_capacity ||
        limits.maximum_consecutive_undecodable_bytes == 0 ||
        limits.maximum_consecutive_undecodable_bytes > limits.maximum_tile_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "Capstone tile decode limits are invalid", kPhase));
    }
    return workspace_result_t<void>::success();
}

std::uint64_t capstone_tile_identity_hash(const capstone_tile_identity_t& identity) noexcept
{
    std::uint64_t value = identity.stable_source_id;
    value = combine(value, static_cast<std::uint64_t>(identity.decoder_key.architecture));
    value = combine(value, static_cast<std::uint64_t>(identity.decoder_key.mode));
    value = combine(value, static_cast<std::uint64_t>(identity.decoder_key.endian));
    value = combine(value, static_cast<std::uint64_t>(identity.decoder_key.abi));
    value = combine(value, identity.decoder_key.address_width_bits);
    value = combine(value, static_cast<std::uint64_t>(identity.start.space));
    value = combine(value, identity.start.value);
    value = combine(value, static_cast<std::uint64_t>(identity.start.architecture));
    value = combine(value, static_cast<std::uint64_t>(identity.start.mode));
    value = combine(value, identity.provider_offset);
    value = combine(value, identity.runtime_address);
    value = combine(value, identity.image_base);
    value = combine(value, identity.image_size);
    value = combine(value, identity.byte_count);
    value = combine(value, identity.snapshot_generation);
    value = combine(value, static_cast<std::uint64_t>(identity.provenance));
    return combine(value, identity.confidence);
}

worker_owned_capstone_tile_decoder_t::worker_owned_capstone_tile_decoder_t(
    std::unique_ptr<worker_owned_arch_decoder_t> worker,
    capstone_tile_decode_limits_t tile_limits) noexcept
    : worker_(std::move(worker)),
      tile_limits_(tile_limits) {}

worker_owned_capstone_tile_decoder_t::~worker_owned_capstone_tile_decoder_t() = default;

workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>
worker_owned_capstone_tile_decoder_t::create(
    const arch_decoder_key_t& key,
    capstone_tile_decoder_options_t options,
    const cancellation_token_t& cancellation)
{
    return create(default_arch_decoder_registry(), key, options, cancellation);
}

workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>
worker_owned_capstone_tile_decoder_t::create(
    arch_decoder_registry_t& registry,
    const arch_decoder_key_t& key,
    capstone_tile_decoder_options_t options,
    const cancellation_token_t& cancellation)
{
    auto key_valid = validate_arch_decoder_key(key);
    if (!key_valid) {
        return workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>::failure(
            key_valid.error());
    }
    if (!is_capstone_tile_architecture(key)) {
        return workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>::failure(error(
            workspace_error_code_t::unsupported_format,
            "Capstone tile decoder does not support the requested architecture mode"));
    }
    auto limits_valid = validate_capstone_tile_decode_limits(options.tile_limits);
    if (!limits_valid) {
        return workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>::failure(
            limits_valid.error());
    }
    if (cancellation.stop_requested()) {
        auto cancelled = stopped(cancellation);
        return workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>::failure(
            cancelled.error());
    }
    auto worker = registry.create_worker(key, options.worker_budget, cancellation);
    if (!worker) {
        return workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>::failure(worker.error());
    }
    const auto& registration = worker.value()->registration();
    if (registration.implementation_id.rfind("capstone.", 0) != 0) {
        return workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>::failure(error(
            workspace_error_code_t::integrity_failure,
            "Capstone tile decoder resolved a non-Capstone backend"));
    }
    if (options.tile_limits.maximum_tile_bytes < registration.limits.minimum_instruction_bytes ||
        options.tile_limits.maximum_instruction_records >
            options.worker_budget.max_instructions) {
        return workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>::failure(error(
            workspace_error_code_t::invalid_argument,
            "Capstone tile limits exceed the worker decode budget"));
    }
    try {
        std::unique_ptr<worker_owned_capstone_tile_decoder_t> decoder(
            new worker_owned_capstone_tile_decoder_t(worker.take_value(), options.tile_limits));
        return workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>::success(
            std::move(decoder));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::unique_ptr<worker_owned_capstone_tile_decoder_t>>::failure(error(
            workspace_error_code_t::limit_exceeded,
            "Capstone tile decoder allocation exceeded the configured resource budget"));
    }
}

const arch_decoder_key_t& worker_owned_capstone_tile_decoder_t::key() const noexcept
{
    return worker_->key();
}

const arch_decoder_registration_t& worker_owned_capstone_tile_decoder_t::registration() const noexcept
{
    return worker_->registration();
}

const arch_decode_usage_t& worker_owned_capstone_tile_decoder_t::worker_usage() const noexcept
{
    return worker_->usage();
}

const capstone_tile_decode_limits_t& worker_owned_capstone_tile_decoder_t::tile_limits() const noexcept
{
    return tile_limits_;
}

workspace_result_t<capstone_tile_result_t> worker_owned_capstone_tile_decoder_t::decode_tile(
    const provider_snapshot_t& snapshot,
    const capstone_tile_identity_t& identity,
    const cancellation_token_t& cancellation)
{
    if (!worker_) {
        return workspace_result_t<capstone_tile_result_t>::failure(error(
            workspace_error_code_t::integrity_failure,
            "Capstone tile decoder has no worker-owned decoder handle", &identity,
            identity.provider_offset));
    }
    if (cancellation.stop_requested()) {
        auto cancelled = stopped(cancellation);
        return workspace_result_t<capstone_tile_result_t>::failure(cancelled.error());
    }
    auto active = worker_->poll();
    if (!active)
        return workspace_result_t<capstone_tile_result_t>::failure(active.error());
    auto valid = validate_identity(identity, worker_->key(), worker_->registration(),
                                   tile_limits_, snapshot);
    if (!valid)
        return workspace_result_t<capstone_tile_result_t>::failure(valid.error());
    auto source_valid = snapshot.validate_source();
    if (!source_valid)
        return workspace_result_t<capstone_tile_result_t>::failure(source_valid.error());
    const std::uint64_t minimum = worker_->registration().limits.minimum_instruction_bytes;
    if (identity.byte_count / minimum + (identity.byte_count % minimum == 0 ? 0 : 1) >
        tile_limits_.maximum_instruction_records) {
        return workspace_result_t<capstone_tile_result_t>::failure(error(
            workspace_error_code_t::limit_exceeded,
            "Capstone tile can exceed its normalized instruction record budget", &identity,
            identity.provider_offset));
    }
    auto lease = snapshot.lease(identity.provider_offset, identity.byte_count, cancellation);
    if (!lease)
        return workspace_result_t<capstone_tile_result_t>::failure(lease.error());
    try {
        capstone_tile_result_t result;
        result.identity = identity;
        result.usage.input_bytes = identity.byte_count;
        result.usage.snapshot_window_leases = 1;
        result.usage.snapshot_window_bytes = identity.byte_count;
        const std::size_t record_capacity = static_cast<std::size_t>(
            identity.byte_count / minimum + (identity.byte_count % minimum == 0 ? 0 : 1));
        result.instructions.reserve(record_capacity);
        result.operand_facts.reserve(static_cast<std::size_t>(
            std::min<std::uint64_t>(tile_limits_.maximum_operand_facts,
                                    record_capacity * arch_decode_result_t::operand_capacity)));
        result.target_facts.reserve(static_cast<std::size_t>(
            std::min<std::uint64_t>(tile_limits_.maximum_target_facts,
                                    record_capacity * arch_decode_result_t::target_capacity)));
        result.delay_slot_counts.reserve(record_capacity);
        result.coverage.reserve(record_capacity);
        std::uint64_t relative_offset = 0;
        std::uint64_t consecutive_undecodable = 0;
        while (relative_offset < identity.byte_count) {
            if (cancellation.stop_requested()) {
                auto cancelled = stopped(cancellation);
                return workspace_result_t<capstone_tile_result_t>::failure(cancelled.error());
            }
            active = worker_->poll();
            if (!active)
                return workspace_result_t<capstone_tile_result_t>::failure(active.error());
            if (result.coverage.size() >= tile_limits_.maximum_coverage_spans) {
                return workspace_result_t<capstone_tile_result_t>::failure(error(
                    workspace_error_code_t::limit_exceeded,
                    "Capstone tile coverage-span budget exhausted", &identity,
                    identity.provider_offset + relative_offset));
            }
            const std::uint64_t remaining = identity.byte_count - relative_offset;
            const std::uint64_t window = std::min<std::uint64_t>(remaining,
                worker_->registration().limits.maximum_instruction_bytes);
            const auto request = make_request(identity, relative_offset,
                static_cast<std::uint16_t>(window));
            if (!request)
                return workspace_result_t<capstone_tile_result_t>::failure(request.error());
            if (remaining < minimum) {
                if (exceeds(consecutive_undecodable, remaining,
                            tile_limits_.maximum_consecutive_undecodable_bytes)) {
                    return workspace_result_t<capstone_tile_result_t>::failure(error(
                        workspace_error_code_t::decode_failure,
                        "Capstone tile exceeded the consecutive undecodable-byte budget", &identity,
                        identity.provider_offset + relative_offset));
                }
                result.coverage.push_back(coverage(request.value(), remaining,
                    coverage_reason_t::undecodable, 0, workspace_error_code_t::decode_failure));
                ++result.usage.coverage_spans;
                result.usage.undecodable_bytes += remaining;
                result.usage.bytes_consumed += remaining;
                break;
            }
            arch_decode_result_t decoded;
            ++result.usage.decode_attempts;
            auto decoded_result = worker_->decode_one(lease.value(), identity.provider_offset,
                                                      request.value(), decoded);
            if (decoded_result) {
                if (decoded.instruction.length == 0 || decoded.instruction.length > remaining) {
                    return workspace_result_t<capstone_tile_result_t>::failure(error(
                        workspace_error_code_t::integrity_failure,
                        "Capstone tile worker produced an out-of-range instruction length", &identity,
                        identity.provider_offset + relative_offset));
                }
                result.coverage.push_back(coverage(request.value(), decoded.instruction.length,
                    coverage_reason_t::decoded, identity.confidence, workspace_error_code_t::none));
                ++result.usage.coverage_spans;
                if (result.instructions.size() >= tile_limits_.maximum_instruction_records ||
                    result.operand_facts.size() >
                        (std::numeric_limits<std::uint32_t>::max)() - decoded.operand_count ||
                    result.target_facts.size() >
                        (std::numeric_limits<std::uint32_t>::max)() - decoded.target_count ||
                    result.operand_facts.size() + decoded.operand_count >
                        tile_limits_.maximum_operand_facts ||
                    result.target_facts.size() + decoded.target_count >
                        tile_limits_.maximum_target_facts) {
                    return workspace_result_t<capstone_tile_result_t>::failure(error(
                        workspace_error_code_t::limit_exceeded,
                        "Capstone tile normalized fact budget exhausted", &identity,
                        identity.provider_offset + relative_offset));
                }
                auto instruction = decoded.instruction;
                instruction.operand_fact_begin = static_cast<std::uint32_t>(result.operand_facts.size());
                instruction.operand_fact_count = decoded.operand_count;
                instruction.target_fact_begin = static_cast<std::uint32_t>(result.target_facts.size());
                instruction.target_fact_count = decoded.target_count;
                result.operand_facts.insert(result.operand_facts.end(), decoded.operands.begin(),
                                            decoded.operands.begin() + decoded.operand_count);
                result.target_facts.insert(result.target_facts.end(), decoded.targets.begin(),
                                           decoded.targets.begin() + decoded.target_count);
                result.instructions.push_back(std::move(instruction));
                result.delay_slot_counts.push_back(decoded.delay_slot_count);
                ++result.usage.instructions;
                result.usage.operand_facts += decoded.operand_count;
                result.usage.target_facts += decoded.target_count;
                result.usage.decoded_bytes += decoded.instruction.length;
                result.usage.bytes_consumed += decoded.instruction.length;
                relative_offset += decoded.instruction.length;
                consecutive_undecodable = 0;
                continue;
            }
            if (decoded_result.error().code != workspace_error_code_t::decode_failure) {
                return workspace_result_t<capstone_tile_result_t>::failure(decoded_result.error());
            }
            const std::uint64_t progress = std::min<std::uint64_t>(remaining,
                worker_->registration().limits.instruction_alignment);
            if (progress == 0 || exceeds(consecutive_undecodable, progress,
                                         tile_limits_.maximum_consecutive_undecodable_bytes)) {
                return workspace_result_t<capstone_tile_result_t>::failure(error(
                    workspace_error_code_t::decode_failure,
                    "Capstone tile exceeded the consecutive undecodable-byte budget", &identity,
                    identity.provider_offset + relative_offset));
            }
            result.coverage.push_back(coverage(request.value(), progress,
                coverage_reason_t::undecodable, 0, workspace_error_code_t::decode_failure));
            ++result.usage.coverage_spans;
            result.usage.undecodable_bytes += progress;
            result.usage.bytes_consumed += progress;
            consecutive_undecodable += progress;
            relative_offset += progress;
        }
        return workspace_result_t<capstone_tile_result_t>::success(std::move(result));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<capstone_tile_result_t>::failure(error(
            workspace_error_code_t::limit_exceeded,
            "Capstone tile result allocation exceeded the configured record budget", &identity,
            identity.provider_offset));
    }
}

}
