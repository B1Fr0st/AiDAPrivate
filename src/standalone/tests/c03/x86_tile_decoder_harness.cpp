#include "x86_tile_decoder_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decode/x86_tile_decoder.hpp"
#include "../../src/core/analysis/provider_snapshot.hpp"
#include "../../src/core/analysis/workspace/byte_provider.hpp"

#include <Windows.h>

#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace aida::analysis::c03 {
namespace {

using decode::worker_owned_x86_tile_decoder_t;
using decode::x86_tile_decode_request_t;
using decode::x86_tile_decode_result_t;

using tile_decode_signature_t = workspace_result_t<x86_tile_decode_result_t>
    (worker_owned_x86_tile_decoder_t::*)(const provider_snapshot_t&,
                                         const x86_tile_decode_request_t&,
                                         const cancellation_token_t&);

static_assert(std::is_same_v<decltype(&worker_owned_x86_tile_decoder_t::decode_tile),
                             tile_decode_signature_t>);

void require(bool condition, const char* message)
{
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

template <typename value_t>
value_t require_value(workspace_result_t<value_t> result, const char* message)
{
	const bool accepted = static_cast<bool>(result);
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		accepted, message, __FILE__, __LINE__);
    if (!accepted)
        throw std::runtime_error(message);
    return result.take_value();
}

void write_fixture(const std::filesystem::path& path,
                   const std::vector<std::uint8_t>& bytes)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(static_cast<bool>(output), "fixture output could not be opened");
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    require(static_cast<bool>(output), "fixture output could not be written");
}

std::shared_ptr<provider_snapshot_t> materialize_fixture(
    const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes)
{
    write_fixture(path, bytes);
    auto source = require_value(mapped_file_provider_t::open(path.u8string()),
                                "fixture provider could not be opened");
    return require_value(provider_snapshot_t::materialize(source),
                         "fixture provider could not be materialized");
}

address_t relative_address(std::uint64_t value, architecture_mode_t mode)
{
    address_t address;
    address.space = address_space_id_t::relative_virtual;
    address.value = value;
    address.architecture = mode == architecture_mode_t::x86_64
        ? architecture_id_t::x86_64 : architecture_id_t::x86;
    address.mode = mode;
    return address;
}

x86_tile_decode_request_t request_for(address_t address, std::uint64_t byte_count,
                                      std::uint64_t image_base,
                                      std::uint64_t image_size)
{
    x86_tile_decode_request_t request;
    request.start_address = address;
    request.byte_count = byte_count;
    request.image_base = image_base;
    request.image_size = image_size;
    request.provenance = fact_provenance_t::recursive_decode;
    request.confidence = 93;
    request.stable_source_id = 0xC03B05ULL;
    return request;
}

std::uint64_t hash_byte(std::uint64_t hash, std::uint8_t value)
{
    hash ^= value;
    return hash * 1099511628211ULL;
}

template <typename unsigned_t>
std::uint64_t hash_unsigned(std::uint64_t hash, unsigned_t value)
{
    static_assert(std::is_unsigned_v<unsigned_t>);
    for (std::size_t index = 0; index < sizeof(value); ++index)
        hash = hash_byte(hash, static_cast<std::uint8_t>(value >> (index * 8U)));
    return hash;
}

std::uint64_t hash_address(std::uint64_t hash, const address_t& address)
{
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(address.space));
    hash = hash_unsigned(hash, address.value);
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(address.architecture));
    return hash_unsigned(hash, static_cast<std::uint8_t>(address.mode));
}

std::uint64_t hash_instruction(std::uint64_t hash, const instruction_record_t& instruction)
{
    hash = hash_unsigned(hash, instruction.id);
    hash = hash_address(hash, instruction.address);
    hash = hash_unsigned(hash, instruction.length);
    hash = hash_unsigned(hash, instruction.mnemonic_id);
    hash = hash_unsigned(hash, instruction.opcode_id);
    hash = hash_unsigned(hash, instruction.flow_flags);
    hash = hash_unsigned(hash, instruction.operand_fact_begin);
    hash = hash_unsigned(hash, instruction.operand_fact_count);
    hash = hash_unsigned(hash, instruction.target_fact_begin);
    hash = hash_unsigned(hash, instruction.target_fact_count);
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(instruction.provenance));
    hash = hash_unsigned(hash, instruction.confidence);
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(instruction.coverage));
    return hash_unsigned(hash, instruction.stable_source_id);
}

std::uint64_t hash_operand(std::uint64_t hash, const operand_fact_t& operand)
{
    hash = hash_unsigned(hash, operand.id);
    hash = hash_unsigned(hash, operand.instruction_id);
    hash = hash_unsigned(hash, operand.address_expression_id);
    hash = hash_unsigned(hash, operand.operand_index);
    hash = hash_unsigned(hash, operand.decoder_operand_id);
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(operand.kind));
    hash = hash_unsigned(hash, operand.access);
    hash = hash_unsigned(hash, operand.visibility);
    hash = hash_unsigned(hash, operand.encoding);
    hash = hash_unsigned(hash, operand.memory_type);
    hash = hash_unsigned(hash, operand.access_width);
    hash = hash_unsigned(hash, operand.bit_width);
    hash = hash_unsigned(hash, operand.access_width_bits);
    hash = hash_unsigned(hash, operand.access_count);
    hash = hash_unsigned(hash, operand.element_width_bits);
    hash = hash_unsigned(hash, operand.element_count);
    hash = hash_unsigned(hash, operand.address_width_bits);
    hash = hash_unsigned(hash, operand.reg);
    hash = hash_unsigned(hash, operand.segment_reg);
    hash = hash_unsigned(hash, operand.base_reg);
    hash = hash_unsigned(hash, operand.index_reg);
    hash = hash_unsigned(hash, operand.scale);
    hash = hash_byte(hash, operand.relative ? 1U : 0U);
    hash = hash_byte(hash, operand.signed_value ? 1U : 0U);
    hash = hash_byte(hash, operand.has_displacement ? 1U : 0U);
    hash = hash_byte(hash, operand.has_resolved_expression_value ? 1U : 0U);
    hash = hash_unsigned(hash, static_cast<std::uint64_t>(operand.displacement));
    hash = hash_unsigned(hash, operand.immediate);
    hash = hash_unsigned(hash, operand.resolved_expression_value);
    hash = hash_unsigned(hash, operand.address_components);
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(operand.address_expression));
    return hash_unsigned(hash, static_cast<std::uint8_t>(operand.address_resolution));
}

std::uint64_t hash_target(std::uint64_t hash, const target_fact_t& target)
{
    hash = hash_unsigned(hash, target.instruction_id);
    hash = hash_unsigned(hash, target.operand_fact_id);
    hash = hash_unsigned(hash, target.address_expression_id);
    hash = hash_address(hash, target.target);
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(target.kind));
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(target.resolution));
    hash = hash_unsigned(hash, target.operand_index);
    hash = hash_unsigned(hash, target.access_width_bits);
    hash = hash_unsigned(hash, target.access_count);
    hash = hash_byte(hash, target.direct ? 1U : 0U);
    return hash_byte(hash, target.is_external ? 1U : 0U);
}

std::uint64_t hash_coverage(std::uint64_t hash, const coverage_span_t& coverage)
{
    hash = hash_address(hash, coverage.start);
    hash = hash_unsigned(hash, coverage.size);
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(coverage.reason));
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(coverage.provenance));
    hash = hash_unsigned(hash, coverage.confidence);
    return hash_unsigned(hash, coverage.detail_code);
}

std::uint64_t hash_usage(std::uint64_t hash, const decode::x86_tile_decode_usage_t& usage)
{
    hash = hash_unsigned(hash, usage.input_bytes);
    hash = hash_unsigned(hash, usage.bytes_consumed);
    hash = hash_unsigned(hash, usage.decoded_bytes);
    hash = hash_unsigned(hash, usage.decode_attempts);
    hash = hash_unsigned(hash, usage.instructions);
    hash = hash_unsigned(hash, usage.operand_facts);
    hash = hash_unsigned(hash, usage.target_facts);
    hash = hash_unsigned(hash, usage.invalid_bytes);
    hash = hash_unsigned(hash, usage.coverage_spans);
    hash = hash_unsigned(hash, usage.snapshot_window_leases);
    return hash_unsigned(hash, usage.snapshot_window_bytes);
}

template <typename value_t>
std::uint64_t hash_vector(std::uint64_t hash, const std::vector<value_t>& values,
                          std::uint64_t (*hash_value)(std::uint64_t, const value_t&))
{
    hash = hash_unsigned(hash, static_cast<std::uint64_t>(values.size()));
    for (const auto& value : values)
        hash = hash_value(hash, value);
    return hash;
}

std::uint64_t result_fingerprint(const x86_tile_decode_result_t& result)
{
    std::uint64_t hash = 1469598103934665603ULL;
    hash = hash_unsigned(hash, static_cast<std::uint8_t>(result.mode));
    hash = hash_address(hash, result.start_address);
    hash = hash_unsigned(hash, result.provider_offset);
    hash = hash_unsigned(hash, result.byte_count);
    hash = hash_usage(hash, result.usage);
    hash = hash_vector(hash, result.instructions, &hash_instruction);
    hash = hash_vector(hash, result.operand_facts, &hash_operand);
    hash = hash_vector(hash, result.target_facts, &hash_target);
    return hash_vector(hash, result.coverage, &hash_coverage);
}

const operand_fact_t* first_memory_operand(const x86_tile_decode_result_t& result)
{
    for (const auto& operand : result.operand_facts) {
        if (operand.kind == operand_kind_t::memory)
            return &operand;
    }
    return nullptr;
}

const target_fact_t* find_target(const x86_tile_decode_result_t& result,
                                 target_kind_record_t kind)
{
    for (const auto& target : result.target_facts) {
        if (target.kind == kind)
            return &target;
    }
    return nullptr;
}

void verify_normalized_record_links(const x86_tile_decode_result_t& result)
{
    for (const auto& instruction : result.instructions) {
        require(instruction.id != 0, "instruction record lost its stable identifier");
        const auto operand_end = static_cast<std::uint64_t>(instruction.operand_fact_begin) +
                                 instruction.operand_fact_count;
        const auto target_end = static_cast<std::uint64_t>(instruction.target_fact_begin) +
                                instruction.target_fact_count;
        require(operand_end <= result.operand_facts.size(),
                "instruction operand range is outside the tile record vector");
        require(target_end <= result.target_facts.size(),
                "instruction target range is outside the tile record vector");
        for (std::uint64_t index = instruction.operand_fact_begin; index < operand_end; ++index) {
            const auto& operand = result.operand_facts[static_cast<std::size_t>(index)];
            require(operand.id != 0 && operand.instruction_id == instruction.id,
                    "operand record linkage is not normalized");
        }
        for (std::uint64_t index = instruction.target_fact_begin; index < target_end; ++index) {
            const auto& target = result.target_facts[static_cast<std::size_t>(index)];
            require(target.instruction_id == instruction.id,
                    "target record linkage is not normalized");
            if (target.kind != target_kind_record_t::fallthrough) {
                require(target.operand_fact_id != 0 && target.operand_index != 0xFFU,
                        "resolved target lost its operand linkage");
            }
        }
    }
}

void verify_x64_fixture(const std::filesystem::path& root)
{
    const std::vector<std::uint8_t> bytes{
        0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00,
        0xE8, 0x05, 0x00, 0x00, 0x00,
        0x75, 0x02,
        0xC3,
        0xC7, 0xC7, 0xC7,
        0x90
    };
    const auto equivalent_bytes = std::vector<std::uint8_t>(bytes.begin(), bytes.end());
    const auto first_snapshot = materialize_fixture(root / "x64_tile_first.bin", bytes);
    const auto second_snapshot = materialize_fixture(root / "x64_tile_second.bin", equivalent_bytes);
    auto first_decoder = require_value(worker_owned_x86_tile_decoder_t::create(
        architecture_mode_t::x86_64), "x64 tile worker could not be created");
    auto second_decoder = require_value(worker_owned_x86_tile_decoder_t::create(
        architecture_mode_t::x86_64), "independent x64 tile worker could not be created");
    const auto first_request = request_for(relative_address(0x1000, architecture_mode_t::x86_64),
                                      bytes.size(), 0x140000000ULL, 0x4000);
    const auto second_request = request_for(relative_address(0x1000, architecture_mode_t::x86_64),
        equivalent_bytes.size(), 0x140000000ULL, 0x4000);
    const auto first = require_value(first_decoder->decode_tile(*first_snapshot, first_request),
                                      "x64 tile decode failed");
    const auto second = require_value(second_decoder->decode_tile(*second_snapshot, second_request),
                                       "independent x64 tile decode failed");
    require(first.usage.snapshot_window_leases == 1 &&
                first.usage.snapshot_window_bytes == bytes.size(),
            "x64 tile did not use exactly one snapshot window lease");
    require(first.usage.decode_attempts > first.instructions.size(),
            "x64 tile did not account for invalid-byte decode attempts");
    require(first.usage.invalid_bytes == 3 && first.coverage.size() == 1 &&
                first.coverage.front().size == 3 &&
                first.coverage.front().reason == coverage_reason_t::undecodable,
            "x64 tile did not preserve the bounded invalid-byte run");
    require(first.usage.bytes_consumed == bytes.size() &&
                first.usage.decoded_bytes + first.usage.invalid_bytes == bytes.size(),
            "x64 tile did not make deterministic forward progress");
    require(result_fingerprint(first) == result_fingerprint(second),
            "x64 tile normalized records are not stable across equivalent independent inputs");
    require(first.instructions.size() == 5, "x64 tile instruction count is unexpected");
    verify_normalized_record_links(first);

    const auto* memory = first_memory_operand(first);
    require(memory != nullptr && memory->address_expression ==
                address_expression_kind_t::instruction_relative &&
                memory->has_displacement && memory->has_resolved_expression_value,
            "x64 RIP-relative operand was not normalized");
    const auto* call = find_target(first, target_kind_record_t::call);
    require(call != nullptr && call->direct &&
                call->target.space == address_space_id_t::relative_virtual &&
                call->target.value == 0x1011 &&
                call->resolution == target_resolution_t::image_relative,
            "x64 relative call target was not relocatable");
    const auto* branch = find_target(first, target_kind_record_t::branch);
    require(branch != nullptr && branch->direct && branch->target.value == 0x1010,
            "x64 conditional branch target was not normalized");
    require((first.instructions[1].flow_flags & (flow_call | flow_direct | flow_fallthrough)) ==
                (flow_call | flow_direct | flow_fallthrough),
            "x64 call control flow was not normalized");
    require((first.instructions[2].flow_flags &
             (flow_branch | flow_conditional | flow_direct | flow_fallthrough)) ==
                (flow_branch | flow_conditional | flow_direct | flow_fallthrough),
            "x64 conditional flow was not normalized");
    require((first.instructions[3].flow_flags & (flow_return | flow_terminal | flow_indirect)) ==
                (flow_return | flow_terminal | flow_indirect),
            "x64 return control flow was not normalized");

    auto bounded = first_request;
    bounded.limits.maximum_invalid_bytes = 2;
    bounded.limits.maximum_coverage_spans = 2;
    const auto exhausted = first_decoder->decode_tile(*first_snapshot, bounded);
    require(!exhausted && exhausted.error().code == workspace_error_code_t::limit_exceeded,
            "x64 invalid-byte bound did not fail closed");

    auto instruction_bounded = first_request;
    instruction_bounded.limits.maximum_instructions = 4;
    instruction_bounded.limits.maximum_operand_facts = 40;
    instruction_bounded.limits.maximum_target_facts = 44;
    const auto instruction_exhausted = first_decoder->decode_tile(*first_snapshot,
        instruction_bounded);
    require(!instruction_exhausted &&
                instruction_exhausted.error().code == workspace_error_code_t::limit_exceeded,
            "x64 instruction resource bound did not fail closed");

    auto mismatched = first_request;
    mismatched.start_address = relative_address(0x1000, architecture_mode_t::x86_32);
    const auto rejected = first_decoder->decode_tile(*first_snapshot, mismatched);
    require(!rejected && rejected.error().code == workspace_error_code_t::invalid_argument,
            "x64 worker accepted a mismatched x86 tile mode");

    cancellation_source_t cancellation;
    cancellation.request_cancel();
    const auto cancelled = first_decoder->decode_tile(*first_snapshot, first_request,
        cancellation.token());
    require(!cancelled && cancelled.error().code == workspace_error_code_t::cancelled &&
                cancelled.error().cancellation,
            "x64 tile cancellation was not propagated before leasing");
}

void verify_x86_fixture(const std::filesystem::path& root)
{
    const std::vector<std::uint8_t> bytes{
        0x8B, 0x05, 0x78, 0x56, 0x34, 0x12,
        0xE8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };
    const auto snapshot = materialize_fixture(root / "x86_tile.bin", bytes);
    auto decoder = require_value(worker_owned_x86_tile_decoder_t::create(
        architecture_mode_t::x86_32), "x86 tile worker could not be created");
    const auto request = request_for(relative_address(0x2000, architecture_mode_t::x86_32),
                                     bytes.size(), 0x400000, 0x3000);
    const auto result = require_value(decoder->decode_tile(*snapshot, request),
                                      "x86 tile decode failed");
    require(result.instructions.size() == 3 && result.usage.invalid_bytes == 0,
            "x86 tile decoded an unexpected instruction sequence");
    verify_normalized_record_links(result);
    const auto* memory = first_memory_operand(result);
    require(memory != nullptr && memory->address_expression ==
                address_expression_kind_t::absolute && memory->has_resolved_expression_value,
            "x86 absolute memory operand was not normalized");
    const auto* data = find_target(result, target_kind_record_t::data);
    require(data != nullptr && data->target.space == address_space_id_t::virtual_address &&
                data->target.value == 0x12345678 && data->is_external &&
                data->resolution == target_resolution_t::external_virtual,
            "x86 absolute memory target was not classified as external");
    const auto* call = find_target(result, target_kind_record_t::call);
    require(call != nullptr && call->target.space == address_space_id_t::relative_virtual &&
                call->target.value == 0x200C,
            "x86 relative call target was not relocated");
}

}

int run_x86_tile_decoder_harness()
{
    std::filesystem::path root;
    std::error_code cleanup_error;
    try {
        root = std::filesystem::temp_directory_path() /
            ("aida-c03-x86-tile-" + std::to_string(::GetCurrentProcessId()));
        std::filesystem::remove_all(root, cleanup_error);
        std::filesystem::create_directories(root);
        verify_x64_fixture(root);
        verify_x86_fixture(root);
        std::filesystem::remove_all(root, cleanup_error);
        std::cout << "x86 tile decoder harness passed\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::filesystem::remove_all(root, cleanup_error);
        std::cerr << "x86 tile decoder harness failed: " << error.what() << '\n';
        return 1;
    }
}

}

int main()
{
    return aida::analysis::c03::run_x86_tile_decoder_harness();
}
