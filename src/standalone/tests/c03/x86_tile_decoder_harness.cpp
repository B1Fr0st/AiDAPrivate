#include "x86_tile_decoder_harness.hpp"

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
    if (!condition)
        throw std::runtime_error(message);
}

template <typename value_t>
value_t require_value(workspace_result_t<value_t> result, const char* message)
{
    if (!result)
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

std::uint64_t hash_bytes(std::uint64_t hash, const void* data, std::size_t size)
{
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    for (std::size_t index = 0; index < size; ++index) {
        hash ^= bytes[index];
        hash *= 1099511628211ULL;
    }
    return hash;
}

template <typename value_t>
std::uint64_t hash_vector(std::uint64_t hash, const std::vector<value_t>& values)
{
    const auto size = values.size();
    hash = hash_bytes(hash, &size, sizeof(size));
    for (const auto& value : values)
        hash = hash_bytes(hash, &value, sizeof(value));
    return hash;
}

std::uint64_t result_fingerprint(const x86_tile_decode_result_t& result)
{
    std::uint64_t hash = 1469598103934665603ULL;
    hash = hash_bytes(hash, &result.mode, sizeof(result.mode));
    hash = hash_bytes(hash, &result.start_address, sizeof(result.start_address));
    hash = hash_bytes(hash, &result.provider_offset, sizeof(result.provider_offset));
    hash = hash_bytes(hash, &result.byte_count, sizeof(result.byte_count));
    hash = hash_bytes(hash, &result.usage, sizeof(result.usage));
    hash = hash_vector(hash, result.instructions);
    hash = hash_vector(hash, result.operand_facts);
    hash = hash_vector(hash, result.target_facts);
    return hash_vector(hash, result.coverage);
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
    const auto snapshot = materialize_fixture(root / "x64_tile.bin", bytes);
    auto decoder = require_value(worker_owned_x86_tile_decoder_t::create(
        architecture_mode_t::x86_64), "x64 tile worker could not be created");
    const auto request = request_for(relative_address(0x1000, architecture_mode_t::x86_64),
                                     bytes.size(), 0x140000000ULL, 0x4000);
    const auto first = require_value(decoder->decode_tile(*snapshot, request),
                                     "x64 tile decode failed");
    const auto second = require_value(decoder->decode_tile(*snapshot, request),
                                      "repeat x64 tile decode failed");
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
            "x64 tile normalized records are not stable across repeated decode");
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

    auto bounded = request;
    bounded.limits.maximum_invalid_bytes = 2;
    bounded.limits.maximum_coverage_spans = 2;
    const auto exhausted = decoder->decode_tile(*snapshot, bounded);
    require(!exhausted && exhausted.error().code == workspace_error_code_t::limit_exceeded,
            "x64 invalid-byte bound did not fail closed");

    auto instruction_bounded = request;
    instruction_bounded.limits.maximum_instructions = 4;
    instruction_bounded.limits.maximum_operand_facts = 40;
    instruction_bounded.limits.maximum_target_facts = 44;
    const auto instruction_exhausted = decoder->decode_tile(*snapshot, instruction_bounded);
    require(!instruction_exhausted &&
                instruction_exhausted.error().code == workspace_error_code_t::limit_exceeded,
            "x64 instruction resource bound did not fail closed");

    auto mismatched = request;
    mismatched.start_address = relative_address(0x1000, architecture_mode_t::x86_32);
    const auto rejected = decoder->decode_tile(*snapshot, mismatched);
    require(!rejected && rejected.error().code == workspace_error_code_t::invalid_argument,
            "x64 worker accepted a mismatched x86 tile mode");

    cancellation_source_t cancellation;
    cancellation.request_cancel();
    const auto cancelled = decoder->decode_tile(*snapshot, request, cancellation.token());
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
