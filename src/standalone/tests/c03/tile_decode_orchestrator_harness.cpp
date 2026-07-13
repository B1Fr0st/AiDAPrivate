#include "tile_decode_orchestrator_harness.hpp"

#include "../../src/core/analysis/image_layout_index.hpp"
#include "../../src/core/analysis/packed_analysis_store.hpp"
#include "../../src/core/analysis/provider_snapshot.hpp"
#include "../../src/core/analysis/tile_decode_orchestrator.hpp"
#include "../../src/core/analysis/workspace/byte_provider.hpp"

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace aida::analysis::c03 {
namespace {

void require(bool condition, std::string_view message)
{
    if (!condition)
        throw std::runtime_error(std::string(message));
}

arch_decoder_key_t x64_key()
{
    arch_decoder_key_t key;
    key.architecture = architecture_id_t::x86_64;
    key.mode = architecture_mode_t::x86_64;
    key.endian = endian_t::little;
    key.abi = abi_id_t::windows_x64;
    key.address_width_bits = 64;
    return key;
}

address_t rva_address(std::uint64_t value)
{
    address_t address;
    address.space = address_space_id_t::relative_virtual;
    address.value = value;
    address.architecture = architecture_id_t::x86_64;
    address.mode = architecture_mode_t::x86_64;
    return address;
}

binary_id_t content_id(std::uint8_t seed)
{
    binary_id_t result;
    for (std::size_t index = 0; index < result.bytes.size(); ++index)
        result.bytes[index] = static_cast<std::uint8_t>(seed + index * 13U);
    return result;
}

class mapped_fixture_t final {
public:
    explicit mapped_fixture_t(const std::vector<std::uint8_t>& bytes)
    {
        if (bytes.empty())
            throw std::runtime_error("orchestrator fixture bytes are empty");
        const auto root = std::filesystem::temp_directory_path();
        path_ = root / ("aida-c03-orch-" +
                        std::to_string(static_cast<unsigned long>(GetCurrentProcessId())) + "-" +
                        std::to_string(static_cast<unsigned long long>(GetTickCount64())) + "-" +
                        std::to_string(static_cast<unsigned long long>(next_id_++)) + ".bin");
        std::ofstream output(path_, std::ios::binary | std::ios::trunc);
        if (!output)
            throw std::runtime_error("orchestrator fixture file could not be created");
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        output.close();
        if (!output)
            throw std::runtime_error("orchestrator fixture file could not be committed");
        auto opened = mapped_file_provider_t::open(path_.u8string());
        if (!opened)
            throw std::runtime_error("orchestrator fixture provider could not be opened");
        provider_ = opened.take_value();
        auto captured = provider_snapshot_t::capture(provider_);
        if (!captured)
            throw std::runtime_error("orchestrator fixture snapshot could not be captured");
        snapshot_ = captured.take_value();
    }

    ~mapped_fixture_t()
    {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    mapped_fixture_t(const mapped_fixture_t&) = delete;
    mapped_fixture_t& operator=(const mapped_fixture_t&) = delete;

    const provider_snapshot_t& snapshot() const noexcept { return *snapshot_; }

private:
    inline static std::uint64_t next_id_ = 0;
    std::filesystem::path path_;
    std::shared_ptr<mapped_file_provider_t> provider_;
    std::shared_ptr<provider_snapshot_t> snapshot_;
};

image_layout_index_t build_layout(std::uint64_t text_rva, std::uint64_t text_size,
                                   std::uint64_t text_file_offset,
                                   std::uint64_t provider_size,
                                   std::uint64_t data_rva = 0,
                                   std::uint64_t data_size = 0,
                                   std::uint64_t data_file_offset = 0,
                                   std::uint64_t text_virtual_size = 0)
{
    image_layout_definition_t definition;
    definition.identity.content_id = content_id(7U);
    definition.identity.format = format_id_t::pe32_plus;
    definition.identity.endian = endian_t::little;
    definition.identity.address_width_bits = 64;
    definition.identity.image_base = 0x0000000140000000ULL;
    definition.identity.provider_size = provider_size;

    const auto base = definition.identity.image_base;
    const auto effective_text_virtual_size =
        text_virtual_size == 0 ? text_size : text_virtual_size;

    definition.segments.push_back({10U, ".image", text_rva,
                                    text_rva + (data_size > 0 ? data_size : text_size),
                                    0U, provider_size,
                                    image_permission_read | image_permission_execute});

    definition.sections.push_back({1U, ".text", text_rva, effective_text_virtual_size,
                                     text_file_offset, text_size,
                                     image_permission_read | image_permission_execute});

    definition.mappings.push_back({100U, text_rva, base + text_rva,
                                     effective_text_virtual_size,
                                     text_file_offset, text_size,
                                    image_permission_read | image_permission_execute,
                                    1U, 10U, std::nullopt});

    if (data_size > 0) {
        definition.sections.push_back({2U, ".data", data_rva, data_size,
                                        data_file_offset, data_size,
                                        image_permission_read | image_permission_write});
        definition.mappings.push_back({101U, data_rva, base + data_rva, data_size,
                                        data_file_offset, data_size,
                                        image_permission_read | image_permission_write,
                                        2U, 10U, std::nullopt});
    }

    auto result = image_layout_index_t::build(std::move(definition));
    require(result.has_value(), "orchestrator fixture layout build failed");
    return result.value();
}

enum class mock_completion_fault_t : std::uint8_t {
    none = 0,
    duplicate,
    missing,
    unknown,
    partial
};

struct mock_tile_decode_executor_options_t final {
    std::uint64_t maximum_request_bytes = 64ULL * 1024ULL;
    bool reverse_completions = false;
    bool duplicate_targets = false;
    mock_completion_fault_t completion_fault = mock_completion_fault_t::none;
};

class mock_tile_decode_executor_t final : public tile_decode_executor_t {
public:
    explicit mock_tile_decode_executor_t(
        mock_tile_decode_executor_options_t options = {})
        : options_(options)
    {
        caps_.decoder_key = x64_key();
        caps_.maximum_request_bytes = options_.maximum_request_bytes;
        caps_.minimum_instruction_bytes = 1;
        caps_.maximum_instruction_bytes = 15;
        caps_.instruction_alignment = 1;
        caps_.worker_count = 1;
    }

    const tile_decode_executor_capabilities_t& capabilities() const noexcept override
    {
        return caps_;
    }

    std::uint64_t maximum_observed_gap_request_bytes() const noexcept
    {
        return maximum_observed_gap_request_bytes_;
    }

    const std::vector<tile_decode_request_t>& observed_requests() const noexcept
    {
        return observed_requests_;
    }

    workspace_result_t<std::vector<tile_decode_completion_t>> execute_batch(
        const provider_snapshot_t& snapshot,
        const std::vector<tile_decode_request_t>& requests,
        const cancellation_token_t& cancellation) override
    {
        std::vector<tile_decode_completion_t> completions;
        completions.reserve(requests.size());
        for (const auto& request : requests) {
            observed_requests_.push_back(request);
            if (request.pass == tile_decode_pass_t::gap) {
                maximum_observed_gap_request_bytes_ = (std::max)(
                    maximum_observed_gap_request_bytes_, request.byte_count);
            }
            if (cancellation.stop_requested()) {
                tile_decode_completion_t cancelled;
                cancelled.request_id = request.request_id;
                auto err = make_workspace_error(
                    workspace_error_code_t::cancelled,
                    "mock executor cancelled", "mock_executor");
                err.cancellation = true;
                cancelled.error = std::move(err);
                completions.push_back(std::move(cancelled));
                continue;
            }
            completions.push_back(decode_one(snapshot, request, cancellation));
        }

        if (options_.reverse_completions)
            std::reverse(completions.begin(), completions.end());
        if (!completions.empty()) {
            if (options_.completion_fault == mock_completion_fault_t::duplicate) {
                completions.push_back(completions.front());
            } else if (options_.completion_fault == mock_completion_fault_t::missing) {
                completions.pop_back();
            } else if (options_.completion_fault == mock_completion_fault_t::unknown) {
                completions.front().request_id =
                    (std::numeric_limits<std::uint64_t>::max)();
            } else if (options_.completion_fault == mock_completion_fault_t::partial &&
                       completions.front().records.bytes_consumed != 0) {
                --completions.front().records.bytes_consumed;
            }
        }
        return workspace_result_t<std::vector<tile_decode_completion_t>>::success(
            std::move(completions));
    }

private:
    mock_tile_decode_executor_options_t options_;
    tile_decode_executor_capabilities_t caps_;
    std::uint64_t maximum_observed_gap_request_bytes_ = 0;
    std::vector<tile_decode_request_t> observed_requests_;

    tile_decode_completion_t decode_one(
        const provider_snapshot_t& snapshot,
        const tile_decode_request_t& request,
        const cancellation_token_t& cancellation)
    {
        tile_decode_completion_t completion;
        completion.request_id = request.request_id;

        auto lease_result = snapshot.lease(request.provider_offset, request.byte_count, cancellation);
        if (!lease_result) {
            completion.error = lease_result.error();
            return completion;
        }

        const auto view = lease_result.value();
        const auto* data = view.data();
        const auto size = view.size();

        std::uint64_t offset = 0;
        std::uint64_t invalid_bytes = 0;
        std::uint32_t operand_idx = 0;
        std::uint32_t target_idx = 0;

        while (offset < size) {
            if (cancellation.stop_requested())
                break;

            const auto remaining = size - offset;
            const auto rva = request.start.value + offset;

            instruction_record_t instr;
            instr.address = rva_address(rva);
            instr.provenance = request.provenance;
            instr.confidence = request.confidence;
            instr.stable_source_id = request.stable_source_id;
            instr.operand_fact_begin = operand_idx;
            instr.target_fact_begin = target_idx;

            bool decoded = false;

            if (data[offset] == 0x90 && remaining >= 1) {
                instr.length = 1;
                instr.mnemonic_id = 1;
                instr.opcode_id = 0x90;
                instr.flow_flags = flow_fallthrough;
                instr.coverage = coverage_reason_t::decoded;
                decoded = true;
            } else if (data[offset] == 0xC3 && remaining >= 1) {
                instr.length = 1;
                instr.mnemonic_id = 2;
                instr.opcode_id = 0xC3;
                instr.flow_flags = flow_return | flow_terminal;
                instr.coverage = coverage_reason_t::decoded;
                decoded = true;
            } else if (data[offset] == 0xCC && remaining >= 1) {
                instr.length = 1;
                instr.mnemonic_id = 3;
                instr.opcode_id = 0xCC;
                instr.flow_flags = flow_interrupt | flow_terminal;
                instr.coverage = coverage_reason_t::decoded;
                decoded = true;
            } else if (data[offset] == 0xE8 && remaining >= 5) {
                instr.length = 5;
                instr.mnemonic_id = 4;
                instr.opcode_id = 0xE8;
                instr.flow_flags = flow_call | flow_direct;
                instr.coverage = coverage_reason_t::decoded;
                decoded = true;

                std::int32_t rel32 = 0;
                std::memcpy(&rel32, data + offset + 1, 4);
                const auto target_rva = rva + 5 + static_cast<std::int64_t>(rel32);

                target_fact_t target;
                target.instruction_id = 0;
                target.target = rva_address(static_cast<std::uint64_t>(target_rva));
                target.kind = target_kind_record_t::call;
                target.resolution = target_resolution_t::image_relative;
                target.direct = true;
                completion.records.target_facts.push_back(target);
                ++target_idx;
                if (options_.duplicate_targets) {
                    completion.records.target_facts.push_back(target);
                    ++target_idx;
                }

                coverage_span_t span;
                span.start = rva_address(rva);
                span.size = 5;
                span.reason = coverage_reason_t::decoded;
                span.provenance = request.provenance;
                span.confidence = request.confidence;
                completion.records.coverage.push_back(span);
            } else if (data[offset] == 0xE9 && remaining >= 5) {
                instr.length = 5;
                instr.mnemonic_id = 5;
                instr.opcode_id = 0xE9;
                instr.flow_flags = flow_branch | flow_direct;
                instr.coverage = coverage_reason_t::decoded;
                decoded = true;

                std::int32_t rel32 = 0;
                std::memcpy(&rel32, data + offset + 1, 4);
                const auto target_rva = rva + 5 + static_cast<std::int64_t>(rel32);

                target_fact_t target;
                target.instruction_id = 0;
                target.target = rva_address(static_cast<std::uint64_t>(target_rva));
                target.kind = target_kind_record_t::branch;
                target.resolution = target_resolution_t::image_relative;
                target.direct = true;
                completion.records.target_facts.push_back(target);
                ++target_idx;
                if (options_.duplicate_targets) {
                    completion.records.target_facts.push_back(target);
                    ++target_idx;
                }

                coverage_span_t span;
                span.start = rva_address(rva);
                span.size = 5;
                span.reason = coverage_reason_t::decoded;
                span.provenance = request.provenance;
                span.confidence = request.confidence;
                completion.records.coverage.push_back(span);
            } else if (data[offset] == 0x48 && remaining >= 3 &&
                       data[offset + 1] == 0x89 && data[offset + 2] == 0xC0) {
                instr.length = 3;
                instr.mnemonic_id = 6;
                instr.opcode_id = 0x89;
                instr.flow_flags = flow_fallthrough;
                instr.coverage = coverage_reason_t::decoded;
                decoded = true;
            } else if (data[offset] == 0x48 && remaining >= 7 &&
                       data[offset + 1] == 0x8B && data[offset + 2] == 0x05) {
                instr.length = 7;
                instr.mnemonic_id = 7;
                instr.opcode_id = 0x8B;
                instr.flow_flags = flow_fallthrough;
                instr.coverage = coverage_reason_t::decoded;
                decoded = true;

                std::int32_t displacement = 0;
                std::memcpy(&displacement, data + offset + 3, 4);
                const auto target_rva = static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(rva) + 7 + displacement);

                operand_fact_t operand;
                operand.id = static_cast<entity_id_t>(operand_idx) + 1;
                operand.address_expression_id = operand.id;
                operand.operand_index = 0;
                operand.kind = operand_kind_t::memory;
                operand.access_width_bits = 64;
                operand.access_count = 1;
                operand.address_width_bits = 64;
                operand.base_reg = 1;
                operand.has_displacement = true;
                operand.has_resolved_expression_value = true;
                operand.displacement = displacement;
                operand.resolved_expression_value = target_rva;
                operand.address_components = address_component_base |
                    address_component_displacement |
                    address_component_instruction_pointer;
                operand.address_expression =
                    address_expression_kind_t::instruction_relative;
                operand.address_resolution = target_resolution_t::image_relative;
                completion.records.operand_facts.push_back(operand);
                ++operand_idx;

                target_fact_t target;
                target.operand_fact_id = operand.id;
                target.address_expression_id = operand.address_expression_id;
                target.target = rva_address(target_rva);
                target.kind = target_kind_record_t::data;
                target.resolution = target_resolution_t::image_relative;
                target.operand_index = operand.operand_index;
                target.access_width_bits = operand.access_width_bits;
                target.access_count = operand.access_count;
                completion.records.target_facts.push_back(target);
                ++target_idx;
            }

            if (!decoded) {
                ++invalid_bytes;
                coverage_span_t span;
                span.start = rva_address(rva);
                span.size = 1;
                span.reason = coverage_reason_t::undecodable;
                span.provenance = request.provenance;
                span.confidence = request.confidence;
                completion.records.coverage.push_back(span);
                ++offset;
                continue;
            }

            instr.operand_fact_count = static_cast<std::uint16_t>(operand_idx - instr.operand_fact_begin);
            instr.target_fact_count = static_cast<std::uint16_t>(target_idx - instr.target_fact_begin);

            if (instr.operand_fact_count == 0)
                instr.operand_fact_begin = 0;
            if (instr.target_fact_count == 0)
                instr.target_fact_begin = 0;

            completion.records.instructions.push_back(instr);
            completion.records.delay_slot_counts.push_back(0);

            if ((instr.flow_flags & (flow_call | flow_branch | flow_return | flow_interrupt)) == 0) {
                coverage_span_t span;
                span.start = rva_address(rva);
                span.size = instr.length;
                span.reason = coverage_reason_t::decoded;
                span.provenance = request.provenance;
                span.confidence = request.confidence;
                completion.records.coverage.push_back(span);
            }

            offset += instr.length;
        }

        completion.records.bytes_consumed = offset;
        completion.records.invalid_bytes = invalid_bytes;
        return completion;
    }
};

class adversarial_tile_decode_executor_t final : public tile_decode_executor_t {
public:
    adversarial_tile_decode_executor_t()
    {
        capabilities_.decoder_key = x64_key();
        capabilities_.maximum_request_bytes = 32;
        capabilities_.minimum_instruction_bytes = 1;
        capabilities_.maximum_instruction_bytes = 15;
        capabilities_.instruction_alignment = 1;
        capabilities_.worker_count = 1;
    }

    const tile_decode_executor_capabilities_t& capabilities() const noexcept override
    {
        return capabilities_;
    }

    workspace_result_t<std::vector<tile_decode_completion_t>> execute_batch(
        const provider_snapshot_t&,
        const std::vector<tile_decode_request_t>& requests,
        const cancellation_token_t&) override
    {
        std::vector<tile_decode_completion_t> completions;
        completions.reserve(requests.size());
        for (const auto& request : requests) {
            tile_decode_completion_t completion;
            completion.request_id = request.request_id;
            if (request.pass == tile_decode_pass_t::recursive) {
                instruction_record_t first;
                first.address = rva_address(request.start.value);
                first.length = 3;
                first.mnemonic_id = 10;
                first.opcode_id = 0x100;
                first.flow_flags = flow_terminal;
                first.provenance = request.provenance;
                first.confidence = 60;
                first.stable_source_id = 10;
                first.operand_fact_begin = 0;
                first.operand_fact_count = 2;

                operand_fact_t destination;
                destination.operand_index = 0;
                destination.kind = operand_kind_t::reg;
                destination.bit_width = 64;
                destination.reg = 1;
                completion.records.operand_facts.push_back(destination);
                auto source = destination;
                source.operand_index = 1;
                source.reg = 2;
                completion.records.operand_facts.push_back(source);
                completion.records.instructions.push_back(first);

                auto overlap = first;
                overlap.address = rva_address(request.start.value + 1);
                overlap.length = 2;
                overlap.mnemonic_id = 11;
                overlap.opcode_id = 0x101;
                overlap.confidence = 50;
                overlap.stable_source_id = 11;
                overlap.operand_fact_begin = 0;
                overlap.operand_fact_count = 0;
                completion.records.instructions.push_back(overlap);

                auto replacement = first;
                replacement.length = 2;
                replacement.mnemonic_id = 12;
                replacement.opcode_id = 0x102;
                replacement.confidence = 90;
                replacement.stable_source_id = 9;
                completion.records.instructions.push_back(replacement);

                auto outside = first;
                outside.address = rva_address(request.owned_end_rva);
                outside.length = 1;
                outside.mnemonic_id = 13;
                outside.opcode_id = 0x103;
                outside.confidence = 100;
                outside.stable_source_id = 8;
                completion.records.instructions.push_back(outside);

                completion.records.delay_slot_counts.resize(
                    completion.records.instructions.size(), 0);

                coverage_span_t clipped;
                clipped.start = rva_address(request.owned_end_rva - 1);
                clipped.size = 4;
                clipped.reason = coverage_reason_t::decoded;
                clipped.provenance = request.provenance;
                clipped.confidence = request.confidence;
                completion.records.coverage.push_back(clipped);

                auto outside_coverage = clipped;
                outside_coverage.start = rva_address(request.owned_end_rva);
                outside_coverage.size = 1;
                completion.records.coverage.push_back(outside_coverage);
                completion.records.bytes_consumed = request.byte_count;
            } else {
                coverage_span_t undecodable;
                undecodable.start = request.start;
                undecodable.size = request.byte_count;
                undecodable.reason = coverage_reason_t::undecodable;
                undecodable.provenance = request.provenance;
                undecodable.confidence = request.confidence;
                completion.records.coverage.push_back(undecodable);
                completion.records.bytes_consumed = request.byte_count;
                completion.records.invalid_bytes = request.byte_count;
            }
            completions.push_back(std::move(completion));
        }
        return workspace_result_t<std::vector<tile_decode_completion_t>>::success(
            std::move(completions));
    }

private:
    tile_decode_executor_capabilities_t capabilities_;
};

class in_flight_cancelling_executor_t final : public tile_decode_executor_t {
public:
    explicit in_flight_cancelling_executor_t(cancellation_source_t& source)
        : source_(source)
    {
        capabilities_.decoder_key = x64_key();
        capabilities_.maximum_request_bytes = 64;
        capabilities_.minimum_instruction_bytes = 1;
        capabilities_.maximum_instruction_bytes = 15;
        capabilities_.instruction_alignment = 1;
        capabilities_.worker_count = 1;
    }

    const tile_decode_executor_capabilities_t& capabilities() const noexcept override
    {
        return capabilities_;
    }

    workspace_result_t<std::vector<tile_decode_completion_t>> execute_batch(
        const provider_snapshot_t&,
        const std::vector<tile_decode_request_t>& requests,
        const cancellation_token_t&) override
    {
        std::vector<tile_decode_completion_t> completions;
        completions.reserve(requests.size());
        for (const auto& request : requests) {
            tile_decode_completion_t completion;
            completion.request_id = request.request_id;
            completions.push_back(std::move(completion));
        }
        source_.request_cancel();
        return workspace_result_t<std::vector<tile_decode_completion_t>>::success(
            std::move(completions));
    }

private:
    cancellation_source_t& source_;
    tile_decode_executor_capabilities_t capabilities_;
};

template <typename T,
          std::enable_if_t<std::is_integral_v<T> &&
                           !std::is_same_v<T, bool>, int> = 0>
void append_integral(std::vector<std::uint8_t>& output, T value)
{
    using unsigned_t = std::make_unsigned_t<T>;
    auto encoded = static_cast<std::uint64_t>(
        static_cast<unsigned_t>(value));
    for (std::size_t index = 0; index < sizeof(unsigned_t); ++index) {
        output.push_back(static_cast<std::uint8_t>(encoded & 0xFFU));
        encoded >>= 8U;
    }
}

void append_integral(std::vector<std::uint8_t>& output, bool value)
{
    output.push_back(value ? 1U : 0U);
}

template <typename T, std::enable_if_t<std::is_enum_v<T>, int> = 0>
void append_enum(std::vector<std::uint8_t>& output, T value)
{
    append_integral(output, static_cast<std::underlying_type_t<T>>(value));
}

void append_address(std::vector<std::uint8_t>& output, const address_t& address)
{
    append_enum(output, address.space);
    append_integral(output, address.value);
    append_enum(output, address.architecture);
    append_enum(output, address.mode);
}

void append_string(std::vector<std::uint8_t>& output, std::string_view value)
{
    append_integral(output, static_cast<std::uint64_t>(value.size()));
    for (const auto character : value) {
        output.push_back(static_cast<std::uint8_t>(
            static_cast<unsigned char>(character)));
    }
}

std::vector<std::uint8_t> orchestration_bytes(
    const tile_decode_orchestration_result_t& result)
{
    std::vector<std::uint8_t> output;
    append_integral(output, static_cast<std::uint64_t>(result.shards.size()));
    for (const auto& shard : result.shards) {
        append_integral(output, shard.tile_id);
        append_integral(output, shard.shard_id);
        append_integral(output, shard.instruction_count);
        append_integral(output, shard.operand_count);
        append_integral(output, shard.target_count);
        append_integral(output, shard.edge_count);
    }

    append_integral(output,
                    static_cast<std::uint64_t>(result.delay_slot_counts.size()));
    for (const auto count : result.delay_slot_counts)
        append_integral(output, count);

    append_integral(output,
                    static_cast<std::uint64_t>(result.cross_tile_edges.size()));
    for (const auto& edge : result.cross_tile_edges) {
        append_integral(output, edge.source_tile_id);
        append_integral(output, edge.target_tile_id);
        append_address(output, edge.source);
        append_address(output, edge.target);
        append_enum(output, edge.kind);
    }

    append_integral(output, static_cast<std::uint64_t>(result.coverage.size()));
    for (const auto& span : result.coverage) {
        append_address(output, span.start);
        append_integral(output, span.size);
        append_enum(output, span.reason);
        append_enum(output, span.provenance);
        append_integral(output, span.confidence);
        append_integral(output, span.detail_code);
    }

    const auto& statistics = result.statistics;
    append_integral(output, statistics.initialized_executable_bytes);
    append_integral(output, statistics.zero_fill_executable_bytes);
    append_integral(output, statistics.recursive_requests);
    append_integral(output, statistics.gap_requests);
    append_integral(output, statistics.decoded_instruction_candidates);
    append_integral(output, statistics.accepted_instructions);
    append_integral(output, statistics.duplicate_instruction_candidates);
    append_integral(output, statistics.overlap_instruction_candidates);
    append_integral(output, statistics.accepted_operands);
    append_integral(output, statistics.accepted_target_facts);
    append_integral(output, statistics.accepted_edges);
    append_integral(output, statistics.duplicate_edges);
    append_integral(output, statistics.cross_tile_edges);
    append_integral(output, statistics.invalid_bytes);
    append_integral(output, statistics.invalid_runs);
    append_integral(output, statistics.frontier.unique_seed_count);
    append_integral(output, statistics.frontier.pending_seed_count);
    append_integral(output, statistics.frontier.claimed_seed_count);
    append_integral(output, statistics.frontier.duplicate_seed_count);
    append_integral(output, statistics.frontier.strengthened_seed_count);
    append_integral(output, statistics.frontier.outside_seed_count);
    append_integral(output, statistics.frontier.cross_tile_route_count);

    append_integral(output, result.packed_store != nullptr);
    if (result.packed_store == nullptr)
        return output;

    const auto& store = *result.packed_store;
    append_integral(output, store.instruction_count());
    append_integral(output, store.operand_count());
    append_integral(output, store.edge_count());
    append_integral(output, store.string_record_count());
    append_integral(output, store.symbol_count());
    append_integral(output, store.address_expression_count());
    append_integral(output, store.basic_block_count());
    append_integral(output, store.function_count());
    append_integral(output, store.function_chunk_count());
    append_integral(output, store.target_fact_count());
    append_integral(output, store.xref_count());
    append_integral(output, store.coverage_count());

    for (std::size_t index = 0; index < store.instruction_count(); ++index) {
        const auto instruction = store.instruction(index);
        require(instruction.has_value(), "packed instruction view is unavailable");
        append_integral(output, instruction->id.value());
        append_address(output, instruction->address);
        append_integral(output, instruction->length);
        append_integral(output, instruction->mnemonic_id);
        append_string(output, instruction->mnemonic);
        append_integral(output, instruction->opcode_id);
        append_integral(output, instruction->flow_flags);
        append_integral(output, instruction->first_operand);
        append_integral(output, instruction->operand_count);
        append_enum(output, instruction->provenance);
        append_integral(output, instruction->confidence);
        append_enum(output, instruction->coverage);
        append_integral(output, instruction->stable_source_id);
    }

    for (std::size_t index = 0; index < store.operand_count(); ++index) {
        const auto operand = store.operand(index);
        require(operand.has_value(), "packed operand view is unavailable");
        append_integral(output, operand->id.value());
        append_integral(output, operand->instruction_id.value());
        append_integral(output, operand->address_expression_id.value());
        append_integral(output, operand->operand_index);
        append_integral(output, operand->decoder_operand_id);
        append_enum(output, operand->kind);
        append_integral(output, operand->access);
        append_integral(output, operand->visibility);
        append_integral(output, operand->encoding);
        append_integral(output, operand->memory_type);
        append_integral(output, operand->access_width);
        append_integral(output, operand->bit_width);
        append_integral(output, operand->access_width_bits);
        append_integral(output, operand->access_count);
        append_integral(output, operand->element_width_bits);
        append_integral(output, operand->element_count);
        append_integral(output, operand->address_width_bits);
        append_integral(output, operand->reg);
        append_integral(output, operand->segment_reg);
        append_integral(output, operand->base_reg);
        append_integral(output, operand->index_reg);
        append_integral(output, operand->scale);
        append_integral(output, operand->relative);
        append_integral(output, operand->signed_value);
        append_integral(output, operand->has_displacement);
        append_integral(output, operand->has_resolved_expression_value);
        append_integral(output, operand->displacement);
        append_integral(output, operand->immediate);
        append_integral(output, operand->resolved_expression_value);
        append_integral(output, operand->address_components);
        append_enum(output, operand->address_expression_kind);
        append_enum(output, operand->address_resolution);
    }

    for (std::size_t index = 0; index < store.address_expression_count(); ++index) {
        const auto expression = store.address_expression(index);
        require(expression.has_value(),
                "packed address-expression view is unavailable");
        append_integral(output, expression->id.value());
        append_integral(output, expression->instruction_id.value());
        append_integral(output, expression->base_reg);
        append_integral(output, expression->index_reg);
        append_integral(output, expression->scale);
        append_integral(output, expression->displacement);
        append_integral(output, expression->segment_reg);
        append_integral(output, expression->address_components);
        append_enum(output, expression->kind);
        append_enum(output, expression->resolution);
        append_enum(output, expression->provenance);
        append_integral(output, expression->confidence);
    }

    for (std::size_t index = 0; index < store.target_fact_count(); ++index) {
        const auto target = store.target_fact(index);
        require(target.has_value(), "packed target-fact view is unavailable");
        append_integral(output, target->id.value());
        append_integral(output, target->instruction_id.value());
        append_integral(output, target->operand_id.value());
        append_integral(output, target->address_expression_id.value());
        append_address(output, target->target);
        append_enum(output, target->kind);
        append_enum(output, target->resolution);
        append_integral(output, target->operand_index);
        append_integral(output, target->access_width_bits);
        append_integral(output, target->access_count);
        append_integral(output, target->direct);
        append_integral(output, target->is_external);
        append_enum(output, target->provenance);
        append_integral(output, target->confidence);
    }

    for (std::size_t index = 0; index < store.edge_count(); ++index) {
        const auto edge = store.edge(index);
        require(edge.has_value(), "packed edge view is unavailable");
        append_integral(output, edge->id.value());
        append_integral(output, edge->source_entity.value());
        append_integral(output, edge->target_entity.has_value());
        if (edge->target_entity)
            append_integral(output, edge->target_entity->value());
        append_address(output, edge->source);
        append_address(output, edge->target);
        append_enum(output, edge->kind);
        append_enum(output, edge->provenance);
        append_integral(output, edge->confidence);
    }

    for (std::size_t index = 0; index < store.coverage_count(); ++index) {
        const auto coverage = store.coverage(index);
        require(coverage.has_value(), "packed coverage view is unavailable");
        append_integral(output, coverage->id.value());
        append_address(output, coverage->span_begin);
        append_address(output, coverage->span_end);
        append_enum(output, coverage->reason);
        append_integral(output, coverage->undecodable_count);
        append_enum(output, coverage->provenance);
        append_integral(output, coverage->confidence);
    }

    return output;
}

tile_decode_orchestrator_limits_t small_limits()
{
    tile_decode_orchestrator_limits_t limits;
    limits.target_tile_bytes = 256;
    limits.maximum_tiles = 64;
    limits.maximum_frontier_seeds = 4096;
    limits.maximum_frontier_wave = 64;
    limits.maximum_decode_requests = 4096;
    limits.maximum_instructions = 65536;
    limits.maximum_operand_facts = 65536;
    limits.maximum_edges = 65536;
    limits.maximum_coverage_spans = 65536;
    limits.invalid_run_policy.maximum_invalid_bytes_per_tile = 128;
    limits.invalid_run_policy.maximum_invalid_runs_per_tile = 32;
    limits.invalid_run_policy.maximum_gap_resynchronization_bytes = 256;
    return limits;
}

tile_decode_seed_t export_seed(std::uint64_t rva, std::uint64_t source_id = 1)
{
    tile_decode_seed_t seed;
    seed.address = rva_address(rva);
    seed.provenance = fact_provenance_t::export_entry;
    seed.confidence = 100;
    seed.stable_source_id = source_id;
    return seed;
}

void require_limit_exceeded(
    const workspace_result_t<tile_decode_orchestration_result_t>& result,
    std::string_view message)
{
    require(!result, message);
    require(result.error().code == workspace_error_code_t::limit_exceeded,
            "orchestrator exhaustion did not return limit_exceeded");
    const auto resource = std::find_if(
        result.error().details.begin(), result.error().details.end(),
        [](const auto& detail) { return detail.first == "resource"; });
    require(resource != result.error().details.end() && !resource->second.empty(),
            "orchestrator exhaustion omitted typed resource metadata");
}

void test_request_correlation_and_completion_contract()
{
    std::vector<std::uint8_t> text(8, 0x90);
    text.back() = 0xC3;
    std::vector<std::uint8_t> file_bytes(0x800, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, text.size(), 0x400, file_bytes.size());
    auto limits = small_limits();
    limits.target_tile_bytes = 8;
    limits.seed_executable_range_starts = false;

    auto orchestrator_result = tile_decode_orchestrator_t::create(limits);
    require(orchestrator_result.has_value(),
            "request-correlation orchestrator create failed");
    const std::vector<tile_decode_seed_t> seeds{export_seed(0x1000)};

    mock_tile_decode_executor_options_t ordered_options;
    ordered_options.maximum_request_bytes = 1;
    ordered_options.reverse_completions = true;
    mock_tile_decode_executor_t ordered_executor(ordered_options);
    auto ordered_result = orchestrator_result.value().run(
        fixture.snapshot(), layout, seeds, ordered_executor);
    require(ordered_result.has_value(),
            "globally numbered out-of-order completions were not correlated");
    require(ordered_result.value().packed_store != nullptr,
            "request-correlation run produced no packed store");
    require(ordered_result.value().packed_store->instruction_count() == text.size(),
            "request correlation lost recursively scheduled instructions");

    const mock_completion_fault_t faults[] = {
        mock_completion_fault_t::duplicate,
        mock_completion_fault_t::missing,
        mock_completion_fault_t::unknown,
        mock_completion_fault_t::partial};
    for (const auto fault : faults) {
        mock_tile_decode_executor_options_t fault_options;
        fault_options.maximum_request_bytes = text.size();
        fault_options.completion_fault = fault;
        mock_tile_decode_executor_t fault_executor(fault_options);
        auto fault_result = orchestrator_result.value().run(
            fixture.snapshot(), layout, seeds, fault_executor);
        require(!fault_result,
                "malformed completion cardinality was accepted");
        require(fault_result.error().code ==
                    workspace_error_code_t::integrity_failure,
                "malformed completion cardinality returned the wrong error type");
    }
}

void test_duplicate_overlap_and_ownership()
{
    std::vector<std::uint8_t> text(0x10, 0x90);
    std::vector<std::uint8_t> file_bytes(0x800, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, text.size(), 0x400, file_bytes.size());
    auto limits = small_limits();
    limits.target_tile_bytes = 8;
    limits.seed_executable_range_starts = false;

    auto orchestrator_result = tile_decode_orchestrator_t::create(limits);
    require(orchestrator_result.has_value(),
            "ownership orchestrator create failed");
    adversarial_tile_decode_executor_t executor;
    const std::vector<tile_decode_seed_t> seeds{export_seed(0x1000)};
    auto run_result = orchestrator_result.value().run(
        fixture.snapshot(), layout, seeds, executor);
    require(run_result.has_value(), "ownership decode run failed");

    const auto& result = run_result.value();
    require(result.packed_store != nullptr,
            "ownership decode produced no packed store");
    require(result.packed_store->instruction_count() == 1,
            "duplicate or overlapping instructions escaped arbitration");
    const auto instruction = result.packed_store->instruction(0);
    require(instruction.has_value(),
            "retained ownership instruction is unavailable");
    require(instruction->address.value == 0x1000 && instruction->length == 2 &&
                instruction->mnemonic_id == 12,
            "strongest duplicate instruction was not retained");
    require(result.statistics.duplicate_instruction_candidates == 1,
            "duplicate instruction candidate was not counted");
    require(result.statistics.overlap_instruction_candidates == 1,
            "overlap instruction candidate was not counted");
    require(result.statistics.accepted_instructions == 1 &&
                result.statistics.accepted_operands == 2,
            "accepted instruction or operand totals do not reflect retained ownership");
    const auto clipped_coverage = std::find_if(result.coverage.begin(),
        result.coverage.end(), [](const coverage_span_t& span) {
            return span.reason == coverage_reason_t::decoded &&
                span.start.value == 0x1007 && span.size == 1;
        });
    require(clipped_coverage != result.coverage.end(),
            "cross-boundary coverage was not clipped to tile ownership");
    const auto escaped_coverage = std::find_if(result.coverage.begin(),
        result.coverage.end(), [](const coverage_span_t& span) {
            return span.reason == coverage_reason_t::decoded &&
                span.start.value >= 0x1008;
        });
    require(escaped_coverage == result.coverage.end(),
            "out-of-ownership decoded coverage was retained");
}

void test_typed_exhaustion_failures()
{
    std::vector<std::uint8_t> text(0x40, 0x90);
    std::vector<std::uint8_t> file_bytes(0x800, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);
    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, text.size(), 0x400, file_bytes.size());
    const std::vector<tile_decode_seed_t> seeds{export_seed(0x1000)};

    {
        auto limits = small_limits();
        limits.target_tile_bytes = 8;
        limits.maximum_tiles = 1;
        limits.seed_executable_range_starts = false;
        auto orchestrator = tile_decode_orchestrator_t::create(limits);
        require(orchestrator.has_value(), "tile-limit orchestrator create failed");
        mock_tile_decode_executor_t executor;
        auto result = orchestrator.value().run(
            fixture.snapshot(), layout, seeds, executor);
        require_limit_exceeded(result, "tile exhaustion was silently truncated");
    }

    {
        auto limits = small_limits();
        limits.target_tile_bytes = text.size();
        limits.maximum_decode_requests = 1;
        limits.seed_executable_range_starts = false;
        auto orchestrator = tile_decode_orchestrator_t::create(limits);
        require(orchestrator.has_value(), "request-limit orchestrator create failed");
        mock_tile_decode_executor_options_t options;
        options.maximum_request_bytes = 1;
        mock_tile_decode_executor_t executor(options);
        auto result = orchestrator.value().run(
            fixture.snapshot(), layout, seeds, executor);
        require_limit_exceeded(result,
                               "decode request exhaustion was silently truncated");
    }

    {
        auto limits = small_limits();
        limits.target_tile_bytes = text.size();
        limits.maximum_instructions = 2;
        limits.seed_executable_range_starts = false;
        auto orchestrator = tile_decode_orchestrator_t::create(limits);
        require(orchestrator.has_value(),
                "instruction-limit orchestrator create failed");
        mock_tile_decode_executor_t executor;
        auto result = orchestrator.value().run(
            fixture.snapshot(), layout, seeds, executor);
        require_limit_exceeded(result,
                               "instruction exhaustion was detected too late");
    }

    {
        auto limits = small_limits();
        limits.target_tile_bytes = text.size();
        limits.maximum_operand_facts = 1;
        limits.seed_executable_range_starts = false;
        auto orchestrator = tile_decode_orchestrator_t::create(limits);
        require(orchestrator.has_value(), "operand-limit orchestrator create failed");
        adversarial_tile_decode_executor_t executor;
        auto result = orchestrator.value().run(
            fixture.snapshot(), layout, seeds, executor);
        require_limit_exceeded(result,
                               "operand exhaustion was detected too late");
    }

    {
        auto limits = small_limits();
        limits.target_tile_bytes = text.size();
        limits.maximum_coverage_spans = 1;
        limits.seed_executable_range_starts = false;
        auto orchestrator = tile_decode_orchestrator_t::create(limits);
        require(orchestrator.has_value(),
                "coverage-limit orchestrator create failed");
        mock_tile_decode_executor_t executor;
        auto result = orchestrator.value().run(
            fixture.snapshot(), layout, seeds, executor);
        require_limit_exceeded(result,
                               "coverage span exhaustion was not enforced");
    }

    {
        auto edge_bytes = text;
        edge_bytes[0x00] = 0xE8;
        edge_bytes[0x01] = 0x0B;
        edge_bytes[0x02] = 0x00;
        edge_bytes[0x03] = 0x00;
        edge_bytes[0x04] = 0x00;
        edge_bytes[0x05] = 0xE8;
        edge_bytes[0x06] = 0x16;
        edge_bytes[0x07] = 0x00;
        edge_bytes[0x08] = 0x00;
        edge_bytes[0x09] = 0x00;
        edge_bytes[0x0A] = 0xC3;
        std::vector<std::uint8_t> edge_file(0x800, 0x00);
        std::copy(edge_bytes.begin(), edge_bytes.end(),
                  edge_file.begin() + 0x400);
        mapped_fixture_t edge_fixture(edge_file);
        auto edge_layout = build_layout(
            0x1000, edge_bytes.size(), 0x400, edge_file.size());

        auto limits = small_limits();
        limits.target_tile_bytes = edge_bytes.size();
        limits.maximum_edges = 1;
        limits.seed_executable_range_starts = false;
        auto orchestrator = tile_decode_orchestrator_t::create(limits);
        require(orchestrator.has_value(), "edge-limit orchestrator create failed");
        mock_tile_decode_executor_t executor;
        auto result = orchestrator.value().run(
            edge_fixture.snapshot(), edge_layout, seeds, executor);
        require_limit_exceeded(result, "edge exhaustion was detected too late");
    }
}

void test_deterministic_decode_fixtures()
{
    std::vector<std::uint8_t> text(0x400, 0x90);
    text[0x000] = 0x90;
    text[0x001] = 0x48;
    text[0x002] = 0x89;
    text[0x003] = 0xC0;
    text[0x004] = 0xC3;
    text[0x100] = 0x90;
    text[0x101] = 0x48;
    text[0x102] = 0x8B;
    text[0x103] = 0x05;
    text[0x104] = 0x00;
    text[0x105] = 0x00;
    text[0x106] = 0x00;
    text[0x107] = 0x00;
    text[0x108] = 0xC3;

    std::vector<std::uint8_t> file_bytes(0x1000, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, 0x400, 0x400, 0x1000);

    auto orch_result = tile_decode_orchestrator_t::create(small_limits());
    require(orch_result.has_value(), "orchestrator create failed");
    auto& orch = orch_result.value();

    std::vector<tile_decode_seed_t> seeds;
    tile_decode_seed_t seed;
    seed.address = rva_address(0x1000);
    seed.provenance = fact_provenance_t::export_entry;
    seed.confidence = 100;
    seed.stable_source_id = 1;
    seeds.push_back(seed);

    mock_tile_decode_executor_t executor;
    auto run_result = orch.run(fixture.snapshot(), layout, seeds, executor);
    require(run_result.has_value(), "deterministic decode run failed");

    const auto& result = run_result.value();
    require(result.statistics.accepted_instructions > 0,
            "deterministic decode produced no instructions");
    require(!result.shards.empty(), "deterministic decode produced no shards");
    require(result.packed_store != nullptr, "deterministic decode produced no packed store");
    require(result.packed_store->instruction_count() > 0,
            "packed store has no instructions");

    auto run_result2 = orch.run(fixture.snapshot(), layout, seeds, executor);
    require(run_result2.has_value(), "second deterministic decode run failed");

    const auto bytes1 = orchestration_bytes(run_result.value());
    const auto bytes2 = orchestration_bytes(run_result2.value());
    require(bytes1 == bytes2,
            "deterministic decode is not byte-identical across runs");
}

void test_cross_tile_edge_routing()
{
    std::vector<std::uint8_t> text(0x800, 0x90);
    text[0x000] = 0xE8;
    text[0x001] = 0xFB;
    text[0x002] = 0x01;
    text[0x003] = 0x00;
    text[0x004] = 0x00;
    text[0x200] = 0x90;
    text[0x201] = 0xC3;

    std::vector<std::uint8_t> file_bytes(0x1000, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, 0x800, 0x400, 0x1000);

    tile_decode_orchestrator_limits_t limits = small_limits();
    limits.target_tile_bytes = 0x200;

    auto orch_result = tile_decode_orchestrator_t::create(limits);
    require(orch_result.has_value(), "cross-tile orchestrator create failed");
    auto& orch = orch_result.value();

    std::vector<tile_decode_seed_t> seeds;
    tile_decode_seed_t seed;
    seed.address = rva_address(0x1000);
    seed.provenance = fact_provenance_t::export_entry;
    seed.confidence = 100;
    seed.stable_source_id = 1;
    seeds.push_back(seed);

    mock_tile_decode_executor_options_t executor_options;
    executor_options.duplicate_targets = true;
    mock_tile_decode_executor_t executor(executor_options);
    auto run_result = orch.run(fixture.snapshot(), layout, seeds, executor);
    require(run_result.has_value(), "cross-tile decode run failed");

    const auto& result = run_result.value();
    require(!result.cross_tile_edges.empty(),
            "cross-tile edges were not routed");
    require(result.statistics.cross_tile_edges > 0,
            "cross-tile edge count statistic is zero");
    require(result.packed_store != nullptr &&
                result.packed_store->target_fact_count() ==
                    result.statistics.accepted_target_facts &&
                result.statistics.accepted_target_facts > 0,
            "accepted target facts did not reach the packed publication");
    const auto target = result.packed_store->compatibility_view().target_fact(0);
    require(target.has_value() && target->instruction_id != 0,
            "packed target fact lost its instruction relationship");

    const auto call_edges = static_cast<std::size_t>(std::count_if(
        result.cross_tile_edges.begin(), result.cross_tile_edges.end(),
        [](const auto& edge) {
            return edge.source.value == 0x1000 && edge.target.value == 0x1200 &&
                   edge.kind == edge_kind_t::call;
        }));
    const auto fallthrough_edges = static_cast<std::size_t>(std::count_if(
        result.cross_tile_edges.begin(), result.cross_tile_edges.end(),
        [](const auto& edge) {
            return edge.source.value == 0x11FF && edge.target.value == 0x1200 &&
                   edge.kind == edge_kind_t::fallthrough;
        }));
    require(call_edges == 1, "cross-tile call edge was not deduplicated");
    require(fallthrough_edges == 1,
            "cross-tile boundary fallthrough was not routed exactly once");
    require(result.statistics.duplicate_edges > 0,
            "duplicate cross-tile edge candidates were not tracked");
    require(result.statistics.cross_tile_edges == result.cross_tile_edges.size(),
            "cross-tile edge statistic does not match unique output");
}

void test_gap_decode()
{
    std::vector<std::uint8_t> text(0x200, 0x90);
    text[0x000] = 0x90;
    text[0x001] = 0xC3;
    text[0x100] = 0x90;
    text[0x101] = 0xC3;

    std::vector<std::uint8_t> file_bytes(0x1000, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, 0x200, 0x400, 0x1000);

    tile_decode_orchestrator_limits_t limits = small_limits();
    limits.seed_executable_range_starts = false;
    limits.invalid_run_policy.maximum_gap_resynchronization_bytes = 32;

    auto orch_result = tile_decode_orchestrator_t::create(limits);
    require(orch_result.has_value(), "gap decode orchestrator create failed");
    auto& orch = orch_result.value();

    std::vector<tile_decode_seed_t> seeds;
    tile_decode_seed_t seed;
    seed.address = rva_address(0x1000);
    seed.provenance = fact_provenance_t::export_entry;
    seed.confidence = 100;
    seed.stable_source_id = 1;
    seeds.push_back(seed);

    mock_tile_decode_executor_options_t executor_options;
    executor_options.maximum_request_bytes = 32;
    mock_tile_decode_executor_t executor(executor_options);
    auto run_result = orch.run(fixture.snapshot(), layout, seeds, executor);
    require(run_result.has_value(), "gap decode run failed");

    const auto& result = run_result.value();
    require(result.statistics.gap_requests > 0,
            "gap pass did not produce any gap requests");
    require(result.statistics.accepted_instructions > 2,
            "gap decode did not recover instructions beyond recursive pass");
    require(result.statistics.gap_requests > 1,
            "gap recovery did not traverse a multi-window gap");
    require(executor.maximum_observed_gap_request_bytes() ==
                limits.invalid_run_policy.maximum_gap_resynchronization_bytes,
            "gap decode request exceeded the resynchronization byte limit");
    require(result.packed_store != nullptr &&
                result.packed_store->instruction_count() > 0,
            "gap recovery did not publish instructions");
    const auto final_instruction = result.packed_store->compatibility_view().instruction(
        result.packed_store->instruction_count() - 1);
    require(final_instruction.has_value() &&
                final_instruction->address.value == 0x11FF,
            "gap recovery returned success before attempting the full gap");
}

void test_invalid_run_handling()
{
    std::vector<std::uint8_t> text(0x200, 0xFF);

    std::vector<std::uint8_t> file_bytes(0x1000, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, 0x200, 0x400, 0x1000);

    tile_decode_orchestrator_limits_t limits = small_limits();
    limits.invalid_run_policy.maximum_invalid_bytes_per_tile = 8;
    limits.invalid_run_policy.maximum_invalid_runs_per_tile = 4;

    auto orch_result = tile_decode_orchestrator_t::create(limits);
    require(orch_result.has_value(), "invalid-run orchestrator create failed");
    auto& orch = orch_result.value();

    std::vector<tile_decode_seed_t> seeds;
    tile_decode_seed_t seed;
    seed.address = rva_address(0x1000);
    seed.provenance = fact_provenance_t::export_entry;
    seed.confidence = 100;
    seed.stable_source_id = 1;
    seeds.push_back(seed);

    mock_tile_decode_executor_t executor;
    auto run_result = orch.run(fixture.snapshot(), layout, seeds, executor);
    require(!run_result.has_value(),
            "invalid-run exhaustion returned a partial successful decode");
    require(run_result.error().code == workspace_error_code_t::limit_exceeded,
            "invalid-run exhaustion did not report a limit error");
}

void test_zero_fill_is_not_submitted_for_decode()
{
    std::vector<std::uint8_t> file_bytes(0x800, 0x00);
    std::fill(file_bytes.begin() + 0x400, file_bytes.begin() + 0x500, 0x90);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, 0x100, 0x400, file_bytes.size(),
        0, 0, 0, 0x200);
    auto orch_result = tile_decode_orchestrator_t::create(small_limits());
    require(orch_result.has_value(), "zero-fill orchestrator create failed");

    mock_tile_decode_executor_t executor;
    auto run_result = orch_result.value().run(
        fixture.snapshot(), layout, {export_seed(0x1000)}, executor);
    require(run_result.has_value(), "zero-fill decode run failed");
    const auto& result = run_result.value();
    require(result.statistics.initialized_executable_bytes == 0x100,
            "initialized executable byte accounting is incorrect");
    require(result.statistics.zero_fill_executable_bytes == 0x100,
            "zero-fill executable byte accounting is incorrect");
    for (const auto& request : executor.observed_requests()) {
        std::uint64_t provider_end = 0;
        require(checked_add_u64(request.provider_offset, request.byte_count,
                    provider_end) && provider_end <= 0x500,
                "zero-fill bytes were submitted as provider-backed decode input");
    }
    const auto zero_fill = std::find_if(result.coverage.begin(), result.coverage.end(),
        [](const coverage_span_t& span) {
            return span.start.value == 0x1100 && span.size == 0x100 &&
                span.reason == coverage_reason_t::undecodable &&
                span.detail_code == static_cast<std::uint32_t>(
                    tile_coverage_detail_t::zero_fill);
        });
    require(zero_fill != result.coverage.end(),
            "zero-fill range did not publish a typed undecodable span");
}

void test_address_expression_publication_and_data_frontier_filter()
{
    std::vector<std::uint8_t> text(0x200, 0xCC);
    text[0] = 0x48;
    text[1] = 0x8B;
    text[2] = 0x05;
    const std::int32_t displacement = 0xF9;
    std::memcpy(text.data() + 3, &displacement, sizeof(displacement));
    text[7] = 0xC3;
    text[0x100] = 0x90;

    std::vector<std::uint8_t> file_bytes(0x800, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, text.size(), 0x400,
        file_bytes.size());
    auto orch_result = tile_decode_orchestrator_t::create(small_limits());
    require(orch_result.has_value(),
            "address-expression orchestrator create failed");

    mock_tile_decode_executor_options_t executor_options;
    executor_options.maximum_request_bytes = 32;
    mock_tile_decode_executor_t executor(executor_options);
    auto run_result = orch_result.value().run(
        fixture.snapshot(), layout, {export_seed(0x1000)}, executor);
    require(run_result.has_value(), "address-expression decode run failed");

    const auto recursive_data_request = std::find_if(
        executor.observed_requests().begin(), executor.observed_requests().end(),
        [](const tile_decode_request_t& request) {
            return request.pass == tile_decode_pass_t::recursive &&
                request.start.value == 0x1100;
        });
    require(recursive_data_request == executor.observed_requests().end(),
            "data target was routed into the recursive code frontier");

    const auto& result = run_result.value();
    require(result.packed_store != nullptr &&
                result.packed_store->operand_count() > 0 &&
                result.packed_store->target_fact_count() > 0 &&
                result.packed_store->address_expression_count() > 0,
            "address-expression facts did not reach packed publication");
    const auto view = result.packed_store->compatibility_view();
    const auto operand = view.operand(0);
    const auto target = view.target_fact(0);
    require(operand.has_value() && target.has_value() &&
                operand->address_expression_id != 0 &&
                target->operand_fact_id == operand->id &&
                target->address_expression_id == operand->address_expression_id &&
                target->kind == target_kind_record_t::data,
            "packed data target lost its operand or address-expression relation");
}

void test_cancellation()
{
    std::vector<std::uint8_t> text(0x1000, 0x90);

    std::vector<std::uint8_t> file_bytes(0x2000, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, 0x1000, 0x400, 0x2000);

    auto orch_result = tile_decode_orchestrator_t::create(small_limits());
    require(orch_result.has_value(), "cancellation orchestrator create failed");
    auto& orch = orch_result.value();

    std::vector<tile_decode_seed_t> seeds;
    tile_decode_seed_t seed;
    seed.address = rva_address(0x1000);
    seed.provenance = fact_provenance_t::export_entry;
    seed.confidence = 100;
    seed.stable_source_id = 1;
    seeds.push_back(seed);

    mock_tile_decode_executor_t executor;
    cancellation_source_t cancellation;
    cancellation.request_cancel();

    auto run_result = orch.run(fixture.snapshot(), layout, seeds, executor,
                                cancellation.token());
    require(!run_result, "cancelled orchestrator run did not fail");
    require(run_result.error().code == workspace_error_code_t::cancelled ||
            run_result.error().code == workspace_error_code_t::deadline_exceeded,
             "cancelled orchestrator run did not report cancellation");
}

void test_in_flight_cancellation()
{
    std::vector<std::uint8_t> text(0x40, 0x90);
    std::vector<std::uint8_t> file_bytes(0x800, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, text.size(), 0x400, file_bytes.size());
    auto limits = small_limits();
    limits.target_tile_bytes = text.size();
    limits.seed_executable_range_starts = false;

    auto orchestrator_result = tile_decode_orchestrator_t::create(limits);
    require(orchestrator_result.has_value(),
            "in-flight cancellation orchestrator create failed");
    cancellation_source_t cancellation;
    in_flight_cancelling_executor_t executor(cancellation);
    const std::vector<tile_decode_seed_t> seeds{export_seed(0x1000)};

    auto run_result = orchestrator_result.value().run(
        fixture.snapshot(), layout, seeds, executor, cancellation.token());
    require(!run_result, "in-flight cancellation was ignored");
    require(run_result.error().code == workspace_error_code_t::cancelled,
            "in-flight cancellation returned the wrong error type");
    require(run_result.error().cancellation,
            "in-flight cancellation did not preserve cancellation metadata");
}

void test_shard_output()
{
    std::vector<std::uint8_t> text(0x100, 0x90);
    text[0x000] = 0x90;
    text[0x001] = 0x48;
    text[0x002] = 0x89;
    text[0x003] = 0xC0;
    text[0x004] = 0xC3;

    std::vector<std::uint8_t> file_bytes(0x800, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, 0x100, 0x400, 0x800);

    auto orch_result = tile_decode_orchestrator_t::create(small_limits());
    require(orch_result.has_value(), "shard output orchestrator create failed");
    auto& orch = orch_result.value();

    std::vector<tile_decode_seed_t> seeds;
    tile_decode_seed_t seed;
    seed.address = rva_address(0x1000);
    seed.provenance = fact_provenance_t::export_entry;
    seed.confidence = 100;
    seed.stable_source_id = 1;
    seeds.push_back(seed);

    mock_tile_decode_executor_t executor;
    auto run_result = orch.run(fixture.snapshot(), layout, seeds, executor);
    require(run_result.has_value(), "shard output decode run failed");

    const auto& result = run_result.value();
    require(!result.shards.empty(), "shard output produced no shards");
    require(result.packed_store != nullptr, "shard output produced no packed store");

    for (const auto& summary : result.shards) {
        require(summary.instruction_count > 0,
                "shard summary has zero instructions");
        require(summary.shard_id == static_cast<std::uint16_t>(summary.tile_id),
                "shard id does not match tile id");
    }

    std::uint32_t total_instructions = 0;
    for (const auto& summary : result.shards)
        total_instructions += summary.instruction_count;
    require(result.packed_store->instruction_count() == total_instructions,
            "packed store instruction count does not match shard summaries");
}

void test_randomized_scheduling_byte_identical()
{
    std::vector<std::uint8_t> text(0x400, 0x90);
    text[0x000] = 0xE8;
    text[0x001] = 0x10;
    text[0x002] = 0x00;
    text[0x003] = 0x00;
    text[0x004] = 0x00;
    text[0x005] = 0x90;
    text[0x006] = 0xC3;
    text[0x015] = 0x90;
    text[0x016] = 0xC3;
    text[0x200] = 0xE9;
    text[0x201] = 0x00;
    text[0x202] = 0xFE;
    text[0x203] = 0xFF;
    text[0x204] = 0xFF;
    text[0x205] = 0xC3;

    std::vector<std::uint8_t> file_bytes(0x1000, 0x00);
    std::copy(text.begin(), text.end(), file_bytes.begin() + 0x400);

    mapped_fixture_t fixture(file_bytes);
    auto layout = build_layout(0x1000, 0x400, 0x400, 0x1000);

    auto orch_result = tile_decode_orchestrator_t::create(small_limits());
    require(orch_result.has_value(), "randomized scheduling orchestrator create failed");
    auto& orch = orch_result.value();

    std::vector<tile_decode_seed_t> base_seeds;
    for (int i = 0; i < 4; ++i) {
        tile_decode_seed_t seed;
        seed.address = rva_address(0x1000 + i * 0x100);
        seed.provenance = fact_provenance_t::export_entry;
        seed.confidence = 100;
        seed.stable_source_id = static_cast<std::uint64_t>(i + 1);
        base_seeds.push_back(seed);
    }

    std::mt19937_64 rng(42);
    std::vector<std::uint8_t> first_bytes;
    bool first = true;

    for (int trial = 0; trial < 8; ++trial) {
        auto shuffled = base_seeds;
        std::shuffle(shuffled.begin(), shuffled.end(), rng);

        mock_tile_decode_executor_options_t options;
        options.reverse_completions = (trial % 2) != 0;
        mock_tile_decode_executor_t executor(options);

        auto run_result = orch.run(fixture.snapshot(), layout, shuffled, executor);
        require(run_result.has_value(), "randomized scheduling run failed");

        const auto bytes = orchestration_bytes(run_result.value());
        if (first) {
            first_bytes = bytes;
            first = false;
        } else {
            require(bytes == first_bytes,
                    "randomized scheduling is not byte-identical across orderings");
        }
    }
}

}

bool run_tile_decode_orchestrator_harness(std::string& failure)
{
    try {
        test_request_correlation_and_completion_contract();
        test_duplicate_overlap_and_ownership();
        test_typed_exhaustion_failures();
        test_deterministic_decode_fixtures();
        test_cross_tile_edge_routing();
        test_gap_decode();
        test_invalid_run_handling();
        test_zero_fill_is_not_submitted_for_decode();
        test_address_expression_publication_and_data_frontier_filter();
        test_cancellation();
        test_in_flight_cancellation();
        test_shard_output();
        test_randomized_scheduling_byte_identical();
        return true;
    } catch (const std::exception& error) {
        failure = error.what();
        return false;
    }
}

}

int main()
{
    std::string failure;
    return aida::analysis::c03::run_tile_decode_orchestrator_harness(failure) ? 0 : 1;
}
