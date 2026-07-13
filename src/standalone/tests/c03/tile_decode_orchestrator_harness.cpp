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
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
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

std::vector<std::uint8_t> pad_bytes(const std::vector<std::uint8_t>& src,
                                     std::size_t target_size)
{
    std::vector<std::uint8_t> result(target_size, 0x90);
    std::copy(src.begin(), src.end(), result.begin());
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
                                   std::uint64_t data_file_offset = 0)
{
    image_layout_definition_t definition;
    definition.identity.content_id = content_id(7U);
    definition.identity.format = format_id_t::pe32_plus;
    definition.identity.endian = endian_t::little;
    definition.identity.address_width_bits = 64;
    definition.identity.image_base = 0x0000000140000000ULL;
    definition.identity.provider_size = provider_size;

    const auto base = definition.identity.image_base;

    definition.segments.push_back({10U, ".image", text_rva,
                                    text_rva + (data_size > 0 ? data_size : text_size),
                                    0U, provider_size,
                                    image_permission_read | image_permission_execute});

    definition.sections.push_back({1U, ".text", text_rva, text_size,
                                    text_file_offset, text_size,
                                    image_permission_read | image_permission_execute});

    definition.mappings.push_back({100U, text_rva, base + text_rva, text_size,
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

class mock_tile_decode_executor_t final : public tile_decode_executor_t {
public:
    mock_tile_decode_executor_t()
    {
        caps_.decoder_key = x64_key();
        caps_.maximum_request_bytes = 64ULL * 1024ULL;
        caps_.minimum_instruction_bytes = 1;
        caps_.maximum_instruction_bytes = 15;
        caps_.instruction_alignment = 1;
        caps_.worker_count = 1;
    }

    const tile_decode_executor_capabilities_t& capabilities() const noexcept override
    {
        return caps_;
    }

    workspace_result_t<std::vector<tile_decode_completion_t>> execute_batch(
        const provider_snapshot_t& snapshot,
        const std::vector<tile_decode_request_t>& requests,
        const cancellation_token_t& cancellation) override
    {
        std::vector<tile_decode_completion_t> completions;
        completions.reserve(requests.size());
        for (const auto& request : requests) {
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
        return workspace_result_t<std::vector<tile_decode_completion_t>>::success(
            std::move(completions));
    }

private:
    tile_decode_executor_capabilities_t caps_;

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

std::uint64_t orchestration_hash(const tile_decode_orchestration_result_t& result) noexcept
{
    std::uint64_t value = 0;
    for (const auto& s : result.shards) {
        value = combine(value, s.tile_id);
        value = combine(value, s.shard_id);
        value = combine(value, s.instruction_count);
        value = combine(value, s.operand_count);
        value = combine(value, s.edge_count);
    }
    for (const auto& e : result.cross_tile_edges) {
        value = combine(value, e.source_tile_id);
        value = combine(value, e.target_tile_id);
        value = combine(value, e.source.value);
        value = combine(value, e.target.value);
        value = combine(value, static_cast<std::uint64_t>(e.kind));
    }
    value = combine(value, result.statistics.accepted_instructions);
    value = combine(value, result.statistics.accepted_operands);
    value = combine(value, result.statistics.accepted_edges);
    value = combine(value, result.statistics.cross_tile_edges);
    value = combine(value, result.statistics.invalid_bytes);
    value = combine(value, result.statistics.recursive_requests);
    value = combine(value, result.statistics.gap_requests);
    if (result.packed_store) {
        value = combine(value, result.packed_store->instruction_count());
        value = combine(value, result.packed_store->operand_count());
        value = combine(value, result.packed_store->edge_count());
        value = combine(value, result.packed_store->coverage_count());
    }
    return value;
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

    const auto hash1 = orchestration_hash(run_result.value());
    const auto hash2 = orchestration_hash(run_result2.value());
    require(hash1 == hash2, "deterministic decode is not byte-identical across runs");
}

void test_cross_tile_edge_routing()
{
    std::vector<std::uint8_t> text(0x800, 0x90);
    text[0x000] = 0xE8;
    text[0x001] = 0xFB;
    text[0x002] = 0x01;
    text[0x003] = 0x00;
    text[0x004] = 0x00;
    text[0x005] = 0xC3;
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

    mock_tile_decode_executor_t executor;
    auto run_result = orch.run(fixture.snapshot(), layout, seeds, executor);
    require(run_result.has_value(), "cross-tile decode run failed");

    const auto& result = run_result.value();
    require(!result.cross_tile_edges.empty(),
            "cross-tile edges were not routed");
    require(result.statistics.cross_tile_edges > 0,
            "cross-tile edge count statistic is zero");

    const auto& edge = result.cross_tile_edges.front();
    require(edge.source_tile_id != edge.target_tile_id,
            "cross-tile edge does not cross tiles");
    require(edge.target.value == 0x1200,
            "cross-tile edge target is incorrect");
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

    mock_tile_decode_executor_t executor;
    auto run_result = orch.run(fixture.snapshot(), layout, seeds, executor);
    require(run_result.has_value(), "gap decode run failed");

    const auto& result = run_result.value();
    require(result.statistics.gap_requests > 0,
            "gap pass did not produce any gap requests");
    require(result.statistics.accepted_instructions > 2,
            "gap decode did not recover instructions beyond recursive pass");
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
    require(run_result.has_value(), "invalid-run decode run failed");

    const auto& result = run_result.value();
    require(result.statistics.invalid_policy_cutoffs > 0,
            "invalid-run policy did not trigger any cutoffs");
    require(result.statistics.invalid_bytes > 0,
            "invalid-run policy did not track invalid bytes");
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

    mock_tile_decode_executor_t executor;

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
    std::uint64_t first_hash = 0;
    bool first = true;

    for (int trial = 0; trial < 8; ++trial) {
        auto shuffled = base_seeds;
        std::shuffle(shuffled.begin(), shuffled.end(), rng);

        auto run_result = orch.run(fixture.snapshot(), layout, shuffled, executor);
        require(run_result.has_value(), "randomized scheduling run failed");

        const auto hash = orchestration_hash(run_result.value());
        if (first) {
            first_hash = hash;
            first = false;
        } else {
            require(hash == first_hash,
                    "randomized scheduling is not byte-identical across orderings");
        }
    }
}

}

bool run_tile_decode_orchestrator_harness(std::string& failure)
{
    try {
        test_deterministic_decode_fixtures();
        test_cross_tile_edge_routing();
        test_gap_decode();
        test_invalid_run_handling();
        test_cancellation();
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
