#include "tile_decode_orchestrator.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace aida::analysis {

namespace {

constexpr const char* kPhase = "tile_decode_orchestrator";

workspace_error_t orchestrator_error(workspace_error_code_t code, std::string message,
                                     std::optional<std::uint64_t> rva = std::nullopt)
{
    auto error = make_workspace_error(code, std::move(message), kPhase);
    if (rva) {
        address_t address;
        address.space = address_space_id_t::relative_virtual;
        address.value = *rva;
        error.address = address;
    }
    return error;
}

edge_kind_t flow_to_edge_kind(std::uint32_t flow_flags) noexcept
{
    if ((flow_flags & flow_return) != 0)
        return edge_kind_t::return_edge;
    if ((flow_flags & flow_call) != 0) {
        if ((flow_flags & flow_branch) != 0)
            return edge_kind_t::tail_call;
        return edge_kind_t::call;
    }
    if ((flow_flags & flow_branch) != 0) {
        if ((flow_flags & flow_conditional) != 0)
            return edge_kind_t::conditional_taken;
        return edge_kind_t::unconditional;
    }
    if ((flow_flags & flow_indirect) != 0)
        return edge_kind_t::indirect;
    return edge_kind_t::fallthrough;
}

decode_frontier_seed_kind_t flow_to_target_seed_kind(std::uint32_t flow_flags) noexcept
{
    if ((flow_flags & flow_call) != 0)
        return decode_frontier_seed_kind_t::call_target;
    if ((flow_flags & flow_branch) != 0)
        return decode_frontier_seed_kind_t::branch_target;
    return decode_frontier_seed_kind_t::fallthrough;
}

bool instruction_stronger(const instruction_record_t& a,
                          const instruction_record_t& b) noexcept
{
    if (a.provenance != b.provenance)
        return provenance_rank(a.provenance) > provenance_rank(b.provenance);
    if (a.confidence != b.confidence)
        return a.confidence > b.confidence;
    return a.stable_source_id < b.stable_source_id;
}

struct tile_instruction_entry_t {
    instruction_record_t record;
    std::vector<operand_fact_t> operands;
    std::vector<target_fact_t> targets;
    std::uint8_t delay_slots = 0;
};

struct tile_accumulator_t {
    const executable_decode_tile_t* tile = nullptr;
    std::map<std::uint64_t, tile_instruction_entry_t> instructions;
    std::vector<coverage_span_t> coverage;
    std::set<std::uint64_t> decoded_rvas;
    std::uint64_t invalid_bytes = 0;
    std::uint64_t invalid_runs = 0;
    bool cutoff = false;
};

void merge_coverage_into(std::vector<coverage_span_t>& dest,
                         const std::vector<coverage_span_t>& src)
{
    for (const auto& span : src) {
        if (span.size == 0)
            continue;
        dest.push_back(span);
    }
    std::sort(dest.begin(), dest.end(), [](const auto& a, const auto& b) {
        if (a.start.space != b.start.space)
            return a.start.space < b.start.space;
        return a.start.value < b.start.value;
    });
    std::vector<coverage_span_t> merged;
    merged.reserve(dest.size());
    for (auto& span : dest) {
        if (!merged.empty()) {
            auto& last = merged.back();
            if (last.start.space == span.start.space &&
                last.start.value + last.size >= span.start.value &&
                last.reason == span.reason &&
                last.provenance == span.provenance) {
                const auto end_val = (std::max)(last.start.value + last.size,
                                                span.start.value + span.size);
                last.size = end_val - last.start.value;
                continue;
            }
        }
        merged.push_back(span);
    }
    dest = std::move(merged);
}

class production_tile_decode_executor_t final : public tile_decode_executor_t {
public:
    static workspace_result_t<std::unique_ptr<tile_decode_executor_t>>
        create(production_tile_decode_executor_options_t options,
               const cancellation_token_t& cancellation)
    {
        auto key_validation = validate_arch_decoder_key(options.decoder_key);
        if (!key_validation)
            return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::failure(
                key_validation.error());

        if (options.worker_count == 0)
            options.worker_count = 1;

        const bool use_x86 =
            (options.decoder_key.architecture == architecture_id_t::x86 ||
             options.decoder_key.architecture == architecture_id_t::x86_64);

        tile_decode_executor_capabilities_t caps;
        caps.decoder_key = options.decoder_key;
        caps.worker_count = options.worker_count;

        if (use_x86) {
            caps.maximum_request_bytes = options.x86_limits.maximum_window_bytes;
            caps.minimum_instruction_bytes = 1;
            caps.maximum_instruction_bytes = 15;
            caps.instruction_alignment = 1;
        } else {
            auto probe = decode::worker_owned_capstone_tile_decoder_t::create(
                options.decoder_key, options.capstone_options, cancellation);
            if (!probe)
                return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::failure(
                    probe.error());
            const auto& reg = probe.value()->registration();
            caps.maximum_request_bytes = options.capstone_options.tile_limits.maximum_tile_bytes;
            caps.minimum_instruction_bytes = reg.limits.minimum_instruction_bytes;
            caps.maximum_instruction_bytes = reg.limits.maximum_instruction_bytes;
            caps.instruction_alignment = reg.limits.instruction_alignment;
        }

        auto* raw = new production_tile_decode_executor_t();
        raw->options_ = std::move(options);
        raw->capabilities_ = caps;
        raw->use_x86_ = use_x86;
        raw->creation_cancellation_ = cancellation;
        std::unique_ptr<tile_decode_executor_t> owned(raw);
        return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::success(
            std::move(owned));
    }

    const tile_decode_executor_capabilities_t& capabilities() const noexcept override
    {
        return capabilities_;
    }

    workspace_result_t<std::vector<tile_decode_completion_t>> execute_batch(
        const provider_snapshot_t& snapshot,
        const std::vector<tile_decode_request_t>& requests,
        const cancellation_token_t& cancellation) override
    {
        std::vector<tile_decode_completion_t> completions;
        completions.reserve(requests.size());

        if (capabilities_.worker_count <= 1) {
            for (const auto& request : requests) {
                if (cancellation.stop_requested()) {
                    tile_decode_completion_t cancelled;
                    cancelled.request_id = request.request_id;
                    auto err = make_workspace_error(
                        workspace_error_code_t::cancelled,
                        "tile decode batch cancelled", kPhase);
                    err.cancellation = true;
                    cancelled.error = std::move(err);
                    completions.push_back(std::move(cancelled));
                    continue;
                }
                completions.push_back(execute_one(snapshot, request, cancellation));
            }
        } else {
            completions = execute_parallel(snapshot, requests, cancellation);
        }
        return workspace_result_t<std::vector<tile_decode_completion_t>>::success(
            std::move(completions));
    }

private:
    production_tile_decode_executor_t() = default;

    production_tile_decode_executor_options_t options_;
    tile_decode_executor_capabilities_t capabilities_;
    bool use_x86_ = false;
    cancellation_token_t creation_cancellation_;
    std::unique_ptr<decode::worker_owned_capstone_tile_decoder_t> capstone_decoder_;
    std::unique_ptr<decode::worker_owned_x86_tile_decoder_t> x86_decoder_;

    tile_decode_completion_t execute_one(
        const provider_snapshot_t& snapshot,
        const tile_decode_request_t& request,
        const cancellation_token_t& cancellation)
    {
        if (use_x86_)
            return execute_x86(snapshot, request, cancellation);
        return execute_capstone(snapshot, request, cancellation);
    }

    tile_decode_completion_t execute_capstone(
        const provider_snapshot_t& snapshot,
        const tile_decode_request_t& request,
        const cancellation_token_t& cancellation)
    {
        if (!capstone_decoder_) {
            auto created = decode::worker_owned_capstone_tile_decoder_t::create(
                options_.decoder_key, options_.capstone_options, creation_cancellation_);
            if (!created) {
                tile_decode_completion_t completion;
                completion.request_id = request.request_id;
                completion.error = created.error();
                return completion;
            }
            capstone_decoder_ = std::move(created.value());
        }

        decode::capstone_tile_identity_t identity;
        identity.decoder_key = options_.decoder_key;
        identity.start = request.start;
        identity.provider_offset = request.provider_offset;
        identity.runtime_address = request.runtime_address;
        identity.image_base = request.image_base;
        identity.image_size = request.image_size;
        identity.byte_count = request.byte_count;
        identity.snapshot_generation = snapshot.generation();
        identity.stable_source_id = request.stable_source_id;
        identity.provenance = request.provenance;
        identity.confidence = request.confidence;

        auto result = capstone_decoder_->decode_tile(snapshot, identity, cancellation);
        if (!result) {
            tile_decode_completion_t completion;
            completion.request_id = request.request_id;
            completion.error = result.error();
            return completion;
        }

        auto decoded = result.take_value();
        tile_decode_completion_t completion;
        completion.request_id = request.request_id;
        completion.records.instructions = std::move(decoded.instructions);
        completion.records.operand_facts = std::move(decoded.operand_facts);
        completion.records.target_facts = std::move(decoded.target_facts);
        completion.records.delay_slot_counts = std::move(decoded.delay_slot_counts);
        completion.records.coverage = std::move(decoded.coverage);
        completion.records.bytes_consumed = decoded.usage.bytes_consumed;
        completion.records.invalid_bytes = decoded.usage.undecodable_bytes;
        return completion;
    }

    tile_decode_completion_t execute_x86(
        const provider_snapshot_t& snapshot,
        const tile_decode_request_t& request,
        const cancellation_token_t& cancellation)
    {
        if (!x86_decoder_) {
            auto created = decode::worker_owned_x86_tile_decoder_t::create(
                options_.decoder_key.mode);
            if (!created) {
                tile_decode_completion_t completion;
                completion.request_id = request.request_id;
                completion.error = created.error();
                return completion;
            }
            x86_decoder_ = std::move(created.value());
        }

        decode::x86_tile_decode_request_t x86_request;
        x86_request.start_address = request.start;
        x86_request.provider_offset = request.provider_offset;
        x86_request.byte_count = request.byte_count;
        x86_request.runtime_address = request.runtime_address;
        x86_request.image_base = request.image_base;
        x86_request.image_size = request.image_size;
        x86_request.provenance = request.provenance;
        x86_request.confidence = request.confidence;
        x86_request.stable_source_id = request.stable_source_id;
        x86_request.limits = options_.x86_limits;

        auto result = x86_decoder_->decode_tile(snapshot, x86_request, cancellation);
        if (!result) {
            tile_decode_completion_t completion;
            completion.request_id = request.request_id;
            completion.error = result.error();
            return completion;
        }

        auto decoded = result.take_value();
        tile_decode_completion_t completion;
        completion.request_id = request.request_id;
        completion.records.instructions = std::move(decoded.instructions);
        completion.records.operand_facts = std::move(decoded.operand_facts);
        completion.records.target_facts = std::move(decoded.target_facts);
        completion.records.coverage = std::move(decoded.coverage);
        completion.records.bytes_consumed = decoded.usage.bytes_consumed;
        completion.records.invalid_bytes = decoded.usage.invalid_bytes;
        completion.records.delay_slot_counts.resize(
            completion.records.instructions.size(), 0);
        return completion;
    }

    std::vector<tile_decode_completion_t> execute_parallel(
        const provider_snapshot_t& snapshot,
        const std::vector<tile_decode_request_t>& requests,
        const cancellation_token_t& cancellation)
    {
        const auto worker_count = (std::min)(
            static_cast<std::size_t>(capabilities_.worker_count),
            requests.size());
        if (worker_count == 0 || requests.empty())
            return {};

        std::vector<std::vector<std::size_t>> partitions(worker_count);
        for (std::size_t i = 0; i < requests.size(); ++i)
            partitions[i % worker_count].push_back(i);

        std::vector<tile_decode_completion_t> results(requests.size());

        auto worker_fn = [&](const std::vector<std::size_t>& indices) {
            std::unique_ptr<decode::worker_owned_capstone_tile_decoder_t> capstone;
            std::unique_ptr<decode::worker_owned_x86_tile_decoder_t> x86;

            if (use_x86_) {
                auto created = decode::worker_owned_x86_tile_decoder_t::create(
                    options_.decoder_key.mode);
                if (!created) {
                    for (auto idx : indices) {
                        tile_decode_completion_t c;
                        c.request_id = requests[idx].request_id;
                        c.error = created.error();
                        results[idx] = std::move(c);
                    }
                    return;
                }
                x86 = std::move(created.value());
            } else {
                auto created = decode::worker_owned_capstone_tile_decoder_t::create(
                    options_.decoder_key, options_.capstone_options,
                    creation_cancellation_);
                if (!created) {
                    for (auto idx : indices) {
                        tile_decode_completion_t c;
                        c.request_id = requests[idx].request_id;
                        c.error = created.error();
                        results[idx] = std::move(c);
                    }
                    return;
                }
                capstone = std::move(created.value());
            }

            for (auto idx : indices) {
                if (cancellation.stop_requested()) {
                    tile_decode_completion_t cancelled;
                    cancelled.request_id = requests[idx].request_id;
                    auto err = make_workspace_error(
                        workspace_error_code_t::cancelled,
                        "tile decode batch cancelled", kPhase);
                    err.cancellation = true;
                    cancelled.error = std::move(err);
                    results[idx] = std::move(cancelled);
                    continue;
                }

                const auto& req = requests[idx];

                if (use_x86_) {
                    decode::x86_tile_decode_request_t xr;
                    xr.start_address = req.start;
                    xr.provider_offset = req.provider_offset;
                    xr.byte_count = req.byte_count;
                    xr.runtime_address = req.runtime_address;
                    xr.image_base = req.image_base;
                    xr.image_size = req.image_size;
                    xr.provenance = req.provenance;
                    xr.confidence = req.confidence;
                    xr.stable_source_id = req.stable_source_id;
                    xr.limits = options_.x86_limits;

                    auto result = x86->decode_tile(snapshot, xr, cancellation);
                    if (!result) {
                        tile_decode_completion_t c;
                        c.request_id = req.request_id;
                        c.error = result.error();
                        results[idx] = std::move(c);
                    } else {
                        auto decoded = result.take_value();
                        tile_decode_completion_t c;
                        c.request_id = req.request_id;
                        c.records.instructions = std::move(decoded.instructions);
                        c.records.operand_facts = std::move(decoded.operand_facts);
                        c.records.target_facts = std::move(decoded.target_facts);
                        c.records.coverage = std::move(decoded.coverage);
                        c.records.bytes_consumed = decoded.usage.bytes_consumed;
                        c.records.invalid_bytes = decoded.usage.invalid_bytes;
                        c.records.delay_slot_counts.resize(
                            c.records.instructions.size(), 0);
                        results[idx] = std::move(c);
                    }
                } else {
                    decode::capstone_tile_identity_t identity;
                    identity.decoder_key = options_.decoder_key;
                    identity.start = req.start;
                    identity.provider_offset = req.provider_offset;
                    identity.runtime_address = req.runtime_address;
                    identity.image_base = req.image_base;
                    identity.image_size = req.image_size;
                    identity.byte_count = req.byte_count;
                    identity.snapshot_generation = snapshot.generation();
                    identity.stable_source_id = req.stable_source_id;
                    identity.provenance = req.provenance;
                    identity.confidence = req.confidence;

                    auto result = capstone->decode_tile(snapshot, identity, cancellation);
                    if (!result) {
                        tile_decode_completion_t c;
                        c.request_id = req.request_id;
                        c.error = result.error();
                        results[idx] = std::move(c);
                    } else {
                        auto decoded = result.take_value();
                        tile_decode_completion_t c;
                        c.request_id = req.request_id;
                        c.records.instructions = std::move(decoded.instructions);
                        c.records.operand_facts = std::move(decoded.operand_facts);
                        c.records.target_facts = std::move(decoded.target_facts);
                        c.records.delay_slot_counts = std::move(decoded.delay_slot_counts);
                        c.records.coverage = std::move(decoded.coverage);
                        c.records.bytes_consumed = decoded.usage.bytes_consumed;
                        c.records.invalid_bytes = decoded.usage.undecodable_bytes;
                        results[idx] = std::move(c);
                    }
                }
            }
        };

        std::vector<std::thread> threads;
        threads.reserve(worker_count);
        for (std::size_t w = 0; w < worker_count; ++w)
            threads.emplace_back(worker_fn, std::cref(partitions[w]));
        for (auto& t : threads)
            t.join();

        return results;
    }
};

}

workspace_result_t<executable_decode_partition_t> partition_executable_decode_ranges(
    const image_layout_index_t& layout,
    const tile_decode_executor_capabilities_t& capabilities,
    const tile_decode_orchestrator_limits_t& limits,
    const cancellation_token_t& cancellation)
{
    executable_decode_partition_t partition;

    std::uint32_t range_id = 0;
    std::uint32_t tile_id = 0;

    const auto& mappings = layout.mappings();
    for (const auto& mapping : mappings) {
        if ((mapping.permissions & image_permission_execute) == 0)
            continue;
        if (mapping.virtual_size == 0)
            continue;

        if (cancellation.stop_requested()) {
            auto err = make_workspace_error(
                cancellation.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "partition cancelled", kPhase);
            err.cancellation = !cancellation.deadline_exceeded();
            err.deadline = cancellation.deadline_exceeded();
            return workspace_result_t<executable_decode_partition_t>::failure(
                std::move(err));
        }

        executable_decode_range_t range;
        range.range_id = range_id++;
        range.mapping_id = mapping.id;
        range.start_rva = mapping.rva;
        range.start_virtual_address = mapping.virtual_address;
        range.provider_offset = mapping.file_offset;
        range.byte_count = mapping.virtual_size;

        partition.ranges.push_back(range);

        const std::uint64_t initialized = (std::min)(mapping.file_size, mapping.virtual_size);
        partition.initialized_executable_bytes += initialized;
        if (mapping.virtual_size > mapping.file_size)
            partition.zero_fill_executable_bytes += mapping.virtual_size - mapping.file_size;

        std::uint64_t offset = 0;
        std::uint64_t remaining = mapping.virtual_size;
        while (remaining > 0 && tile_id < limits.maximum_tiles) {
            const auto tile_bytes = (std::min)(remaining, limits.target_tile_bytes);

            executable_decode_tile_t tile;
            tile.tile_id = tile_id++;
            tile.shard_id = static_cast<std::uint16_t>(
                (tile_id - 1) > 0xFFFF ? 0xFFFF : (tile_id - 1));
            tile.range_id = range.range_id;
            tile.mapping_id = mapping.id;
            tile.start_rva = mapping.rva + offset;
            tile.start_virtual_address = mapping.virtual_address + offset;
            tile.provider_offset = (offset < mapping.file_size)
                ? mapping.file_offset + offset
                : mapping.file_offset + mapping.file_size;
            tile.byte_count = tile_bytes;
            tile.lookahead_bytes = (remaining > tile_bytes)
                ? (std::min)(static_cast<std::uint64_t>(capabilities.maximum_instruction_bytes),
                             remaining - tile_bytes)
                : 0;

            partition.tiles.push_back(tile);

            offset += tile_bytes;
            remaining -= tile_bytes;
        }
    }

    return workspace_result_t<executable_decode_partition_t>::success(
        std::move(partition));
}

workspace_result_t<std::unique_ptr<tile_decode_executor_t>>
create_production_tile_decode_executor(
    production_tile_decode_executor_options_t options,
    const cancellation_token_t& cancellation)
{
    return production_tile_decode_executor_t::create(std::move(options), cancellation);
}

tile_decode_orchestrator_t::tile_decode_orchestrator_t(
    tile_decode_orchestrator_limits_t limits) noexcept
    : limits_(std::move(limits))
{
}

workspace_result_t<tile_decode_orchestrator_t>
tile_decode_orchestrator_t::create(
    tile_decode_orchestrator_limits_t limits)
{
    if (limits.target_tile_bytes == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "target tile bytes must be non-zero"));
    if (limits.maximum_tiles == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "maximum tiles must be non-zero"));
    if (limits.maximum_frontier_seeds == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "maximum frontier seeds must be non-zero"));
    if (limits.maximum_frontier_wave == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "maximum frontier wave must be non-zero"));
    if (limits.maximum_decode_requests == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "maximum decode requests must be non-zero"));
    if (limits.invalid_run_policy.maximum_gap_resynchronization_bytes == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "maximum gap resynchronization bytes must be non-zero"));

    return workspace_result_t<tile_decode_orchestrator_t>::success(
        tile_decode_orchestrator_t(std::move(limits)));
}

workspace_result_t<tile_decode_orchestration_result_t>
tile_decode_orchestrator_t::run(
    const provider_snapshot_t& snapshot,
    const image_layout_index_t& layout,
    std::vector<tile_decode_seed_t> seeds,
    tile_decode_executor_t& executor,
    const cancellation_token_t& cancellation) const
{
    const auto& caps = executor.capabilities();

    auto partition_result = partition_executable_decode_ranges(
        layout, caps, limits_, cancellation);
    if (!partition_result)
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            partition_result.error());
    auto partition = partition_result.take_value();

    std::vector<decode_frontier_tile_t> frontier_tiles;
    frontier_tiles.reserve(partition.tiles.size());
    for (const auto& tile : partition.tiles) {
        decode_frontier_tile_t ft;
        ft.id = tile.tile_id;
        ft.start_rva = tile.start_rva;
        ft.byte_count = tile.byte_count;
        frontier_tiles.push_back(ft);
    }

    auto frontier_build = decode_frontier_t::build(
        std::move(frontier_tiles), limits_.maximum_frontier_seeds);
    if (!frontier_build)
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            frontier_build.error());
    auto frontier = frontier_build.take_value();

    for (const auto& seed : seeds) {
        decode_frontier_seed_t fs;
        fs.rva = seed.address.value;
        fs.kind = decode_frontier_seed_kind_t::explicit_entry;
        fs.provenance = seed.provenance;
        fs.confidence = seed.confidence;
        fs.stable_source_id = seed.stable_source_id;
        auto add_result = frontier.add_seed(fs);
        if (!add_result)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                add_result.error());
    }

    if (limits_.seed_executable_range_starts) {
        for (const auto& range : partition.ranges) {
            decode_frontier_seed_t fs;
            fs.rva = range.start_rva;
            fs.kind = decode_frontier_seed_kind_t::range_entry;
            fs.provenance = fact_provenance_t::linear_validation;
            fs.confidence = 80;
            auto add_result = frontier.add_seed(fs);
            if (!add_result)
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    add_result.error());
        }
    }

    std::vector<tile_accumulator_t> accumulators(partition.tiles.size());
    for (std::size_t i = 0; i < partition.tiles.size(); ++i)
        accumulators[i].tile = &partition.tiles[i];

    std::vector<executable_decode_tile_t> tiles_by_id = partition.tiles;
    std::sort(tiles_by_id.begin(), tiles_by_id.end(),
              [](const auto& a, const auto& b) { return a.tile_id < b.tile_id; });

    std::vector<tile_decode_cross_tile_edge_t> cross_tile_edges;
    tile_decode_orchestrator_statistics_t stats;
    stats.initialized_executable_bytes = partition.initialized_executable_bytes;
    stats.zero_fill_executable_bytes = partition.zero_fill_executable_bytes;

    const std::uint64_t image_base = layout.identity().image_base;
    const std::uint64_t image_size = layout.identity().provider_size;

    std::uint64_t request_id_counter = 0;
    std::uint64_t total_decode_requests = 0;
    std::uint64_t total_instructions = 0;
    std::uint64_t total_operand_facts = 0;
    std::uint64_t total_edges = 0;
    std::uint64_t total_coverage_spans = 0;

    while (!frontier.empty()) {
        if (cancellation.stop_requested()) {
            auto err = make_workspace_error(
                cancellation.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "orchestrator recursive pass cancelled", kPhase);
            err.cancellation = !cancellation.deadline_exceeded();
            err.deadline = cancellation.deadline_exceeded();
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                std::move(err));
        }

        auto wave_result = frontier.take_wave(limits_.maximum_frontier_wave);
        if (!wave_result)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                wave_result.error());
        auto wave = wave_result.take_value();
        if (wave.empty())
            break;

        std::vector<tile_decode_request_t> requests;
        requests.reserve(wave.size());

        for (const auto& seed : wave) {
            if (total_decode_requests >= limits_.maximum_decode_requests)
                break;
            if (seed.tile_id >= partition.tiles.size())
                continue;

            const auto& tile = partition.tiles[seed.tile_id];
            if (accumulators[seed.tile_id].cutoff)
                continue;

            const std::uint64_t offset_in_tile = seed.rva - tile.start_rva;
            const std::uint64_t remaining = tile.byte_count - offset_in_tile;
            const std::uint64_t effective_bytes = (std::min)(
                remaining + tile.lookahead_bytes, caps.maximum_request_bytes);

            tile_decode_request_t req;
            req.request_id = request_id_counter++;
            req.tile_id = seed.tile_id;
            req.pass = tile_decode_pass_t::recursive;
            req.seed_kind = seed.kind;
            req.start.space = address_space_id_t::relative_virtual;
            req.start.value = seed.rva;
            req.start.architecture = caps.decoder_key.architecture;
            req.start.mode = caps.decoder_key.mode;
            req.provider_offset = tile.provider_offset + offset_in_tile;
            req.runtime_address = tile.start_virtual_address + offset_in_tile;
            req.image_base = image_base;
            req.image_size = image_size;
            req.byte_count = effective_bytes;
            req.owned_end_rva = tile.start_rva + tile.byte_count;
            req.stable_source_id = seed.stable_source_id;
            req.provenance = seed.provenance;
            req.confidence = seed.confidence;

            requests.push_back(req);
            ++total_decode_requests;
            ++stats.recursive_requests;
        }

        if (requests.empty())
            continue;

        auto batch_result = executor.execute_batch(snapshot, requests, cancellation);
        if (!batch_result)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                batch_result.error());
        auto completions = batch_result.take_value();

        for (const auto& completion : completions) {
            if (!completion.succeeded())
                continue;

            if (completion.request_id >= requests.size())
                continue;

            const auto& req = requests[completion.request_id];
            if (req.tile_id >= accumulators.size())
                continue;

            auto& acc = accumulators[req.tile_id];
            const auto& records = completion.records;

            for (std::size_t i = 0; i < records.instructions.size(); ++i) {
                const auto& instr = records.instructions[i];
                const auto rva = instr.address.value;

                if (rva < acc.tile->start_rva || rva >= acc.tile->start_rva + acc.tile->byte_count)
                    continue;

                ++stats.decoded_instruction_candidates;

                auto existing = acc.instructions.find(rva);
                if (existing != acc.instructions.end()) {
                    ++stats.duplicate_instruction_candidates;
                    if (instruction_stronger(instr, existing->second.record)) {
                        tile_instruction_entry_t entry;
                        entry.record = instr;
                        if (i < records.delay_slot_counts.size())
                            entry.delay_slots = records.delay_slot_counts[i];
                        for (std::uint32_t op = instr.operand_fact_begin;
                             op < instr.operand_fact_begin + instr.operand_fact_count &&
                             op < records.operand_facts.size(); ++op)
                            entry.operands.push_back(records.operand_facts[op]);
                        for (std::uint32_t tf = instr.target_fact_begin;
                             tf < instr.target_fact_begin + instr.target_fact_count &&
                             tf < records.target_facts.size(); ++tf)
                            entry.targets.push_back(records.target_facts[tf]);
                        existing->second = std::move(entry);
                    }
                    continue;
                }

                auto overlap_it = acc.instructions.end();
                for (auto it2 = acc.instructions.begin(); it2 != acc.instructions.end(); ++it2) {
                    if (rva < it2->first + it2->second.record.length &&
                        rva + instr.length > it2->first) {
                        ++stats.overlap_instruction_candidates;
                        overlap_it = it2;
                        break;
                    }
                }
                if (overlap_it != acc.instructions.end()) {
                    if (instruction_stronger(instr, overlap_it->second.record)) {
                        acc.instructions.erase(overlap_it);
                    } else {
                        continue;
                    }
                }

                tile_instruction_entry_t entry;
                entry.record = instr;
                if (i < records.delay_slot_counts.size())
                    entry.delay_slots = records.delay_slot_counts[i];
                for (std::uint32_t op = instr.operand_fact_begin;
                     op < instr.operand_fact_begin + instr.operand_fact_count &&
                     op < records.operand_facts.size(); ++op) {
                    entry.operands.push_back(records.operand_facts[op]);
                    ++stats.accepted_operands;
                    ++total_operand_facts;
                }
                for (std::uint32_t tf = instr.target_fact_begin;
                     tf < instr.target_fact_begin + instr.target_fact_count &&
                     tf < records.target_facts.size(); ++tf) {
                    entry.targets.push_back(records.target_facts[tf]);
                }

                acc.instructions.emplace(rva, std::move(entry));
                acc.decoded_rvas.insert(rva);
                ++stats.accepted_instructions;
                ++total_instructions;

                if ((instr.flow_flags & flow_fallthrough) != 0) {
                    const auto ft_rva = rva + instr.length;
                    if (ft_rva < req.owned_end_rva) {
                        decode_frontier_seed_t ft_seed;
                        ft_seed.rva = ft_rva;
                        ft_seed.kind = decode_frontier_seed_kind_t::fallthrough;
                        ft_seed.provenance = instr.provenance;
                        ft_seed.confidence = instr.confidence;
                        ft_seed.source_rva = rva;
                        auto add_result = frontier.add_seed(ft_seed, req.tile_id);
                        if (!add_result)
                            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                                add_result.error());
                    }
                }

                for (const auto& target : entry.targets) {
                    const auto target_rva = target.target.value;
                    const auto target_kind = flow_to_target_seed_kind(instr.flow_flags);

                    decode_frontier_seed_t target_seed;
                    target_seed.rva = target_rva;
                    target_seed.kind = target_kind;
                    target_seed.provenance = instr.provenance;
                    target_seed.confidence = instr.confidence;
                    target_seed.source_rva = rva;

                    auto add_result = frontier.add_seed(target_seed, req.tile_id);
                    if (!add_result)
                        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                            add_result.error());

                    if (add_result.value().cross_tile) {
                        tile_decode_cross_tile_edge_t edge;
                        edge.source_tile_id = req.tile_id;
                        edge.target_tile_id = add_result.value().tile_id.value_or(0);
                        edge.source = instr.address;
                        edge.target = target.target;
                        edge.kind = flow_to_edge_kind(instr.flow_flags);
                        cross_tile_edges.push_back(edge);
                        ++stats.cross_tile_edges;
                    }

                    ++stats.accepted_edges;
                    ++total_edges;
                }
            }

            merge_coverage_into(acc.coverage, records.coverage);
            for (const auto& span : records.coverage)
                total_coverage_spans += span.size;

            acc.invalid_bytes += records.invalid_bytes;
            if (records.invalid_bytes > 0) {
                ++acc.invalid_runs;
                ++stats.invalid_runs;
            }
            stats.invalid_bytes += records.invalid_bytes;

            if (acc.invalid_bytes > limits_.invalid_run_policy.maximum_invalid_bytes_per_tile ||
                acc.invalid_runs > limits_.invalid_run_policy.maximum_invalid_runs_per_tile) {
                acc.cutoff = true;
                ++stats.invalid_policy_cutoffs;
            }
        }
    }

    if (total_instructions > limits_.maximum_instructions) {
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            orchestrator_error(workspace_error_code_t::limit_exceeded,
                "maximum instructions exceeded"));
    }
    if (total_operand_facts > limits_.maximum_operand_facts) {
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            orchestrator_error(workspace_error_code_t::limit_exceeded,
                "maximum operand facts exceeded"));
    }
    if (total_edges > limits_.maximum_edges) {
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            orchestrator_error(workspace_error_code_t::limit_exceeded,
                "maximum edges exceeded"));
    }

    if (cancellation.stop_requested()) {
            auto err = make_workspace_error(
                cancellation.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "orchestrator gap pass cancelled", kPhase);
            err.cancellation = !cancellation.deadline_exceeded();
            err.deadline = cancellation.deadline_exceeded();
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                std::move(err));
        }

        for (std::size_t tile_idx = 0; tile_idx < partition.tiles.size(); ++tile_idx) {
            auto& acc = accumulators[tile_idx];
            const auto* tile = acc.tile;
            if (!tile || acc.cutoff)
                continue;

            std::uint64_t cursor = tile->start_rva;
            const std::uint64_t tile_end = tile->start_rva + tile->byte_count;

            std::vector<tile_decode_request_t> gap_requests;

            while (cursor < tile_end) {
                if (total_decode_requests >= limits_.maximum_decode_requests)
                    break;

                if (acc.decoded_rvas.count(cursor) > 0) {
                    auto it = acc.instructions.find(cursor);
                    if (it != acc.instructions.end())
                        cursor += it->second.record.length;
                    else
                        ++cursor;
                    continue;
                }

                std::uint64_t gap_start = cursor;
                while (cursor < tile_end && acc.decoded_rvas.count(cursor) == 0)
                    ++cursor;

                std::uint64_t gap_length = cursor - gap_start;
                if (gap_length == 0)
                    continue;

                const std::uint64_t offset_in_tile = gap_start - tile->start_rva;
                const std::uint64_t effective_bytes = (std::min)(
                    gap_length, caps.maximum_request_bytes);

                tile_decode_request_t req;
                req.request_id = request_id_counter++;
                req.tile_id = static_cast<decode_tile_id_t>(tile_idx);
                req.pass = tile_decode_pass_t::gap;
                req.seed_kind = decode_frontier_seed_kind_t::fallthrough;
                req.start.space = address_space_id_t::relative_virtual;
                req.start.value = gap_start;
                req.start.architecture = caps.decoder_key.architecture;
                req.start.mode = caps.decoder_key.mode;
                req.provider_offset = tile->provider_offset + offset_in_tile;
                req.runtime_address = tile->start_virtual_address + offset_in_tile;
                req.image_base = image_base;
                req.image_size = image_size;
                req.byte_count = effective_bytes;
                req.owned_end_rva = tile_end;
                req.stable_source_id = 0;
                req.provenance = fact_provenance_t::gap_recovery;
                req.confidence = 50;

                gap_requests.push_back(req);
                ++total_decode_requests;
                ++stats.gap_requests;
            }

            if (gap_requests.empty())
                continue;

            auto gap_batch = executor.execute_batch(snapshot, gap_requests, cancellation);
            if (!gap_batch)
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    gap_batch.error());
            auto gap_completions = gap_batch.take_value();

            for (const auto& completion : gap_completions) {
                if (!completion.succeeded())
                    continue;

                const auto& records = completion.records;

                for (std::size_t i = 0; i < records.instructions.size(); ++i) {
                    const auto& instr = records.instructions[i];
                    const auto rva = instr.address.value;

                    if (rva < tile->start_rva || rva >= tile_end)
                        continue;

                    if (acc.instructions.count(rva) > 0)
                        continue;

                    ++stats.decoded_instruction_candidates;

                    tile_instruction_entry_t entry;
                    entry.record = instr;
                    if (i < records.delay_slot_counts.size())
                        entry.delay_slots = records.delay_slot_counts[i];
                    for (std::uint32_t op = instr.operand_fact_begin;
                         op < instr.operand_fact_begin + instr.operand_fact_count &&
                         op < records.operand_facts.size(); ++op) {
                        entry.operands.push_back(records.operand_facts[op]);
                        ++stats.accepted_operands;
                        ++total_operand_facts;
                    }
                    for (std::uint32_t tf = instr.target_fact_begin;
                         tf < instr.target_fact_begin + instr.target_fact_count &&
                         tf < records.target_facts.size(); ++tf)
                        entry.targets.push_back(records.target_facts[tf]);

                    acc.instructions.emplace(rva, std::move(entry));
                    acc.decoded_rvas.insert(rva);
                    ++stats.accepted_instructions;
                    ++total_instructions;
                }

                merge_coverage_into(acc.coverage, records.coverage);
                acc.invalid_bytes += records.invalid_bytes;
                if (records.invalid_bytes > 0) {
                    ++acc.invalid_runs;
                    ++stats.invalid_runs;
                }
                stats.invalid_bytes += records.invalid_bytes;

                if (acc.invalid_bytes > limits_.invalid_run_policy.maximum_invalid_bytes_per_tile ||
                    acc.invalid_runs > limits_.invalid_run_policy.maximum_invalid_runs_per_tile) {
                    acc.cutoff = true;
                    ++stats.invalid_policy_cutoffs;
            }
        }
    }

    std::vector<packed_analysis_shard_t> shards;
    std::vector<tile_decode_shard_summary_t> shard_summaries;
    std::vector<coverage_span_t> merged_coverage;

    for (std::size_t tile_idx = 0; tile_idx < partition.tiles.size(); ++tile_idx) {
        if (cancellation.stop_requested()) {
            auto err = make_workspace_error(
                cancellation.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "orchestrator shard build cancelled", kPhase);
            err.cancellation = !cancellation.deadline_exceeded();
            err.deadline = cancellation.deadline_exceeded();
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                std::move(err));
        }

        const auto& acc = accumulators[tile_idx];
        if (!acc.tile)
            continue;

        packed_analysis_shard_builder_t builder(acc.tile->shard_id);

        std::uint64_t instruction_source_id = 1;
        std::uint32_t instruction_count = 0;
        std::uint32_t operand_count = 0;
        std::uint32_t edge_count = 0;

        for (const auto& [rva, entry] : acc.instructions) {
            packed_instruction_input_t instr_input;
            instr_input.source_id = instruction_source_id;
            instr_input.address = entry.record.address;
            instr_input.length = entry.record.length;
            instr_input.mnemonic_id = entry.record.mnemonic_id;
            instr_input.opcode_id = entry.record.opcode_id;
            instr_input.flow_flags = entry.record.flow_flags;
            instr_input.provenance = entry.record.provenance;
            instr_input.confidence = entry.record.confidence;
            instr_input.coverage = entry.record.coverage;
            instr_input.stable_source_id = entry.record.stable_source_id;

            auto instr_result = builder.add_instruction(instr_input);
            if (!instr_result)
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed store instruction add failed", rva));

            for (const auto& op : entry.operands) {
                packed_operand_input_t op_input;
                op_input.source_id = static_cast<entity_id_t>(operand_count + 1);
                op_input.instruction = packed_entity_reference_t::local(
                    packed_entity_domain_t::instruction, instruction_source_id);
                op_input.operand_index = op.operand_index;
                op_input.decoder_operand_id = op.decoder_operand_id;
                op_input.kind = op.kind;
                op_input.access = op.access;
                op_input.visibility = op.visibility;
                op_input.encoding = op.encoding;
                op_input.memory_type = op.memory_type;
                op_input.access_width = op.access_width;
                op_input.bit_width = op.bit_width;
                op_input.access_width_bits = op.access_width_bits;
                op_input.access_count = op.access_count;
                op_input.element_width_bits = op.element_width_bits;
                op_input.element_count = op.element_count;
                op_input.address_width_bits = op.address_width_bits;
                op_input.reg = op.reg;
                op_input.segment_reg = op.segment_reg;
                op_input.base_reg = op.base_reg;
                op_input.index_reg = op.index_reg;
                op_input.scale = op.scale;
                op_input.relative = op.relative;
                op_input.signed_value = op.signed_value;
                op_input.has_displacement = op.has_displacement;
                op_input.has_resolved_expression_value = op.has_resolved_expression_value;
                op_input.displacement = op.displacement;
                op_input.immediate = op.immediate;
                op_input.resolved_expression_value = op.resolved_expression_value;
                op_input.address_components = op.address_components;
                op_input.address_expression_kind = op.address_expression;
                op_input.address_resolution = op.address_resolution;

                auto op_result = builder.add_operand(op_input);
                if (!op_result)
                    return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "packed store operand add failed", rva));

                ++operand_count;
            }

            if ((entry.record.flow_flags & (flow_branch | flow_call | flow_return | flow_indirect)) != 0) {
                for (const auto& target : entry.targets) {
                    packed_edge_input_t edge_input;
                    edge_input.source_id = static_cast<entity_id_t>(edge_count + 1);
                    edge_input.source_entity = packed_entity_reference_t::local(
                        packed_entity_domain_t::instruction, instruction_source_id);
                    edge_input.source = entry.record.address;
                    edge_input.target = target.target;
                    edge_input.kind = flow_to_edge_kind(entry.record.flow_flags);
                    edge_input.provenance = entry.record.provenance;
                    edge_input.confidence = entry.record.confidence;

                    auto edge_result = builder.add_edge(edge_input);
                    if (!edge_result)
                        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                            orchestrator_error(workspace_error_code_t::integrity_failure,
                                "packed store edge add failed", rva));

                    ++edge_count;
                }
            }

            ++instruction_source_id;
            ++instruction_count;
        }

        for (const auto& span : acc.coverage) {
            packed_coverage_input_t cov_input;
            cov_input.source_id = 0;
            cov_input.span_begin = span.start;
            cov_input.span_end = span.start;
            cov_input.span_end.value = span.start.value + span.size;
            cov_input.reason = span.reason;
            cov_input.provenance = span.provenance;
            cov_input.confidence = span.confidence;

            auto cov_result = builder.add_coverage(cov_input);
            if (!cov_result)
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed store coverage add failed"));

            merged_coverage.push_back(span);
        }

        auto shard_result = std::move(builder).finalize();
        if (!shard_result)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "packed store shard finalize failed"));

        shards.push_back(std::move(shard_result).take_value());

        tile_decode_shard_summary_t summary;
        summary.tile_id = acc.tile->tile_id;
        summary.shard_id = acc.tile->shard_id;
        summary.instruction_count = instruction_count;
        summary.operand_count = operand_count;
        summary.edge_count = edge_count;
        shard_summaries.push_back(summary);
    }

    auto store_result = packed_analysis_store_t::merge(std::move(shards));
    if (!store_result)
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "packed store merge failed"));

    std::sort(cross_tile_edges.begin(), cross_tile_edges.end(),
              [](const auto& a, const auto& b) {
                  if (a.source_tile_id != b.source_tile_id)
                      return a.source_tile_id < b.source_tile_id;
                  if (a.target_tile_id != b.target_tile_id)
                      return a.target_tile_id < b.target_tile_id;
                  if (a.source.value != b.source.value)
                      return a.source.value < b.source.value;
                  return a.target.value < b.target.value;
              });

    merge_coverage_into(merged_coverage, {});

    std::sort(shard_summaries.begin(), shard_summaries.end(),
              [](const auto& a, const auto& b) { return a.tile_id < b.tile_id; });

    stats.frontier = frontier.snapshot();

    tile_decode_orchestration_result_t result;
    result.packed_store = std::make_unique<packed_analysis_store_t>(
        std::move(store_result).take_value());
    result.coverage = std::move(merged_coverage);
    result.cross_tile_edges = std::move(cross_tile_edges);
    result.shards = std::move(shard_summaries);
    result.statistics = stats;

    return workspace_result_t<tile_decode_orchestration_result_t>::success(
        std::move(result));
}

}
