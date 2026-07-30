#include "benchmark_runner.hpp"

#include "../../../../tests/analysis_workspace/large_pe_fixture_builder.hpp"

#include "../workspace/baseline_pipeline.hpp"
#include "../workspace/checked_range.hpp"
#include "../workspace/decompiler_service.hpp"
#include "../workspace/search_index.hpp"
#include "../workspace/workspace_registry.hpp"
#include "../tile_decode_orchestrator.hpp"
#include "../../infra/taskflow_runtime.hpp"
#include "../../../helpers/diag_log.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>

#pragma comment(lib, "bcrypt.lib")

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <intrin.h>
#include <iterator>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace aida::analysis::benchmark {
namespace {

using json = nlohmann::json;
using steady_clock_t = std::chrono::steady_clock;

const char* mode_name(benchmark_mode_t mode) noexcept
{
    return mode == benchmark_mode_t::synthetic ? "synthetic" : "real";
}

std::uint64_t nanoseconds_since(steady_clock_t::time_point begin)
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        steady_clock_t::now() - begin).count());
}

std::string utc_stamp_filename()
{
    SYSTEMTIME utc{};
    GetSystemTime(&utc);
    char stamp[32]{};
    _snprintf_s(stamp, sizeof(stamp), _TRUNCATE, "%04u%02u%02u_%02u%02u%02u",
        static_cast<unsigned>(utc.wYear), static_cast<unsigned>(utc.wMonth),
        static_cast<unsigned>(utc.wDay), static_cast<unsigned>(utc.wHour),
        static_cast<unsigned>(utc.wMinute), static_cast<unsigned>(utc.wSecond));
    return stamp;
}

std::string utc_run_id()
{
    SYSTEMTIME utc{};
    GetSystemTime(&utc);
    char stamp[32]{};
    _snprintf_s(stamp, sizeof(stamp), _TRUNCATE, "%04u%02u%02uT%02u%02u%02uZ",
        static_cast<unsigned>(utc.wYear), static_cast<unsigned>(utc.wMonth),
        static_cast<unsigned>(utc.wDay), static_cast<unsigned>(utc.wHour),
        static_cast<unsigned>(utc.wMinute), static_cast<unsigned>(utc.wSecond));
    return std::string(stamp) + "-" + std::to_string(GetCurrentProcessId());
}

std::uint64_t process_cpu_ns_now()
{
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        return 0;
    ULARGE_INTEGER kernel_value{}, user_value{};
    kernel_value.LowPart = kernel.dwLowDateTime;
    kernel_value.HighPart = kernel.dwHighDateTime;
    user_value.LowPart = user.dwLowDateTime;
    user_value.HighPart = user.dwHighDateTime;
    return (kernel_value.QuadPart + user_value.QuadPart) * 100ULL;
}

std::uint64_t count_zero_bytes(const std::filesystem::path& path, std::uint64_t expected_size)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
        throw std::runtime_error("benchmark fixture cannot be opened for zero-padding measurement");
    std::vector<char> buffer(1024 * 1024);
    std::uint64_t consumed = 0;
    std::uint64_t zeros = 0;
    while (stream) {
        stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = stream.gcount();
        if (count <= 0)
            break;
        consumed += static_cast<std::uint64_t>(count);
        zeros += static_cast<std::uint64_t>(std::count(buffer.begin(), buffer.begin() + count, '\0'));
    }
    if (stream.bad() || consumed != expected_size)
        throw std::runtime_error("benchmark fixture changed or failed during zero-padding measurement");
    return zeros;
}

std::uint64_t executable_bytes_of(const std::shared_ptr<const workspace_image_t>& image)
{
    std::uint64_t total = 0;
    if (!image)
        return total;
    for (const auto& section : image->sections) {
        if ((section.permissions & image_permission_execute) != 0)
            total += (std::max)(section.virtual_size, section.file_size);
    }
    if (total == 0) {
        for (const auto& segment : image->segments) {
            if ((segment.permissions & image_permission_execute) != 0)
                total += (std::max)(segment.virtual_size, segment.file_size);
        }
    }
    return total;
}

void remove_database_artifacts(const std::string& database_path)
{
    if (database_path.empty())
        return;
    std::error_code error;
    for (const auto& candidate : {database_path, database_path + "-wal", database_path + "-shm"})
        std::filesystem::remove(std::filesystem::u8path(candidate), error);
}

void close_benchmark_workspace(const std::shared_ptr<analysis_workspace_t>& workspace,
                               bool remove_database)
{
    if (!workspace)
        return;
    const std::string database_path =
        workspace->database() ? workspace->database()->path() : std::string();
    auto closed = workspace_registry().close(workspace->identity().binary_id(),
        steady_clock_t::now() + std::chrono::seconds(30));
    if (!closed)
        throw std::runtime_error("benchmark workspace close failed: " +
            closed.error().stable_code() + ":" + closed.error().message);
    if (remove_database)
        remove_database_artifacts(database_path);
}

struct phase_windows_t {
    std::optional<steady_clock_t::time_point> decode_begin;
    std::optional<steady_clock_t::time_point> decode_end;
    std::optional<steady_clock_t::time_point> merge_begin;
    std::optional<steady_clock_t::time_point> merge_end;
    std::optional<steady_clock_t::time_point> publish_begin;
    std::optional<steady_clock_t::time_point> publish_end;

    static bool has_token(const std::string& phase, const char* token)
    {
        std::size_t offset = 0;
        while (offset <= phase.size()) {
            const auto plus = phase.find('+', offset);
            const std::string_view piece(phase.data() + offset,
                plus == std::string::npos ? phase.size() - offset : plus - offset);
            if (piece == token)
                return true;
            if (plus == std::string::npos)
                break;
            offset = plus + 1;
        }
        return false;
    }

    void sample(const workspace_progress_t& progress, bool finished)
    {
        const auto now = steady_clock_t::now();
        const bool decode = has_token(progress.phase, "decode");
        const bool merge = has_token(progress.phase, "decode_merge");
        const bool publish = has_token(progress.phase, "publish_ready");
        if (decode && !decode_begin)
            decode_begin = now;
        if (!decode && decode_begin && !decode_end)
            decode_end = now;
        if (merge && !merge_begin)
            merge_begin = now;
        if (!merge && merge_begin && !merge_end)
            merge_end = now;
        if (publish && !publish_begin)
            publish_begin = now;
        if (!publish && publish_begin && !publish_end)
            publish_end = now;
        if (finished) {
            if (decode_begin && !decode_end)
                decode_end = now;
            if (merge_begin && !merge_end)
                merge_end = now;
            if (publish_begin && !publish_end)
                publish_end = now;
        }
    }

    std::uint64_t window_ns(const std::optional<steady_clock_t::time_point>& begin,
                            const std::optional<steady_clock_t::time_point>& end) const
    {
        if (!begin || !end || *end < *begin)
            return 0;
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            *end - *begin).count());
    }

    std::uint64_t decode_wall_ns() const { return window_ns(decode_begin, decode_end); }
    std::uint64_t merge_wall_ns() const { return window_ns(merge_begin, merge_end); }
    std::uint64_t publish_wall_ns() const { return window_ns(publish_begin, publish_end); }
};

struct analysis_once_result_t {
    std::shared_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<const analysis_snapshot_t> snapshot;
    phase_windows_t windows;
    std::uint64_t wall_ns = 0;
    std::uint64_t decode_window_ns = 0;
    std::uint64_t decoded_bytes = 0;
    std::uint64_t file_bytes = 0;
    std::uint64_t instruction_count = 0;
    std::uint64_t code_bytes = 0;
};

analysis_once_result_t run_analysis_once(const open_static_workspace_request_t& open_request,
                                         std::uint32_t worker_budget,
                                         const cancellation_token_t& cancel)
{
    analysis_once_result_t outcome;
    try {
        auto opened = workspace_registry().open_static(open_request, cancel);
        if (!opened)
            throw std::runtime_error("benchmark workspace open failed: " +
                opened.error().stable_code() + ":" + opened.error().message);
        outcome.workspace = opened.take_value();
        const auto image = outcome.workspace->normalized_image();
        if (!image)
            throw std::runtime_error("benchmark fixture image metadata is unavailable");
        outcome.code_bytes = executable_bytes_of(image);
        if (outcome.code_bytes == 0)
            throw std::runtime_error("benchmark fixture has no normalized executable bytes");

        baseline_analysis_settings_t settings;
        settings.decode_worker_lanes = worker_budget;
        auto started = baseline_analysis_service_t::start(outcome.workspace, settings);
        if (!started)
            throw std::runtime_error("baseline analysis submission failed: " +
                started.error().stable_code() + ":" + started.error().message);

        const auto analysis_begin = steady_clock_t::now();
        bool analysis_cancelled = false;
        for (;;) {
            const auto waited = aida::infra::taskflow_runtime::wait_for(started.value(), 25);
            outcome.windows.sample(outcome.workspace->progress(), !waited.timed_out);
            if (waited.completed || waited.failed || waited.cancelled)
                break;
            if (cancel.stop_requested()) {
                baseline_analysis_service_t::cancel(started.value());
                (void)aida::infra::taskflow_runtime::wait_for(started.value(), 10000);
                analysis_cancelled = true;
                break;
            }
        }
        outcome.wall_ns = nanoseconds_since(analysis_begin);
        const auto progress = outcome.workspace->progress();
        if (analysis_cancelled || cancel.stop_requested())
            throw std::runtime_error("benchmark analysis cancelled");
        if (progress.error)
            throw std::runtime_error("baseline analysis failed: " +
                progress.error->stable_code() + ":" + progress.error->message);
        if (progress.readiness != workspace_readiness_t::baseline_ready ||
            !outcome.workspace->snapshot())
            throw std::runtime_error("baseline graph completed without a ready publication");

        outcome.snapshot = outcome.workspace->snapshot();
        for (const auto& span : outcome.snapshot->coverage) {
            if (span.reason == coverage_reason_t::decoded)
                outcome.decoded_bytes += span.size;
        }
        outcome.file_bytes = outcome.workspace->provider().size();
        outcome.decode_window_ns = outcome.windows.decode_wall_ns() +
            outcome.windows.merge_wall_ns();
        outcome.instruction_count = outcome.snapshot->instructions.size();
        return outcome;
    } catch (...) {
        if (outcome.workspace) {
            try { close_benchmark_workspace(outcome.workspace, true); } catch (...) {}
        }
        throw;
    }
}

struct determinism_walker_t {
    test_fixture::detail::large_pe_sha256_stream_t stream;

    void bytes(const void* data, std::size_t size)
    {
        stream.update(static_cast<const std::uint8_t*>(data), size);
    }
    void u8(std::uint8_t value) { bytes(&value, sizeof(value)); }
    void boolean(bool value) { u8(value ? static_cast<std::uint8_t>(1) : static_cast<std::uint8_t>(0)); }
    void u16(std::uint16_t value)
    {
        u8(static_cast<std::uint8_t>(value & 0xFFU));
        u8(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
    }
    void u32(std::uint32_t value)
    {
        u16(static_cast<std::uint16_t>(value & 0xFFFFU));
        u16(static_cast<std::uint16_t>((value >> 16) & 0xFFFFU));
    }
    void u64(std::uint64_t value)
    {
        u32(static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
        u32(static_cast<std::uint32_t>((value >> 32) & 0xFFFFFFFFULL));
    }
    void i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }
    void address(const address_t& value)
    {
        u8(static_cast<std::uint8_t>(value.space));
        u64(value.value);
        u8(static_cast<std::uint8_t>(value.architecture));
        u8(static_cast<std::uint8_t>(value.mode));
    }
    void address_opt(const std::optional<address_t>& value)
    {
        boolean(value.has_value());
        if (value)
            address(*value);
    }
    void entity_opt(const std::optional<entity_id_t>& value)
    {
        boolean(value.has_value());
        if (value)
            u64(*value);
    }
    void string_bytes(const std::string& value)
    {
        u64(value.size());
        if (!value.empty())
            bytes(value.data(), value.size());
    }
    void digest_bytes(const sha256_digest_t& value)
    {
        bytes(value.bytes.data(), value.bytes.size());
    }
};

void walk_instruction(determinism_walker_t& walk, const instruction_record_t& record)
{
    walk.u64(record.id);
    walk.address(record.address);
    walk.u8(record.length);
    walk.u16(record.mnemonic_id);
    walk.u32(record.opcode_id);
    walk.u32(record.flow_flags);
    walk.u32(record.operand_fact_begin);
    walk.u16(record.operand_fact_count);
    walk.u32(record.target_fact_begin);
    walk.u16(record.target_fact_count);
    walk.u8(static_cast<std::uint8_t>(record.provenance));
    walk.u8(record.confidence);
    walk.u8(static_cast<std::uint8_t>(record.coverage));
    walk.u64(record.stable_source_id);
}

void walk_operand_fact(determinism_walker_t& walk, const operand_fact_t& record)
{
    walk.u64(record.id);
    walk.u64(record.instruction_id);
    walk.u64(record.address_expression_id);
    walk.u8(record.operand_index);
    walk.u8(record.decoder_operand_id);
    walk.u8(static_cast<std::uint8_t>(record.kind));
    walk.u8(record.access);
    walk.u8(record.visibility);
    walk.u8(record.encoding);
    walk.u8(record.memory_type);
    walk.u8(record.access_width);
    walk.u16(record.bit_width);
    walk.u16(record.access_width_bits);
    walk.u16(record.access_count);
    walk.u16(record.element_width_bits);
    walk.u16(record.element_count);
    walk.u16(record.address_width_bits);
    walk.u16(record.reg);
    walk.u16(record.segment_reg);
    walk.u16(record.base_reg);
    walk.u16(record.index_reg);
    walk.u8(record.scale);
    walk.boolean(record.relative);
    walk.boolean(record.signed_value);
    walk.boolean(record.has_displacement);
    walk.boolean(record.has_resolved_expression_value);
    walk.i64(record.displacement);
    walk.u64(record.immediate);
    walk.u64(record.resolved_expression_value);
    walk.u16(record.address_components);
    walk.u8(static_cast<std::uint8_t>(record.address_expression));
    walk.u8(static_cast<std::uint8_t>(record.address_resolution));
}

void walk_target_fact(determinism_walker_t& walk, const target_fact_t& record)
{
    walk.u64(record.instruction_id);
    walk.u64(record.operand_fact_id);
    walk.u64(record.address_expression_id);
    walk.address(record.target);
    walk.u8(static_cast<std::uint8_t>(record.kind));
    walk.u8(static_cast<std::uint8_t>(record.resolution));
    walk.u8(record.operand_index);
    walk.u16(record.access_width_bits);
    walk.u16(record.access_count);
    walk.boolean(record.direct);
    walk.boolean(record.is_external);
}

void walk_block(determinism_walker_t& walk, const basic_block_record_t& record)
{
    walk.u64(record.id);
    walk.u64(record.function_id);
    walk.address(record.start);
    walk.address(record.end);
    walk.u32(record.first_instruction);
    walk.u32(record.instruction_count);
    walk.u8(static_cast<std::uint8_t>(record.provenance));
    walk.u8(record.confidence);
}

void walk_chunk(determinism_walker_t& walk, const function_chunk_record_t& record)
{
    walk.u64(record.id);
    walk.u64(record.function_id);
    walk.address(record.start);
    walk.address(record.end);
    walk.u32(record.first_block);
    walk.u32(record.block_count);
    walk.u8(static_cast<std::uint8_t>(record.provenance));
    walk.u8(record.confidence);
    walk.boolean(record.cold);
    walk.boolean(record.shared);
}

void walk_membership(determinism_walker_t& walk,
                     const function_block_membership_record_t& record)
{
    walk.u64(record.function_id);
    walk.u64(record.chunk_id);
    walk.u64(record.block_id);
    walk.u32(record.block_index);
    walk.u32(record.ordinal);
    walk.boolean(record.shared);
}

void walk_function(determinism_walker_t& walk, const function_record_t& record)
{
    walk.u64(record.id);
    walk.address(record.start);
    walk.address(record.end);
    walk.u32(record.first_block);
    walk.u32(record.block_count);
    walk.u32(record.first_chunk);
    walk.u32(record.chunk_count);
    walk.u32(record.first_block_membership);
    walk.u32(record.block_membership_count);
    walk.entity_opt(record.symbol_id);
    walk.u8(static_cast<std::uint8_t>(record.provenance));
    walk.u8(record.confidence);
    walk.boolean(record.thunk);
    walk.boolean(record.noreturn);
    walk.u64(record.chunks.size());
    for (const auto& chunk : record.chunks) {
        walk.u64(chunk.rva_start);
        walk.u64(chunk.rva_end);
        walk.u8(chunk.chunk_kind);
    }
}

void walk_edge(determinism_walker_t& walk, const edge_record_t& record)
{
    walk.u64(record.id);
    walk.u64(record.source_entity);
    walk.entity_opt(record.target_entity);
    walk.address(record.source);
    walk.address(record.target);
    walk.u8(static_cast<std::uint8_t>(record.kind));
    walk.u8(static_cast<std::uint8_t>(record.provenance));
    walk.u8(record.confidence);
}

void walk_call_quality(determinism_walker_t& walk, const call_graph_quality_t& quality)
{
    walk.u8(static_cast<std::uint8_t>(quality.provenance));
    walk.u8(quality.confidence);
    walk.u32(quality.contributor_count);
    walk.boolean(quality.conflicted);
}

void walk_call_graph(determinism_walker_t& walk, const call_graph_publication_t& graph)
{
    walk.u64(graph.nodes.size());
    for (const auto& record : graph.nodes) {
        walk.u64(record.function_id);
        walk.address(record.address);
        walk.u64(record.incoming_edges);
        walk.u64(record.outgoing_edges);
        walk.u64(record.indirect_edges);
        walk.u64(record.unresolved_sites);
    }
    walk.u64(graph.call_sites.size());
    for (const auto& record : graph.call_sites) {
        walk.u64(record.id);
        walk.u64(record.source_function_id);
        walk.u64(record.source_block_id);
        walk.u64(record.instruction_id);
        walk.address(record.address);
        walk.u32(record.first_candidate);
        walk.u32(record.candidate_count);
        walk.boolean(record.indirect);
        walk.boolean(record.tail_call);
        walk.boolean(record.unresolved);
    }
    walk.u64(graph.candidates.size());
    for (const auto& record : graph.candidates) {
        walk.u64(record.id);
        walk.u64(record.call_site_id);
        walk.address(record.target);
        walk.entity_opt(record.target_function_id);
        walk.u8(static_cast<std::uint8_t>(record.kind));
        walk_call_quality(walk, record.quality);
        walk.u64(record.stable_source_id);
        walk.u32(record.rank);
        walk.boolean(record.external_target);
    }
    walk.u64(graph.edges.size());
    for (const auto& record : graph.edges) {
        walk.u64(record.id);
        walk.u64(record.call_site_id);
        walk.u64(record.source_function_id);
        walk.u64(record.source_block_id);
        walk.entity_opt(record.target_function_id);
        walk.address(record.call_site);
        walk.address(record.target);
        walk.u8(static_cast<std::uint8_t>(record.resolution));
        walk_call_quality(walk, record.quality);
        walk.u32(record.candidate_rank);
        walk.boolean(record.external_target);
        walk.boolean(record.target_noreturn);
    }
    walk.u64(graph.conflicts.size());
    for (const auto& record : graph.conflicts) {
        walk.u64(record.id);
        walk.u8(static_cast<std::uint8_t>(record.kind));
        walk.u64(record.instruction_id);
        walk.u64(record.source_function_id);
        walk.u64(record.call_site_rva);
        walk.u64(record.selected_target_rva);
        walk.u64(record.competing_target_rva);
        walk.u64(record.selected_target_function_id);
        walk.u64(record.competing_target_function_id);
    }
    walk.u64(graph.indirect_site_count);
    walk.u64(graph.unresolved_site_count);
    walk.boolean(graph.bounded);
}

void walk_xref(determinism_walker_t& walk, const xref_record_t& record)
{
    walk.u64(record.id);
    walk.address(record.source);
    walk.address(record.target);
    walk.u8(static_cast<std::uint8_t>(record.kind));
    walk.u8(static_cast<std::uint8_t>(record.provenance));
    walk.u8(record.confidence);
}

void walk_string_record(determinism_walker_t& walk, const string_record_t& record)
{
    walk.u64(record.id);
    walk.address(record.address);
    walk.u64(record.byte_length);
    walk.u8(static_cast<std::uint8_t>(record.encoding));
    walk.string_bytes(record.value);
    walk.u8(static_cast<std::uint8_t>(record.provenance));
    walk.u8(record.confidence);
}

void walk_symbol(determinism_walker_t& walk, const symbol_record_t& record)
{
    walk.u64(record.id);
    walk.address(record.address);
    walk.string_bytes(record.name);
    walk.u8(static_cast<std::uint8_t>(record.kind));
    walk.u8(static_cast<std::uint8_t>(record.provenance));
    walk.u8(record.confidence);
}

void walk_rich_facts(determinism_walker_t& walk,
                     const analysis_rich_fact_publication_t& facts)
{
    walk.u64(facts.data_candidates.size());
    for (const auto& record : facts.data_candidates) {
        walk.u64(record.id);
        walk.address(record.address);
        walk.u64(record.size);
        walk.u8(static_cast<std::uint8_t>(record.kind));
        walk.address_opt(record.target);
        walk.u8(static_cast<std::uint8_t>(record.provenance));
        walk.u8(record.confidence);
    }
    walk.u64(facts.data_pointer_facts.size());
    for (const auto& record : facts.data_pointer_facts) {
        walk.u64(record.id);
        walk.address(record.slot);
        walk.address(record.target);
        walk.u8(static_cast<std::uint8_t>(record.candidate_kind));
        walk.u8(static_cast<std::uint8_t>(record.encoding));
        walk.u8(record.width_bytes);
        walk.u8(static_cast<std::uint8_t>(record.provenance));
        walk.u8(record.confidence);
    }
    walk.u64(facts.data_conflicts.size());
    for (const auto& record : facts.data_conflicts) {
        walk.u64(record.id);
        walk.address(record.address);
        walk.u8(static_cast<std::uint8_t>(record.kind));
        walk.address_opt(record.selected_target);
        walk.address_opt(record.rejected_target);
        walk.u8(static_cast<std::uint8_t>(record.selected_provenance));
        walk.u8(static_cast<std::uint8_t>(record.rejected_provenance));
        walk.u8(record.selected_confidence);
        walk.u8(record.rejected_confidence);
    }
    walk.u64(facts.type_candidates.size());
    for (const auto& record : facts.type_candidates) {
        walk.u64(record.id);
        walk.address_opt(record.address);
        walk.address_opt(record.related_address);
        walk.u8(static_cast<std::uint8_t>(record.kind));
        walk.string_bytes(record.display_name);
        walk.string_bytes(record.canonical_type);
        walk.string_bytes(record.source_key);
        walk.u8(static_cast<std::uint8_t>(record.provenance));
        walk.u8(record.confidence);
        walk.boolean(record.explicitly_unknown);
    }
    walk.u64(facts.type_references.size());
    for (const auto& record : facts.type_references) {
        walk.u64(record.id);
        walk.address_opt(record.source);
        walk.address_opt(record.target);
        walk.u64(record.source_entity);
        walk.u64(record.target_entity);
        walk.u8(static_cast<std::uint8_t>(record.kind));
        walk.u8(static_cast<std::uint8_t>(record.provenance));
        walk.u8(record.confidence);
        walk.string_bytes(record.source_key);
    }
    walk.u64(facts.metadata_conflicts.size());
    for (const auto& record : facts.metadata_conflicts) {
        walk.u64(record.id);
        walk.address_opt(record.address);
        walk.string_bytes(record.identity);
        walk.u8(static_cast<std::uint8_t>(record.kind));
        walk.string_bytes(record.selected_value);
        walk.string_bytes(record.rejected_value);
        walk.u8(static_cast<std::uint8_t>(record.selected_provenance));
        walk.u8(static_cast<std::uint8_t>(record.rejected_provenance));
        walk.u8(record.selected_confidence);
        walk.u8(record.rejected_confidence);
    }
}

void walk_coverage(determinism_walker_t& walk, const coverage_span_t& record)
{
    walk.address(record.start);
    walk.u64(record.size);
    walk.u8(static_cast<std::uint8_t>(record.reason));
    walk.u8(static_cast<std::uint8_t>(record.provenance));
    walk.u8(record.confidence);
    walk.u32(record.detail_code);
}

std::string snapshot_determinism_sha256(const analysis_snapshot_t& snapshot)
{
    constexpr std::uint32_t field_walk_version = 1;
    determinism_walker_t walk;
    walk.stream.open();
    walk.u32(field_walk_version);
    walk.digest_bytes(snapshot.binary_id);
    walk.digest_bytes(snapshot.load_profile_hash);
    walk.u64(snapshot.generation);
    walk.u64(snapshot.analysis_revision);
    walk.u64(snapshot.overlay_revision);
    walk.boolean(snapshot.baseline_complete);
    walk.u64(snapshot.instructions.size());
    for (const auto& record : snapshot.instructions)
        walk_instruction(walk, record);
    walk.u64(snapshot.delay_slot_counts.size());
    if (!snapshot.delay_slot_counts.empty())
        walk.bytes(snapshot.delay_slot_counts.data(), snapshot.delay_slot_counts.size());
    walk.u64(snapshot.operand_facts.size());
    for (const auto& record : snapshot.operand_facts)
        walk_operand_fact(walk, record);
    walk.u64(snapshot.target_facts.size());
    for (const auto& record : snapshot.target_facts)
        walk_target_fact(walk, record);
    walk.u64(snapshot.blocks.size());
    for (const auto& record : snapshot.blocks)
        walk_block(walk, record);
    walk.u64(snapshot.function_chunks.size());
    for (const auto& record : snapshot.function_chunks)
        walk_chunk(walk, record);
    walk.u64(snapshot.function_block_memberships.size());
    for (const auto& record : snapshot.function_block_memberships)
        walk_membership(walk, record);
    walk.u64(snapshot.functions.size());
    for (const auto& record : snapshot.functions)
        walk_function(walk, record);
    walk.u64(snapshot.edges.size());
    for (const auto& record : snapshot.edges)
        walk_edge(walk, record);
    walk_call_graph(walk, snapshot.call_graph);
    walk.u64(snapshot.xrefs.size());
    for (const auto& record : snapshot.xrefs)
        walk_xref(walk, record);
    walk.u64(snapshot.strings.size());
    for (const auto& record : snapshot.strings)
        walk_string_record(walk, record);
    walk.u64(snapshot.symbols.size());
    for (const auto& record : snapshot.symbols)
        walk_symbol(walk, record);
    walk_rich_facts(walk, snapshot.rich_facts);
    walk.u64(snapshot.coverage.size());
    for (const auto& record : snapshot.coverage)
        walk_coverage(walk, record);
    const auto digest = walk.stream.finish();
    return test_fixture::detail::large_pe_hex(digest.data(), digest.size());
}

std::string stage_config_fingerprint()
{
    const baseline_analysis_settings_t settings;
    const std::string canonical = settings.canonical_json();
    test_fixture::detail::large_pe_sha256_stream_t stream;
    stream.open();
    stream.update(reinterpret_cast<const std::uint8_t*>(canonical.data()), canonical.size());
    const auto digest = stream.finish();
    return test_fixture::detail::large_pe_hex(digest.data(), digest.size());
}

std::uint32_t hardware_default_budget() noexcept
{
    const auto hardware = (std::max)(1U, std::thread::hardware_concurrency());
    return (std::min)(16U, (std::max)(2U, hardware));
}

struct stage_run_measurement_t {
    std::uint32_t budget = 0;
    std::uint64_t wall_ns = 0;
    std::uint64_t decode_window_ns = 0;
    std::uint64_t decoded_bytes = 0;
    std::uint64_t instruction_count = 0;
    std::string snapshot_sha256;
};

stage_run_measurement_t run_stage_measurement(
    const open_static_workspace_request_t& open_request, std::uint32_t budget,
    const cancellation_token_t& cancel)
{
    stage_run_measurement_t measurement;
    measurement.budget = budget;
    auto once = run_analysis_once(open_request, budget, cancel);
    measurement.wall_ns = once.wall_ns;
    measurement.decode_window_ns = once.decode_window_ns;
    measurement.decoded_bytes = once.decoded_bytes;
    measurement.instruction_count = once.instruction_count;
    try {
        measurement.snapshot_sha256 = snapshot_determinism_sha256(*once.snapshot);
    } catch (...) {
        try { close_benchmark_workspace(once.workspace, true); } catch (...) {}
        throw;
    }
    close_benchmark_workspace(once.workspace, true);
    return measurement;
}


const json& program_sla_thresholds()
{
    static const json thresholds = {
        {"threshold_schema", "aida.hyperperf.program-sla-thresholds"},
        {"threshold_schema_version", 2},
        {"total_wall_ms_max_300mb", 300000.0},
        {"total_wall_ms_stretch_300mb", 180000.0},
        {"decode_throughput_bytes_per_s_min", 26214400.0},
        {"file_throughput_bytes_per_s_min", 1048576.0},
        {"instructions_per_s_min", 2000000.0},
        {"publish_ready_ms_max", 50.0},
        {"indexed_query_p95_ms_max", 50.0},
        {"metadata_ready_ms_max", 3000.0},
        {"warm_reopen_ms_max", 10000.0},
        {"cancellation_p95_ms_max", 250.0},
        {"incremental_private_bytes_max", 8589934592ULL},
        {"workspace_mapped_bytes_max", 1073741824ULL},
        {"global_mapped_bytes_max", 2147483648ULL},
        {"decompile_all_funcs_per_s_min", 5.0},
        {"decompile_all_funcs_per_s_stretch", 10.0},
        {"scaling_wall16_over_wall1_max", 0.20},
        {"scaling_efficiency_16_min", 0.5},
        {"determinism_hash_match", true}
    };
    return thresholds;
}

json verdict_entry(const char* key, const json& target, const json& actual,
                   const char* verdict)
{
    return json{{"key", key}, {"target", target}, {"actual", actual},
        {"verdict", verdict}};
}

std::uint64_t percentile_value(std::vector<std::uint64_t> values, double rank)
{
    if (values.empty())
        return 0;
    std::sort(values.begin(), values.end());
    const auto index = static_cast<std::size_t>((values.size() - 1) * rank);
    return values[index];
}

std::string json_value_text(const json& value)
{
    return value.is_null() ? std::string("null") : value.dump();
}

struct benchmark_async_state_t {
    std::atomic<bool> active{false};
    std::atomic<std::uint64_t> started_ms{0};
    std::atomic<std::uint64_t> finished_ms{0};
    std::atomic<std::uint64_t> job_id{0};
    std::atomic<bool> run_scaling_stage{false};
    std::atomic<bool> run_determinism_stage{false};
    std::atomic<std::uint32_t> determinism_runs{2};
    mutable std::mutex mutex;
    std::string mode;
    std::string verdict;
    std::string error;
    std::string report_path;
};

benchmark_async_state_t g_async_state;

class synthetic_fixture_root_t final {
public:
    explicit synthetic_fixture_root_t()
    {
        static std::atomic<std::uint64_t> sequence{0};
        const auto value = sequence.fetch_add(1, std::memory_order_relaxed) + 1;
        path_ = std::filesystem::temp_directory_path() /
            ("aida_benchmark_" + std::to_string(GetCurrentProcessId()) + "_" +
             std::to_string(value));
        std::filesystem::create_directories(path_);
    }
    ~synthetic_fixture_root_t()
    {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }
    const std::filesystem::path& path() const noexcept { return path_; }
private:
    std::filesystem::path path_;
};

std::string hash_file_sha256(const std::filesystem::path& path)
{
    test_fixture::detail::large_pe_sha256_stream_t stream;
    stream.open();
    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error("benchmark fixture cannot be opened for digest verification");
    std::vector<std::uint8_t> buffer(1024 * 1024);
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count <= 0)
            break;
        stream.update(buffer.data(), static_cast<std::size_t>(count));
    }
    if (input.bad())
        throw std::runtime_error("benchmark fixture failed during digest verification");
    const auto digest = stream.finish();
    return test_fixture::detail::large_pe_hex(digest.data(), digest.size());
}

json host_identity_block(const std::filesystem::path& fixture_path)
{
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    GlobalMemoryStatusEx(&memory);
    int registers[4]{};
    __cpuid(registers, 0);
    char vendor[13]{};
    std::memcpy(vendor, &registers[1], 4);
    std::memcpy(vendor + 4, &registers[3], 4);
    std::memcpy(vendor + 8, &registers[2], 4);
    std::string model;
    __cpuid(registers, static_cast<int>(0x80000000u));
    if (static_cast<std::uint32_t>(registers[0]) >= 0x80000004u) {
        char brand[49]{};
        for (std::uint32_t leaf = 0x80000002u; leaf <= 0x80000004u; ++leaf) {
            __cpuid(registers, static_cast<int>(leaf));
            std::memcpy(brand + (leaf - 0x80000002u) * 16, registers, 16);
        }
        model = brand;
        const auto first = model.find_first_not_of(' ');
        const auto last = model.find_last_not_of(' ');
        model = first == std::string::npos ? std::string()
            : model.substr(first, last - first + 1);
    }
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    using rtl_get_version_t = LONG(WINAPI*)(OSVERSIONINFOW*);
    const auto rtl_get_version = reinterpret_cast<rtl_get_version_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    if (rtl_get_version)
        rtl_get_version(&version);
    std::string filesystem_name;
    json bus_type = nullptr;
    wchar_t volume_path[MAX_PATH]{};
    const auto absolute = std::filesystem::absolute(fixture_path).wstring();
    if (GetVolumePathNameW(absolute.c_str(), volume_path,
        static_cast<DWORD>(std::size(volume_path)))) {
        wchar_t fs_name[MAX_PATH]{};
        DWORD serial = 0, maximum_component = 0, flags = 0;
        if (GetVolumeInformationW(volume_path, nullptr, 0, &serial, &maximum_component,
            &flags, fs_name, static_cast<DWORD>(std::size(fs_name))))
            filesystem_name = std::filesystem::path(fs_name).u8string();
        const std::wstring device = std::wstring(L"\\\\.\\") + volume_path[0] + L":";
        HANDLE handle = CreateFileW(device.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            STORAGE_PROPERTY_QUERY query{};
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;
            std::vector<std::uint8_t> buffer(4096);
            DWORD returned = 0;
            if (DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr) &&
                returned >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
                const auto* descriptor =
                    reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
                bus_type = static_cast<unsigned>(descriptor->BusType);
            }
            CloseHandle(handle);
        }
    }
    return json{{"cpu_vendor", vendor}, {"cpu_model", model},
        {"logical_processors", system.dwNumberOfProcessors},
        {"installed_memory_bytes", memory.ullTotalPhys},
        {"os", json{{"major", version.dwMajorVersion},
            {"minor", version.dwMinorVersion}, {"build", version.dwBuildNumber}}},
        {"filesystem", filesystem_name},
        {"storage_device", json{{"bus_type", bus_type}}}};
}

void write_json_file(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream << text;
    stream.flush();
    if (!stream)
        throw std::runtime_error("benchmark results write failed: " + path.u8string());
}

std::string write_benchmark_artifacts(const std::string& out_dir, const char* mode,
                                      json& scorecard)
{
    const std::string directory =
        out_dir.empty() ? benchmark_results_dir() : out_dir;
    std::error_code error;
    std::filesystem::create_directories(std::filesystem::u8path(directory), error);
    if (error)
        throw std::runtime_error("benchmark results directory creation failed: " + error.message());
    const auto timestamped = std::filesystem::u8path(directory) /
        ("benchmark_" + std::string(mode) + "_" + utc_stamp_filename() + ".json");
    scorecard["artifacts"]["report_json"] = timestamped.u8string();
    const std::string text = scorecard.dump(2);
    write_json_file(timestamped, text);
    const auto latest = std::filesystem::u8path(directory) /
        ("benchmark_" + std::string(mode) + "_latest.json");
    const std::string temporary = latest.u8string() + ".tmp";
    write_json_file(std::filesystem::u8path(temporary), text);
    if (!MoveFileExW(std::filesystem::u8path(temporary).wstring().c_str(),
        latest.wstring().c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("benchmark latest artifact replace failed: " +
            std::to_string(GetLastError()));
    return timestamped.u8string();
}

}

std::string benchmark_results_dir()
{
    wchar_t module[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, module, MAX_PATH);
    if (length == 0 || length >= MAX_PATH)
        return std::string();
    return (std::filesystem::path(module).parent_path() / "benchmark_results").u8string();
}

benchmark_run_result_t run_benchmark(const benchmark_run_request_t& request,
                                     const cancellation_token_t& cancel)
{
    benchmark_run_result_t result;
    const char* mode = mode_name(request.mode);
    const auto run_begin = steady_clock_t::now();
    const auto cpu_begin = process_cpu_ns_now();
    diag::log_tagged_fmt("benchmark",
        "run_begin mode=%s path=%s code_mb=%llu seed=0x%llX lanes=%u scaling=%d determinism=%d",
        mode, request.real_path.c_str(),
        static_cast<unsigned long long>(request.synthetic_code_bytes / (1024ULL * 1024ULL)),
        static_cast<unsigned long long>(request.synthetic_seed),
        static_cast<unsigned>(request.lanes),
        request.run_scaling_stage ? 1 : 0,
        request.run_determinism_stage ? 1 : 0);

    std::shared_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<analysis_workspace_t> warm_workspace;
    std::string database_path;
    try {
        std::filesystem::path fixture_path;
        json generator = nullptr;
        test_fixture::large_pe_params_t synthetic_params;
        test_fixture::large_pe_manifest_t synthetic_manifest;
        std::optional<synthetic_fixture_root_t> synthetic_root;
        if (request.mode == benchmark_mode_t::synthetic) {
            constexpr std::uint64_t mib = 1024ULL * 1024ULL;
            if (request.synthetic_code_bytes < 8ULL * mib ||
                request.synthetic_code_bytes > 256ULL * mib)
                throw std::runtime_error("synthetic benchmark code_bytes must be within 8..256 MiB");
            synthetic_params.code_bytes = request.synthetic_code_bytes;
            synthetic_params.seed = request.synthetic_seed;
            synthetic_params = test_fixture::validated_large_pe_params(synthetic_params);
            synthetic_manifest = test_fixture::describe_large_pe(synthetic_params);
            const tile_decode_orchestrator_limits_t tile_limits;
            const baseline_analysis_settings_t analysis_settings;
            const std::uint64_t instruction_limit = (std::min<std::uint64_t>)(
                tile_limits.maximum_instructions, analysis_settings.max_decoded_instructions);
            if (synthetic_manifest.instruction_count_estimate >= instruction_limit)
                throw std::runtime_error("synthetic instruction estimate " +
                    std::to_string(synthetic_manifest.instruction_count_estimate) +
                    " meets or exceeds the active decode limit " +
                    std::to_string(instruction_limit));
            synthetic_root.emplace();
            fixture_path = synthetic_root->path() / "synthetic.exe";
            test_fixture::write_large_pe64(fixture_path, synthetic_params);
            if (hash_file_sha256(fixture_path) != test_fixture::large_pe_sha256(synthetic_params))
                throw std::runtime_error("synthetic fixture digest diverged from the deterministic generator");
            json sections = json::array();
            for (const auto& section : synthetic_manifest.sections) {
                sections.push_back(json{{"name", section.name}, {"rva", section.rva},
                    {"raw_offset", section.raw_offset}, {"virtual_size", section.virtual_size},
                    {"raw_size", section.raw_size}});
            }
            generator = json{{"kind", "synthetic_large_pe64"},
                {"params", json{{"code_bytes", synthetic_params.code_bytes},
                    {"function_count", synthetic_params.function_count},
                    {"seed", synthetic_params.seed},
                    {"code_sections", synthetic_params.code_sections},
                    {"string_count", synthetic_params.string_count},
                    {"data_pointer_count", synthetic_params.data_pointer_count},
                    {"seed_pdata", synthetic_params.seed_pdata},
                    {"call_density_pct", synthetic_params.call_density_pct},
                    {"jump_density_pct", synthetic_params.jump_density_pct},
                    {"padding_pct", synthetic_params.padding_pct}}},
                {"manifest", json{{"sections", std::move(sections)},
                    {"function_rva_begin", synthetic_manifest.function_rva_begin},
                    {"function_rva_end", synthetic_manifest.function_rva_end},
                    {"function_count", synthetic_manifest.function_count},
                    {"instruction_count_estimate", synthetic_manifest.instruction_count_estimate},
                    {"code_bytes", synthetic_manifest.code_bytes},
                    {"pdata_bytes", synthetic_manifest.pdata_bytes},
                    {"xdata_bytes", synthetic_manifest.xdata_bytes},
                    {"rdata_bytes", synthetic_manifest.rdata_bytes},
                    {"data_bytes", synthetic_manifest.data_bytes},
                    {"reloc_bytes", synthetic_manifest.reloc_bytes},
                    {"file_size", synthetic_manifest.file_size}}}};
        } else {
            if (request.real_path.empty())
                throw std::runtime_error("real benchmark requires a fixture path");
            fixture_path = std::filesystem::u8path(request.real_path);
            if (!std::filesystem::is_regular_file(fixture_path))
                throw std::runtime_error("real benchmark fixture does not exist: " + request.real_path);
            const auto size = std::filesystem::file_size(fixture_path);
            if (size < 300000000ULL || size > 500000000ULL)
                throw std::runtime_error("real benchmark fixture size " + std::to_string(size) +
                    " is outside the program-gate 300000000..500000000 byte window");
        }

        const auto fixture_size = std::filesystem::file_size(fixture_path);
        const auto fixture_zero_bytes = count_zero_bytes(fixture_path, fixture_size);

        open_static_workspace_request_t open_request;
        open_request.source_path = fixture_path.u8string();
        open_request.bin_name = fixture_path.filename().u8string();
        open_request.load_profile = {1, 0, 1, 0};
        auto primary = run_analysis_once(open_request, request.lanes, cancel);
        workspace = std::move(primary.workspace);
        analysis_metrics_t run_metrics(workspace->generation());
        run_metrics.sample_process_memory();

        const auto image = workspace->normalized_image();
        const std::uint64_t code_bytes = primary.code_bytes;
        const auto snapshot = primary.snapshot;
        const auto search = workspace->search_index();
        const auto database = workspace->database()->snapshot();
        const std::uint64_t decoded_bytes = primary.decoded_bytes;
        const std::uint64_t file_bytes = primary.file_bytes;
        const auto& windows = primary.windows;
        const std::uint64_t analysis_wall_ns = primary.wall_ns;
        const std::uint64_t decode_window_ns = primary.decode_window_ns;

        std::uint64_t batch_completed = 0;
        std::uint64_t batch_failed = 0;
        std::uint64_t batch_wall_ns = 0;
        double batch_funcs_per_s = 0.0;
        bool batch_ran = false;
        std::vector<std::uint64_t> decompile_samples;
        if (!snapshot->functions.empty() && workspace->decompiler()) {
            batch_ran = true;
            const auto service = workspace->decompiler();
            const auto service_before = service->snapshot();
            const std::size_t batch_target = (std::min<std::size_t>)(snapshot->functions.size(),
                request.decompile_batch_max_functions);
            const auto batch_begin = steady_clock_t::now();
            std::uint64_t consecutive_failures = 0;
            for (std::size_t index = 0; index < batch_target; ++index) {
                if (cancel.stop_requested()) {
                    run_metrics.add(analysis_metric_t::decompile_batch_cancelled,
                        batch_target - index);
                    break;
                }
                if (nanoseconds_since(batch_begin) / 1000000ULL >= request.decompile_batch_max_ms)
                    break;
                const auto& function = snapshot->functions[index];
                auto address = function.start;
                if (address.space == address_space_id_t::relative_virtual) {
                    address.space = address_space_id_t::virtual_address;
                    if (!checked_add_u64(address.value, image->image_base, address.value))
                        throw std::runtime_error("benchmark decompile address overflowed image base");
                }
                run_metrics.add(analysis_metric_t::decompile_batch_calls);
                const auto call_begin = steady_clock_t::now();
                auto value = service->decompile(address, {}, cancel);
                const auto call_ns = nanoseconds_since(call_begin);
                run_metrics.set_max(analysis_metric_t::decompile_batch_queue_depth_peak,
                    service->snapshot().active_contexts);
                const bool valid = value && value.value().function_id != 0 &&
                    value.value().pseudocode.find_first_not_of(" \t\r\n") != std::string::npos &&
                    !value.value().line_to_address.empty();
                if (!valid) {
                    run_metrics.add(analysis_metric_t::decompile_batch_failed);
                    ++batch_failed;
                    if (++consecutive_failures >= 64)
                        break;
                    continue;
                }
                consecutive_failures = 0;
                run_metrics.add(analysis_metric_t::decompile_batch_completed);
                ++batch_completed;
                decompile_samples.push_back(call_ns);
            }
            batch_wall_ns = nanoseconds_since(batch_begin);
            run_metrics.add(analysis_metric_t::decompile_batch_wall_ns, batch_wall_ns);
            const auto service_after = service->snapshot();
            run_metrics.set(analysis_metric_t::decompile_memory_cache_hits,
                service_after.memory_cache_hits - service_before.memory_cache_hits);
            run_metrics.set(analysis_metric_t::decompile_persistent_cache_hits,
                service_after.persistent_cache_hits - service_before.persistent_cache_hits);
            if (batch_wall_ns != 0) {
                batch_funcs_per_s = static_cast<double>(batch_completed) * 1000000000.0 /
                    static_cast<double>(batch_wall_ns);
            }
        }

        std::vector<std::uint64_t> query_samples;
        if (search) {
            static const char* const query_terms[] = {"mov", "call", "push", "test"};
            for (std::size_t sample = 0; sample < 16; ++sample) {
                const auto query_begin = steady_clock_t::now();
                auto page = search->find_text(query_terms[sample % 4], 0, 16,
                    workspace->cancellation_token());
                const auto query_ns = nanoseconds_since(query_begin);
                if (page)
                    query_samples.push_back(query_ns);
            }
        }
        run_metrics.sample_process_memory();
        run_metrics.mark_finished();
        const auto metrics_snapshot = run_metrics.snapshot();

        const std::string cold_database_path = workspace->database()->path();
        database_path = cold_database_path;
        close_benchmark_workspace(workspace, false);
        workspace.reset();

        double warm_reopen_ms = 0.0;
        bool warm_reopen_measured = false;
        {
            const auto warm_begin = steady_clock_t::now();
            auto reopened = workspace_registry().open_static(open_request, cancel);
            if (!reopened)
                throw std::runtime_error("warm reopen acquisition failed: " +
                    reopened.error().stable_code() + ":" + reopened.error().message);
            warm_workspace = reopened.take_value();
            auto loaded = warm_workspace->database()->load_snapshot(
                warm_workspace->normalized_image(), warm_workspace->image(),
                warm_workspace->cancellation_token());
            if (!loaded || !loaded.value())
                throw std::runtime_error("warm reopen found no committed baseline");
            auto persisted = loaded.take_value();
            auto products = warm_workspace->database()->load_search_products(
                persisted->generation, persisted->analysis_revision,
                persisted->overlay_revision, warm_workspace->cancellation_token());
            if (!products)
                throw std::runtime_error("warm reopen search products failed: " +
                    products.error().stable_code() + ":" + products.error().message);
            auto index_metrics = std::make_shared<analysis_metrics_t>(persisted->generation);
            auto index = search_index_t::build(persisted,
                std::move(products.value().data_candidates),
                std::move(products.value().switches),
                std::move(products.value().types), index_metrics, {},
                warm_workspace->cancellation_token());
            if (!index)
                throw std::runtime_error("warm reopen index rebuild failed: " +
                    index.error().stable_code() + ":" + index.error().message);
            auto published = warm_workspace->publish_analysis_bundle(
                warm_workspace->generation(), warm_workspace->analysis_revision(),
                persisted, index.take_value(), true);
            if (!published || warm_workspace->progress().readiness !=
                workspace_readiness_t::baseline_ready)
                throw std::runtime_error("warm reopen publication failed");
            warm_reopen_ms = static_cast<double>(nanoseconds_since(warm_begin)) / 1000000.0;
            warm_reopen_measured = true;
            close_benchmark_workspace(warm_workspace, true);
            warm_workspace.reset();
            database_path.clear();
        }
        remove_database_artifacts(cold_database_path);
        database_path.clear();

        json scaling_block = nullptr;
        json determinism_block = nullptr;
        bool scaling_gate_applicable = false;
        double scaling_wall16_over_wall1 = 0.0;
        double scaling_efficiency_16 = 0.0;
        bool determinism_measured = false;
        bool determinism_match = false;
        if (request.run_scaling_stage || request.run_determinism_stage) {
            std::vector<std::uint32_t> budgets = request.scaling_worker_budgets;
            if (budgets.empty()) {
                const auto default_budget = hardware_default_budget();
                budgets = {1, default_budget, default_budget};
            }
            for (auto& budget : budgets) {
                if (budget == 0)
                    budget = hardware_default_budget();
            }
            if (request.run_determinism_stage) {
                const std::uint32_t tail_budget = budgets.back();
                std::uint32_t tail_count = 0;
                for (auto cursor = budgets.rbegin();
                     cursor != budgets.rend() && *cursor == tail_budget; ++cursor)
                    ++tail_count;
                const auto required = (std::max)(1U, request.determinism_runs);
                for (std::uint32_t have = tail_count; have < required; ++have)
                    budgets.push_back(tail_budget);
            }
            std::vector<stage_run_measurement_t> stage_runs;
            stage_runs.reserve(budgets.size());
            const auto stage_begin = steady_clock_t::now();
            for (const auto budget : budgets) {
                if (cancel.stop_requested())
                    throw std::runtime_error("benchmark scaling/determinism stage cancelled");
                stage_runs.push_back(run_stage_measurement(open_request, budget, cancel));
                diag::log_tagged_fmt("benchmark",
                    "stage_run budget=%u wall_ms=%llu decode_window_ms=%llu instructions=%llu snapshot_sha256=%s",
                    static_cast<unsigned>(stage_runs.back().budget),
                    static_cast<unsigned long long>(stage_runs.back().wall_ns / 1000000ULL),
                    static_cast<unsigned long long>(
                        stage_runs.back().decode_window_ns / 1000000ULL),
                    static_cast<unsigned long long>(stage_runs.back().instruction_count),
                    stage_runs.back().snapshot_sha256.c_str());
            }

            std::optional<std::uint64_t> wall_budget1;
            for (const auto& run : stage_runs) {
                if (run.budget == 1) {
                    wall_budget1 = run.wall_ns;
                    break;
                }
            }
            SYSTEM_INFO host_system{};
            GetNativeSystemInfo(&host_system);
            const auto host_logical =
                static_cast<std::uint32_t>(host_system.dwNumberOfProcessors);
            json budget_values = json::array();
            json wall_ms_values = json::array();
            json ratio_values = json::array();
            json efficiency_values = json::array();
            json rows = json::array();
            bool has_budget16 = false;
            std::optional<std::uint64_t> wall_budget16;
            std::optional<double> efficiency_budget16;
            std::uint32_t n16 = 0;
            for (const auto& run : stage_runs) {
                json ratio = nullptr;
                json efficiency = nullptr;
                if (wall_budget1 && *wall_budget1 != 0 && run.wall_ns != 0) {
                    ratio = static_cast<double>(run.wall_ns) /
                        static_cast<double>(*wall_budget1);
                    efficiency = static_cast<double>(*wall_budget1) /
                        (static_cast<double>(run.wall_ns) *
                            static_cast<double>(run.budget));
                }
                budget_values.push_back(run.budget);
                wall_ms_values.push_back(static_cast<double>(run.wall_ns) / 1000000.0);
                ratio_values.push_back(ratio);
                efficiency_values.push_back(efficiency);
                rows.push_back(json{{"budget", run.budget},
                    {"wall_ns", run.wall_ns},
                    {"wall_ms", static_cast<double>(run.wall_ns) / 1000000.0},
                    {"decode_window_ns", run.decode_window_ns},
                    {"decoded_bytes", run.decoded_bytes},
                    {"instructions", run.instruction_count},
                    {"ratio", ratio},
                    {"efficiency", efficiency},
                    {"snapshot_sha256", run.snapshot_sha256}});
                if (run.budget <= 16)
                    n16 = (std::max)(n16, run.budget);
                if (run.budget == 16 && !has_budget16) {
                    has_budget16 = true;
                    wall_budget16 = run.wall_ns;
                    if (efficiency.is_number())
                        efficiency_budget16 = efficiency.get<double>();
                }
            }
            scaling_gate_applicable =
                wall_budget1.has_value() && has_budget16 && host_logical >= 16;
            if (scaling_gate_applicable && *wall_budget1 != 0 && wall_budget16 &&
                *wall_budget16 != 0) {
                scaling_wall16_over_wall1 = static_cast<double>(*wall_budget16) /
                    static_cast<double>(*wall_budget1);
                scaling_efficiency_16 = efficiency_budget16.value_or(0.0);
            }
            scaling_block = json{{"budgets", std::move(budget_values)},
                {"wall_ms", std::move(wall_ms_values)},
                {"ratio", std::move(ratio_values)},
                {"efficiency", std::move(efficiency_values)},
                {"rows", std::move(rows)},
                {"n16", n16},
                {"has_budget_16", has_budget16},
                {"wall16_over_wall1",
                    scaling_gate_applicable ? json(scaling_wall16_over_wall1) : json(nullptr)},
                {"efficiency_16",
                    scaling_gate_applicable ? json(scaling_efficiency_16) : json(nullptr)},
                {"gate_applicable", scaling_gate_applicable},
                {"host_logical_processors", host_logical},
                {"note", n16 < 16 ? json(std::string(
                     "worker sweep caps below 16 on this host; the 16-worker scaling gate is not measurable"))
                    : json(nullptr)}};
            const std::string wall16_text = scaling_gate_applicable
                ? std::to_string(scaling_wall16_over_wall1) : std::string("null");
            const std::string eff16_text = scaling_gate_applicable
                ? std::to_string(scaling_efficiency_16) : std::string("null");
            diag::log_tagged_fmt("benchmark",
                "scaling gate_applicable=%d n16=%u host_logical=%u wall16_over_wall1=%s efficiency_16=%s",
                scaling_gate_applicable ? 1 : 0, static_cast<unsigned>(n16),
                static_cast<unsigned>(host_logical), wall16_text.c_str(), eff16_text.c_str());

            determinism_measured = stage_runs.size() >= 2;
            determinism_match = determinism_measured;
            for (std::size_t index = 1; index < stage_runs.size(); ++index) {
                if (stage_runs[index].snapshot_sha256 != stage_runs.front().snapshot_sha256)
                    determinism_match = false;
            }
            json hash_runs = json::array();
            for (std::size_t index = 0; index < stage_runs.size(); ++index) {
                hash_runs.push_back(json{{"label", "run_" + std::to_string(index)},
                    {"budget", stage_runs[index].budget},
                    {"snapshot_sha256", stage_runs[index].snapshot_sha256}});
            }
            determinism_block = json{{"runs", std::move(hash_runs)},
                {"match", determinism_measured ? json(determinism_match) : json(nullptr)},
                {"field_walk", json{{"contract", "aida.hyperperf.benchmark-determinism-walk"},
                    {"version", 1}}},
                {"config_fingerprint", stage_config_fingerprint()}};
            diag::log_tagged_fmt("benchmark",
                "determinism runs=%zu match=%d stage_wall_ms=%llu",
                stage_runs.size(), determinism_match ? 1 : 0,
                static_cast<unsigned long long>(nanoseconds_since(stage_begin) / 1000000ULL));
        }


        const double wall_ms = static_cast<double>(analysis_wall_ns) / 1000000.0;
        const auto& thresholds = program_sla_thresholds();
        const double wall_scale = request.mode == benchmark_mode_t::synthetic
            ? static_cast<double>(request.synthetic_code_bytes) / (300.0 * 1024.0 * 1024.0)
            : 1.0;
        const double decode_wall_s = decode_window_ns == 0
            ? 0.0 : static_cast<double>(decode_window_ns) / 1000000000.0;
        const json decode_bps = decode_window_ns == 0 ? json(nullptr)
            : json(static_cast<double>(decoded_bytes) / decode_wall_s);
        const json file_bps = analysis_wall_ns == 0 ? json(nullptr)
            : json(static_cast<double>(file_bytes) * 1000000000.0 /
                static_cast<double>(analysis_wall_ns));
        const json instructions_s = decode_window_ns == 0 ? json(nullptr)
            : json(static_cast<double>(snapshot->instructions.size()) / decode_wall_s);
        const json publish_ms = windows.publish_wall_ns() == 0 ? json(nullptr)
            : json(static_cast<double>(windows.publish_wall_ns()) / 1000000.0);
        const json query_p95_ms = query_samples.empty() ? json(nullptr)
            : json(static_cast<double>(percentile_value(query_samples, 0.95)) / 1000000.0);
        const json decompile_p95_ms = decompile_samples.empty() ? json(nullptr)
            : json(static_cast<double>(percentile_value(decompile_samples, 0.95)) / 1000000.0);

        json verdicts = json::array();
        const auto push_max = [&](const char* key, double target, const json& actual) {
            if (actual.is_null()) {
                verdicts.push_back(verdict_entry(key, target, nullptr, "NOT_MEASURED"));
                return;
            }
            verdicts.push_back(verdict_entry(key, target, actual,
                actual.get<double>() <= target ? "PASS" : "FAIL"));
        };
        const auto push_min = [&](const char* key, double target, const json& actual) {
            if (actual.is_null()) {
                verdicts.push_back(verdict_entry(key, target, nullptr, "NOT_MEASURED"));
                return;
            }
            verdicts.push_back(verdict_entry(key, target, actual,
                actual.get<double>() >= target ? "PASS" : "FAIL"));
        };
        push_max("total_wall_ms_max_300mb",
            thresholds["total_wall_ms_max_300mb"].get<double>() * wall_scale, wall_ms);
        {
            const double stretch = thresholds["total_wall_ms_stretch_300mb"].get<double>() *
                wall_scale;
            verdicts.push_back(verdict_entry("total_wall_ms_stretch_300mb", stretch, wall_ms,
                wall_ms <= stretch ? "PASS" : "WARN"));
        }
        push_min("decode_throughput_bytes_per_s_min",
            thresholds["decode_throughput_bytes_per_s_min"].get<double>(), decode_bps);
        push_min("file_throughput_bytes_per_s_min",
            thresholds["file_throughput_bytes_per_s_min"].get<double>(), file_bps);
        push_min("instructions_per_s_min",
            thresholds["instructions_per_s_min"].get<double>(), instructions_s);
        push_max("publish_ready_ms_max", thresholds["publish_ready_ms_max"].get<double>(),
            publish_ms);
        push_max("indexed_query_p95_ms_max",
            thresholds["indexed_query_p95_ms_max"].get<double>(), query_p95_ms);
        verdicts.push_back(verdict_entry("metadata_ready_ms_max",
            thresholds["metadata_ready_ms_max"], nullptr, "NOT_MEASURED"));
        push_max("warm_reopen_ms_max", thresholds["warm_reopen_ms_max"].get<double>(),
            warm_reopen_measured ? json(warm_reopen_ms) : json(nullptr));
        verdicts.push_back(verdict_entry("cancellation_p95_ms_max",
            thresholds["cancellation_p95_ms_max"], nullptr, "NOT_MEASURED"));
        verdicts.push_back(verdict_entry("incremental_private_bytes_max",
            thresholds["incremental_private_bytes_max"],
            metrics_snapshot.value(analysis_metric_t::peak_private_bytes),
            metrics_snapshot.value(analysis_metric_t::peak_private_bytes) <=
                thresholds["incremental_private_bytes_max"].get<std::uint64_t>()
                ? "PASS" : "FAIL"));
        verdicts.push_back(verdict_entry("workspace_mapped_bytes_max",
            thresholds["workspace_mapped_bytes_max"], nullptr, "NOT_MEASURED"));
        verdicts.push_back(verdict_entry("global_mapped_bytes_max",
            thresholds["global_mapped_bytes_max"], nullptr, "NOT_MEASURED"));
        push_min("decompile_all_funcs_per_s_min",
            thresholds["decompile_all_funcs_per_s_min"].get<double>(),
            batch_ran ? json(batch_funcs_per_s) : json(nullptr));
        if (batch_ran) {
            verdicts.push_back(verdict_entry("decompile_all_funcs_per_s_stretch",
                thresholds["decompile_all_funcs_per_s_stretch"], batch_funcs_per_s,
                batch_funcs_per_s >= thresholds["decompile_all_funcs_per_s_stretch"].get<double>()
                    ? "PASS" : "WARN"));
        } else {
            verdicts.push_back(verdict_entry("decompile_all_funcs_per_s_stretch",
                thresholds["decompile_all_funcs_per_s_stretch"], nullptr, "NOT_MEASURED"));
        }
        if (scaling_gate_applicable) {
            verdicts.push_back(verdict_entry("scaling_wall16_over_wall1_max",
                thresholds["scaling_wall16_over_wall1_max"], scaling_wall16_over_wall1,
                scaling_wall16_over_wall1 <=
                    thresholds["scaling_wall16_over_wall1_max"].get<double>()
                    ? "PASS" : "FAIL"));
            verdicts.push_back(verdict_entry("scaling_efficiency_16_min",
                thresholds["scaling_efficiency_16_min"], scaling_efficiency_16,
                scaling_efficiency_16 >=
                    thresholds["scaling_efficiency_16_min"].get<double>()
                    ? "PASS" : "WARN"));
        } else {
            verdicts.push_back(verdict_entry("scaling_wall16_over_wall1_max",
                thresholds["scaling_wall16_over_wall1_max"], nullptr, "NOT_MEASURED"));
            verdicts.push_back(verdict_entry("scaling_efficiency_16_min",
                thresholds["scaling_efficiency_16_min"], nullptr, "NOT_MEASURED"));
        }
        if (determinism_measured) {
            verdicts.push_back(verdict_entry("determinism_hash_match",
                thresholds["determinism_hash_match"], determinism_match,
                determinism_match ? "PASS" : "FAIL"));
        } else {
            verdicts.push_back(verdict_entry("determinism_hash_match",
                thresholds["determinism_hash_match"], nullptr, "NOT_MEASURED"));
        }

        bool any_fail = false;
        bool all_pass_or_warn = true;
        for (const auto& verdict : verdicts) {
            const auto value = verdict.value("verdict", std::string());
            if (value == "FAIL")
                any_fail = true;
            if (value != "PASS" && value != "WARN")
                all_pass_or_warn = false;
        }
        const std::string sla_overall =
            any_fail ? "FAIL" : (all_pass_or_warn ? "PASS" : "NOT_MEASURED");
        json sla = json{{"thresholds", thresholds},
            {"verdicts", std::move(verdicts)},
            {"overall", sla_overall}};

        diag::log_tagged_fmt("benchmark",
            "phase name=%s wall_ms=%llu cpu_ms=%llu bytes_in=%llu work_items=%llu",
            "baseline_analysis", static_cast<unsigned long long>(analysis_wall_ns / 1000000ULL),
            static_cast<unsigned long long>((process_cpu_ns_now() - cpu_begin) / 1000000ULL),
            static_cast<unsigned long long>(file_bytes),
            static_cast<unsigned long long>(snapshot->instructions.size()));
        diag::log_tagged_fmt("benchmark",
            "phase name=%s wall_ms=%llu cpu_ms=%llu bytes_in=%llu work_items=%llu",
            "decode_window", static_cast<unsigned long long>(decode_window_ns / 1000000ULL),
            0ULL, static_cast<unsigned long long>(decoded_bytes),
            static_cast<unsigned long long>(snapshot->instructions.size()));
        if (batch_ran) {
            diag::log_tagged_fmt("benchmark",
                "phase name=%s wall_ms=%llu cpu_ms=%llu bytes_in=%llu work_items=%llu",
                "decompile_batch", static_cast<unsigned long long>(batch_wall_ns / 1000000ULL),
                0ULL, 0ULL, static_cast<unsigned long long>(batch_completed));
        }
        diag::log_tagged_fmt("benchmark",
            "memory peak_private=%llu resident_peak=%llu mapped_ws_peak=%llu mapped_global_peak=%llu spill_peak=%llu",
            static_cast<unsigned long long>(
                metrics_snapshot.value(analysis_metric_t::peak_private_bytes)),
            static_cast<unsigned long long>(
                metrics_snapshot.value(analysis_metric_t::resident_bytes_peak)),
            0ULL, 0ULL, 0ULL);
        diag::log_tagged_fmt("benchmark",
            "throughput file_Bps=%.1f decode_Bps=%.1f instr_s=%.1f funcs_s=%.2f",
            file_bps.is_number() ? file_bps.get<double>() : 0.0,
            decode_bps.is_number() ? decode_bps.get<double>() : 0.0,
            instructions_s.is_number() ? instructions_s.get<double>() : 0.0,
            batch_funcs_per_s);
        for (const auto& verdict : sla["verdicts"]) {
            diag::log_tagged_fmt("benchmark", "sla key=%s target=%s actual=%s verdict=%s",
                verdict.value("key", std::string()).c_str(),
                json_value_text(verdict["target"]).c_str(),
                json_value_text(verdict["actual"]).c_str(),
                verdict.value("verdict", std::string()).c_str());
        }

        const std::string verdict = sla_overall == "FAIL"
            ? (request.sla_relaxed ? "PASS" : "FAIL") : "PASS";
        json scorecard = json{
            {"scorecard_schema", "aida.hyperperf.program-scorecard"},
            {"scorecard_schema_version", 1},
            {"run_id", utc_run_id()},
            {"mode", mode},
            {"claim_status", "measurement_only"},
            {"host", host_identity_block(fixture_path)},
            {"fixture", json{{"kind", request.mode == benchmark_mode_t::synthetic
                ? "synthetic" : "real"},
                {"path", request.mode == benchmark_mode_t::real
                    ? json(fixture_path.u8string()) : json(nullptr)},
                {"size_bytes", fixture_size},
                {"executable_code_bytes", code_bytes},
                {"code_density", static_cast<double>(code_bytes) /
                    static_cast<double>(fixture_size)},
                {"zero_ratio", static_cast<double>(fixture_zero_bytes) /
                    static_cast<double>(fixture_size)},
                {"generator", std::move(generator)}}},
            {"run", json{{"lanes", request.lanes}, {"load_profile_pinned", true},
                {"run_scaling_stage", request.run_scaling_stage},
                {"run_determinism_stage", request.run_determinism_stage},
                {"determinism_runs", request.determinism_runs},
                {"scaling_worker_budgets", request.scaling_worker_budgets},
                {"wall_ns", analysis_wall_ns},
                {"process_cpu_ns", process_cpu_ns_now() - cpu_begin},
                {"analysis_revision", snapshot->analysis_revision},
                {"overlay_revision", snapshot->overlay_revision},
                {"generation", snapshot->generation},
                {"decode_window_ns", decode_window_ns},
                {"decode_window_granularity_ms", 25}}},
            {"phases", json::array({
                json{{"name", "baseline_analysis"}, {"invocations", 1},
                    {"wall_ns", analysis_wall_ns},
                    {"throughput_bytes_per_s", file_bps}},
                json{{"name", "decode_window"}, {"invocations", 1},
                    {"wall_ns", decode_window_ns},
                    {"throughput_bytes_per_s", decode_bps}}})},
            {"throughput", json{{"file_bytes_per_s", file_bps},
                {"decode_bytes_per_s", decode_bps},
                {"instructions_per_s", instructions_s},
                {"functions_per_s", analysis_wall_ns == 0 ? json(nullptr)
                    : json(static_cast<double>(snapshot->functions.size()) * 1000000000.0 /
                        static_cast<double>(analysis_wall_ns))},
                {"index_bytes_per_s", nullptr},
                {"persist_bytes_per_s", database.last_commit_elapsed_us == 0 ? json(nullptr)
                    : json(static_cast<double>(database.last_commit_page_write_bytes) /
                        (static_cast<double>(database.last_commit_elapsed_us) / 1000000.0))},
                {"decompile_all_funcs_per_s",
                    batch_ran ? json(batch_funcs_per_s) : json(nullptr)}}},
            {"worker_pool", nullptr},
            {"decode_detail", json{{"decoded_bytes", decoded_bytes},
                {"decode_window_ns", decode_window_ns},
                {"merge_window_ns", windows.merge_wall_ns()}}},
            {"memory", json{
                {"peak_private_bytes", metrics_snapshot.value(analysis_metric_t::peak_private_bytes)},
                {"peak_committed_bytes", metrics_snapshot.value(analysis_metric_t::peak_committed_bytes)},
                {"resident_bytes_peak", metrics_snapshot.value(analysis_metric_t::resident_bytes_peak)},
                {"mapped_workspace_peak", 0},
                {"mapped_global_peak", 0},
                {"spill_bytes_peak", 0}}},
            {"persistence", json{{"database_bytes", database.database_bytes},
                {"wal_bytes", database.wal_bytes},
                {"logical_bytes", database.cumulative_logical_bytes},
                {"rows", database.cumulative_rows},
                {"page_write_bytes", database.cumulative_page_write_bytes},
                {"last_commit_elapsed_us", database.last_commit_elapsed_us}}},
            {"interaction", json{{"warm_reopen_ms",
                warm_reopen_measured ? json(warm_reopen_ms) : json(nullptr)},
                {"metadata_ready_ms", nullptr},
                {"indexed_query_p95_ms", query_p95_ms},
                {"decompile_p95_ms", decompile_p95_ms},
                {"cancellation_request_to_completion_ms", nullptr}}},
            {"counts", json{{"instructions", snapshot->instructions.size()},
                {"blocks", snapshot->blocks.size()},
                {"functions", snapshot->functions.size()},
                {"edges", snapshot->edges.size()},
                {"xrefs", snapshot->xrefs.size()},
                {"strings", snapshot->strings.size()},
                {"symbols", snapshot->symbols.size()},
                {"decoded_bytes", decoded_bytes}}},
            {"scaling", std::move(scaling_block)},
            {"determinism", std::move(determinism_block)},
            {"sla", std::move(sla)},
            {"artifacts", json{{"report_json", nullptr},
                {"compare_verdict_json", nullptr}, {"receipt_json", nullptr}}},
            {"verdict", verdict}};

        if (scorecard["determinism"].is_object() &&
            scorecard["determinism"].contains("runs") &&
            scorecard["determinism"].contains("match")) {
            const auto manifest = scorecard["determinism"]["runs"].dump();
            const auto& match = scorecard["determinism"]["match"];
            diag::log_tagged_fmt("benchmark", "determinism manifest=%s match=%d",
                manifest.c_str(), match.is_boolean() && match.get<bool>() ? 1 : 0);
        } else {
            scorecard["determinism"] = json{
                {"status", "not_measured"},
                {"note", "no determinism stage ran for this request; determinism_hash_match remains NOT_MEASURED"}};
        }

        const std::string report_path = write_benchmark_artifacts(
            request.out_dir, mode, scorecard);
        diag::log_tagged_fmt("benchmark", "run_end wall_ms=%llu verdict=%s report=%s",
            static_cast<unsigned long long>(wall_ms), verdict.c_str(), report_path.c_str());
        result.ok = true;
        result.verdict = verdict;
        result.sla_overall = sla_overall;
        result.report_json_path = report_path;
        result.scorecard_json = scorecard.dump(2);
        return result;
    } catch (const std::exception& error) {
        if (warm_workspace) {
            try { close_benchmark_workspace(warm_workspace, true); } catch (...) {}
        }
        if (workspace) {
            try { close_benchmark_workspace(workspace, true); } catch (...) {}
        }
        if (!database_path.empty())
            remove_database_artifacts(database_path);
        diag::log_tagged_fmt("benchmark", "run_end wall_ms=%llu verdict=%s report=%s",
            static_cast<unsigned long long>(nanoseconds_since(run_begin) / 1000000ULL),
            "FAIL", error.what());
        result.verdict = "FAIL";
        result.sla_overall = "FAIL";
        result.error = error.what();
        return result;
    }
}

bool start_benchmark_async(const benchmark_run_request_t& request)
{
    bool expected = false;
    if (!g_async_state.active.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel, std::memory_order_acquire))
        return false;
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::long_running;
    descriptor.owner_subsystem = "analysis_benchmark";
    descriptor.label = "benchmark_run";
    descriptor.shutdown_policy = "drain";
    descriptor.body = [request]() {
        try {
            auto result = run_benchmark(request, {});
            std::lock_guard<std::mutex> lock(g_async_state.mutex);
            g_async_state.verdict = result.verdict;
            g_async_state.error = result.error;
            g_async_state.report_path = result.report_json_path;
        } catch (const std::exception& error) {
            std::lock_guard<std::mutex> lock(g_async_state.mutex);
            g_async_state.verdict = "FAIL";
            g_async_state.error = error.what();
            g_async_state.report_path.clear();
        } catch (...) {
            std::lock_guard<std::mutex> lock(g_async_state.mutex);
            g_async_state.verdict = "FAIL";
            g_async_state.error = "unknown";
            g_async_state.report_path.clear();
        }
        g_async_state.finished_ms.store(GetTickCount64(), std::memory_order_release);
        g_async_state.active.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        g_async_state.active.store(false, std::memory_order_release);
        diag::log_tagged_fmt("benchmark", "run_submit_refused reason=%s",
            submitted.reject_reason.c_str());
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_async_state.mutex);
        g_async_state.mode = mode_name(request.mode);
        g_async_state.verdict.clear();
        g_async_state.error.clear();
        g_async_state.report_path.clear();
    }
    g_async_state.run_scaling_stage.store(request.run_scaling_stage,
        std::memory_order_release);
    g_async_state.run_determinism_stage.store(request.run_determinism_stage,
        std::memory_order_release);
    g_async_state.determinism_runs.store(request.determinism_runs, std::memory_order_release);
    g_async_state.started_ms.store(GetTickCount64(), std::memory_order_release);
    g_async_state.finished_ms.store(0, std::memory_order_release);
    g_async_state.job_id.store(submitted.handle.id, std::memory_order_release);
    return true;
}

nlohmann::json benchmark_run_status()
{
    const bool active = g_async_state.active.load(std::memory_order_acquire);
    const std::uint64_t started = g_async_state.started_ms.load(std::memory_order_acquire);
    const std::uint64_t finished = g_async_state.finished_ms.load(std::memory_order_acquire);
    std::string mode;
    std::string verdict;
    std::string error;
    std::string report_path;
    {
        std::lock_guard<std::mutex> lock(g_async_state.mutex);
        mode = g_async_state.mode;
        verdict = g_async_state.verdict;
        error = g_async_state.error;
        report_path = g_async_state.report_path;
    }
    const std::uint64_t now = GetTickCount64();
    std::uint64_t elapsed = 0;
    if (started != 0) {
        elapsed = (active ? now : (finished != 0 ? finished : now)) - started;
    }
    return json{{"active", active}, {"mode", mode},
        {"started_ms", started}, {"finished_ms", finished},
        {"elapsed_ms", elapsed},
        {"job_id", g_async_state.job_id.load(std::memory_order_acquire)},
        {"run_scaling_stage", g_async_state.run_scaling_stage.load(std::memory_order_acquire)},
        {"run_determinism_stage",
            g_async_state.run_determinism_stage.load(std::memory_order_acquire)},
        {"determinism_runs", g_async_state.determinism_runs.load(std::memory_order_acquire)},
        {"verdict", verdict}, {"error", error},
        {"report_json", report_path}};
}

nlohmann::json benchmark_last_result()
{
    const std::string directory = benchmark_results_dir();
    const auto load_latest = [&](const char* mode) -> json {
        const auto path = std::filesystem::u8path(directory) /
            ("benchmark_" + std::string(mode) + "_latest.json");
        std::error_code error;
        if (!std::filesystem::is_regular_file(path, error))
            return nullptr;
        std::ifstream stream(path, std::ios::binary);
        if (!stream)
            return nullptr;
        json value;
        try {
            stream >> value;
        } catch (const json::exception&) {
            return nullptr;
        }
        return value;
    };
    json real = load_latest("real");
    json synthetic = load_latest("synthetic");
    json newest = nullptr;
    if (!real.is_null() && !synthetic.is_null()) {
        std::error_code error_real, error_synthetic;
        const auto real_time = std::filesystem::last_write_time(
            std::filesystem::u8path(directory) / "benchmark_real_latest.json", error_real);
        const auto synthetic_time = std::filesystem::last_write_time(
            std::filesystem::u8path(directory) / "benchmark_synthetic_latest.json",
            error_synthetic);
        newest = (!error_real && !error_synthetic && synthetic_time > real_time)
            ? synthetic : real;
    } else {
        newest = !real.is_null() ? real : synthetic;
    }
    return json{{"results_dir", directory}, {"real", std::move(real)},
        {"synthetic", std::move(synthetic)}, {"newest", std::move(newest)}};
}

}
