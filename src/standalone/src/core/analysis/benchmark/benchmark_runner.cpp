#include "benchmark_runner.hpp"

#include "benchmark_scorecard.hpp"

#include "../../../../tests/analysis_workspace/large_pe_fixture_builder.hpp"

#include "../workspace/baseline_pipeline.hpp"
#include "../workspace/search_index.hpp"
#include "../workspace/workspace_registry.hpp"
#include "../decompiler/decompile_batch_orchestrator.hpp"
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
#include <Psapi.h>

#pragma comment(lib, "bcrypt.lib")

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
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

struct runtime_memory_sample_t {
    std::uint64_t rss_bytes = 0;
    std::uint64_t private_bytes = 0;
    std::uint64_t active_workers = 0;
};

class benchmark_runtime_sampler_t final {
public:
    static constexpr std::size_t ring_capacity = 8192;

    benchmark_runtime_sampler_t() = default;
    ~benchmark_runtime_sampler_t() { stop(); }
    benchmark_runtime_sampler_t(const benchmark_runtime_sampler_t&) = delete;
    benchmark_runtime_sampler_t& operator=(const benchmark_runtime_sampler_t&) = delete;

    void start(std::uint32_t interval_ms)
    {
        if (interval_ms == 0)
            interval_ms = 250;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (running_)
                return;
            stop_requested_ = false;
            interval_ms_ = interval_ms;
            write_index_.store(0, std::memory_order_release);
            running_ = true;
        }
        try {
            thread_ = std::thread([this]() { run(); });
        } catch (...) {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
            throw;
        }
        diag::log_tagged_fmt("benchmark", "runtime_sampler_start interval_ms=%u ring=%zu",
            static_cast<unsigned>(interval_ms), ring_capacity);
    }

    void stop() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_)
                return;
            stop_requested_ = true;
            wake_.notify_all();
        }
        if (thread_.joinable())
            thread_.join();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
        diag::log_tagged_fmt("benchmark", "runtime_sampler_stop samples=%llu",
            static_cast<unsigned long long>(write_index_.load(std::memory_order_acquire)));
    }

    json summary_json() const
    {
        const auto total = write_index_.load(std::memory_order_acquire);
        const auto count = static_cast<std::size_t>((std::min<std::uint64_t>)(total, ring_capacity));
        std::uint64_t peak_rss = 0;
        std::uint64_t peak_private = 0;
        std::uint64_t peak_workers = 0;
        long double rss_sum = 0.0;
        for (std::size_t index = 0; index < count; ++index) {
            const auto& sample = ring_[index];
            peak_rss = (std::max)(peak_rss, sample.rss_bytes);
            peak_private = (std::max)(peak_private, sample.private_bytes);
            peak_workers = (std::max)(peak_workers, sample.active_workers);
            rss_sum += static_cast<long double>(sample.rss_bytes);
        }
        return json{{"sample_count", count},
            {"sample_interval_ms", interval_ms_},
            {"peak_rss_bytes", count == 0 ? json(nullptr) : json(peak_rss)},
            {"mean_rss_bytes", count == 0 ? json(nullptr)
                : json(static_cast<double>(rss_sum / count))},
            {"peak_private_bytes", count == 0 ? json(nullptr) : json(peak_private)},
            {"peak_active_workers", count == 0 ? json(nullptr) : json(peak_workers)}};
    }

private:
    void run() noexcept
    {
        for (;;) {
            try {
                PROCESS_MEMORY_COUNTERS_EX counters{};
                counters.cb = static_cast<DWORD>(sizeof(counters));
                runtime_memory_sample_t sample;
                if (GetProcessMemoryInfo(GetCurrentProcess(),
                    reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&counters),
                    static_cast<DWORD>(sizeof(counters)))) {
                    sample.rss_bytes = static_cast<std::uint64_t>(counters.WorkingSetSize);
                    sample.private_bytes = static_cast<std::uint64_t>(counters.PrivateUsage);
                }
                sample.active_workers = static_cast<std::uint64_t>(
                    aida::infra::taskflow_runtime::active_snapshot().total_active);
                const auto index = write_index_.fetch_add(1, std::memory_order_acq_rel);
                ring_[static_cast<std::size_t>(index % ring_capacity)] = sample;
            } catch (...) {
            }
            std::unique_lock<std::mutex> lock(mutex_);
            if (stop_requested_)
                break;
            wake_.wait_for(lock, std::chrono::milliseconds(interval_ms_),
                [this]() { return stop_requested_; });
            if (stop_requested_)
                break;
        }
    }

    mutable std::mutex mutex_;
    std::condition_variable wake_;
    std::thread thread_;
    bool running_ = false;
    bool stop_requested_ = false;
    std::uint32_t interval_ms_ = 250;
    std::array<runtime_memory_sample_t, ring_capacity> ring_{};
    std::atomic<std::uint64_t> write_index_{0};
};

class latency_reservoir_t final {
public:
    static constexpr std::size_t capacity = 4096;

    explicit latency_reservoir_t(std::uint64_t seed)
        : state_(seed != 0 ? seed : 0x9E3779B97F4A7C15ULL)
    {
        values_.reserve(capacity);
    }

    void push(std::uint64_t value)
    {
        ++seen_;
        if (values_.size() < capacity) {
            values_.push_back(value);
            return;
        }
        const auto slot = next() % seen_;
        if (slot < capacity)
            values_[static_cast<std::size_t>(slot)] = value;
    }

    std::size_t size() const noexcept { return values_.size(); }
    std::uint64_t seen() const noexcept { return seen_; }

    json percentile(double rank) const
    {
        if (values_.empty())
            return nullptr;
        auto ordered = values_;
        std::sort(ordered.begin(), ordered.end());
        return ordered[static_cast<std::size_t>((ordered.size() - 1) * rank)];
    }

private:
    std::uint64_t next() noexcept
    {
        state_ += 0x9E3779B97F4A7C15ULL;
        auto value = state_;
        value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ULL;
        value = (value ^ (value >> 27)) * 0x94D049BB133111EBULL;
        return value ^ (value >> 31);
    }

    std::uint64_t state_;
    std::uint64_t seen_ = 0;
    std::vector<std::uint64_t> values_;
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
    std::shared_ptr<const analysis_metrics_snapshot_t> harvested_metrics;
    std::shared_ptr<decompile_batch_orchestrator_t> decompile_orchestrator;
    std::shared_ptr<analysis_metrics_t> decompile_metrics;
    bool decompile_orchestrator_owned = false;
};

analysis_once_result_t run_analysis_once(const open_static_workspace_request_t& open_request,
                                         std::uint32_t worker_budget,
                                         const cancellation_token_t& cancel,
                                         benchmark_runtime_sampler_t* sampler = nullptr,
                                         std::uint32_t sample_interval_ms = 250)
{
    analysis_once_result_t outcome;
    try {
        auto opened = workspace_registry().open_static(open_request, cancel);
        if (!opened)
            throw std::runtime_error("benchmark workspace open failed: " +
                opened.error().stable_code() + ":" + opened.error().message);
        outcome.workspace = opened.take_value();

        struct sampler_guard_t {
            benchmark_runtime_sampler_t* sampler = nullptr;
            ~sampler_guard_t() { if (sampler) sampler->stop(); }
        } sampler_guard;
        if (sampler) {
            sampler->start(sample_interval_ms);
            sampler_guard.sampler = sampler;
        }

        outcome.decompile_orchestrator = outcome.workspace->background_decompile();
        if (outcome.decompile_orchestrator) {
            outcome.decompile_metrics = outcome.workspace->background_metrics();
        } else {
            auto sink = std::make_shared<analysis_metrics_t>(outcome.workspace->generation());
            auto created = decompile_batch_orchestrator_t::create(outcome.workspace, sink);
            if (created) {
                outcome.decompile_orchestrator = created.take_value();
                outcome.decompile_metrics = std::move(sink);
                outcome.decompile_orchestrator_owned = true;
                diag::log_tagged_fmt("benchmark",
                    "decompile_orchestrator wiring=%s reason=%s",
                    "benchmark_owned_orchestrator", "workspace_has_no_registry_orchestrator");
            } else {
                diag::log_tagged_fmt("benchmark",
                    "decompile_orchestrator wiring=%s reason=%s error=%s",
                    "unavailable", "benchmark_owned_create_failed",
                    created.error().message.c_str());
            }
        }

        const auto image = outcome.workspace->normalized_image();
        if (!image)
            throw std::runtime_error("benchmark fixture image metadata is unavailable");
        outcome.code_bytes = executable_bytes_of(image);
        if (outcome.code_bytes == 0)
            throw std::runtime_error("benchmark fixture has no normalized executable bytes");

        baseline_analysis_settings_t settings;
        settings.decode_worker_lanes = worker_budget;
        settings.fact_pass_worker_budget = worker_budget;
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

        outcome.harvested_metrics = harvest_workspace_baseline_metrics(outcome.workspace);
        diag::log_tagged_fmt("benchmark", "baseline_metrics_harvest available=%d",
            outcome.harvested_metrics ? 1 : 0);
        outcome.snapshot = outcome.workspace->snapshot();
        for (const auto& span : outcome.snapshot->coverage) {
            if (span.reason == coverage_reason_t::decoded)
                outcome.decoded_bytes += span.size;
        }
        outcome.file_bytes = outcome.workspace->provider().size();
        outcome.decode_window_ns = outcome.windows.decode_wall_ns() +
            outcome.windows.merge_wall_ns();
        outcome.instruction_count = outcome.snapshot->instructions.size();
        sampler_guard.sampler = nullptr;
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
    return (std::min)(64U, (std::max)(2U, hardware));
}

struct stage_run_measurement_t {
    std::uint32_t budget = 0;
    std::uint64_t wall_ns = 0;
    std::uint64_t decode_window_ns = 0;
    std::uint64_t decoded_bytes = 0;
    std::uint64_t instruction_count = 0;
    std::string snapshot_sha256;
    std::shared_ptr<const analysis_metrics_snapshot_t> harvested_metrics;
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
    measurement.harvested_metrics = std::move(once.harvested_metrics);
    try {
        measurement.snapshot_sha256 = snapshot_determinism_sha256(*once.snapshot);
    } catch (...) {
        try { close_benchmark_workspace(once.workspace, true); } catch (...) {}
        throw;
    }
    close_benchmark_workspace(once.workspace, true);
    return measurement;
}

struct parallel_decompile_stage_t {
    bool ran = false;
    std::string wiring;
    std::string unavailable_reason;
    std::uint64_t total = 0;
    std::uint64_t calls = 0;
    std::uint64_t completed = 0;
    std::uint64_t failed = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t wall_ns = 0;
    std::uint64_t queue_depth_peak = 0;
    std::uint64_t memory_cache_hits = 0;
    std::uint64_t persistent_cache_hits = 0;
    std::uint64_t slots = 0;
    std::uint64_t slots_effective_peak = 0;
    std::uint64_t latency_samples = 0;
    bool truncated = false;
    double funcs_per_s = 0.0;
    json latency_p50_ns = nullptr;
    json latency_p95_ns = nullptr;
};

parallel_decompile_stage_t run_parallel_decompile_stage(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    const std::shared_ptr<decompile_batch_orchestrator_t>& orchestrator,
    const std::shared_ptr<analysis_metrics_t>& sink,
    const analysis_snapshot_t& snapshot,
    std::uint32_t max_functions,
    std::uint32_t max_ms,
    std::uint64_t seed,
    bool orchestrator_owned,
    const cancellation_token_t& cancel)
{
    parallel_decompile_stage_t stage;
    if (snapshot.functions.empty()) {
        stage.unavailable_reason = "no_recovered_functions";
        return stage;
    }
    if (!workspace->decompiler()) {
        stage.unavailable_reason = "decompiler_service_unavailable";
        return stage;
    }
    if (!orchestrator || !sink) {
        stage.unavailable_reason = "decompile_batch_orchestrator_unavailable";
        return stage;
    }
    stage.ran = true;
    stage.wiring = orchestrator_owned ? "benchmark_owned_orchestrator" : "registry_orchestrator";
    const auto metrics_before = sink->snapshot();
    const auto stage_begin = steady_clock_t::now();
    latency_reservoir_t reservoir(seed ^ 0xDEC0DE17ULL);
    std::uint64_t previous_completed = 0;
    auto previous_at = steady_clock_t::now();
    bool started_once = false;
    bool cancel_requested = false;
    decompile_batch_orchestrator_t::run_snapshot_t last;
    diag::log_tagged_fmt("benchmark",
        "decompile_stage_begin max_functions=%u max_ms=%u functions=%llu",
        static_cast<unsigned>(max_functions), static_cast<unsigned>(max_ms),
        static_cast<unsigned long long>(snapshot.functions.size()));
    for (;;) {
        last = orchestrator->run_snapshot();
        stage.slots = (std::max)(stage.slots, last.slots);
        stage.slots_effective_peak = (std::max)(stage.slots_effective_peak,
            last.slots_effective);
        if (last.active || last.total != 0)
            started_once = true;
        const auto now = steady_clock_t::now();
        const auto interval_ns = nanoseconds_since(previous_at);
        const auto completed_delta = last.completed >= previous_completed
            ? last.completed - previous_completed : 0;
        if (completed_delta != 0 && interval_ns != 0) {
            const auto slots = (std::max<std::uint64_t>)(1, last.slots_effective);
            reservoir.push(slots * interval_ns / completed_delta);
            previous_completed = last.completed;
            previous_at = now;
        }
        const auto elapsed_ms = nanoseconds_since(stage_begin) / 1000000ULL;
        const auto processed = last.completed + last.failed + last.cancelled;
        if (started_once && !last.active && last.total != 0 && processed >= last.total)
            break;
        if (last.completed >= max_functions) {
            stage.truncated = true;
            break;
        }
        if (elapsed_ms >= max_ms) {
            stage.truncated = true;
            break;
        }
        if (cancel.stop_requested())
            break;
        if (!started_once && elapsed_ms >= (std::min<std::uint64_t>)(max_ms, 30000ULL))
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (started_once) {
        last = orchestrator->run_snapshot();
        stage.slots = (std::max)(stage.slots, last.slots);
        stage.slots_effective_peak = (std::max)(stage.slots_effective_peak,
            last.slots_effective);
        if (last.active) {
            cancel_requested = true;
            orchestrator->request_cancel();
        }
        const auto drained = orchestrator->drain(
            steady_clock_t::now() + std::chrono::seconds(30));
        if (!drained)
            diag::log_tagged_fmt("benchmark",
                "decompile_stage_drain_timeout code=%s message=%s",
                drained.error().stable_code().c_str(), drained.error().message.c_str());
        last = orchestrator->run_snapshot();
    }
    const auto stage_wall_ns = nanoseconds_since(stage_begin);
    const auto metrics_after = sink->snapshot();
    const auto counter_delta = [&](analysis_metric_t metric) {
        const auto after = metrics_after.value(metric);
        const auto before = metrics_before.value(metric);
        return after >= before ? after - before : 0ULL;
    };
    stage.calls = counter_delta(analysis_metric_t::decompile_batch_calls);
    stage.completed = counter_delta(analysis_metric_t::decompile_batch_completed);
    stage.failed = counter_delta(analysis_metric_t::decompile_batch_failed);
    stage.cancelled = counter_delta(analysis_metric_t::decompile_batch_cancelled);
    stage.wall_ns = counter_delta(analysis_metric_t::decompile_batch_wall_ns);
    stage.total = last.total != 0 ? last.total : snapshot.functions.size();
    stage.queue_depth_peak = metrics_after.value(
        analysis_metric_t::decompile_batch_queue_depth_peak) >=
            metrics_before.value(analysis_metric_t::decompile_batch_queue_depth_peak)
        ? metrics_after.value(analysis_metric_t::decompile_batch_queue_depth_peak)
        : metrics_before.value(analysis_metric_t::decompile_batch_queue_depth_peak);
    stage.memory_cache_hits = counter_delta(analysis_metric_t::decompile_memory_cache_hits);
    stage.persistent_cache_hits = counter_delta(
        analysis_metric_t::decompile_persistent_cache_hits);
    if (stage.wall_ns == 0)
        stage.wall_ns = stage_wall_ns;
    if (stage.wall_ns != 0) {
        stage.funcs_per_s = static_cast<double>(stage.completed) * 1000000000.0 /
            static_cast<double>(stage.wall_ns);
    }
    if (reservoir.size() == 0 && stage.completed >= 2 && stage.wall_ns != 0) {
        reservoir.push((std::max<std::uint64_t>)(1, stage.slots_effective_peak) *
            stage.wall_ns / stage.completed);
    }
    stage.latency_samples = reservoir.seen();
    stage.latency_p50_ns = reservoir.percentile(0.50);
    stage.latency_p95_ns = reservoir.percentile(0.95);
    diag::log_tagged_fmt("benchmark",
        "decompile_stage_end completed=%llu failed=%llu cancelled=%llu total=%llu wall_ms=%llu funcs_s=%.2f slots=%llu slots_effective_peak=%llu truncated=%d cancel=%d drain_cancelled=%d",
        static_cast<unsigned long long>(stage.completed),
        static_cast<unsigned long long>(stage.failed),
        static_cast<unsigned long long>(stage.cancelled),
        static_cast<unsigned long long>(stage.total),
        static_cast<unsigned long long>(stage.wall_ns / 1000000ULL),
        stage.funcs_per_s,
        static_cast<unsigned long long>(stage.slots),
        static_cast<unsigned long long>(stage.slots_effective_peak),
        stage.truncated ? 1 : 0,
        cancel.stop_requested() ? 1 : 0,
        cancel_requested ? 1 : 0);
    return stage;
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
        benchmark_runtime_sampler_t sampler;
        auto primary = run_analysis_once(open_request, request.lanes, cancel,
            &sampler, request.memory_sample_interval_ms);
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
        const auto harvested = primary.harvested_metrics;
        const bool harvested_available = harvested != nullptr;

        const auto decompile_stage = run_parallel_decompile_stage(workspace,
            primary.decompile_orchestrator, primary.decompile_metrics, *snapshot,
            request.decompile_batch_max_functions, request.decompile_batch_max_ms,
            request.synthetic_seed, primary.decompile_orchestrator_owned, cancel);
        const bool batch_ran = decompile_stage.ran;
        const double batch_funcs_per_s = decompile_stage.funcs_per_s;

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
        sampler.stop();
        const auto sampler_summary = sampler.summary_json();
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
                    {"phases", run.harvested_metrics
                        ? scorecard_phase_entries(*run.harvested_metrics) : json(nullptr)},
                    {"phases_status", run.harvested_metrics
                        ? json("measured") : json(
                            "not_applicable:workspace_baseline_metrics_publication_unavailable")},
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
        const std::uint64_t harvested_decode_wall_ns = harvested_available
            ? harvested->phases[static_cast<std::size_t>(baseline_phase_t::decode)].wall_ns +
                harvested->phases[static_cast<std::size_t>(baseline_phase_t::decode_merge)].wall_ns
            : 0;
        const std::uint64_t decode_effective_ns =
            harvested_available ? harvested_decode_wall_ns : decode_window_ns;
        if (harvested_available) {
            diag::log_tagged_fmt("benchmark",
                "phase_window_crosscheck harvested_decode_merge_ms=%llu inferred_decode_window_ms=%llu granularity_ms=%u",
                static_cast<unsigned long long>(harvested_decode_wall_ns / 1000000ULL),
                static_cast<unsigned long long>(decode_window_ns / 1000000ULL), 25U);
        }
        const double decode_wall_s = decode_effective_ns == 0
            ? 0.0 : static_cast<double>(decode_effective_ns) / 1000000000.0;
        const json decode_bps = decode_effective_ns == 0 ? json(nullptr)
            : json(static_cast<double>(decoded_bytes) / decode_wall_s);
        const json file_bps = analysis_wall_ns == 0 ? json(nullptr)
            : json(static_cast<double>(file_bytes) * 1000000000.0 /
                static_cast<double>(analysis_wall_ns));
        const json instructions_s = decode_effective_ns == 0 ? json(nullptr)
            : json(static_cast<double>(snapshot->instructions.size()) / decode_wall_s);
        const json publish_ms = harvested_available
            ? json(static_cast<double>(
                harvested->phases[static_cast<std::size_t>(
                    baseline_phase_t::publish_ready)].wall_ns) / 1000000.0)
            : (windows.publish_wall_ns() == 0 ? json(nullptr)
                : json(static_cast<double>(windows.publish_wall_ns()) / 1000000.0));
        const json query_p95_ms = query_samples.empty() ? json(nullptr)
            : json(static_cast<double>(percentile_value(query_samples, 0.95)) / 1000000.0);
        const json decompile_p95_ms = decompile_stage.latency_p95_ns.is_number()
            ? json(decompile_stage.latency_p95_ns.get<std::uint64_t>() / 1000000.0)
            : json(nullptr);
        const json metadata_ready_ms = harvested_available
            ? json(static_cast<double>(
                harvested->phases[static_cast<std::size_t>(
                    baseline_phase_t::metadata_symbols_types)].wall_ns) / 1000000.0)
            : json(nullptr);
        const std::uint64_t mapped_workspace_peak = harvested_available
            ? harvested->value(analysis_metric_t::mapped_window_bytes_peak) : 0;
        const std::uint64_t mapped_global_peak = harvested_available
            ? harvested->value(analysis_metric_t::mapped_window_bytes_global_peak) : 0;

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
        const auto push_max_u64 = [&](const char* key, std::uint64_t target,
                                      std::uint64_t actual, bool measured) {
            if (!measured) {
                verdicts.push_back(verdict_entry(key, target, nullptr, "NOT_MEASURED"));
                return;
            }
            verdicts.push_back(verdict_entry(key, target, actual,
                actual <= target ? "PASS" : "FAIL"));
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
        push_max("metadata_ready_ms_max",
            thresholds["metadata_ready_ms_max"].get<double>(), metadata_ready_ms);
        push_max("warm_reopen_ms_max", thresholds["warm_reopen_ms_max"].get<double>(),
            warm_reopen_measured ? json(warm_reopen_ms) : json(nullptr));
        verdicts.push_back(verdict_entry("cancellation_p95_ms_max",
            thresholds["cancellation_p95_ms_max"], nullptr, "NOT_MEASURED"));
        push_max_u64("incremental_private_bytes_max",
            thresholds["incremental_private_bytes_max"].get<std::uint64_t>(),
            metrics_snapshot.value(analysis_metric_t::peak_private_bytes), true);
        push_max_u64("workspace_mapped_bytes_max",
            thresholds["workspace_mapped_bytes_max"].get<std::uint64_t>(),
            mapped_workspace_peak, harvested_available && mapped_workspace_peak != 0);
        push_max_u64("global_mapped_bytes_max",
            thresholds["global_mapped_bytes_max"].get<std::uint64_t>(),
            mapped_global_peak, harvested_available && mapped_global_peak != 0);
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
                "decompile_batch",
                static_cast<unsigned long long>(decompile_stage.wall_ns / 1000000ULL),
                0ULL, 0ULL, static_cast<unsigned long long>(decompile_stage.completed));
        }
        diag::log_tagged_fmt("benchmark",
            "memory peak_private=%llu resident_peak=%llu mapped_ws_peak=%llu mapped_global_peak=%llu spill_peak=%llu",
            static_cast<unsigned long long>(
                metrics_snapshot.value(analysis_metric_t::peak_private_bytes)),
            static_cast<unsigned long long>(
                metrics_snapshot.value(analysis_metric_t::resident_bytes_peak)),
            static_cast<unsigned long long>(mapped_workspace_peak),
            static_cast<unsigned long long>(mapped_global_peak),
            static_cast<unsigned long long>(harvested_available
                ? harvested->value(analysis_metric_t::spill_bytes_peak) : 0));
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

        std::string verdict = sla_overall == "FAIL"
            ? (request.sla_relaxed ? "PASS" : "FAIL") : "PASS";

        const json phases_block = harvested_available
            ? scorecard_phase_entries(*harvested)
            : json::array({
                json{{"name", "baseline_analysis"}, {"invocations", 1},
                    {"wall_ns", analysis_wall_ns},
                    {"throughput_bytes_per_s", file_bps}},
                json{{"name", "decode_window"}, {"invocations", 1},
                    {"wall_ns", decode_window_ns},
                    {"throughput_bytes_per_s", decode_bps}}});
        const char* phases_status = harvested_available
            ? "measured" : "not_applicable:workspace_baseline_metrics_publication_unavailable";

        SYSTEM_INFO host_system{};
        GetNativeSystemInfo(&host_system);
        const auto host_logical =
            static_cast<std::uint64_t>((std::max)(1U, host_system.dwNumberOfProcessors));
        const std::uint64_t slots_busy_ns = harvested_available
            ? harvested->value(analysis_metric_t::worker_slots_busy_ns) : 0;
        const std::uint64_t slots_scheduled_ns = harvested_available
            ? harvested->value(analysis_metric_t::worker_slots_scheduled_ns) : 0;
        json parallelism_efficiency = nullptr;
        if (harvested_available && analysis_wall_ns != 0 && slots_busy_ns != 0) {
            const double denominator = static_cast<double>(analysis_wall_ns) *
                static_cast<double>(host_logical);
            parallelism_efficiency = (std::min)(1.0,
                static_cast<double>(slots_busy_ns) / denominator);
        }
        const json worker_pool_block = harvested_available
            ? json{{"status", "measured"},
                {"slots_busy_ns", slots_busy_ns},
                {"slots_scheduled_ns", slots_scheduled_ns},
                {"utilization", slots_scheduled_ns == 0 ? json(nullptr)
                    : json(static_cast<double>(slots_busy_ns) /
                        static_cast<double>(slots_scheduled_ns))},
                {"parallelism_efficiency", parallelism_efficiency},
                {"logical_cores", host_logical},
                {"queue_wait_ns_total",
                    harvested->value(analysis_metric_t::queue_wait_ns_total)},
                {"queue_wait_max_ns",
                    harvested->value(analysis_metric_t::queue_wait_max_ns)},
                {"queue_depth_mean",
                    harvested->value(analysis_metric_t::queue_depth_samples) == 0
                        ? json(nullptr)
                        : json(static_cast<double>(
                            harvested->value(analysis_metric_t::queue_depth_sum)) /
                            static_cast<double>(
                                harvested->value(analysis_metric_t::queue_depth_samples)))},
                {"queue_depth_peak",
                    harvested->value(analysis_metric_t::peak_queue_depth)},
                {"tasks_scheduled",
                    harvested->value(analysis_metric_t::tasks_scheduled)},
                {"tasks_completed",
                    harvested->value(analysis_metric_t::tasks_completed)},
                {"tasks_rejected",
                    harvested->value(analysis_metric_t::tasks_rejected)}}
            : json{{"status", "not_applicable"},
                {"reason", metrics_unavailable_reason},
                {"slots_busy_ns", nullptr},
                {"slots_scheduled_ns", nullptr},
                {"utilization", nullptr},
                {"parallelism_efficiency", nullptr}};

        const std::uint64_t harvested_search_index_wall_ns = harvested_available
            ? harvested->phases[static_cast<std::size_t>(
                baseline_phase_t::search_index)].wall_ns
            : 0;
        const std::uint64_t harvested_persistence_wall_ns = harvested_available
            ? harvested->phases[static_cast<std::size_t>(
                baseline_phase_t::persistence)].wall_ns
            : 0;
        const json index_bps = harvested_available
            ? nullable_rate(harvested->value(analysis_metric_t::index_text_bytes),
                harvested_search_index_wall_ns)
            : json(nullptr);
        const json persist_bps = harvested_available
            ? nullable_rate(harvested->value(analysis_metric_t::database_bytes_written),
                harvested_persistence_wall_ns)
            : (database.last_commit_elapsed_us == 0 ? json(nullptr)
                : json(static_cast<double>(database.last_commit_page_write_bytes) /
                    (static_cast<double>(database.last_commit_elapsed_us) / 1000000.0)));

        const json decode_detail_block = harvested_available
            ? json{{"status", "measured"},
                {"decoded_bytes", decoded_bytes},
                {"tiles", harvested->value(analysis_metric_t::decode_tiles)},
                {"requests", harvested->value(analysis_metric_t::decode_requests)},
                {"waves", harvested->value(analysis_metric_t::decode_waves)},
                {"frontier_seeds",
                    harvested->value(analysis_metric_t::decode_frontier_seeds)},
                {"cross_tile_edges",
                    harvested->value(analysis_metric_t::decode_cross_tile_edges)},
                {"invalid_bytes",
                    harvested->value(analysis_metric_t::decode_invalid_bytes)},
                {"invalid_runs",
                    harvested->value(analysis_metric_t::decode_invalid_runs)},
                {"duplicate_instructions",
                    harvested->value(analysis_metric_t::decode_duplicate_instructions)},
                {"merge_ns", harvested->value(analysis_metric_t::decode_merge_ns)},
                {"lane_wall_ns_max",
                    harvested->value(analysis_metric_t::decode_lane_wall_ns_max)},
                {"bytes_attempted",
                    harvested->value(analysis_metric_t::decode_bytes_attempted)}}
            : json{{"status", "not_applicable"},
                {"reason", metrics_unavailable_reason},
                {"decoded_bytes", decoded_bytes},
                {"decode_window_ns", decode_window_ns},
                {"merge_window_ns", windows.merge_wall_ns()}};

        const json memory_block = json{
            {"status", harvested_available ? "measured" : "partial"},
            {"peak_private_bytes",
                metrics_snapshot.value(analysis_metric_t::peak_private_bytes)},
            {"peak_committed_bytes",
                metrics_snapshot.value(analysis_metric_t::peak_committed_bytes)},
            {"resident_bytes_peak",
                metrics_snapshot.value(analysis_metric_t::resident_bytes_peak)},
            {"peak_rss_bytes", sampler_summary["peak_rss_bytes"]},
            {"mean_rss_bytes", sampler_summary["mean_rss_bytes"]},
            {"sample_count", sampler_summary["sample_count"]},
            {"sample_interval_ms", sampler_summary["sample_interval_ms"]},
            {"peak_active_workers", sampler_summary["peak_active_workers"]},
            {"mapped_workspace_peak",
                harvested_available ? json(mapped_workspace_peak) : json(nullptr)},
            {"mapped_global_peak",
                harvested_available ? json(mapped_global_peak) : json(nullptr)},
            {"spill_bytes_peak", harvested_available
                ? json(harvested->value(analysis_metric_t::spill_bytes_peak))
                : json(nullptr)},
            {"spill_bytes_written", harvested_available
                ? json(harvested->value(analysis_metric_t::spill_bytes_written))
                : json(nullptr)},
            {"spill_bytes_read", harvested_available
                ? json(harvested->value(analysis_metric_t::spill_bytes_read))
                : json(nullptr)},
            {"budget_rejections", harvested_available
                ? json(harvested->value(analysis_metric_t::budget_rejections))
                : json(nullptr)},
            {"pressure_events", harvested_available
                ? json(harvested->value(analysis_metric_t::memory_pressure_events))
                : json(nullptr)}};

        const std::uint64_t persist_logical_bytes = harvested_available
            ? harvested->value(analysis_metric_t::database_logical_bytes)
            : database.cumulative_logical_bytes;
        const std::uint64_t persist_bytes_written = harvested_available
            ? harvested->value(analysis_metric_t::database_bytes_written)
            : database.cumulative_page_write_bytes;
        json write_amplification = nullptr;
        if (persist_logical_bytes != 0) {
            write_amplification = static_cast<double>(persist_bytes_written) /
                static_cast<double>(persist_logical_bytes);
        }
        const json persistence_block = json{
            {"status", harvested_available ? "measured" : "partial"},
            {"database_bytes", database.database_bytes},
            {"wal_bytes", database.wal_bytes},
            {"logical_bytes", persist_logical_bytes},
            {"rows", database.cumulative_rows},
            {"bytes_written", persist_bytes_written},
            {"page_write_bytes", database.cumulative_page_write_bytes},
            {"last_commit_elapsed_us", database.last_commit_elapsed_us},
            {"commit_elapsed_ns", harvested_available
                ? json(harvested->value(analysis_metric_t::database_commit_elapsed_ns))
                : json(nullptr)},
            {"write_amplification", write_amplification},
            {"queue_wait_ns", harvested_available
                ? json(harvested->value(analysis_metric_t::persist_queue_wait_ns))
                : json(nullptr)},
            {"queue_depth_peak", harvested_available
                ? json(harvested->value(analysis_metric_t::persist_queue_depth_peak))
                : json(nullptr)},
            {"pages_written", harvested_available
                ? json(harvested->value(analysis_metric_t::persist_pages_written))
                : json(nullptr)},
            {"wal_bytes_peak", harvested_available
                ? json(harvested->value(analysis_metric_t::persist_wal_bytes_peak))
                : json(nullptr)}};

        json decompile_block;
        if (batch_ran) {
            const std::uint64_t cache_hits = decompile_stage.memory_cache_hits +
                decompile_stage.persistent_cache_hits;
            decompile_block = json{
                {"engine", "parallel_batch"},
                {"wiring", decompile_stage.wiring},
                {"calls", decompile_stage.calls},
                {"completed", decompile_stage.completed},
                {"failed", decompile_stage.failed},
                {"cancelled", decompile_stage.cancelled},
                {"total", decompile_stage.total},
                {"wall_ns", decompile_stage.wall_ns},
                {"funcs_per_s", decompile_stage.funcs_per_s},
                {"p50_ns", decompile_stage.latency_p50_ns},
                {"p95_ns", decompile_stage.latency_p95_ns},
                {"latency_model", "interval_throughput_derived_service_time"},
                {"latency_samples", decompile_stage.latency_samples},
                {"memory_cache_hits", decompile_stage.memory_cache_hits},
                {"persistent_cache_hits", decompile_stage.persistent_cache_hits},
                {"cache_hit_rate", decompile_stage.calls == 0 ? json(nullptr)
                    : json(static_cast<double>(cache_hits) /
                        static_cast<double>(decompile_stage.calls))},
                {"queue_depth_peak", decompile_stage.queue_depth_peak},
                {"slots", decompile_stage.slots},
                {"slots_effective_peak", decompile_stage.slots_effective_peak},
                {"truncated", decompile_stage.truncated}};
        } else {
            decompile_block = json{
                {"engine", "parallel_batch"},
                {"status", "not_applicable"},
                {"reason", decompile_stage.unavailable_reason.empty()
                    ? "decompile_stage_not_run" : decompile_stage.unavailable_reason},
                {"funcs_per_s", nullptr}};
        }

        const json phase_budgets_block = evaluate_phase_budgets(
            phases_block, wall_ms, wall_scale);

        json scorecard = json{
            {"scorecard_schema", scorecard_schema_v2},
            {"scorecard_schema_version", scorecard_schema_v2_version},
            {"run_id", utc_run_id()},
            {"mode", mode},
            {"claim_status", "measurement_only"},
            {"claim", json{
                {"tracks", json::array({
                    json{{"id", "auto_analysis_wall"},
                        {"definition", "total_wall_ms open-to-baseline_ready at or below total_wall_ms_max_300mb on a 300..500MB real binary"}},
                    json{{"id", "batch_decompile_throughput"},
                        {"definition", "decompile_all_funcs_per_s on the parallel production batch engine; a throughput claim, never a minutes claim"}}})},
                {"real_mode_invocation",
                    "Test Lab analysis_benchmark_real_300mb with AIDA_BENCHMARK_REAL_PE=<path> (optional AIDA_BENCHMARK_REAL_SLA_RELAX=1), or MCP analysis_benchmark_manage run_real, or headless analysis_benchmark_harness real <path>"}}},
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
                {"decompile_batch_lanes", request.decompile_batch_lanes},
                {"decompile_batch_max_functions", request.decompile_batch_max_functions},
                {"decompile_batch_max_ms", request.decompile_batch_max_ms},
                {"memory_sample_interval_ms", request.memory_sample_interval_ms},
                {"baseline_report_path", request.baseline_report_path.empty()
                    ? json(nullptr) : json(request.baseline_report_path)},
                {"record_baseline_name", request.record_baseline_name.empty()
                    ? json(nullptr) : json(request.record_baseline_name)},
                {"wall_ns", analysis_wall_ns},
                {"process_cpu_ns", process_cpu_ns_now() - cpu_begin},
                {"analysis_revision", snapshot->analysis_revision},
                {"overlay_revision", snapshot->overlay_revision},
                {"generation", snapshot->generation},
                {"decode_window_ns", decode_window_ns},
                {"phase_window_crosscheck", json{
                    {"decode_window_ns", windows.decode_wall_ns()},
                    {"merge_window_ns", windows.merge_wall_ns()},
                    {"publish_window_ns", windows.publish_wall_ns()},
                    {"sample_granularity_ms", 25}}}}},
            {"phases", std::move(phases_block)},
            {"phases_status", phases_status},
            {"throughput", json{{"file_bytes_per_s", file_bps},
                {"decode_bytes_per_s", decode_bps},
                {"instructions_per_s", instructions_s},
                {"functions_per_s", analysis_wall_ns == 0 ? json(nullptr)
                    : json(static_cast<double>(snapshot->functions.size()) * 1000000000.0 /
                        static_cast<double>(analysis_wall_ns))},
                {"index_bytes_per_s", index_bps},
                {"persist_bytes_per_s", persist_bps},
                {"decompile_all_funcs_per_s",
                    batch_ran ? json(batch_funcs_per_s) : json(nullptr)}}},
            {"worker_pool", std::move(worker_pool_block)},
            {"decode_detail", std::move(decode_detail_block)},
            {"memory", std::move(memory_block)},
            {"persistence", std::move(persistence_block)},
            {"decompile", std::move(decompile_block)},
            {"interaction", json{{"warm_reopen_ms",
                warm_reopen_measured ? json(warm_reopen_ms) : json(nullptr)},
                {"metadata_ready_ms", metadata_ready_ms},
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
                {"types", search ? json(search->types().size()) : json(nullptr)},
                {"decoded_bytes", decoded_bytes}}},
            {"phase_budgets", std::move(phase_budgets_block)},
            {"scaling", std::move(scaling_block)},
            {"determinism", std::move(determinism_block)},
            {"sla", std::move(sla)},
            {"artifacts", json{{"report_json", nullptr},
                {"baseline_json", nullptr},
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

        const std::string artifact_directory =
            request.out_dir.empty() ? benchmark_results_dir() : request.out_dir;
        json compare_verdict = nullptr;
        std::string compare_artifact_path;
        if (!request.baseline_report_path.empty()) {
            std::ifstream baseline_stream(
                std::filesystem::u8path(request.baseline_report_path), std::ios::binary);
            if (!baseline_stream)
                throw std::runtime_error("baseline report is unavailable: " +
                    request.baseline_report_path);
            json baseline_report;
            try {
                baseline_stream >> baseline_report;
            } catch (const json::exception& exception) {
                throw std::runtime_error(std::string(
                    "baseline report JSON is invalid: ") + exception.what());
            }
            compare_verdict = compare_scorecards(baseline_report, scorecard);
            compare_verdict["baseline"] = request.baseline_report_path;
            compare_verdict["candidate"] = "current_run";
            const auto compare_overall = compare_verdict.value("overall", std::string());
            if (compare_overall == "FAIL" && !request.sla_relaxed) {
                verdict = "FAIL";
                scorecard["verdict"] = verdict;
            }
            compare_artifact_path = (std::filesystem::u8path(artifact_directory) /
                ("compare_" + std::string(mode) + "_" + utc_stamp_filename() + ".json"))
                    .u8string();
            scorecard["artifacts"]["compare_verdict_json"] = compare_artifact_path;
            diag::log_tagged_fmt("benchmark", "compare overall=%s baseline=%s",
                compare_overall.c_str(), request.baseline_report_path.c_str());
            for (const auto& entry : compare_verdict["verdicts"]) {
                diag::log_tagged_fmt("benchmark",
                    "compare key=%s baseline=%s candidate=%s delta_pct=%s verdict=%s",
                    entry.value("key", std::string()).c_str(),
                    json_value_text(entry["baseline"]).c_str(),
                    json_value_text(entry["candidate"]).c_str(),
                    json_value_text(entry["delta_pct"]).c_str(),
                    entry.value("verdict", std::string()).c_str());
            }
        }

        std::string baseline_record_path;
        if (!request.record_baseline_name.empty()) {
            const auto& name = request.record_baseline_name;
            const bool valid_name = !name.empty() && name.size() <= 64 &&
                name.find("..") == std::string::npos &&
                std::all_of(name.begin(), name.end(), [](char ch) {
                    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
                });
            if (!valid_name)
                throw std::runtime_error(
                    "record_baseline_name must be 1..64 chars of [A-Za-z0-9._-] without '..'");
            const auto baseline_dir = std::filesystem::u8path(artifact_directory) / "baselines";
            std::error_code baseline_dir_error;
            std::filesystem::create_directories(baseline_dir, baseline_dir_error);
            if (baseline_dir_error)
                throw std::runtime_error("baseline directory creation failed: " +
                    baseline_dir_error.message());
            baseline_record_path = (baseline_dir / (name + ".json")).u8string();
            scorecard["artifacts"]["baseline_json"] = baseline_record_path;
        }

        const std::string report_path = write_benchmark_artifacts(
            request.out_dir, mode, scorecard);
        if (!compare_verdict.is_null()) {
            write_json_file(std::filesystem::u8path(compare_artifact_path),
                compare_verdict.dump(2));
        }
        if (!baseline_record_path.empty()) {
            const std::string temporary = baseline_record_path + ".tmp";
            write_json_file(std::filesystem::u8path(temporary), scorecard.dump(2));
            if (!MoveFileExW(std::filesystem::u8path(temporary).wstring().c_str(),
                std::filesystem::u8path(baseline_record_path).wstring().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw std::runtime_error("baseline artifact replace failed: " +
                    std::to_string(GetLastError()));
        }
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
