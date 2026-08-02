#include "provider_snapshot.hpp"

#include "mapped_window_cache.hpp"
#include "spill_provider.hpp"
#include "workspace/checked_range.hpp"
#include "workspace/live_snapshot_provider.hpp"
#include "../infra/taskflow_runtime.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kMaximumMaterializedBytes = 1024ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaximumCopyChunkBytes = 64ULL * 1024ULL * 1024ULL;

bool same_identity(const byte_provider_identity_t& lhs,
                   const byte_provider_identity_t& rhs) noexcept {
    return lhs.normalized_source == rhs.normalized_source && lhs.size == rhs.size &&
           lhs.volume_serial == rhs.volume_serial && lhs.file_id == rhs.file_id &&
           lhs.last_write_time_100ns == rhs.last_write_time_100ns &&
           lhs.immutable_snapshot == rhs.immutable_snapshot &&
           lhs.content_sha256 == rhs.content_sha256 && lhs.member == rhs.member;
}

workspace_error_t stale_error(const byte_provider_identity_t& identity, const char* phase) {
    auto error = make_workspace_error(workspace_error_code_t::file_changed,
                                      "provider source changed after snapshot capture", phase);
    error.details.emplace_back("source", identity.normalized_source);
    return error;
}

workspace_error_t stop_error(const cancellation_token_t& cancel, const char* phase) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                                          "operation deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                      "operation cancelled", phase);
    error.cancellation = true;
    return error;
}

std::uint64_t next_generation() noexcept {
    static std::atomic<std::uint64_t> value{1};
    for (;;) {
        const std::uint64_t generation = value.fetch_add(1, std::memory_order_relaxed);
        if (generation != 0)
            return generation;
    }
}

workspace_result_t<void> revalidate_provider(const std::shared_ptr<const byte_provider_t>& source) {
    if (const auto mapped = std::dynamic_pointer_cast<const mapped_file_provider_t>(source))
        return mapped->revalidate();
    if (const auto cached = std::dynamic_pointer_cast<const mapped_window_cache_t>(source))
        return cached->revalidate();
    if (const auto spill = std::dynamic_pointer_cast<const spill_provider_t>(source))
        return spill->revalidate();
    if (const auto live = std::dynamic_pointer_cast<const live_snapshot_provider_t>(source))
        return live->validate_current_identity();
    return workspace_result_t<void>::success();
}

byte_provider_identity_t snapshot_identity(const byte_provider_identity_t& source,
                                           std::uint64_t generation) {
    byte_provider_identity_t result = source;
    result.normalized_source += "#snapshot:" + std::to_string(generation);
    result.immutable_snapshot = true;
    return result;
}

}

workspace_result_t<std::shared_ptr<provider_snapshot_t>> provider_snapshot_t::capture(
    std::shared_ptr<const byte_provider_t> source, std::uint64_t generation,
    const cancellation_token_t& cancel) {
    const auto started = std::chrono::steady_clock::now();
    if (!source)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "snapshot source is null", "provider_snapshot_capture"));
    if (const auto mapped =
            std::dynamic_pointer_cast<const mapped_file_provider_t>(source)) {
        if (mapped->content_pin_active() &&
            !source->identity().content_sha256) {
            auto awaited = mapped->await_content_hash(cancel);
            if (!awaited) {
                return workspace_result_t<
                    std::shared_ptr<provider_snapshot_t>>::failure(awaited.error());
            }
        }
    }
    const byte_provider_identity_t source_identity = source->identity();
    if (!source_identity.immutable_snapshot)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "snapshot source is not immutable", "provider_snapshot_capture"));
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            stop_error(cancel, "provider_snapshot_capture"));
    if (generation == 0)
        generation = next_generation();
    auto revalidated = revalidate_provider(source);
    if (!revalidated)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(revalidated.error());
    if (!same_identity(source_identity, source->identity()))
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            stale_error(source_identity, "provider_snapshot_capture"));
    auto identity = snapshot_identity(source_identity, generation);
    bool hash_recomputed = false;
    if (source_identity.content_sha256) {
        if (source->content_pin_active()) {
            identity.content_sha256 = *source_identity.content_sha256;
        } else {
            auto digest = source->compute_content_sha256(cancel);
            if (!digest)
                return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(digest.error());
            if (*source_identity.content_sha256 != digest.value())
                return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                                         "snapshot source content identity verification failed",
                                         "provider_snapshot_capture"));
            identity.content_sha256 = digest.take_value();
            hash_recomputed = true;
        }
        revalidated = revalidate_provider(source);
        if (!revalidated)
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(revalidated.error());
        if (!same_identity(source_identity, source->identity()))
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
                stale_error(source_identity, "provider_snapshot_capture"));
    }
    try {
        auto snapshot = std::shared_ptr<provider_snapshot_t>(new provider_snapshot_t(
            std::move(source), source_identity, identity, generation));
        snapshot->metrics_.elapsed_ns = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - started).count());
        snapshot->metrics_.bytes = identity.size;
        snapshot->metrics_.hash_recomputed = hash_recomputed;
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::success(
            std::move(snapshot));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "snapshot allocation failed", "provider_snapshot_capture"));
    }
}

workspace_result_t<std::shared_ptr<provider_snapshot_t>> provider_snapshot_t::materialize(
    std::shared_ptr<const byte_provider_t> source, provider_snapshot_options_t options,
    const cancellation_token_t& cancel) {
    const auto started = std::chrono::steady_clock::now();
    if (!source)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "snapshot source is null", "provider_snapshot_materialize"));
    if (options.max_materialized_bytes == 0 ||
        options.max_materialized_bytes > kMaximumMaterializedBytes ||
        options.copy_chunk_bytes == 0 || options.copy_chunk_bytes > kMaximumCopyChunkBytes ||
        options.copy_chunk_bytes > options.max_materialized_bytes) {
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "snapshot materialization options are invalid",
                                 "provider_snapshot_materialize"));
    }
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            stop_error(cancel, "provider_snapshot_materialize"));
    const byte_provider_identity_t original_identity = source->identity();
    if (source->size() != original_identity.size)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            stale_error(original_identity, "provider_snapshot_materialize"));
    if (original_identity.size > options.max_materialized_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "snapshot source exceeds materialization capacity",
                                          "provider_snapshot_materialize");
        error.size = original_identity.size;
        error.details.emplace_back("max_materialized_bytes",
                                   std::to_string(options.max_materialized_bytes));
        provider_metrics_relay::record_budget_rejection();
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(std::move(error));
    }
    const std::uint64_t generation = next_generation();
    spill_provider_options_t spill_options;
    spill_options.max_spill_bytes = options.max_materialized_bytes;
    spill_options.write_chunk_bytes = options.copy_chunk_bytes;
    auto sink = spill_sink_t::create("snapshot-" + std::to_string(generation), spill_options);
    if (!sink)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(sink.error());
    const std::uint64_t buffer_size = (std::min)(original_identity.size, options.copy_chunk_bytes);
    const std::uint64_t chunk_count = original_identity.size == 0
        ? 0
        : (original_identity.size + options.copy_chunk_bytes - 1) / options.copy_chunk_bytes;
    std::array<std::vector<std::uint8_t>, 2> buffers;
    if (buffer_size != 0) {
        try {
            buffers[0].resize(static_cast<std::size_t>(buffer_size));
            buffers[1].resize(static_cast<std::size_t>(buffer_size));
        } catch (const std::bad_alloc&) {
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                                     "snapshot copy buffer allocation failed",
                                     "provider_snapshot_materialize"));
        }
    }
    struct pipeline_state_t {
        std::mutex mutex;
        std::condition_variable buffer_ready;
        std::condition_variable buffer_free;
        std::uint64_t filled = 0;
        std::uint64_t drained = 0;
        std::optional<workspace_error_t> first_error;
    };
    pipeline_state_t pipeline;
    std::uint64_t hash_bytes = 0;
    std::uint64_t hash_ns = 0;
    infra::taskflow_runtime::job_handle_t reader_job;
    if (chunk_count != 0) {
        infra::taskflow_runtime::task_descriptor_t reader_desc;
        reader_desc.domain = infra::taskflow_runtime::executor_domain_t::feature_worker;
        reader_desc.owner_subsystem = "provider_snapshot";
        reader_desc.label = "provider_snapshot.materialize_reader";
        reader_desc.priority = 3;
        reader_desc.shutdown_policy = "cancel_pending";
        reader_desc.cancellable_body = [&](const infra::taskflow_runtime::cancellation_token_t&) {
                try {
                    for (std::uint64_t chunk = 0; chunk < chunk_count; ++chunk) {
                        {
                            std::unique_lock<std::mutex> lock(pipeline.mutex);
                            while (!pipeline.first_error &&
                                   pipeline.filled - pipeline.drained == 2)
                                pipeline.buffer_free.wait_for(lock,
                                    std::chrono::milliseconds(1));
                            if (pipeline.first_error)
                                break;
                        }
                        if (cancel.stop_requested()) {
                            std::lock_guard<std::mutex> lock(pipeline.mutex);
                            if (!pipeline.first_error)
                                pipeline.first_error =
                                    stop_error(cancel, "provider_snapshot_materialize");
                            break;
                        }
                        if (chunk % 16 == 0) {
                            auto current = revalidate_provider(source);
                            if (!current) {
                                std::lock_guard<std::mutex> lock(pipeline.mutex);
                                if (!pipeline.first_error)
                                    pipeline.first_error = current.error();
                                break;
                            }
                        }
                        if (!same_identity(original_identity, source->identity())) {
                            std::lock_guard<std::mutex> lock(pipeline.mutex);
                            if (!pipeline.first_error)
                                pipeline.first_error =
                                    stale_error(original_identity, "provider_snapshot_materialize");
                            break;
                        }
                        const std::uint64_t offset = chunk * options.copy_chunk_bytes;
                        const std::uint64_t amount = (std::min)(
                            original_identity.size - offset, options.copy_chunk_bytes);
                        const std::size_t slot = static_cast<std::size_t>(chunk & 1ULL);
                        auto read = source->read_exact(offset, buffers[slot].data(), amount,
                                                       cancel);
                        if (!read) {
                            std::lock_guard<std::mutex> lock(pipeline.mutex);
                            if (!pipeline.first_error)
                                pipeline.first_error = read.error();
                            break;
                        }
                        if (!same_identity(original_identity, source->identity())) {
                            std::lock_guard<std::mutex> lock(pipeline.mutex);
                            if (!pipeline.first_error)
                                pipeline.first_error =
                                    stale_error(original_identity, "provider_snapshot_materialize");
                            break;
                        }
                        {
                            std::lock_guard<std::mutex> lock(pipeline.mutex);
                            pipeline.filled = chunk + 1;
                        }
                        pipeline.buffer_ready.notify_one();
                    }
                } catch (...) {
                    std::lock_guard<std::mutex> lock(pipeline.mutex);
                    if (!pipeline.first_error)
                        pipeline.first_error = make_workspace_error(
                            workspace_error_code_t::io_failure,
                            "snapshot materialization reader failed",
                            "provider_snapshot_materialize");
                }
                pipeline.buffer_ready.notify_all();
            };
        reader_desc.cancel_hook = [&]() {
            {
                std::lock_guard<std::mutex> lock(pipeline.mutex);
                if (!pipeline.first_error)
                    pipeline.first_error = stop_error(cancel, "provider_snapshot_materialize");
            }
            pipeline.buffer_free.notify_all();
            pipeline.buffer_ready.notify_all();
        };
        auto reader_submission = infra::taskflow_runtime::submit(std::move(reader_desc));
        if (!reader_submission.submitted) {
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                                     "snapshot materialization worker creation failed",
                                     "provider_snapshot_materialize"));
        }
        reader_job = reader_submission.handle;
    }
    for (std::uint64_t chunk = 0; chunk < chunk_count; ++chunk) {
        {
            std::unique_lock<std::mutex> lock(pipeline.mutex);
            while (!pipeline.first_error && pipeline.filled <= chunk)
                pipeline.buffer_ready.wait_for(lock, std::chrono::milliseconds(1));
            if (pipeline.first_error)
                break;
        }
        if (cancel.stop_requested()) {
            std::lock_guard<std::mutex> lock(pipeline.mutex);
            if (!pipeline.first_error)
                pipeline.first_error = stop_error(cancel, "provider_snapshot_materialize");
            break;
        }
        const std::uint64_t offset = chunk * options.copy_chunk_bytes;
        const std::uint64_t amount = (std::min)(original_identity.size - offset,
                                                options.copy_chunk_bytes);
        const std::size_t slot = static_cast<std::size_t>(chunk & 1ULL);
        const auto append_started = std::chrono::steady_clock::now();
        auto appended = sink.value()->append(buffers[slot].data(), amount, cancel);
        hash_ns += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - append_started).count());
        if (!appended) {
            std::lock_guard<std::mutex> lock(pipeline.mutex);
            if (!pipeline.first_error)
                pipeline.first_error = appended.error();
            break;
        }
        hash_bytes += amount;
        {
            std::lock_guard<std::mutex> lock(pipeline.mutex);
            pipeline.drained = chunk + 1;
        }
        pipeline.buffer_free.notify_one();
    }
    pipeline.buffer_free.notify_all();
    pipeline.buffer_ready.notify_all();
    if (reader_job.valid())
        infra::taskflow_runtime::wait_for(reader_job, 0xFFFFFFFFu);
    if (pipeline.first_error)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            std::move(*pipeline.first_error));
    auto current = revalidate_provider(source);
    if (!current)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(current.error());
    if (!same_identity(original_identity, source->identity()))
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            stale_error(original_identity, "provider_snapshot_materialize"));
    auto spilled = sink.value()->finalize(cancel);
    if (!spilled)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(spilled.error());
    current = revalidate_provider(source);
    if (!current)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(current.error());
    if (!same_identity(original_identity, source->identity()))
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            stale_error(original_identity, "provider_snapshot_materialize"));
    const auto spilled_identity = spilled.value()->identity();
    if (!spilled_identity.content_sha256)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "materialized snapshot has no content identity",
                                 "provider_snapshot_materialize"));
    if (original_identity.content_sha256 &&
        *original_identity.content_sha256 != *spilled_identity.content_sha256)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "materialized snapshot content identity diverged from its source",
                                 "provider_snapshot_materialize"));
    auto identity = snapshot_identity(original_identity, generation);
    identity.content_sha256 = spilled_identity.content_sha256;
    try {
        auto snapshot = std::shared_ptr<provider_snapshot_t>(new provider_snapshot_t(
            std::shared_ptr<const byte_provider_t>(spilled.take_value()), spilled_identity,
            identity, generation));
        snapshot->metrics_.elapsed_ns = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - started).count());
        snapshot->metrics_.bytes = original_identity.size;
        snapshot->metrics_.hash_bytes = hash_bytes;
        snapshot->metrics_.hash_ns = hash_ns;
        snapshot->metrics_.materialized = true;
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::success(
            std::move(snapshot));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "snapshot allocation failed", "provider_snapshot_materialize"));
    }
}

provider_snapshot_t::provider_snapshot_t(std::shared_ptr<const byte_provider_t> source,
                                         byte_provider_identity_t source_identity,
                                         byte_provider_identity_t identity,
                                         std::uint64_t generation)
    : source_(std::move(source)),
      source_identity_(std::move(source_identity)),
      identity_(std::move(identity)),
      generation_(generation) {}

std::uint64_t provider_snapshot_t::maximum_contiguous_lease(std::uint64_t offset) const noexcept {
    return source_->maximum_contiguous_lease(offset);
}

bool provider_snapshot_t::content_pin_active() const noexcept {
    return source_->content_pin_active();
}

std::optional<mapped_window_cache_statistics_t>
provider_snapshot_t::window_cache_statistics() const noexcept {
    return source_->window_cache_statistics();
}

workspace_result_t<void> provider_snapshot_t::validate_source() const {
    if (!same_identity(source_identity_, source_->identity()))
        return workspace_result_t<void>::failure(
            stale_error(source_identity_, "provider_snapshot_validate"));
    auto revalidated = revalidate_provider(source_);
    if (!revalidated)
        return revalidated;
    if (!same_identity(source_identity_, source_->identity()))
        return workspace_result_t<void>::failure(
            stale_error(source_identity_, "provider_snapshot_validate"));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> provider_snapshot_t::verify_content(
    const cancellation_token_t& cancel) const {
    if (!identity_.content_sha256)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "snapshot has no content identity",
                                 "provider_snapshot_verify"));
    auto valid = validate_source();
    if (!valid)
        return valid;
    auto digest = compute_content_sha256(cancel);
    if (!digest)
        return workspace_result_t<void>::failure(digest.error());
    valid = validate_source();
    if (!valid)
        return valid;
    if (digest.value() != *identity_.content_sha256)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "snapshot content identity verification failed",
                                 "provider_snapshot_verify"));
    return workspace_result_t<void>::success();
}

workspace_result_t<byte_view_t> provider_snapshot_t::lease(
    std::uint64_t offset, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    if (cancel.stop_requested())
        return workspace_result_t<byte_view_t>::failure(
            stop_error(cancel, "provider_snapshot_lease"));
    auto range = validate_span(offset, size_value, identity_.size, "provider_snapshot_lease");
    if (!range)
        return workspace_result_t<byte_view_t>::failure(range.error());
    return source_->lease(offset, size_value, cancel);
}

}
