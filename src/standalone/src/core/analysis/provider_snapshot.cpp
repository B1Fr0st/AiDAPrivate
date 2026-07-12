#include "provider_snapshot.hpp"

#include "mapped_window_cache.hpp"
#include "spill_provider.hpp"
#include "workspace/checked_range.hpp"
#include "workspace/live_snapshot_provider.hpp"

#include <algorithm>
#include <atomic>
#include <memory>
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
    if (!source)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "snapshot source is null", "provider_snapshot_capture"));
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
    auto digest = source->compute_content_sha256(cancel);
    if (!digest)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(digest.error());
    if (source_identity.content_sha256 &&
        *source_identity.content_sha256 != digest.value())
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "snapshot source content identity verification failed",
                                 "provider_snapshot_capture"));
    revalidated = revalidate_provider(source);
    if (!revalidated)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(revalidated.error());
    if (!same_identity(source_identity, source->identity()))
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            stale_error(source_identity, "provider_snapshot_capture"));
    auto identity = snapshot_identity(source_identity, generation);
    identity.content_sha256 = digest.take_value();
    try {
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::success(
            std::shared_ptr<provider_snapshot_t>(new provider_snapshot_t(
                std::move(source), source_identity, std::move(identity), generation)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "snapshot allocation failed", "provider_snapshot_capture"));
    }
}

workspace_result_t<std::shared_ptr<provider_snapshot_t>> provider_snapshot_t::materialize(
    std::shared_ptr<const byte_provider_t> source, provider_snapshot_options_t options,
    const cancellation_token_t& cancel) {
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
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(std::move(error));
    }
    const std::uint64_t generation = next_generation();
    spill_provider_options_t spill_options;
    spill_options.max_spill_bytes = options.max_materialized_bytes;
    spill_options.write_chunk_bytes = options.copy_chunk_bytes;
    auto sink = spill_sink_t::create("snapshot-" + std::to_string(generation), spill_options);
    if (!sink)
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(sink.error());
    std::vector<std::uint8_t> buffer;
    const std::uint64_t buffer_size = (std::min)(original_identity.size, options.copy_chunk_bytes);
    if (buffer_size != 0) {
        try {
            buffer.resize(static_cast<std::size_t>(buffer_size));
        } catch (const std::bad_alloc&) {
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                                     "snapshot copy buffer allocation failed",
                                     "provider_snapshot_materialize"));
        }
    }
    std::uint64_t completed = 0;
    while (completed < original_identity.size) {
        if (cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
                stop_error(cancel, "provider_snapshot_materialize"));
        auto current = revalidate_provider(source);
        if (!current)
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(current.error());
        if (!same_identity(original_identity, source->identity()))
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
                stale_error(original_identity, "provider_snapshot_materialize"));
        const std::uint64_t amount = (std::min)(original_identity.size - completed,
                                                options.copy_chunk_bytes);
        auto read = source->read_exact(completed, buffer.data(), amount, cancel);
        if (!read)
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(read.error());
        current = revalidate_provider(source);
        if (!current)
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(current.error());
        if (!same_identity(original_identity, source->identity()))
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(
                stale_error(original_identity, "provider_snapshot_materialize"));
        auto appended = sink.value()->append(buffer.data(), amount, cancel);
        if (!appended)
            return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::failure(appended.error());
        completed += amount;
    }
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
        return workspace_result_t<std::shared_ptr<provider_snapshot_t>>::success(
            std::shared_ptr<provider_snapshot_t>(new provider_snapshot_t(
                std::shared_ptr<const byte_provider_t>(spilled.take_value()), spilled_identity,
                std::move(identity), generation)));
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
