#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

#include "byte_provider.hpp"

#include "../mapped_window_cache.hpp"
#include "../provider_snapshot.hpp"
#include "../../infra/taskflow_runtime.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <utility>

#pragma comment(lib, "bcrypt.lib")

namespace aida::analysis {
namespace {

static_assert(sizeof(sha256_digest_t) == 32);

struct algorithm_closer_t {
    void operator()(void* value) const noexcept {
        if (value)
            BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(value), 0);
    }
};

struct hash_closer_t {
    void operator()(void* value) const noexcept {
        if (value)
            BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(value));
    }
};

using algorithm_handle_t = std::unique_ptr<void, algorithm_closer_t>;
using hash_handle_t = std::unique_ptr<void, hash_closer_t>;

workspace_error_t crypto_error(const char* operation, NTSTATUS status) {
    auto error = make_workspace_error(workspace_error_code_t::hash_failure,
                                      std::string(operation) + " failed", "provider_hash");
    error.provider_status = static_cast<std::int64_t>(status);
    return error;
}

class sha256_accumulator_t final {
public:
    static workspace_result_t<sha256_accumulator_t> create() {
        BCRYPT_ALG_HANDLE raw_algorithm = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&raw_algorithm, BCRYPT_SHA256_ALGORITHM,
                                                      nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
            return workspace_result_t<sha256_accumulator_t>::failure(
                crypto_error("BCryptOpenAlgorithmProvider", status));
        algorithm_handle_t algorithm(raw_algorithm);
        DWORD object_size = 0;
        DWORD result_size = 0;
        status = BCryptGetProperty(raw_algorithm, BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                                   &result_size, 0);
        if (!BCRYPT_SUCCESS(status))
            return workspace_result_t<sha256_accumulator_t>::failure(
                crypto_error("BCryptGetProperty", status));
        if (result_size != sizeof(object_size) || object_size == 0 ||
            object_size > 1024U * 1024U)
            return workspace_result_t<sha256_accumulator_t>::failure(
                make_workspace_error(workspace_error_code_t::hash_failure,
                                     "BCrypt returned an invalid SHA-256 object size",
                                     "provider_hash"));
        std::vector<std::uint8_t> object;
        try {
            object.resize(object_size);
        } catch (const std::bad_alloc&) {
            return workspace_result_t<sha256_accumulator_t>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                                     "provider hash allocation failed", "provider_hash"));
        }
        BCRYPT_HASH_HANDLE raw_hash = nullptr;
        status = BCryptCreateHash(raw_algorithm, &raw_hash, object.data(), object_size,
                                  nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status))
            return workspace_result_t<sha256_accumulator_t>::failure(
                crypto_error("BCryptCreateHash", status));
        return workspace_result_t<sha256_accumulator_t>::success(
            sha256_accumulator_t(std::move(algorithm), hash_handle_t(raw_hash),
                                 std::move(object)));
    }

    sha256_accumulator_t(sha256_accumulator_t&&) noexcept = default;
    sha256_accumulator_t& operator=(sha256_accumulator_t&&) noexcept = default;
    sha256_accumulator_t(const sha256_accumulator_t&) = delete;
    sha256_accumulator_t& operator=(const sha256_accumulator_t&) = delete;

    workspace_result_t<void> update(const std::uint8_t* data, std::size_t size) {
        const std::uint8_t* cursor = data;
        while (size != 0) {
            const ULONG amount = static_cast<ULONG>((std::min)(
                size, static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));
            const NTSTATUS status = BCryptHashData(
                static_cast<BCRYPT_HASH_HANDLE>(hash_.get()),
                const_cast<PUCHAR>(cursor), amount, 0);
            if (!BCRYPT_SUCCESS(status))
                return workspace_result_t<void>::failure(
                    crypto_error("BCryptHashData", status));
            cursor += amount;
            size -= amount;
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<sha256_digest_t> finish() {
        sha256_digest_t digest;
        const NTSTATUS status = BCryptFinishHash(
            static_cast<BCRYPT_HASH_HANDLE>(hash_.get()), digest.bytes.data(),
            static_cast<ULONG>(digest.bytes.size()), 0);
        if (!BCRYPT_SUCCESS(status))
            return workspace_result_t<sha256_digest_t>::failure(
                crypto_error("BCryptFinishHash", status));
        hash_.reset();
        return workspace_result_t<sha256_digest_t>::success(std::move(digest));
    }

private:
    sha256_accumulator_t(algorithm_handle_t algorithm, hash_handle_t hash,
                         std::vector<std::uint8_t> object)
        : algorithm_(std::move(algorithm)), object_(std::move(object)),
          hash_(std::move(hash)) {}

    algorithm_handle_t algorithm_;
    std::vector<std::uint8_t> object_;
    hash_handle_t hash_;
};

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

constexpr std::size_t kContentHashMemoCapacity = 64;

struct content_hash_memo_entry_t {
    bool occupied = false;
    std::string normalized_source;
    std::uint64_t size = 0;
    std::uint64_t volume_serial = 0;
    std::array<std::uint8_t, 16> file_id{};
    std::uint64_t last_write_time_100ns = 0;
    sha256_digest_t digest{};
    std::uint64_t insert_ms = 0;
};

std::atomic<std::uint64_t>& memo_hit_count() noexcept {
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::atomic<std::uint64_t>& memo_miss_count() noexcept {
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::atomic<std::uint64_t>& memo_eviction_count() noexcept {
    static std::atomic<std::uint64_t> value{0};
    return value;
}

class content_hash_memo_t final {
public:
    std::optional<sha256_digest_t> lookup(const byte_provider_identity_t& identity) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& entry : entries_) {
            if (entry.occupied && matches(entry, identity))
                return entry.digest;
        }
        return std::nullopt;
    }

    void insert(const byte_provider_identity_t& identity, const sha256_digest_t& digest) {
        const std::uint64_t now_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t free_slot = entries_.size();
        std::size_t oldest_slot = entries_.size();
        std::uint64_t oldest_ms = (std::numeric_limits<std::uint64_t>::max)();
        std::size_t occupied = 0;
        for (std::size_t index = 0; index < entries_.size(); ++index) {
            const auto& entry = entries_[index];
            if (!entry.occupied) {
                if (free_slot == entries_.size())
                    free_slot = index;
                continue;
            }
            ++occupied;
            if (matches(entry, identity)) {
                auto& target = entries_[index];
                target.digest = digest;
                target.insert_ms = now_ms;
                return;
            }
            if (entry.insert_ms < oldest_ms) {
                oldest_ms = entry.insert_ms;
                oldest_slot = index;
            }
        }
        std::size_t target_index = free_slot;
        if (target_index == entries_.size()) {
            target_index = oldest_slot;
            const auto evictions =
                memo_eviction_count().fetch_add(1, std::memory_order_relaxed) + 1;
            ::diag::log_tagged_fmt("byte_provider",
                "content_hash_memo evict evicted_source='%s' new_source='%s' evictions=%llu entries=%zu",
                entries_[target_index].normalized_source.c_str(),
                identity.normalized_source.c_str(),
                static_cast<unsigned long long>(evictions), occupied);
        }
        auto& target = entries_[target_index];
        target.occupied = true;
        target.normalized_source = identity.normalized_source;
        target.size = identity.size;
        target.volume_serial = identity.volume_serial;
        target.file_id = identity.file_id;
        target.last_write_time_100ns = identity.last_write_time_100ns;
        target.digest = digest;
        target.insert_ms = now_ms;
    }

    std::size_t size() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t occupied = 0;
        for (const auto& entry : entries_)
            if (entry.occupied)
                ++occupied;
        return occupied;
    }

private:
    static bool matches(const content_hash_memo_entry_t& entry,
                        const byte_provider_identity_t& identity) noexcept {
        return entry.normalized_source == identity.normalized_source &&
               entry.size == identity.size &&
               entry.volume_serial == identity.volume_serial &&
               entry.file_id == identity.file_id &&
               entry.last_write_time_100ns == identity.last_write_time_100ns;
    }

    std::mutex mutex_;
    std::array<content_hash_memo_entry_t, kContentHashMemoCapacity> entries_{};
};

content_hash_memo_t& content_hash_memo() {
    static content_hash_memo_t memo;
    return memo;
}

}

struct mapped_file_provider_t::state_t {
    std::shared_ptr<provider_snapshot_t> snapshot;
    std::shared_ptr<mapped_window_cache_t> window_cache;
    byte_provider_identity_t identity;
    mapped_file_provider_options_t options;
    bool pin_active = false;
    std::mutex pin_mutex;
    std::vector<std::uint64_t> pin_tokens;
    std::shared_future<workspace_result_t<sha256_digest_t>> deferred_hash;
    std::shared_ptr<const sha256_digest_t> ready_digest;
    mutable std::mutex hash_mutex;
};

std::vector<provider_pin_range_t> compute_admission_pin_ranges(
    const workspace_image_t& image) {
    std::vector<provider_pin_range_t> ranges;
    if (image.header_size != 0 && image.header_size <= image.provider_size) {
        provider_pin_range_t header;
        header.file_offset = 0;
        header.size = image.header_size;
        header.max_windows = 2;
        ranges.push_back(header);
    }
    for (const auto& section : image.sections) {
        if ((section.permissions & image_permission_execute) == 0 ||
            section.file_size == 0 || section.file_offset >= image.provider_size)
            continue;
        provider_pin_range_t text;
        text.file_offset = section.file_offset;
        text.size = (std::min)(section.file_size,
                               image.provider_size - section.file_offset);
        text.max_windows = 2;
        ranges.push_back(text);
        break;
    }
    return ranges;
}

workspace_result_t<void> byte_provider_t::read_exact(
    std::uint64_t offset, void* destination, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    if (size_value != 0 && !destination)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "read destination is null", "byte_provider_read"));
    if (size_value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "read size exceeds the process address space",
                                          "byte_provider_read");
        error.size = size_value;
        return workspace_result_t<void>::failure(std::move(error));
    }
    auto range_result = validate_span(offset, size_value, size(), "byte_provider_read");
    if (!range_result)
        return workspace_result_t<void>::failure(range_result.error());
    auto* output = static_cast<std::uint8_t*>(destination);
    std::uint64_t chunk_size = 4ULL * 1024ULL * 1024ULL;
    if (const auto* mapped = dynamic_cast<const mapped_file_provider_t*>(this))
        chunk_size = mapped->state_->options.read_chunk_size;
    std::uint64_t completed = 0;
    while (completed < size_value) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(stop_error(cancel, "byte_provider_read"));
        const std::uint64_t contiguous = maximum_contiguous_lease(offset + completed);
        if (contiguous == 0) {
            auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                              "provider returned no contiguous lease capacity",
                                              "byte_provider_read");
            error.offset = offset + completed;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const std::uint64_t amount = std::min<std::uint64_t>(
            std::min<std::uint64_t>(size_value - completed, chunk_size), contiguous);
        auto lease_result = lease(offset + completed, amount, cancel);
        if (!lease_result)
            return workspace_result_t<void>::failure(lease_result.error());
        lease_result.value().for_each_segment(
            [&](const std::uint8_t* bytes, std::size_t segment_size,
                std::size_t stream_offset) {
                if (segment_size != 0) {
                    std::memcpy(output + static_cast<std::size_t>(completed) + stream_offset,
                                bytes, segment_size);
                }
            });
        completed += amount;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::size_t> byte_provider_t::read_some(
    std::uint64_t offset, void* destination, std::size_t capacity,
    const cancellation_token_t& cancel) const {
    if (capacity != 0 && !destination)
        return workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "read destination is null", "byte_provider_read"));
    if (offset > size()) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "read offset exceeds provider size", "byte_provider_read");
        error.offset = offset;
        return workspace_result_t<std::size_t>::failure(std::move(error));
    }
    const std::uint64_t amount = std::min<std::uint64_t>(capacity, size() - offset);
    auto result = read_exact(offset, destination, amount, cancel);
    if (!result)
        return workspace_result_t<std::size_t>::failure(result.error());
    return workspace_result_t<std::size_t>::success(static_cast<std::size_t>(amount));
}

workspace_result_t<std::vector<std::uint8_t>> byte_provider_t::read_vector(
    std::uint64_t offset, std::uint64_t size_value, std::uint64_t hard_limit,
    const cancellation_token_t& cancel) const {
    constexpr std::uint64_t absolute_limit = 64ULL * 1024ULL * 1024ULL;
    const std::uint64_t effective_limit = std::min(hard_limit, absolute_limit);
    if (size_value > effective_limit) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "requested byte vector exceeds its hard limit",
                                          "byte_provider_read");
        error.size = size_value;
        error.details.emplace_back("hard_limit", std::to_string(effective_limit));
        return workspace_result_t<std::vector<std::uint8_t>>::failure(std::move(error));
    }
    std::size_t allocation = 0;
    if (!u64_to_size(size_value, allocation)) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "requested byte vector exceeds addressable memory",
                                          "byte_provider_read");
        error.size = size_value;
        return workspace_result_t<std::vector<std::uint8_t>>::failure(std::move(error));
    }
    std::vector<std::uint8_t> bytes(allocation);
    auto result = read_exact(offset, bytes.data(), size_value, cancel);
    if (!result)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(result.error());
    return workspace_result_t<std::vector<std::uint8_t>>::success(std::move(bytes));
}

workspace_result_t<sha256_digest_t> byte_provider_t::compute_content_sha256(
    const cancellation_token_t& cancel, std::uint64_t chunk_limit) const {
    if (chunk_limit == 0 || chunk_limit > 64ULL * 1024ULL * 1024ULL)
        return workspace_result_t<sha256_digest_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "provider hash chunk limit is invalid", "provider_hash"));
    if (cancel.stop_requested())
        return workspace_result_t<sha256_digest_t>::failure(
            stop_error(cancel, "provider_hash"));
    auto accumulator = sha256_accumulator_t::create();
    if (!accumulator)
        return workspace_result_t<sha256_digest_t>::failure(accumulator.error());
    auto builder = accumulator.take_value();
    std::uint64_t offset = 0;
    while (offset < size()) {
        if (cancel.stop_requested())
            return workspace_result_t<sha256_digest_t>::failure(
                stop_error(cancel, "provider_hash"));
        const std::uint64_t contiguous = maximum_contiguous_lease(offset);
        if (contiguous == 0)
            return workspace_result_t<sha256_digest_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "provider exposed no hashable contiguous bytes",
                                     "provider_hash"));
        const std::uint64_t amount = (std::min)(
            (std::min)(size() - offset, chunk_limit), contiguous);
        auto view = lease(offset, amount, cancel);
        if (!view)
            return workspace_result_t<sha256_digest_t>::failure(view.error());
        if (static_cast<std::uint64_t>(view.value().size()) != amount)
            return workspace_result_t<sha256_digest_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "provider returned an invalid hash lease",
                                     "provider_hash"));
        workspace_result_t<void> updated = workspace_result_t<void>::success();
        view.value().for_each_segment(
            [&](const std::uint8_t* bytes, std::size_t segment_size,
                std::size_t stream_offset) {
                static_cast<void>(stream_offset);
                if (!updated || segment_size == 0)
                    return;
                if (!bytes) {
                    updated = workspace_result_t<void>::failure(
                        make_workspace_error(workspace_error_code_t::integrity_failure,
                                             "provider returned an invalid hash lease segment",
                                             "provider_hash"));
                    return;
                }
                updated = builder.update(bytes, segment_size);
            });
        if (!updated)
            return workspace_result_t<sha256_digest_t>::failure(updated.error());
        offset += amount;
    }
    return builder.finish();
}

workspace_result_t<std::shared_ptr<mapped_file_provider_t>>
mapped_file_provider_t::open(const std::string& utf8_path,
                             mapped_file_provider_options_t options) {
    if (options.max_lease_size == 0 || options.read_chunk_size == 0 ||
        options.max_lease_size > 256ULL * 1024ULL * 1024ULL ||
        options.read_chunk_size > options.max_lease_size ||
        options.max_lease_size >
            static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "mapped-file provider limits are invalid", "byte_provider_open"));
    mapped_window_cache_options_t cache_options;
    cache_options.window_bytes = 0;
    cache_options.max_cached_window_bytes = 0;
    cache_options.max_lease_bytes = options.max_lease_size;
    cache_options.max_span_windows =
        static_cast<std::uint32_t>(byte_span_storage_t::kMaxSegments);
    cache_options.immutable_source = true;
    auto cached = mapped_window_cache_t::open(utf8_path, cache_options);
    if (!cached)
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            cached.error());
    std::shared_ptr<mapped_window_cache_t> cache = cached.take_value();
    byte_provider_identity_t identity = cache->identity();
    auto snapshot = provider_snapshot_t::capture(cache);
    if (!snapshot)
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            snapshot.error());
    bool pin_active = false;
    std::shared_ptr<const sha256_digest_t> ready_digest;
    std::shared_future<workspace_result_t<sha256_digest_t>> deferred_hash;
    if (options.pin_local_file_snapshot) {
        sha256_digest_t digest;
        auto memoized = content_hash_memo().lookup(identity);
        if (memoized) {
            const auto hits = memo_hit_count().fetch_add(1, std::memory_order_relaxed) + 1;
            ::diag::log_tagged_fmt("byte_provider",
                "content_hash_memo hit source='%s' size=%llu hits=%llu misses=%llu entries=%zu",
                identity.normalized_source.c_str(),
                static_cast<unsigned long long>(identity.size),
                static_cast<unsigned long long>(hits),
                static_cast<unsigned long long>(memo_miss_count().load(std::memory_order_relaxed)),
                content_hash_memo().size());
            digest = *memoized;
        }
        bool hash_resolved = memoized.has_value();
        if (!hash_resolved && options.defer_content_hash) {
            const auto misses = memo_miss_count().fetch_add(1, std::memory_order_relaxed) + 1;
            ::diag::log_tagged_fmt("byte_provider",
                "content_hash_deferred source='%s' size=%llu hits=%llu misses=%llu entries=%zu",
                identity.normalized_source.c_str(),
                static_cast<unsigned long long>(identity.size),
                static_cast<unsigned long long>(memo_hit_count().load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(misses),
                content_hash_memo().size());
            auto revalidated = cache->revalidate();
            if (!revalidated)
                return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
                    revalidated.error());
            identity.immutable_snapshot = true;
            pin_active = true;
            auto promise = std::make_shared<
                std::promise<workspace_result_t<sha256_digest_t>>>();
            deferred_hash = promise->get_future().share();
            const auto hash_identity = identity;
            const auto hash_snapshot = snapshot.value();
            const auto hash_started = std::chrono::steady_clock::now();
            aida::infra::taskflow_runtime::task_descriptor_t hash_task;
            hash_task.domain = aida::infra::taskflow_runtime::executor_domain_t::service;
            hash_task.owner_subsystem = "analysis_workspace";
            hash_task.label = "byte_provider.content_hash";
            hash_task.thread_class = "bounded_provider_hash";
            hash_task.priority = 2;
            hash_task.shutdown_policy = "drain";
            hash_task.body = [promise, hash_identity, hash_snapshot, hash_started]() mutable {
                auto computed = hash_snapshot->compute_content_sha256();
                const auto elapsed_us = static_cast<unsigned long long>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - hash_started).count());
                if (computed) {
                    content_hash_memo().insert(hash_identity,
                                               computed.value());
                    promise->set_value(
                        workspace_result_t<sha256_digest_t>::success(
                            computed.take_value()));
                } else {
                    promise->set_value(
                        workspace_result_t<sha256_digest_t>::failure(
                            computed.error()));
                }
                ::diag::log_tagged_fmt("byte_provider",
                    "content_hash_ready source='%s' us=%llu",
                    hash_identity.normalized_source.c_str(), elapsed_us);
            };
            const auto submitted = aida::infra::taskflow_runtime::submit(std::move(hash_task));
            if (!submitted.submitted) {
                return workspace_result_t<
                    std::shared_ptr<mapped_file_provider_t>>::failure(
                    make_workspace_error(workspace_error_code_t::provider_unavailable,
                                         "deferred content hash worker failed to start",
                                         "byte_provider_open"));
            }
        } else if (!hash_resolved) {
            const auto misses = memo_miss_count().fetch_add(1, std::memory_order_relaxed) + 1;
            ::diag::log_tagged_fmt("byte_provider",
                "content_hash_memo miss source='%s' size=%llu hits=%llu misses=%llu entries=%zu",
                identity.normalized_source.c_str(),
                static_cast<unsigned long long>(identity.size),
                static_cast<unsigned long long>(memo_hit_count().load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(misses),
                content_hash_memo().size());
            auto computed = snapshot.value()->compute_content_sha256();
            if (!computed)
                return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
                    computed.error());
            digest = computed.take_value();
            hash_resolved = true;
        }
        if (!pin_active) {
            auto revalidated = cache->revalidate();
            if (!revalidated)
                return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
                    revalidated.error());
            if (!memoized && hash_resolved)
                content_hash_memo().insert(identity, digest);
            identity.content_sha256 = digest;
            identity.immutable_snapshot = true;
            pin_active = true;
        }
        if (hash_resolved)
            ready_digest = std::make_shared<const sha256_digest_t>(digest);
    } else {
        identity.immutable_snapshot = false;
        identity.content_sha256 = snapshot.value()->identity().content_sha256;
    }
    try {
        auto state = std::make_shared<state_t>();
        state->snapshot = snapshot.take_value();
        state->window_cache = std::move(cache);
        state->identity = std::move(identity);
        state->options = options;
        state->pin_active = pin_active;
        state->deferred_hash = std::move(deferred_hash);
        state->ready_digest = std::move(ready_digest);
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::success(
            std::shared_ptr<mapped_file_provider_t>(new mapped_file_provider_t(std::move(state))));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "mapped-file provider allocation failed", "byte_provider_open"));
    }
}

mapped_file_provider_t::mapped_file_provider_t(std::shared_ptr<state_t> state)
    : state_(std::move(state)) {}

mapped_file_provider_t::~mapped_file_provider_t() {
    if (!state_ || !state_->window_cache)
        return;
    std::vector<std::uint64_t> tokens;
    {
        std::lock_guard<std::mutex> lock(state_->pin_mutex);
        tokens.swap(state_->pin_tokens);
    }
    for (const auto token : tokens)
        state_->window_cache->unpin_range(token);
}

const byte_provider_identity_t& mapped_file_provider_t::identity() const noexcept {
    return state_->identity;
}

bool mapped_file_provider_t::content_hash_ready() const noexcept {
    if (!state_)
        return false;
    if (state_->identity.content_sha256.has_value())
        return true;
    return std::atomic_load_explicit(&state_->ready_digest,
                                     std::memory_order_acquire) != nullptr;
}

workspace_result_t<sha256_digest_t> mapped_file_provider_t::await_content_hash(
    const cancellation_token_t& cancel) const {
    if (!state_) {
        return workspace_result_t<sha256_digest_t>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "mapped-file provider is not initialized",
                                 "byte_provider_hash"));
    }
    if (state_->identity.content_sha256)
        return workspace_result_t<sha256_digest_t>::success(
            *state_->identity.content_sha256);
    if (auto ready = std::atomic_load_explicit(&state_->ready_digest,
                                               std::memory_order_acquire))
        return workspace_result_t<sha256_digest_t>::success(*ready);
    auto future = state_->deferred_hash;
    if (!future.valid()) {
        return workspace_result_t<sha256_digest_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "mapped-file provider content hash is unavailable",
                                 "byte_provider_hash"));
    }
    for (;;) {
        if (cancel.stop_requested())
            return workspace_result_t<sha256_digest_t>::failure(
                stop_error(cancel, "byte_provider_hash"));
        if (future.wait_for(std::chrono::milliseconds(10)) ==
            std::future_status::ready)
            break;
    }
    auto computed = future.get();
    if (!computed)
        return workspace_result_t<sha256_digest_t>::failure(computed.error());
    auto digest = std::make_shared<const sha256_digest_t>(computed.take_value());
    {
        std::lock_guard<std::mutex> lock(state_->hash_mutex);
        if (!state_->identity.content_sha256)
            state_->identity.content_sha256 = *digest;
        std::atomic_store_explicit(&state_->ready_digest, digest,
                                   std::memory_order_release);
    }
    return workspace_result_t<sha256_digest_t>::success(*digest);
}

std::uint64_t mapped_file_provider_t::size() const noexcept {
    return state_->identity.size;
}

std::uint64_t mapped_file_provider_t::maximum_contiguous_lease(
    std::uint64_t offset) const noexcept {
    if (offset >= state_->identity.size)
        return 0;
    return (std::min)(state_->identity.size - offset, state_->options.max_lease_size);
}

bool mapped_file_provider_t::content_pin_active() const noexcept {
    return state_->pin_active;
}

std::optional<mapped_window_cache_statistics_t>
mapped_file_provider_t::window_cache_statistics() const noexcept {
    return state_->snapshot->source()->window_cache_statistics();
}

workspace_result_t<void> mapped_file_provider_t::revalidate() const {
    auto valid = state_->snapshot->validate_source();
    if (!valid)
        return valid;
    const auto& snapshot_hash = state_->snapshot->identity().content_sha256;
    if (snapshot_hash && snapshot_hash != state_->identity.content_sha256)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "mapped snapshot content identity diverged",
                                 "byte_provider_revalidate"));
    return valid;
}

workspace_result_t<byte_view_t> mapped_file_provider_t::lease(
    std::uint64_t offset, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    if (cancel.stop_requested())
        return workspace_result_t<byte_view_t>::failure(stop_error(cancel, "byte_provider_lease"));
    auto range_result = validate_span(offset, size_value, state_->identity.size,
                                      "byte_provider_lease");
    if (!range_result)
        return workspace_result_t<byte_view_t>::failure(range_result.error());
    if (size_value > state_->options.max_lease_size) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "mapped view exceeds configured lease limit",
                                          "byte_provider_lease");
        error.offset = offset;
        error.size = size_value;
        error.details.emplace_back("max_lease_size", std::to_string(state_->options.max_lease_size));
        return workspace_result_t<byte_view_t>::failure(std::move(error));
    }
    if (size_value == 0)
        return workspace_result_t<byte_view_t>::success(
            byte_view_t(std::static_pointer_cast<const void>(state_), nullptr, 0));
    return state_->snapshot->lease(offset, size_value, cancel);
}

workspace_result_t<void> mapped_file_provider_t::pin_ranges(
    const std::vector<provider_pin_range_t>& ranges) const {
    if (!state_->window_cache)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "mapped-file provider has no window cache to pin",
                                 "byte_provider_pin"));
    std::vector<std::uint64_t> tokens;
    for (const auto& range : ranges) {
        if (range.size == 0 || range.max_windows == 0 ||
            range.file_offset >= state_->identity.size ||
            range.size > state_->identity.size - range.file_offset)
            continue;
        auto token = state_->window_cache->pin_range(
            range.file_offset, range.size, range.max_windows, {});
        if (!token) {
            for (const auto held : tokens)
                state_->window_cache->unpin_range(held);
            return workspace_result_t<void>::failure(token.error());
        }
        tokens.push_back(token.value());
    }
    {
        std::lock_guard<std::mutex> lock(state_->pin_mutex);
        state_->pin_tokens.insert(state_->pin_tokens.end(), tokens.begin(), tokens.end());
    }
    const auto stats = state_->window_cache->statistics();
    ::diag::log_tagged_fmt("byte_provider",
        "section pins applied source='%s' ranges=%zu tokens=%zu pinned_windows=%llu cached_window_bytes=%llu",
        state_->identity.normalized_source.c_str(), ranges.size(), tokens.size(),
        static_cast<unsigned long long>(stats.pinned_windows),
        static_cast<unsigned long long>(stats.cached_window_bytes));
    return workspace_result_t<void>::success();
}

}
