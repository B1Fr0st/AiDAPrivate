#include "provider_snapshot_harness.hpp"

#include "../../src/core/analysis/mapped_window_cache.hpp"
#include "../../src/core/analysis/provider_snapshot.hpp"
#include "../../src/core/analysis/spill_provider.hpp"
#include "../../src/core/analysis/subrange_provider.hpp"
#include "../../src/core/analysis/workspace/workspace_identity.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace aida::analysis::c03::test {
namespace {

void require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

template <typename value_t>
value_t require_value(workspace_result_t<value_t> result, const char* message) {
    if (!result)
        throw std::runtime_error(std::string(message) + ":" + result.error().stable_code());
    return result.take_value();
}

void require_success(workspace_result_t<void> result, const char* message) {
    if (!result)
        throw std::runtime_error(std::string(message) + ":" + result.error().stable_code());
}

template <typename result_t>
void require_error(const result_t& result, workspace_error_code_t code, const char* message) {
    require(!result && result.error().code == code, message);
}

void write_fixture(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output)
        throw std::runtime_error("provider fixture open failed");
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.flush();
    if (!output)
        throw std::runtime_error("provider fixture write failed");
}

mapped_window_cache_options_t cache_options() {
    mapped_window_cache_options_t options;
    options.window_bytes = 64ULL * 1024ULL;
    options.max_lease_bytes = 64ULL * 1024ULL;
    options.max_cached_window_bytes = 128ULL * 1024ULL;
    options.max_global_mapped_window_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    options.shard_count = 2;
    return options;
}

spill_provider_options_t spill_options() {
    spill_provider_options_t options;
    options.max_spill_bytes = 256ULL * 1024ULL;
    options.write_chunk_bytes = 32ULL * 1024ULL;
    options.mapped_window_cache = cache_options();
    return options;
}

provider_snapshot_options_t snapshot_options() {
    provider_snapshot_options_t options;
    options.max_materialized_bytes = 256ULL * 1024ULL;
    options.copy_chunk_bytes = 32ULL * 1024ULL;
    return options;
}

class stale_after_read_provider_t final : public byte_provider_t {
public:
    explicit stale_after_read_provider_t(std::shared_ptr<const byte_provider_t> parent)
        : parent_(std::move(parent)), identity_(parent_->identity()) {}

    const byte_provider_identity_t& identity() const noexcept override { return identity_; }
    std::uint64_t size() const noexcept override { return parent_->size(); }
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override {
        return parent_->maximum_contiguous_lease(offset);
    }

    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel = {}) const override {
        auto result = parent_->lease(offset, size, cancel);
        if (result && !changed_) {
            identity_.last_write_time_100ns ^= 1ULL;
            changed_ = true;
        }
        return result;
    }

private:
    std::shared_ptr<const byte_provider_t> parent_;
    mutable byte_provider_identity_t identity_;
    mutable bool changed_ = false;
};

class forged_digest_provider_t final : public byte_provider_t {
public:
    explicit forged_digest_provider_t(std::shared_ptr<const byte_provider_t> parent)
        : parent_(std::move(parent)), identity_(parent_->identity()) {
        if (!identity_.content_sha256)
            throw std::runtime_error("forged digest provider requires a content identity");
        identity_.content_sha256->bytes[0] = static_cast<std::uint8_t>(
            identity_.content_sha256->bytes[0] ^ 1U);
    }

    const byte_provider_identity_t& identity() const noexcept override { return identity_; }
    std::uint64_t size() const noexcept override { return parent_->size(); }
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override {
        return parent_->maximum_contiguous_lease(offset);
    }
    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel = {}) const override {
        return parent_->lease(offset, size, cancel);
    }

private:
    std::shared_ptr<const byte_provider_t> parent_;
    byte_provider_identity_t identity_;
};

class cancel_after_read_provider_t final : public byte_provider_t {
public:
    cancel_after_read_provider_t(std::shared_ptr<const byte_provider_t> parent,
                                 cancellation_source_t& cancellation)
        : parent_(std::move(parent)), cancellation_(cancellation) {}

    const byte_provider_identity_t& identity() const noexcept override {
        return parent_->identity();
    }
    std::uint64_t size() const noexcept override { return parent_->size(); }
    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override {
        return parent_->maximum_contiguous_lease(offset);
    }
    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel = {}) const override {
        auto result = parent_->lease(offset, size, cancel);
        if (result && !cancelled_) {
            cancelled_ = true;
            cancellation_.request_cancel();
        }
        return result;
    }

private:
    std::shared_ptr<const byte_provider_t> parent_;
    cancellation_source_t& cancellation_;
    mutable bool cancelled_ = false;
};

void verify_production_snapshot_provider(const std::filesystem::path& path,
                                         const std::vector<std::uint8_t>& bytes,
                                         const sha256_digest_t& expected_digest) {
    auto provider = require_value(mapped_file_provider_t::open(path.u8string()),
                                  "production provider open failed");
    require(!provider->identity().immutable_snapshot,
            "production static provider was misclassified as a live snapshot");
    auto computed_digest = require_value(provider->compute_content_sha256(),
                                         "production provider hashing failed");
    require(computed_digest == expected_digest, "production provider hash diverged");
    auto readback = require_value(provider->read_vector(0, provider->size(), provider->size()),
                                  "production provider readback failed");
    require(readback == bytes, "production provider readback diverged");
    require_success(provider->revalidate(), "production provider revalidation failed");
}

void verify_cache_and_subrange(const std::filesystem::path& path,
                               const std::vector<std::uint8_t>& bytes) {
    auto cache = require_value(mapped_window_cache_t::open(path.u8string(), cache_options()),
                               "mapped-window cache open failed");
    require(cache->identity().size == bytes.size(), "cache identity size diverged");
    const std::uint64_t boundary = 64ULL * 1024ULL;
    auto direct_crossing = cache->lease(boundary - 16, 32);
    require_error(direct_crossing, workspace_error_code_t::limit_exceeded,
                  "cross-window direct lease was accepted");
    std::vector<std::uint8_t> copied(64);
    require_success(cache->read_exact(boundary - 32, copied.data(), copied.size()),
                    "cross-window exact read failed");
    require(std::equal(copied.begin(), copied.end(), bytes.begin() + boundary - 32),
            "cross-window exact read corrupted bytes");

    auto parent_view = require_value(cache->lease(7, 32), "parent lease failed");
    auto subrange = require_value(subrange_provider_t::create(cache, 7, 32, "harness-subrange"),
                                  "subrange creation failed");
    auto child_view = require_value(subrange->lease(0, 32), "subrange lease failed");
    require(parent_view.data() == child_view.data(), "subrange lease copied parent bytes");
    require(std::equal(child_view.begin(), child_view.end(), bytes.begin() + 7),
            "subrange bytes diverged");

    auto pinned = require_value(cache->lease(0, 1), "pinned cache lease failed");
    require_success(cache->trim(), "cache trim with a pinned lease failed");
    require(cache->statistics().pinned_windows != 0, "cache trim evicted an active lease");
    pinned = byte_view_t{};
    parent_view = byte_view_t{};
    child_view = byte_view_t{};
    require_success(cache->trim(), "cache trim after releasing leases failed");

    require_value(cache->lease(bytes.size(), 0), "EOF zero-length lease failed");
    auto eof = cache->lease(bytes.size(), 1);
    require_error(eof, workspace_error_code_t::out_of_range, "EOF read was accepted");
    auto overflow = cache->lease((std::numeric_limits<std::uint64_t>::max)(), 1);
    require_error(overflow, workspace_error_code_t::range_overflow,
                  "overflowing lease was accepted");

    cancellation_source_t cancellation;
    cancellation.request_cancel();
    auto cancelled = cache->lease(0, 1, cancellation.token());
    require_error(cancelled, workspace_error_code_t::cancelled,
                  "cancelled lease was accepted");
}

void verify_pin_pressure(const std::filesystem::path& path) {
    auto options = cache_options();
    options.max_cached_window_bytes = options.window_bytes;
    auto cache = require_value(mapped_window_cache_t::open(path.u8string(), options),
                               "pin-pressure cache open failed");
    auto pinned = require_value(cache->lease(0, 1), "pin-pressure lease failed");
    auto blocked = cache->lease(options.window_bytes, 1);
    require_error(blocked, workspace_error_code_t::limit_exceeded,
                  "pin pressure exceeded the per-cache window budget");
    require(cache->statistics().pinned_windows == 1,
            "pin-pressure accounting lost the active lease");
    pinned = byte_view_t{};
    auto replacement = require_value(cache->lease(options.window_bytes, 1),
                                     "unpinned window replacement failed");
    require(cache->statistics().evictions != 0, "unpinned window was not evicted");
    replacement = byte_view_t{};
    require_success(cache->trim(), "pin-pressure cache trim failed");
}

void verify_concurrent_accounting(const std::filesystem::path& path) {
    auto options = cache_options();
    options.max_cached_window_bytes = options.window_bytes;
    options.max_global_mapped_window_bytes = options.window_bytes;
    std::array<std::shared_ptr<mapped_window_cache_t>, 2> caches{
        require_value(mapped_window_cache_t::open(path.u8string(), options),
                      "first concurrent cache open failed"),
        require_value(mapped_window_cache_t::open(path.u8string(), options),
                      "second concurrent cache open failed")};
    std::array<std::optional<byte_view_t>, 2> views;
    std::array<std::optional<workspace_error_code_t>, 2> errors;
    std::atomic<std::uint32_t> ready{0};
    std::atomic<bool> start{false};
    std::array<std::thread, 2> workers;
    std::size_t launched = 0;
    try {
        for (; launched < workers.size(); ++launched) {
            workers[launched] = std::thread([&, index = launched]() {
                ready.fetch_add(1, std::memory_order_release);
                while (!start.load(std::memory_order_acquire))
                    std::this_thread::yield();
                auto leased = caches[index]->lease(index * options.window_bytes, 1);
                if (leased)
                    views[index].emplace(leased.take_value());
                else
                    errors[index] = leased.error().code;
            });
        }
    } catch (...) {
        start.store(true, std::memory_order_release);
        for (std::size_t index = 0; index < launched; ++index)
            workers[index].join();
        throw;
    }
    while (ready.load(std::memory_order_acquire) != workers.size())
        std::this_thread::yield();
    start.store(true, std::memory_order_release);
    for (auto& worker : workers)
        worker.join();
    const std::size_t successes = static_cast<std::size_t>(views[0].has_value()) +
                                  static_cast<std::size_t>(views[1].has_value());
    require(successes == 1, "concurrent caches exceeded the global admission budget");
    for (std::size_t index = 0; index < errors.size(); ++index) {
        if (!views[index])
            require(errors[index] && *errors[index] == workspace_error_code_t::limit_exceeded,
                    "concurrent admission returned the wrong rejection");
    }
    const auto admitted = caches[0]->statistics();
    require(admitted.global_admitted_window_bytes <= options.max_global_mapped_window_bytes,
            "authoritative global admission accounting exceeded its limit");
    require(admitted.global_reserved_window_bytes == 0 &&
            admitted.global_mapped_window_bytes == admitted.global_admitted_window_bytes,
            "settled mapped-window accounting is incoherent");
    views[0].reset();
    views[1].reset();
    require_success(caches[0]->trim(), "first concurrent cache trim failed");
    require_success(caches[1]->trim(), "second concurrent cache trim failed");
    require(caches[0]->statistics().global_admitted_window_bytes == 0,
            "global admission bytes leaked after cache trim");
}

std::shared_ptr<spill_provider_t> make_spill(
    const std::vector<std::uint8_t>& bytes, const sha256_digest_t& expected_digest) {
    auto sink = require_value(spill_sink_t::create("harness-spill", spill_options()),
                              "spill sink creation failed");
    require_success(sink->append(bytes.data(), 65536), "spill first append failed");
    require_success(sink->append(bytes.data() + 65536,
                                 static_cast<std::uint64_t>(bytes.size() - 65536)),
                    "spill second append failed");
    auto provider = require_value(sink->finalize(), "spill finalization failed");
    require(provider->identity().immutable_snapshot, "finalized spill is mutable");
    require(provider->identity().content_sha256 &&
            *provider->identity().content_sha256 == expected_digest,
            "finalized spill content identity diverged");
    require(provider->size() == bytes.size(), "finalized spill size diverged");
    require_success(provider->verify_content(), "finalized spill hash verification failed");
    return provider;
}

void verify_spill_stream_and_snapshots(const std::filesystem::path& path,
                                       const std::vector<std::uint8_t>& bytes,
                                       const sha256_digest_t& expected_digest) {
    auto spill = make_spill(bytes, expected_digest);
    auto spill_bytes = require_value(spill->read_vector(0, spill->size(), spill->size()),
                                     "spill readback failed");
    require(spill_bytes == bytes, "spill readback diverged");
    auto partial = require_value(subrange_provider_t::create(spill, 7, 32, "hashed-partial"),
                                 "hashed partial subrange creation failed");
    require(!partial->identity().content_sha256,
            "partial subrange retained its parent content identity");
    auto complete = require_value(subrange_provider_t::create(spill, 0, spill->size(), "hashed-full"),
                                  "hashed full subrange creation failed");
    require(complete->identity().content_sha256 &&
            *complete->identity().content_sha256 == expected_digest,
            "full-byte subrange lost its content identity");

    std::size_t stream_offset = 0;
    auto stream = require_value(spill_provider_t::from_stream(
        "harness-stream",
        [&bytes, &stream_offset](std::uint8_t* destination, std::size_t capacity,
                                 const cancellation_token_t&) -> workspace_result_t<std::size_t> {
            const std::size_t remaining = bytes.size() - stream_offset;
            const std::size_t amount = (std::min)(remaining, capacity);
            if (amount != 0)
                std::copy_n(bytes.data() + stream_offset, amount, destination);
            stream_offset += amount;
            return workspace_result_t<std::size_t>::success(amount);
        }, spill_options()), "stream spill creation failed");
    require(stream->identity().content_sha256 &&
            *stream->identity().content_sha256 == expected_digest,
            "stream spill content identity diverged");
    auto stream_bytes = require_value(stream->read_vector(0, stream->size(), stream->size()),
                                      "stream spill readback failed");
    require(stream_bytes == bytes, "stream spill readback diverged");

    auto captured = require_value(provider_snapshot_t::capture(spill),
                                  "immutable snapshot capture failed");
    require(captured->identity().immutable_snapshot && captured->generation() != 0,
            "immutable snapshot identity is incomplete");
    require(captured->identity().content_sha256 &&
            *captured->identity().content_sha256 == expected_digest,
            "captured snapshot content identity diverged");
    require_success(captured->verify_content(), "captured snapshot verification failed");
    auto captured_bytes = require_value(captured->read_vector(0, captured->size(), captured->size()),
                                        "captured snapshot readback failed");
    require(captured_bytes == bytes, "captured snapshot bytes diverged");

    auto cache = require_value(mapped_window_cache_t::open(path.u8string(), cache_options()),
                               "cache open for materialized snapshot failed");
    auto materialized = require_value(provider_snapshot_t::materialize(cache, snapshot_options()),
                                      "mutable source materialization failed");
    require(materialized->identity().content_sha256 &&
            *materialized->identity().content_sha256 == expected_digest,
            "materialized snapshot content identity diverged");
    require_success(materialized->verify_content(), "materialized snapshot verification failed");
    auto materialized_bytes = require_value(
        materialized->read_vector(0, materialized->size(), materialized->size()),
        "materialized snapshot readback failed");
    require(materialized_bytes == bytes, "materialized snapshot bytes diverged");
}

void verify_spill_adverse_paths(const std::vector<std::uint8_t>& bytes) {
    auto quota_options = spill_options();
    quota_options.max_spill_bytes = 1024;
    quota_options.write_chunk_bytes = 512;
    auto quota_sink = require_value(spill_sink_t::create("quota", quota_options),
                                    "quota spill sink creation failed");
    auto quota = quota_sink->append(bytes.data(), 1025);
    require_error(quota, workspace_error_code_t::limit_exceeded,
                  "spill quota overrun was accepted");
    require(quota_sink->appended_bytes() == 0, "spill quota rejection wrote partial bytes");

    auto over_reported = spill_provider_t::from_stream(
        "over-report",
        [](std::uint8_t*, std::size_t capacity,
           const cancellation_token_t&) -> workspace_result_t<std::size_t> {
            return workspace_result_t<std::size_t>::success(capacity + 1);
        }, quota_options);
    require_error(over_reported, workspace_error_code_t::integrity_failure,
                  "stream over-reporting was accepted");

    auto cancelled_sink = require_value(spill_sink_t::create("cancelled", quota_options),
                                        "cancelled spill sink creation failed");
    require_success(cancelled_sink->append(bytes.data(), 1024),
                    "cancelled spill setup append failed");
    cancellation_source_t cancellation;
    cancellation.request_cancel();
    auto cancelled_finalize = cancelled_sink->finalize(cancellation.token());
    require_error(cancelled_finalize, workspace_error_code_t::cancelled,
                  "cancelled spill finalization succeeded");
    auto recovered = require_value(cancelled_sink->finalize(),
                                   "spill sink did not recover from pre-finalize cancellation");
    require_success(recovered->verify_content(), "recovered spill verification failed");

    auto append_sink = require_value(spill_sink_t::create("append-cancel", quota_options),
                                     "append-cancel spill sink creation failed");
    auto cancelled_append = append_sink->append(bytes.data(), 1, cancellation.token());
    require_error(cancelled_append, workspace_error_code_t::cancelled,
                  "cancelled spill append succeeded");
    require(append_sink->appended_bytes() == 0, "cancelled spill append wrote bytes");

    cancellation_source_t stream_cancellation;
    auto cancelled_stream = spill_provider_t::from_stream(
        "stream-cancel",
        [&stream_cancellation, &bytes](std::uint8_t* destination, std::size_t,
                                       const cancellation_token_t&)
            -> workspace_result_t<std::size_t> {
            destination[0] = bytes[0];
            stream_cancellation.request_cancel();
            return workspace_result_t<std::size_t>::success(1);
        }, quota_options, stream_cancellation.token());
    require_error(cancelled_stream, workspace_error_code_t::cancelled,
                  "in-flight spill stream cancellation succeeded");
}

void verify_snapshot_adverse_paths(const std::filesystem::path& path,
                                   const std::vector<std::uint8_t>& bytes,
                                   const sha256_digest_t& expected_digest) {
    auto cache = require_value(mapped_window_cache_t::open(path.u8string(), cache_options()),
                               "snapshot adverse cache open failed");
    cancellation_source_t cancellation;
    cancellation.request_cancel();
    auto cancelled_materialize = provider_snapshot_t::materialize(
        cache, snapshot_options(), cancellation.token());
    require_error(cancelled_materialize, workspace_error_code_t::cancelled,
                  "cancelled snapshot materialization succeeded");
    cancellation_source_t in_flight_cancellation;
    auto cancelling_source = std::make_shared<cancel_after_read_provider_t>(
        cache, in_flight_cancellation);
    auto in_flight_materialize = provider_snapshot_t::materialize(
        cancelling_source, snapshot_options(), in_flight_cancellation.token());
    require_error(in_flight_materialize, workspace_error_code_t::cancelled,
                  "in-flight snapshot materialization cancellation succeeded");

    auto spill = make_spill(bytes, expected_digest);
    auto cancelled_capture = provider_snapshot_t::capture(spill, 0, cancellation.token());
    require_error(cancelled_capture, workspace_error_code_t::cancelled,
                  "cancelled immutable snapshot capture succeeded");
    auto forged = std::make_shared<forged_digest_provider_t>(spill);
    auto forged_capture = provider_snapshot_t::capture(forged);
    require_error(forged_capture, workspace_error_code_t::integrity_failure,
                  "forged snapshot content identity was accepted");
    auto forged_materialization = provider_snapshot_t::materialize(forged,
                                                                    snapshot_options());
    require_error(forged_materialization, workspace_error_code_t::integrity_failure,
                  "forged materialization content identity was accepted");

    auto stale_source = std::make_shared<stale_after_read_provider_t>(cache);
    auto stale_materialization = provider_snapshot_t::materialize(stale_source,
                                                                  snapshot_options());
    require_error(stale_materialization, workspace_error_code_t::file_changed,
                  "stale source materialization succeeded");
}

void verify_stale_source(const std::filesystem::path& path,
                         const std::vector<std::uint8_t>& bytes) {
    auto cache = require_value(mapped_window_cache_t::open(path.u8string(), cache_options()),
                               "cache open for stale-source validation failed");
    std::vector<std::uint8_t> changed(bytes.begin(), bytes.end() - 1);
    write_fixture(path, changed);
    auto stale = cache->lease(0, 1);
    require_error(stale, workspace_error_code_t::file_changed,
                  "stale source was accepted");
}

}

void run_provider_snapshot_harness(const std::filesystem::path& root) {
    std::filesystem::create_directories(root);
    const auto path = root / "provider_snapshot_fixture.bin";
    std::vector<std::uint8_t> bytes(2ULL * 64ULL * 1024ULL + 257ULL);
    for (std::size_t index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<std::uint8_t>((index * 37U + 19U) & 0xffU);
    const auto expected_digest = require_value(sha256_bytes(bytes.data(), bytes.size()),
                                               "fixture hashing failed");
    try {
        write_fixture(path, bytes);
        verify_production_snapshot_provider(path, bytes, expected_digest);
        verify_cache_and_subrange(path, bytes);
        verify_pin_pressure(path);
        verify_concurrent_accounting(path);
        verify_spill_stream_and_snapshots(path, bytes, expected_digest);
        verify_spill_adverse_paths(bytes);
        verify_snapshot_adverse_paths(path, bytes, expected_digest);
        verify_stale_source(path, bytes);
        std::filesystem::remove(path);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        throw;
    }
}

}
