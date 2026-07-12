#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>

#include "byte_provider.hpp"

#include "../mapped_window_cache.hpp"
#include "../provider_snapshot.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
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

}

struct mapped_file_provider_t::state_t {
    std::shared_ptr<provider_snapshot_t> snapshot;
    byte_provider_identity_t identity;
    mapped_file_provider_options_t options;
};

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
        std::memcpy(output + static_cast<std::size_t>(completed), lease_result.value().data(),
                    lease_result.value().size());
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
        if (static_cast<std::uint64_t>(view.value().size()) != amount ||
            !view.value().data())
            return workspace_result_t<sha256_digest_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "provider returned an invalid hash lease",
                                     "provider_hash"));
        auto updated = builder.update(view.value().data(), view.value().size());
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
    cache_options.max_lease_bytes =
        (std::min)(cache_options.window_bytes, options.max_lease_size);
    cache_options.immutable_source = true;
    auto cached = mapped_window_cache_t::open(utf8_path, cache_options);
    if (!cached)
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            cached.error());
    byte_provider_identity_t identity = cached.value()->identity();
    auto snapshot = provider_snapshot_t::capture(cached.take_value());
    if (!snapshot)
        return workspace_result_t<std::shared_ptr<mapped_file_provider_t>>::failure(
            snapshot.error());
    identity.immutable_snapshot = false;
    identity.content_sha256 = snapshot.value()->identity().content_sha256;
    try {
        auto state = std::make_shared<state_t>();
        state->snapshot = snapshot.take_value();
        state->identity = std::move(identity);
        state->options = options;
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

mapped_file_provider_t::~mapped_file_provider_t() = default;

const byte_provider_identity_t& mapped_file_provider_t::identity() const noexcept {
    return state_->identity;
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

workspace_result_t<void> mapped_file_provider_t::revalidate() const {
    auto valid = state_->snapshot->validate_source();
    if (!valid)
        return valid;
    if (state_->snapshot->identity().content_sha256 != state_->identity.content_sha256)
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
    if (size_value <= state_->snapshot->maximum_contiguous_lease(offset))
        return state_->snapshot->lease(offset, size_value, cancel);
    std::shared_ptr<std::vector<std::uint8_t>> owner;
    try {
        owner = std::make_shared<std::vector<std::uint8_t>>(
            static_cast<std::size_t>(size_value));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<byte_view_t>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "mapped lease copy allocation failed", "byte_provider_lease"));
    }
    auto read = state_->snapshot->read_exact(offset, owner->data(), size_value, cancel);
    if (!read)
        return workspace_result_t<byte_view_t>::failure(read.error());
    const auto* bytes = owner->data();
    return workspace_result_t<byte_view_t>::success(
        byte_view_t(std::static_pointer_cast<const void>(std::move(owner)), bytes,
                    static_cast<std::size_t>(size_value)));
}

}
