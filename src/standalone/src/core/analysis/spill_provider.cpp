#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>

#include "spill_provider.hpp"

#include "workspace/workspace_identity.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace aida::analysis {
namespace {

constexpr std::uint64_t kMaximumSpillBytes = 1024ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaximumWriteChunkBytes = 64ULL * 1024ULL * 1024ULL;

struct handle_closer_t {
    void operator()(void* value) const noexcept {
        if (value && value != INVALID_HANDLE_VALUE)
            CloseHandle(static_cast<HANDLE>(value));
    }
};

using unique_handle_t = std::unique_ptr<void, handle_closer_t>;

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
                                      std::string(operation) + " failed", "spill_hash");
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
                                     "spill_hash"));
        std::vector<std::uint8_t> object;
        try {
            object.resize(object_size);
        } catch (const std::bad_alloc&) {
            return workspace_result_t<sha256_accumulator_t>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                                     "spill hash allocation failed", "spill_hash"));
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

workspace_result_t<std::string> wide_to_utf8(const std::wstring& value) {
    if (value.empty() || value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::io_failure,
                                 "spill path length is invalid", "spill_create"));
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                             static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "spill path conversion failed", "spill_create");
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                            static_cast<int>(value.size()), result.data(), required,
                            nullptr, nullptr) != required) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "spill path conversion failed", "spill_create");
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    return workspace_result_t<std::string>::success(std::move(result));
}

workspace_result_t<std::wstring> create_temporary_path() {
    std::vector<wchar_t> directory(32768, L'\0');
    const DWORD directory_length = GetTempPathW(static_cast<DWORD>(directory.size()), directory.data());
    if (directory_length == 0 || directory_length >= directory.size()) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "temporary directory lookup failed", "spill_create");
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    std::vector<wchar_t> path(32768, L'\0');
    if (GetTempFileNameW(directory.data(), L"aid", 0, path.data()) == 0) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "temporary spill path creation failed", "spill_create");
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    return workspace_result_t<std::wstring>::success(path.data());
}

bool valid_options(const spill_provider_options_t& options) noexcept {
    return options.max_spill_bytes != 0 && options.max_spill_bytes <= kMaximumSpillBytes &&
           options.write_chunk_bytes != 0 && options.write_chunk_bytes <= kMaximumWriteChunkBytes;
}

struct spill_storage_t {
    mutable std::mutex mutex;
    unique_handle_t writer;
    std::wstring path;
    std::string path_utf8;
    std::string source_label;
    spill_provider_options_t options;
    std::uint64_t appended = 0;
    bool finalizing = false;
    bool finalized = false;
    bool failed = false;
    std::optional<sha256_accumulator_t> content_hasher;
    std::shared_ptr<mapped_window_cache_t> cache;

    ~spill_storage_t() {
        cache.reset();
        writer.reset();
        if (!path.empty())
            DeleteFileW(path.c_str());
    }
};

void fail_storage(spill_storage_t& storage) noexcept {
    storage.failed = true;
    storage.finalizing = false;
    storage.cache.reset();
    storage.writer.reset();
    storage.content_hasher.reset();
}

}

struct spill_sink_t::state_t {
    std::shared_ptr<spill_storage_t> storage;
};

struct spill_provider_t::state_t {
    std::shared_ptr<spill_storage_t> storage;
};

workspace_result_t<std::shared_ptr<spill_sink_t>> spill_sink_t::create(
    std::string source_label, spill_provider_options_t options) {
    if (source_label.empty() || source_label.size() > 32768 ||
        source_label.find('\0') != std::string::npos || !valid_options(options)) {
        return workspace_result_t<std::shared_ptr<spill_sink_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "spill provider options are invalid", "spill_create"));
    }
    auto hasher = sha256_accumulator_t::create();
    if (!hasher)
        return workspace_result_t<std::shared_ptr<spill_sink_t>>::failure(hasher.error());
    auto path_result = create_temporary_path();
    if (!path_result)
        return workspace_result_t<std::shared_ptr<spill_sink_t>>::failure(path_result.error());
    HANDLE raw_file = CreateFileW(path_result.value().c_str(), GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, TRUNCATE_EXISTING,
                                  FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (raw_file == INVALID_HANDLE_VALUE) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "temporary spill file open failed", "spill_create");
        error.win32_status = GetLastError();
        DeleteFileW(path_result.value().c_str());
        return workspace_result_t<std::shared_ptr<spill_sink_t>>::failure(std::move(error));
    }
    auto path_utf8 = wide_to_utf8(path_result.value());
    if (!path_utf8) {
        CloseHandle(raw_file);
        DeleteFileW(path_result.value().c_str());
        return workspace_result_t<std::shared_ptr<spill_sink_t>>::failure(path_utf8.error());
    }
    try {
        auto storage = std::make_shared<spill_storage_t>();
        storage->writer.reset(raw_file);
        storage->path = path_result.take_value();
        storage->path_utf8 = path_utf8.take_value();
        storage->source_label = std::move(source_label);
        storage->options = options;
        storage->content_hasher.emplace(hasher.take_value());
        auto state = std::make_shared<state_t>();
        state->storage = std::move(storage);
        return workspace_result_t<std::shared_ptr<spill_sink_t>>::success(
            std::shared_ptr<spill_sink_t>(new spill_sink_t(std::move(state))));
    } catch (const std::bad_alloc&) {
        CloseHandle(raw_file);
        DeleteFileW(path_result.value().c_str());
        return workspace_result_t<std::shared_ptr<spill_sink_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "spill provider allocation failed", "spill_create"));
    }
}

spill_sink_t::spill_sink_t(std::shared_ptr<state_t> state)
    : state_(std::move(state)) {}

spill_sink_t::~spill_sink_t() = default;

workspace_result_t<void> spill_sink_t::append(
    const std::uint8_t* data, std::uint64_t size_value,
    const cancellation_token_t& cancel) {
    if (size_value != 0 && !data)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "spill append data is null", "spill_append"));
    if (size_value > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "spill append exceeds addressable memory", "spill_append");
        error.size = size_value;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(stop_error(cancel, "spill_append"));
    auto storage = state_->storage;
    std::lock_guard<std::mutex> lock(storage->mutex);
    if (storage->failed || storage->finalizing || storage->finalized ||
        !storage->writer || !storage->content_hasher)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::service_conflict,
                                 "spill sink is no longer writable", "spill_append"));
    if (size_value > storage->options.max_spill_bytes - storage->appended) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "spill capacity would be exceeded", "spill_append");
        error.size = size_value;
        error.details.emplace_back("appended_bytes", std::to_string(storage->appended));
        error.details.emplace_back("max_spill_bytes", std::to_string(storage->options.max_spill_bytes));
        return workspace_result_t<void>::failure(std::move(error));
    }
    std::uint64_t completed = 0;
    while (completed < size_value) {
        if (cancel.stop_requested()) {
            if (completed != 0)
                fail_storage(*storage);
            return workspace_result_t<void>::failure(stop_error(cancel, "spill_append"));
        }
        const std::uint64_t remaining = size_value - completed;
        const std::uint64_t portion = (std::min)(
            remaining, (std::min)(storage->options.write_chunk_bytes,
                                  static_cast<std::uint64_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        const BOOL write_result = WriteFile(
            static_cast<HANDLE>(storage->writer.get()),
            data + static_cast<std::size_t>(completed), static_cast<DWORD>(portion),
            &written, nullptr);
        if (!write_result || written == 0 || written > portion) {
            auto error = make_workspace_error(
                written > portion ? workspace_error_code_t::integrity_failure
                                  : workspace_error_code_t::io_failure,
                "spill write failed", "spill_append");
            error.size = portion;
            if (!write_result)
                error.win32_status = GetLastError();
            fail_storage(*storage);
            return workspace_result_t<void>::failure(std::move(error));
        }
        auto hashed = storage->content_hasher->update(
            data + static_cast<std::size_t>(completed), written);
        if (!hashed) {
            fail_storage(*storage);
            return hashed;
        }
        completed += written;
        storage->appended += written;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::shared_ptr<spill_provider_t>> spill_sink_t::finalize(
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
            stop_error(cancel, "spill_finalize"));
    auto storage = state_->storage;
    std::lock_guard<std::mutex> lock(storage->mutex);
    if (storage->failed || storage->finalizing || storage->finalized ||
        !storage->writer || !storage->content_hasher)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::service_conflict,
                                 "spill sink is already finalized", "spill_finalize"));
    storage->finalizing = true;
    if (cancel.stop_requested()) {
        storage->finalizing = false;
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
            stop_error(cancel, "spill_finalize"));
    }
    if (!FlushFileBuffers(static_cast<HANDLE>(storage->writer.get()))) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "spill flush failed", "spill_finalize");
        error.win32_status = GetLastError();
        fail_storage(*storage);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
    }
    if (cancel.stop_requested()) {
        storage->finalizing = false;
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
            stop_error(cancel, "spill_finalize"));
    }
    auto expected_digest = storage->content_hasher->finish();
    if (!expected_digest) {
        auto error = expected_digest.error();
        fail_storage(*storage);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
    }
    storage->content_hasher.reset();
    storage->writer.reset();
    if (cancel.stop_requested()) {
        fail_storage(*storage);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
            stop_error(cancel, "spill_finalize"));
    }
    auto cache_options = storage->options.mapped_window_cache;
    cache_options.immutable_source = true;
    auto cache = mapped_window_cache_t::open(storage->path_utf8, cache_options);
    if (!cache) {
        auto error = cache.error();
        fail_storage(*storage);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
    }
    if (cache.value()->size() != storage->appended) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "spill file size does not match streamed byte count",
                                          "spill_finalize");
        fail_storage(*storage);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
    }
    auto revalidated = cache.value()->revalidate();
    if (!revalidated) {
        auto error = revalidated.error();
        fail_storage(*storage);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
    }
    auto actual_digest = sha256_provider(*cache.value(), cancel,
                                         storage->options.write_chunk_bytes);
    if (!actual_digest) {
        auto error = actual_digest.error();
        fail_storage(*storage);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
    }
    revalidated = cache.value()->revalidate();
    if (!revalidated) {
        auto error = revalidated.error();
        fail_storage(*storage);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
    }
    if (actual_digest.value() != expected_digest.value()) {
        auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          "spill content identity verification failed",
                                          "spill_finalize");
        fail_storage(*storage);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
    }
    byte_provider_identity_t identity = cache.value()->identity();
    identity.normalized_source = "spill://" + storage->source_label;
    identity.size = storage->appended;
    identity.immutable_snapshot = true;
    identity.content_sha256 = actual_digest.take_value();
    identity.member.reset();
    try {
        auto provider_state = std::make_shared<spill_provider_t::state_t>();
        provider_state->storage = storage;
        auto provider = std::shared_ptr<spill_provider_t>(new spill_provider_t(
            std::move(provider_state), std::move(identity)));
        storage->cache = cache.take_value();
        storage->finalizing = false;
        storage->finalized = true;
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::success(
            std::move(provider));
    } catch (const std::bad_alloc&) {
        fail_storage(*storage);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "spill provider allocation failed", "spill_finalize"));
    }
}

std::uint64_t spill_sink_t::appended_bytes() const noexcept {
    const auto storage = state_->storage;
    std::lock_guard<std::mutex> lock(storage->mutex);
    return storage->appended;
}

std::uint64_t spill_sink_t::capacity_bytes() const noexcept {
    return state_->storage->options.max_spill_bytes;
}

spill_provider_t::spill_provider_t(std::shared_ptr<state_t> state, byte_provider_identity_t identity)
    : state_(std::move(state)), identity_(std::move(identity)) {}

workspace_result_t<std::shared_ptr<spill_provider_t>> spill_provider_t::from_stream(
    std::string source_label, spill_stream_reader_t reader, spill_provider_options_t options,
    const cancellation_token_t& cancel) {
    if (!reader)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "spill stream reader is empty", "spill_stream"));
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
            stop_error(cancel, "spill_stream"));
    auto sink = spill_sink_t::create(std::move(source_label), options);
    if (!sink)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(sink.error());
    const std::uint64_t buffer_bytes = (std::min)(options.write_chunk_bytes, options.max_spill_bytes);
    if (buffer_bytes == 0 || buffer_bytes > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "spill stream buffer is invalid", "spill_stream"));
    std::vector<std::uint8_t> buffer;
    try {
        buffer.resize(static_cast<std::size_t>(buffer_bytes));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "spill stream buffer allocation failed", "spill_stream"));
    }
    for (;;) {
        if (cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                stop_error(cancel, "spill_stream"));
        workspace_result_t<std::size_t> read = workspace_result_t<std::size_t>::failure(
            make_workspace_error(workspace_error_code_t::io_failure,
                                 "spill stream reader did not return", "spill_stream"));
        try {
            read = reader(buffer.data(), buffer.size(), cancel);
        } catch (...) {
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::io_failure,
                                     "spill stream reader failed", "spill_stream"));
        }
        if (!read)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(read.error());
        const std::size_t received = read.value();
        if (received > buffer.size())
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "spill stream reader exceeded its buffer", "spill_stream"));
        if (received == 0)
            break;
        auto appended = sink.value()->append(buffer.data(), received, cancel);
        if (!appended)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(appended.error());
    }
    return sink.value()->finalize(cancel);
}

std::uint64_t spill_provider_t::maximum_contiguous_lease(std::uint64_t offset) const noexcept {
    const auto storage = state_->storage;
    return storage->cache ? storage->cache->maximum_contiguous_lease(offset) : 0;
}

workspace_result_t<byte_view_t> spill_provider_t::lease(
    std::uint64_t offset, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    return state_->storage->cache->lease(offset, size_value, cancel);
}

workspace_result_t<void> spill_provider_t::revalidate() const {
    const auto storage = state_->storage;
    if (!storage->finalized || !storage->cache)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "spill provider is not finalized", "spill_revalidate"));
    if (!identity_.content_sha256)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "spill provider has no content identity", "spill_revalidate"));
    if (storage->cache->size() != identity_.size)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::file_changed,
                                 "spill provider size changed", "spill_revalidate"));
    return storage->cache->revalidate();
}

workspace_result_t<void> spill_provider_t::verify_content(
    const cancellation_token_t& cancel) const {
    auto valid = revalidate();
    if (!valid)
        return valid;
    const auto storage = state_->storage;
    auto digest = sha256_provider(*storage->cache, cancel,
                                  storage->options.write_chunk_bytes);
    if (!digest)
        return workspace_result_t<void>::failure(digest.error());
    valid = revalidate();
    if (!valid)
        return valid;
    if (digest.value() != *identity_.content_sha256)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "spill content identity verification failed",
                                 "spill_verify"));
    return workspace_result_t<void>::success();
}

mapped_window_cache_statistics_t spill_provider_t::statistics() const noexcept {
    const auto storage = state_->storage;
    return storage->cache ? storage->cache->statistics() : mapped_window_cache_statistics_t{};
}

}
