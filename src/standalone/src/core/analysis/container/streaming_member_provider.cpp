#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>

#include "streaming_member_provider.hpp"

#include "../spill_provider.hpp"
#include "../subrange_provider.hpp"
#include "../workspace/checked_range.hpp"

#include <zlib.h>
#include <zstd.h>
#include <lzma.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string_view>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace aida::analysis {
namespace {

constexpr std::uint64_t kMaximumBufferBytes = 4ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaximumSpillBytes = 1024ULL * 1024ULL * 1024ULL;

workspace_error_t stream_error(workspace_error_code_t code, std::string message,
                               const char* phase) {
    return make_workspace_error(code, std::move(message), phase);
}

workspace_error_t stop_error(const cancellation_token_t& cancel, const char* phase) {
    if (cancel.deadline_exceeded()) {
        auto error = stream_error(workspace_error_code_t::deadline_exceeded,
                                  "container member operation deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = stream_error(workspace_error_code_t::cancelled,
                              "container member operation cancelled", phase);
    error.cancellation = true;
    return error;
}

workspace_error_t limit_error(const char* message, const char* phase,
                              std::uint64_t value, std::uint64_t limit) {
    auto error = stream_error(workspace_error_code_t::limit_exceeded, message, phase);
    error.details.emplace_back("value", std::to_string(value));
    error.details.emplace_back("limit", std::to_string(limit));
    return error;
}

std::uint64_t saturating_add(std::uint64_t lhs, std::uint64_t rhs) noexcept {
    return rhs > (std::numeric_limits<std::uint64_t>::max)() - lhs
        ? (std::numeric_limits<std::uint64_t>::max)()
        : lhs + rhs;
}

std::uint64_t saturating_multiply(std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (lhs != 0 && rhs > (std::numeric_limits<std::uint64_t>::max)() / lhs)
        return (std::numeric_limits<std::uint64_t>::max)();
    return lhs * rhs;
}

bool normalized_path_is_valid(std::string_view value) noexcept {
    if (value.empty() || value.size() > 32768 || value.front() == '/' ||
        value.find('\\') != std::string_view::npos || value.find('\0') != std::string_view::npos)
        return false;
    std::size_t component_start = 0;
    while (component_start < value.size()) {
        const auto separator = value.find('/', component_start);
        const auto component_end = separator == std::string_view::npos ? value.size() : separator;
        const auto component_size = component_end - component_start;
        if (component_size == 0 ||
            (component_size == 1 && value[component_start] == '.') ||
            (component_size == 2 && value[component_start] == '.' &&
             value[component_start + 1] == '.'))
            return false;
        if (separator == std::string_view::npos)
            break;
        component_start = separator + 1;
    }
    return true;
}

std::string encode_identity_component(std::string_view value) {
    constexpr char digits[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(value.size());
    for (const unsigned char byte : value) {
        if (byte == '%' || byte == '#') {
            result.push_back('%');
            result.push_back(digits[byte >> 4U]);
            result.push_back(digits[byte & 0x0fU]);
        } else {
            result.push_back(static_cast<char>(byte));
        }
    }
    return result;
}

class stream_guard_t final {
public:
    stream_guard_t(const container_stream_limits_t& limits,
                   const cancellation_token_t& cancel,
                   container_stream_charge_t additional_charge)
        : limits_(limits), cancel_(cancel), additional_charge_(std::move(additional_charge)),
          started_(std::chrono::steady_clock::now()) {}

    workspace_result_t<void> poll(const char* phase) {
        if (cancel_.stop_requested())
            return workspace_result_t<void>::failure(stop_error(cancel_, phase));
        if (std::chrono::steady_clock::now() - started_ > limits_.max_elapsed) {
            auto error = stream_error(workspace_error_code_t::deadline_exceeded,
                                      "container member elapsed-time limit exceeded", phase);
            error.deadline = true;
            error.details.emplace_back("max_elapsed_ms", std::to_string(limits_.max_elapsed.count()));
            return workspace_result_t<void>::failure(std::move(error));
        }
        bytes_since_poll_ = 0;
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> charge(std::uint64_t amount, const char* phase) {
        if (amount > limits_.max_work_bytes - work_bytes_)
            return workspace_result_t<void>::failure(limit_error(
                "container member work-byte budget exceeded", phase,
                saturating_add(work_bytes_, amount), limits_.max_work_bytes));
        work_bytes_ += amount;
        if (amount >= limits_.cancellation_poll_bytes - bytes_since_poll_) {
            auto polled = poll(phase);
            if (!polled)
                return polled;
        } else {
            bytes_since_poll_ += amount;
        }
        if (additional_charge_) {
            auto charged = additional_charge_(amount);
            if (!charged)
                return charged;
        }
        return workspace_result_t<void>::success();
    }

    const container_stream_limits_t& limits() const noexcept {
        return limits_;
    }

private:
    const container_stream_limits_t& limits_;
    const cancellation_token_t& cancel_;
    container_stream_charge_t additional_charge_;
    std::chrono::steady_clock::time_point started_;
    std::uint64_t work_bytes_ = 0;
    std::uint64_t bytes_since_poll_ = 0;
};

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
    auto error = stream_error(workspace_error_code_t::hash_failure,
                              std::string(operation) + " failed", "container_stream_hash");
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
            return workspace_result_t<sha256_accumulator_t>::failure(stream_error(
                workspace_error_code_t::hash_failure,
                "BCrypt returned an invalid SHA-256 object size", "container_stream_hash"));
        std::vector<std::uint8_t> object;
        try {
            object.resize(object_size);
        } catch (const std::bad_alloc&) {
            return workspace_result_t<sha256_accumulator_t>::failure(stream_error(
                workspace_error_code_t::provider_unavailable,
                "container member hash allocation failed", "container_stream_hash"));
        }
        BCRYPT_HASH_HANDLE raw_hash = nullptr;
        status = BCryptCreateHash(raw_algorithm, &raw_hash, object.data(), object_size,
                                  nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status))
            return workspace_result_t<sha256_accumulator_t>::failure(
                crypto_error("BCryptCreateHash", status));
        return workspace_result_t<sha256_accumulator_t>::success(
            sha256_accumulator_t(std::move(algorithm), hash_handle_t(raw_hash), std::move(object)));
    }

    sha256_accumulator_t(sha256_accumulator_t&&) noexcept = default;
    sha256_accumulator_t& operator=(sha256_accumulator_t&&) noexcept = default;
    sha256_accumulator_t(const sha256_accumulator_t&) = delete;
    sha256_accumulator_t& operator=(const sha256_accumulator_t&) = delete;

    workspace_result_t<void> update(const std::uint8_t* data, std::size_t size) {
        const std::uint8_t* cursor = data;
        while (size != 0) {
            const auto amount = static_cast<ULONG>((std::min)(
                size, static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));
            const NTSTATUS status = BCryptHashData(static_cast<BCRYPT_HASH_HANDLE>(hash_.get()),
                                                   const_cast<PUCHAR>(cursor), amount, 0);
            if (!BCRYPT_SUCCESS(status))
                return workspace_result_t<void>::failure(crypto_error("BCryptHashData", status));
            cursor += amount;
            size -= amount;
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<sha256_digest_t> finish() {
        sha256_digest_t digest;
        const NTSTATUS status = BCryptFinishHash(static_cast<BCRYPT_HASH_HANDLE>(hash_.get()),
                                                 digest.bytes.data(),
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
        : algorithm_(std::move(algorithm)), object_(std::move(object)), hash_(std::move(hash)) {}

    algorithm_handle_t algorithm_;
    std::vector<std::uint8_t> object_;
    hash_handle_t hash_;
};

class inflate_state_t final {
public:
    inflate_state_t() {
        std::memset(&stream_, 0, sizeof(stream_));
    }

    ~inflate_state_t() {
        if (initialized_)
            inflateEnd(&stream_);
    }

    workspace_result_t<void> initialize() {
        const int status = inflateInit2(&stream_, -MAX_WBITS);
        if (status == Z_OK) {
            initialized_ = true;
            return workspace_result_t<void>::success();
        }
        auto error = stream_error(status == Z_MEM_ERROR ? workspace_error_code_t::limit_exceeded
                                                         : workspace_error_code_t::integrity_failure,
                                  "raw-DEFLATE initialization failed", "container_stream_deflate");
        error.provider_status = status;
        return workspace_result_t<void>::failure(std::move(error));
    }

    z_stream& stream() noexcept {
        return stream_;
    }

private:
    z_stream stream_{};
    bool initialized_ = false;
};

class zstd_state_t final {
public:
    zstd_state_t() = default;

    ~zstd_state_t() {
        if (stream_)
            ZSTD_freeDStream(stream_);
    }

    zstd_state_t(const zstd_state_t&) = delete;
    zstd_state_t& operator=(const zstd_state_t&) = delete;
    zstd_state_t(zstd_state_t&&) = delete;
    zstd_state_t& operator=(zstd_state_t&&) = delete;

    workspace_result_t<void> initialize() {
        stream_ = ZSTD_createDStream();
        if (!stream_)
            return workspace_result_t<void>::failure(stream_error(
                workspace_error_code_t::provider_unavailable,
                "zstd decompression context allocation failed", "container_stream_zstd"));
        const size_t status = ZSTD_initDStream(stream_);
        if (ZSTD_isError(status))
            return workspace_result_t<void>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "zstd decompression stream initialization failed", "container_stream_zstd"));
        return workspace_result_t<void>::success();
    }

    ZSTD_DStream* stream() noexcept {
        return stream_;
    }

private:
    ZSTD_DStream* stream_ = nullptr;
};

class lzma_state_t final {
public:
    lzma_state_t() {
        std::memset(&stream_, 0, sizeof(stream_));
    }

    ~lzma_state_t() {
        if (initialized_)
            lzma_end(&stream_);
    }

    lzma_state_t(const lzma_state_t&) = delete;
    lzma_state_t& operator=(const lzma_state_t&) = delete;
    lzma_state_t(lzma_state_t&&) = delete;
    lzma_state_t& operator=(lzma_state_t&&) = delete;

    workspace_result_t<void> initialize_raw(const lzma_filter* filters) {
        const lzma_ret status = lzma_raw_decoder(&stream_, filters);
        if (status == LZMA_OK) {
            initialized_ = true;
            return workspace_result_t<void>::success();
        }
        auto error = stream_error(status == LZMA_MEM_ERROR
                                      ? workspace_error_code_t::limit_exceeded
                                      : workspace_error_code_t::integrity_failure,
                                  "LZMA raw decoder initialization failed", "container_stream_lzma");
        error.provider_status = static_cast<std::int64_t>(status);
        return workspace_result_t<void>::failure(std::move(error));
    }

    lzma_stream& stream() noexcept {
        return stream_;
    }

private:
    lzma_stream stream_{};
    bool initialized_ = false;
};

workspace_result_t<void> validate_limits(const container_stream_limits_t& limits) {
    if (limits.max_compressed_size == 0 || limits.max_uncompressed_size == 0 ||
        limits.max_expansion_ratio == 0 || limits.max_spill_bytes == 0 ||
        limits.max_spill_bytes > kMaximumSpillBytes || limits.max_work_bytes == 0 ||
        limits.max_io_chunk_size == 0 || limits.cancellation_poll_bytes == 0 ||
        limits.max_elapsed.count() <= 0)
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::invalid_argument,
            "container member streaming limits are invalid", "container_stream_open"));
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_request(const container_stream_member_request_t& request,
                                          const container_stream_limits_t& limits) {
    if (!request.source || !normalized_path_is_valid(request.normalized_path))
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::invalid_argument,
            "container member request is missing a valid source or path", "container_stream_open"));
    if (request.source->identity().normalized_source.empty() ||
        request.source->identity().size != request.source->size())
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::provider_binding_mismatch,
            "container member source identity does not match its provider", "container_stream_open"));
    if (request.compressed_size > limits.max_compressed_size ||
        request.uncompressed_size > limits.max_uncompressed_size)
        return workspace_result_t<void>::failure(limit_error(
            "container member size exceeds its configured limit", "container_stream_open",
            request.compressed_size > limits.max_compressed_size ? request.compressed_size
                                                                  : request.uncompressed_size,
            request.compressed_size > limits.max_compressed_size ? limits.max_compressed_size
                                                                  : limits.max_uncompressed_size));
    if (request.codec == container_stream_codec_t::stored &&
        request.compressed_size != request.uncompressed_size)
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "stored container member has unequal input and output sizes", "container_stream_open"));
    if (request.codec == container_stream_codec_t::raw_deflate && request.compressed_size == 0)
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::malformed_image,
            "raw-DEFLATE container member has no input stream", "container_stream_open"));
    if (request.codec == container_stream_codec_t::zstd && request.compressed_size == 0)
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::malformed_image,
            "zstd container member has no input stream", "container_stream_open"));
    if (request.codec == container_stream_codec_t::lzma && request.compressed_size == 0)
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::malformed_image,
            "LZMA container member has no input stream", "container_stream_open"));
    if (request.compressed_size != 0 &&
        request.uncompressed_size > saturating_multiply(request.compressed_size,
                                                        limits.max_expansion_ratio))
        return workspace_result_t<void>::failure(limit_error(
            "container member expansion ratio exceeds its limit", "container_stream_open",
            request.uncompressed_size,
            saturating_multiply(request.compressed_size, limits.max_expansion_ratio)));
    if (request.codec == container_stream_codec_t::raw_deflate &&
        request.uncompressed_size > limits.max_spill_bytes)
        return workspace_result_t<void>::failure(limit_error(
            "deflated container member exceeds its spill capacity", "container_stream_open",
            request.uncompressed_size, limits.max_spill_bytes));
    if (request.codec == container_stream_codec_t::zstd &&
        request.uncompressed_size > limits.max_spill_bytes)
        return workspace_result_t<void>::failure(limit_error(
            "zstd container member exceeds its spill capacity", "container_stream_open",
            request.uncompressed_size, limits.max_spill_bytes));
    if (request.codec == container_stream_codec_t::lzma &&
        request.uncompressed_size > limits.max_spill_bytes)
        return workspace_result_t<void>::failure(limit_error(
            "LZMA container member exceeds its spill capacity", "container_stream_open",
            request.uncompressed_size, limits.max_spill_bytes));
    if (request.provenance.normalized_member_path != request.normalized_path ||
        request.provenance.container_offset != request.data_offset ||
        request.provenance.compressed_size != request.compressed_size ||
        request.provenance.uncompressed_size != request.uncompressed_size ||
        request.provenance.crc32 != request.crc32 || request.provenance.depth == 0 ||
        request.provenance.depth > 64 ||
        request.provenance.compressed != (request.codec != container_stream_codec_t::stored))
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::provider_binding_mismatch,
            "container member provenance is inconsistent with its stream descriptor",
            "container_stream_open"));
    const auto& parent_member = request.source->member_metadata();
    if ((!parent_member && request.provenance.depth != 1) ||
        (parent_member &&
         (parent_member->depth >= 64 || request.provenance.depth != parent_member->depth + 1)))
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::provider_binding_mismatch,
            "container member provenance depth is inconsistent with its parent", "container_stream_open"));
    if (parent_member &&
        (!normalized_path_is_valid(parent_member->normalized_member_path) ||
         parent_member->compressed_size == 0 ||
         parent_member->uncompressed_size != request.source->size() ||
         (!parent_member->compressed &&
          parent_member->compressed_size != parent_member->uncompressed_size)))
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::provider_binding_mismatch,
            "container member parent provenance is invalid", "container_stream_open"));
    auto range = validate_span(request.data_offset, request.compressed_size,
                               request.source->size(), "container_stream_open");
    if (!range)
        return workspace_result_t<void>::failure(range.error());
    return workspace_result_t<void>::success();
}

std::uint64_t chunk_limit(const container_stream_limits_t& limits) noexcept {
    return (std::min)(kMaximumBufferBytes,
                      (std::min)(limits.max_io_chunk_size, limits.cancellation_poll_bytes));
}

workspace_result_t<sha256_digest_t> verify_stored_member(
    const std::shared_ptr<subrange_provider_t>& member,
    const container_stream_member_request_t& request, stream_guard_t& guard,
    const cancellation_token_t& cancel) {
    auto accumulator = sha256_accumulator_t::create();
    if (!accumulator)
        return workspace_result_t<sha256_digest_t>::failure(accumulator.error());
    auto hash = accumulator.take_value();
    uLong crc = crc32(0L, Z_NULL, 0);
    std::uint64_t completed = 0;
    const std::uint64_t maximum_chunk = chunk_limit(guard.limits());
    while (completed < request.uncompressed_size) {
        auto polled = guard.poll("container_stream_stored");
        if (!polled)
            return workspace_result_t<sha256_digest_t>::failure(std::move(polled.error()));
        const std::uint64_t contiguous = member->maximum_contiguous_lease(completed);
        if (contiguous == 0)
            return workspace_result_t<sha256_digest_t>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "stored container member has no readable contiguous range", "container_stream_stored"));
        const std::uint64_t amount = (std::min)(
            request.uncompressed_size - completed, (std::min)(maximum_chunk, contiguous));
        auto input_charge = guard.charge(amount, "container_stream_stored");
        if (!input_charge)
            return workspace_result_t<sha256_digest_t>::failure(std::move(input_charge.error()));
        auto input = member->lease(completed, amount, cancel);
        if (!input)
            return workspace_result_t<sha256_digest_t>::failure(std::move(input.error()));
        if (input.value().size() != amount || (amount != 0 && input.value().data() == nullptr))
            return workspace_result_t<sha256_digest_t>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "stored container member lease was incomplete", "container_stream_stored"));
        auto hashed = hash.update(input.value().data(), input.value().size());
        if (!hashed)
            return workspace_result_t<sha256_digest_t>::failure(std::move(hashed.error()));
        crc = crc32(crc, reinterpret_cast<const Bytef*>(input.value().data()),
                    static_cast<uInt>(input.value().size()));
        auto output_charge = guard.charge(amount, "container_stream_stored");
        if (!output_charge)
            return workspace_result_t<sha256_digest_t>::failure(std::move(output_charge.error()));
        completed += amount;
    }
    if (static_cast<std::uint32_t>(crc) != request.crc32)
        return workspace_result_t<sha256_digest_t>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "stored container member CRC verification failed", "container_stream_stored"));
    return hash.finish();
}

workspace_result_t<std::shared_ptr<spill_provider_t>> materialize_deflated_member(
    const container_stream_member_request_t& request, const container_stream_limits_t& limits,
    stream_guard_t& guard, const cancellation_token_t& cancel) {
    spill_provider_options_t spill_options;
    spill_options.max_spill_bytes = limits.max_spill_bytes;
    spill_options.write_chunk_bytes = chunk_limit(limits);
    auto sink = spill_sink_t::create("container-member", spill_options);
    if (!sink)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(sink.error()));
    std::vector<std::uint8_t> output;
    try {
        output.resize(static_cast<std::size_t>(chunk_limit(limits)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::provider_unavailable,
            "deflated container member stream buffer allocation failed", "container_stream_deflate"));
    }
    inflate_state_t inflater;
    auto initialized = inflater.initialize();
    if (!initialized)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(initialized.error()));
    z_stream& stream = inflater.stream();
    uLong crc = crc32(0L, Z_NULL, 0);
    std::uint64_t compressed_cursor = 0;
    std::uint64_t output_cursor = 0;
    bool ended = false;
    std::array<std::uint8_t, 1> overflow{};
    while (compressed_cursor < request.compressed_size && !ended) {
        auto polled = guard.poll("container_stream_deflate");
        if (!polled)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                std::move(polled.error()));
        std::uint64_t source_offset = 0;
        if (!checked_add_u64(request.data_offset, compressed_cursor, source_offset))
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::range_overflow,
                "deflated container member source offset overflowed", "container_stream_deflate"));
        const std::uint64_t contiguous = request.source->maximum_contiguous_lease(source_offset);
        if (contiguous == 0)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "deflated container member has no readable contiguous range", "container_stream_deflate"));
        const std::uint64_t amount = (std::min)(
            request.compressed_size - compressed_cursor, (std::min)(chunk_limit(limits), contiguous));
        auto input_charge = guard.charge(amount, "container_stream_deflate");
        if (!input_charge)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                std::move(input_charge.error()));
        auto input = request.source->lease(source_offset, amount, cancel);
        if (!input)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(input.error()));
        if (input.value().size() != amount || input.value().data() == nullptr)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "deflated container member lease was incomplete", "container_stream_deflate"));
        stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input.value().data()));
        stream.avail_in = static_cast<uInt>(amount);
        while (stream.avail_in != 0 && !ended) {
            const std::uint64_t remaining = request.uncompressed_size - output_cursor;
            const std::uint64_t capacity = remaining == 0 ? 1ULL :
                (std::min)(remaining, static_cast<std::uint64_t>(output.size()));
            Bytef* destination = remaining == 0 ? reinterpret_cast<Bytef*>(overflow.data()) :
                reinterpret_cast<Bytef*>(output.data());
            stream.next_out = destination;
            stream.avail_out = static_cast<uInt>(capacity);
            const uInt input_before = stream.avail_in;
            const uInt output_before = stream.avail_out;
            const int status = inflate(&stream, Z_NO_FLUSH);
            const std::uint64_t input_consumed = input_before - stream.avail_in;
            const std::uint64_t produced = output_before - stream.avail_out;
            if (remaining == 0 && produced != 0)
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                    workspace_error_code_t::integrity_failure,
                    "deflated container member exceeded its declared output size",
                    "container_stream_deflate"));
            if (produced != 0) {
                auto output_charge = guard.charge(produced, "container_stream_deflate");
                if (!output_charge)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                        std::move(output_charge.error()));
                auto appended = sink.value()->append(output.data(), produced, cancel);
                if (!appended)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                        std::move(appended.error()));
                crc = crc32(crc, reinterpret_cast<const Bytef*>(output.data()),
                            static_cast<uInt>(produced));
                output_cursor += produced;
            }
            if (status == Z_STREAM_END) {
                if (compressed_cursor + amount != request.compressed_size || stream.avail_in != 0 ||
                    output_cursor != request.uncompressed_size)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                        workspace_error_code_t::integrity_failure,
                        "deflated container member has trailing input or an incorrect output size",
                        "container_stream_deflate"));
                ended = true;
                break;
            }
            if (status != Z_OK) {
                auto error = stream_error(workspace_error_code_t::integrity_failure,
                                          "deflated container member stream validation failed",
                                          "container_stream_deflate");
                error.provider_status = status;
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
            }
            if (input_consumed == 0 && produced == 0)
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                    workspace_error_code_t::integrity_failure,
                    "deflated container member stream made no progress", "container_stream_deflate"));
            polled = guard.poll("container_stream_deflate");
            if (!polled)
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                    std::move(polled.error()));
        }
        compressed_cursor += amount;
    }
    if (!ended)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "deflated container member ended before its terminator", "container_stream_deflate"));
    if (static_cast<std::uint32_t>(crc) != request.crc32)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "deflated container member CRC verification failed", "container_stream_deflate"));
    auto finalized = sink.value()->finalize(cancel);
    if (!finalized)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(finalized.error()));
    auto final_poll = guard.poll("container_stream_deflate");
    if (!final_poll)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(final_poll.error()));
    return finalized;
}

workspace_result_t<std::shared_ptr<spill_provider_t>> materialize_zstd_member(
    const container_stream_member_request_t& request, const container_stream_limits_t& limits,
    stream_guard_t& guard, const cancellation_token_t& cancel) {
    spill_provider_options_t spill_options;
    spill_options.max_spill_bytes = limits.max_spill_bytes;
    spill_options.write_chunk_bytes = chunk_limit(limits);
    auto sink = spill_sink_t::create("container-member", spill_options);
    if (!sink)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(sink.error()));
    std::vector<std::uint8_t> output;
    try {
        output.resize(static_cast<std::size_t>(chunk_limit(limits)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::provider_unavailable,
            "zstd container member stream buffer allocation failed", "container_stream_zstd"));
    }
    zstd_state_t zstd_state;
    auto initialized = zstd_state.initialize();
    if (!initialized)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(initialized.error()));
    ZSTD_DStream* dstream = zstd_state.stream();
    uLong crc = crc32(0L, Z_NULL, 0);
    std::uint64_t compressed_cursor = 0;
    std::uint64_t output_cursor = 0;
    bool ended = false;
    while (compressed_cursor < request.compressed_size && !ended) {
        auto polled = guard.poll("container_stream_zstd");
        if (!polled)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                std::move(polled.error()));
        std::uint64_t source_offset = 0;
        if (!checked_add_u64(request.data_offset, compressed_cursor, source_offset))
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::range_overflow,
                "zstd container member source offset overflowed", "container_stream_zstd"));
        const std::uint64_t contiguous = request.source->maximum_contiguous_lease(source_offset);
        if (contiguous == 0)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "zstd container member has no readable contiguous range", "container_stream_zstd"));
        const std::uint64_t amount = (std::min)(
            request.compressed_size - compressed_cursor, (std::min)(chunk_limit(limits), contiguous));
        auto input_charge = guard.charge(amount, "container_stream_zstd");
        if (!input_charge)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                std::move(input_charge.error()));
        auto input = request.source->lease(source_offset, amount, cancel);
        if (!input)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(input.error()));
        if (input.value().size() != amount || input.value().data() == nullptr)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "zstd container member lease was incomplete", "container_stream_zstd"));
        ZSTD_inBuffer inbuf;
        inbuf.src = input.value().data();
        inbuf.size = amount;
        inbuf.pos = 0;
        while (inbuf.pos < inbuf.size && !ended) {
            const std::uint64_t remaining = request.uncompressed_size - output_cursor;
            const std::uint64_t capacity = remaining == 0 ? 1ULL :
                (std::min)(remaining, static_cast<std::uint64_t>(output.size()));
            ZSTD_outBuffer outbuf;
            outbuf.dst = remaining == 0 ? output.data() : output.data();
            outbuf.size = capacity;
            outbuf.pos = 0;
            const size_t zstatus = ZSTD_decompressStream(dstream, &outbuf, &inbuf);
            const std::uint64_t produced = outbuf.pos;
            if (remaining == 0 && produced != 0)
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                    workspace_error_code_t::integrity_failure,
                    "zstd container member exceeded its declared output size",
                    "container_stream_zstd"));
            if (produced != 0) {
                auto output_charge = guard.charge(produced, "container_stream_zstd");
                if (!output_charge)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                        std::move(output_charge.error()));
                auto appended = sink.value()->append(output.data(), produced, cancel);
                if (!appended)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                        std::move(appended.error()));
                crc = crc32(crc, reinterpret_cast<const Bytef*>(output.data()),
                            static_cast<uInt>(produced));
                output_cursor += produced;
            }
            if (zstatus == 0) {
                if (inbuf.pos != inbuf.size ||
                    compressed_cursor + amount != request.compressed_size ||
                    output_cursor != request.uncompressed_size)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                        workspace_error_code_t::integrity_failure,
                        "zstd container member has trailing input or an incorrect output size",
                        "container_stream_zstd"));
                ended = true;
                break;
            }
            if (ZSTD_isError(zstatus)) {
                auto error = stream_error(workspace_error_code_t::integrity_failure,
                                          "zstd container member stream validation failed",
                                          "container_stream_zstd");
                error.provider_status = static_cast<std::int64_t>(zstatus);
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
            }
            if (inbuf.pos == inbuf.size && produced == 0 && zstatus != 0)
                break;
            polled = guard.poll("container_stream_zstd");
            if (!polled)
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                    std::move(polled.error()));
        }
        compressed_cursor += amount;
    }
    if (!ended)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "zstd container member ended before its terminator", "container_stream_zstd"));
    if (static_cast<std::uint32_t>(crc) != request.crc32)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "zstd container member CRC verification failed", "container_stream_zstd"));
    auto finalized = sink.value()->finalize(cancel);
    if (!finalized)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(finalized.error()));
    auto final_poll = guard.poll("container_stream_zstd");
    if (!final_poll)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(final_poll.error()));
    return finalized;
}

workspace_result_t<std::shared_ptr<spill_provider_t>> materialize_lzma_member(
    const container_stream_member_request_t& request, const container_stream_limits_t& limits,
    stream_guard_t& guard, const cancellation_token_t& cancel) {
    spill_provider_options_t spill_options;
    spill_options.max_spill_bytes = limits.max_spill_bytes;
    spill_options.write_chunk_bytes = chunk_limit(limits);
    auto sink = spill_sink_t::create("container-member", spill_options);
    if (!sink)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(sink.error()));
    std::vector<std::uint8_t> output;
    try {
        output.resize(static_cast<std::size_t>(chunk_limit(limits)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::provider_unavailable,
            "LZMA container member stream buffer allocation failed", "container_stream_lzma"));
    }
    if (request.compressed_size < 4)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::malformed_image,
            "LZMA container member compressed stream is too short for its property header",
            "container_stream_lzma"));
    std::uint64_t header_offset = 0;
    if (!checked_add_u64(request.data_offset, 0, header_offset))
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::range_overflow,
            "LZMA container member header offset overflowed", "container_stream_lzma"));
    const std::uint64_t header_contiguous = request.source->maximum_contiguous_lease(header_offset);
    if (header_contiguous < 4)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "LZMA container member header is not contiguous", "container_stream_lzma"));
    auto header_charge = guard.charge(4, "container_stream_lzma");
    if (!header_charge)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(header_charge.error()));
    auto header_lease = request.source->lease(header_offset, 4, cancel);
    if (!header_lease)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(header_lease.error()));
    if (header_lease.value().size() != 4 || header_lease.value().data() == nullptr)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "LZMA container member header lease was incomplete", "container_stream_lzma"));
    const std::uint8_t* header_bytes = header_lease.value().data();
    const std::uint16_t lzma_props_size = static_cast<std::uint16_t>(
        header_bytes[2]) | static_cast<std::uint16_t>(static_cast<std::uint16_t>(header_bytes[3]) << 8U);
    if (lzma_props_size == 0 || lzma_props_size > 256 ||
        static_cast<std::uint64_t>(4) + lzma_props_size > request.compressed_size)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::malformed_image,
            "LZMA container member property size is invalid", "container_stream_lzma"));
    std::vector<std::uint8_t> lzma_props;
    try {
        lzma_props.resize(lzma_props_size);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::provider_unavailable,
            "LZMA container member property allocation failed", "container_stream_lzma"));
    }
    {
        std::uint64_t props_offset = 0;
        if (!checked_add_u64(request.data_offset, 4, props_offset))
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::range_overflow,
                "LZMA container member property offset overflowed", "container_stream_lzma"));
        const std::uint64_t props_contiguous = request.source->maximum_contiguous_lease(props_offset);
        if (props_contiguous < lzma_props_size)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "LZMA container member properties are not contiguous", "container_stream_lzma"));
        auto props_charge = guard.charge(lzma_props_size, "container_stream_lzma");
        if (!props_charge)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(props_charge.error()));
        auto props_lease = request.source->lease(props_offset, lzma_props_size, cancel);
        if (!props_lease)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(props_lease.error()));
        if (props_lease.value().size() != lzma_props_size || props_lease.value().data() == nullptr)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "LZMA container member property lease was incomplete", "container_stream_lzma"));
        std::memcpy(lzma_props.data(), props_lease.value().data(), lzma_props_size);
    }
    lzma_filter filters[2];
    filters[0].id = LZMA_FILTER_LZMA1;
    filters[0].options = nullptr;
    filters[1].id = LZMA_VLI_UNKNOWN;
    filters[1].options = nullptr;
    const lzma_ret prop_status = lzma_properties_decode(
        &filters[0], nullptr, lzma_props.data(), lzma_props_size);
    if (prop_status != LZMA_OK) {
        auto error = stream_error(workspace_error_code_t::integrity_failure,
                                  "LZMA container member property decoding failed",
                                  "container_stream_lzma");
        error.provider_status = static_cast<std::int64_t>(prop_status);
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
    }
    lzma_state_t lzma_state;
    auto lzma_init = lzma_state.initialize_raw(filters);
    lzma_filters_free(filters, nullptr);
    if (!lzma_init)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(lzma_init.error()));
    lzma_stream& stream = lzma_state.stream();
    uLong crc = crc32(0L, Z_NULL, 0);
    const std::uint64_t stream_start = static_cast<std::uint64_t>(4) + lzma_props_size;
    std::uint64_t compressed_cursor = stream_start;
    std::uint64_t output_cursor = 0;
    bool ended = false;
    while (compressed_cursor < request.compressed_size && !ended) {
        auto polled = guard.poll("container_stream_lzma");
        if (!polled)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                std::move(polled.error()));
        std::uint64_t source_offset = 0;
        if (!checked_add_u64(request.data_offset, compressed_cursor, source_offset))
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::range_overflow,
                "LZMA container member source offset overflowed", "container_stream_lzma"));
        const std::uint64_t contiguous = request.source->maximum_contiguous_lease(source_offset);
        if (contiguous == 0)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "LZMA container member has no readable contiguous range", "container_stream_lzma"));
        const std::uint64_t amount = (std::min)(
            request.compressed_size - compressed_cursor, (std::min)(chunk_limit(limits), contiguous));
        auto input_charge = guard.charge(amount, "container_stream_lzma");
        if (!input_charge)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                std::move(input_charge.error()));
        auto input = request.source->lease(source_offset, amount, cancel);
        if (!input)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(input.error()));
        if (input.value().size() != amount || input.value().data() == nullptr)
            return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "LZMA container member lease was incomplete", "container_stream_lzma"));
        stream.next_in = input.value().data();
        stream.avail_in = static_cast<size_t>(amount);
        while (stream.avail_in != 0 && !ended) {
            const std::uint64_t remaining = request.uncompressed_size - output_cursor;
            const std::uint64_t capacity = remaining == 0 ? 1ULL :
                (std::min)(remaining, static_cast<std::uint64_t>(output.size()));
            stream.next_out = output.data();
            stream.avail_out = static_cast<size_t>(capacity);
            const size_t avail_in_before = stream.avail_in;
            const size_t avail_out_before = stream.avail_out;
            const lzma_ret lzstatus = lzma_code(&stream, LZMA_RUN);
            const std::uint64_t input_consumed = avail_in_before - stream.avail_in;
            const std::uint64_t produced = avail_out_before - stream.avail_out;
            if (remaining == 0 && produced != 0)
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                    workspace_error_code_t::integrity_failure,
                    "LZMA container member exceeded its declared output size",
                    "container_stream_lzma"));
            if (produced != 0) {
                auto output_charge = guard.charge(produced, "container_stream_lzma");
                if (!output_charge)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                        std::move(output_charge.error()));
                auto appended = sink.value()->append(output.data(), produced, cancel);
                if (!appended)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                        std::move(appended.error()));
                crc = crc32(crc, reinterpret_cast<const Bytef*>(output.data()),
                            static_cast<uInt>(produced));
                output_cursor += produced;
            }
            if (lzstatus == LZMA_STREAM_END) {
                if (stream.avail_in != 0 ||
                    compressed_cursor + amount != request.compressed_size ||
                    output_cursor != request.uncompressed_size)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                        workspace_error_code_t::integrity_failure,
                        "LZMA container member has trailing input or an incorrect output size",
                        "container_stream_lzma"));
                ended = true;
                break;
            }
            if (lzstatus != LZMA_OK && lzstatus != LZMA_BUF_ERROR) {
                auto error = stream_error(workspace_error_code_t::integrity_failure,
                                          "LZMA container member stream validation failed",
                                          "container_stream_lzma");
                error.provider_status = static_cast<std::int64_t>(lzstatus);
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
            }
            if (input_consumed == 0 && produced == 0 && lzstatus == LZMA_BUF_ERROR)
                break;
            polled = guard.poll("container_stream_lzma");
            if (!polled)
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                    std::move(polled.error()));
        }
        compressed_cursor += amount;
    }
    if (!ended) {
        stream.next_in = nullptr;
        stream.avail_in = 0;
        while (!ended) {
            const std::uint64_t remaining = request.uncompressed_size - output_cursor;
            if (remaining == 0)
                break;
            const std::uint64_t capacity = (std::min)(remaining, static_cast<std::uint64_t>(output.size()));
            stream.next_out = output.data();
            stream.avail_out = static_cast<size_t>(capacity);
            const size_t avail_out_before = stream.avail_out;
            const lzma_ret lzstatus = lzma_code(&stream, LZMA_FINISH);
            const std::uint64_t produced = avail_out_before - stream.avail_out;
            if (produced != 0) {
                auto output_charge = guard.charge(produced, "container_stream_lzma");
                if (!output_charge)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                        std::move(output_charge.error()));
                auto appended = sink.value()->append(output.data(), produced, cancel);
                if (!appended)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                        std::move(appended.error()));
                crc = crc32(crc, reinterpret_cast<const Bytef*>(output.data()),
                            static_cast<uInt>(produced));
                output_cursor += produced;
            }
            if (lzstatus == LZMA_STREAM_END) {
                if (output_cursor != request.uncompressed_size)
                    return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                        workspace_error_code_t::integrity_failure,
                        "LZMA container member produced an incorrect output size",
                        "container_stream_lzma"));
                ended = true;
                break;
            }
            if (lzstatus != LZMA_OK && lzstatus != LZMA_BUF_ERROR) {
                auto error = stream_error(workspace_error_code_t::integrity_failure,
                                          "LZMA container member flush validation failed",
                                          "container_stream_lzma");
                error.provider_status = static_cast<std::int64_t>(lzstatus);
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(error));
            }
            if (produced == 0 && lzstatus == LZMA_BUF_ERROR)
                break;
            auto polled = guard.poll("container_stream_lzma");
            if (!polled)
                return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(
                    std::move(polled.error()));
        }
    }
    if (!ended)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "LZMA container member ended before its terminator", "container_stream_lzma"));
    if (static_cast<std::uint32_t>(crc) != request.crc32)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "LZMA container member CRC verification failed", "container_stream_lzma"));
    auto finalized = sink.value()->finalize(cancel);
    if (!finalized)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(finalized.error()));
    auto final_poll = guard.poll("container_stream_lzma");
    if (!final_poll)
        return workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(std::move(final_poll.error()));
    return finalized;
}

workspace_result_t<byte_provider_identity_t> make_identity(
    const container_stream_member_request_t& request, const sha256_digest_t& digest,
    bool immutable_snapshot) {
    byte_provider_identity_t identity = request.source->identity();
    identity.normalized_source += "#member:" + encode_identity_component(request.normalized_path);
    identity.size = request.uncompressed_size;
    identity.immutable_snapshot = immutable_snapshot;
    identity.content_sha256 = digest;
    identity.member = request.provenance;
    return workspace_result_t<byte_provider_identity_t>::success(std::move(identity));
}

workspace_result_t<void> validate_expected_hash(
    const container_stream_member_request_t& request, const sha256_digest_t& digest) {
    if (request.expected_content_sha256 && *request.expected_content_sha256 != digest)
        return workspace_result_t<void>::failure(stream_error(
            workspace_error_code_t::integrity_failure,
            "container member SHA-256 verification failed", "container_stream_hash"));
    return workspace_result_t<void>::success();
}

}

streaming_member_provider_t::streaming_member_provider_t(
    std::shared_ptr<const byte_provider_t> source, std::shared_ptr<byte_provider_t> backing,
    byte_provider_identity_t identity, bool subrange_backed)
    : source_(std::move(source)), backing_(std::move(backing)), identity_(std::move(identity)),
      subrange_backed_(subrange_backed) {}

workspace_result_t<std::shared_ptr<streaming_member_provider_t>>
streaming_member_provider_t::open(container_stream_member_request_t request,
                                  container_stream_limits_t limits,
                                  const cancellation_token_t& cancel,
                                  container_stream_charge_t additional_charge) {
    auto valid_limits = validate_limits(limits);
    if (!valid_limits)
        return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(
            std::move(valid_limits.error()));
    auto valid_request = validate_request(request, limits);
    if (!valid_request)
        return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(
            std::move(valid_request.error()));
    try {
        stream_guard_t guard(limits, cancel, std::move(additional_charge));
        auto initial_poll = guard.poll("container_stream_open");
        if (!initial_poll)
            return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(
                std::move(initial_poll.error()));
        if (request.codec == container_stream_codec_t::stored) {
            auto direct = subrange_provider_t::create_member(
                request.source, request.data_offset, request.uncompressed_size, request.provenance);
            if (!direct)
                return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(
                    std::move(direct.error()));
            auto digest = verify_stored_member(direct.value(), request, guard, cancel);
            if (!digest)
                return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(
                    std::move(digest.error()));
            auto expected = validate_expected_hash(request, digest.value());
            if (!expected)
                return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(
                    std::move(expected.error()));
            auto identity = make_identity(request, digest.value(),
                                          direct.value()->identity().immutable_snapshot);
            if (!identity)
                return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(
                    std::move(identity.error()));
            std::shared_ptr<byte_provider_t> backing = direct.take_value();
            return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::success(
                std::shared_ptr<streaming_member_provider_t>(new streaming_member_provider_t(
                    std::move(request.source), std::move(backing), identity.take_value(), true)));
        }
        workspace_result_t<std::shared_ptr<spill_provider_t>> spilled =
            workspace_result_t<std::shared_ptr<spill_provider_t>>::failure(stream_error(
                workspace_error_code_t::invalid_argument,
                "unsupported container stream codec", "container_stream_open"));
        const char* spill_phase = "container_stream_deflate";
        if (request.codec == container_stream_codec_t::raw_deflate)
            spilled = materialize_deflated_member(request, limits, guard, cancel);
        else if (request.codec == container_stream_codec_t::zstd) {
            spilled = materialize_zstd_member(request, limits, guard, cancel);
            spill_phase = "container_stream_zstd";
        } else if (request.codec == container_stream_codec_t::lzma) {
            spilled = materialize_lzma_member(request, limits, guard, cancel);
            spill_phase = "container_stream_lzma";
        }
        if (!spilled)
            return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(
                std::move(spilled.error()));
        if (!spilled.value()->identity().content_sha256)
            return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(stream_error(
                workspace_error_code_t::integrity_failure,
                "compressed container member spill has no content hash", spill_phase));
        auto expected = validate_expected_hash(request, *spilled.value()->identity().content_sha256);
        if (!expected)
            return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(
                std::move(expected.error()));
        auto identity = make_identity(request, *spilled.value()->identity().content_sha256, true);
        if (!identity)
            return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(
                std::move(identity.error()));
        std::shared_ptr<byte_provider_t> backing = spilled.take_value();
        return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::success(
            std::shared_ptr<streaming_member_provider_t>(new streaming_member_provider_t(
                std::move(request.source), std::move(backing), identity.take_value(), false)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(stream_error(
            workspace_error_code_t::provider_unavailable,
            "container member streaming allocation failed", "container_stream_open"));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<streaming_member_provider_t>>::failure(stream_error(
            workspace_error_code_t::provider_unavailable,
            "container member streaming allocation failed", "container_stream_open"));
    }
}

const byte_provider_identity_t& streaming_member_provider_t::identity() const noexcept {
    return identity_;
}

std::uint64_t streaming_member_provider_t::size() const noexcept {
    return identity_.size;
}

std::uint64_t streaming_member_provider_t::maximum_contiguous_lease(std::uint64_t offset) const noexcept {
    return backing_ ? backing_->maximum_contiguous_lease(offset) : 0;
}

workspace_result_t<byte_view_t> streaming_member_provider_t::lease(
    std::uint64_t offset, std::uint64_t size_value, const cancellation_token_t& cancel) const {
    if (!backing_)
        return workspace_result_t<byte_view_t>::failure(stream_error(
            workspace_error_code_t::provider_unavailable,
            "container member backing provider is unavailable", "container_stream_lease"));
    return backing_->lease(offset, size_value, cancel);
}

bool streaming_member_provider_t::is_subrange_backed() const noexcept {
    return subrange_backed_;
}

bool streaming_member_provider_t::is_spill_backed() const noexcept {
    return !subrange_backed_;
}

}
