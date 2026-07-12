#pragma once

#include "../../src/core/analysis/decompiler/decompiler_contracts.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace aida::analysis::native_worker::wire {

constexpr std::uint32_t k_bootstrap_magic = 0x42574e41U;
constexpr std::uint32_t k_frame_magic = 0x46574e41U;
constexpr std::uint16_t k_frame_version = 1;
constexpr std::size_t k_digest_bytes = 32;
constexpr std::size_t k_bootstrap_bytes = 4 + 2 + 2 + k_digest_bytes + k_digest_bytes + k_digest_bytes;
constexpr std::size_t k_frame_header_without_tag_bytes = 4 + 2 + 2 + 8 + 4 + k_digest_bytes;
constexpr std::size_t k_frame_header_bytes = k_frame_header_without_tag_bytes + k_digest_bytes;
inline constexpr char k_protocol_hash_material[] =
    "aida.native-decompiler.worker.frame.v1|bootstrap.v1|hmac-sha256|strict-sequence|readonly-snapshot";

enum class frame_kind_t : std::uint16_t {
    decompiler_contract = 1
};

enum class read_state_t : std::uint8_t {
    incomplete,
    complete,
    failure
};

enum class frame_failure_t : std::uint8_t {
    none,
    io,
    malformed_header,
    nonce_mismatch,
    replay,
    oversize,
    authentication_failed,
    resource_exhausted
};

struct session_material_t {
    std::array<std::uint8_t, k_digest_bytes> nonce{};
    std::array<std::uint8_t, k_digest_bytes> key{};
    sha256_digest_t nonce_hash;
};

struct frame_t {
    frame_kind_t kind = frame_kind_t::decompiler_contract;
    std::uint64_t sequence = 0;
    std::vector<std::uint8_t> payload;
};

inline void write_u16(std::uint8_t* destination, std::uint16_t value) noexcept
{
    destination[0] = static_cast<std::uint8_t>(value);
    destination[1] = static_cast<std::uint8_t>(value >> 8U);
}

inline void write_u32(std::uint8_t* destination, std::uint32_t value) noexcept
{
    for (std::size_t index = 0; index < sizeof(value); ++index)
        destination[index] = static_cast<std::uint8_t>(value >> (index * 8U));
}

inline void write_u64(std::uint8_t* destination, std::uint64_t value) noexcept
{
    for (std::size_t index = 0; index < sizeof(value); ++index)
        destination[index] = static_cast<std::uint8_t>(value >> (index * 8U));
}

inline std::uint16_t read_u16(const std::uint8_t* source) noexcept
{
    return static_cast<std::uint16_t>(source[0]) |
        (static_cast<std::uint16_t>(source[1]) << 8U);
}

inline std::uint32_t read_u32(const std::uint8_t* source) noexcept
{
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index)
        value |= static_cast<std::uint32_t>(source[index]) << (index * 8U);
    return value;
}

inline std::uint64_t read_u64(const std::uint8_t* source) noexcept
{
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index)
        value |= static_cast<std::uint64_t>(source[index]) << (index * 8U);
    return value;
}

inline bool constant_time_equal(const std::uint8_t* lhs, const std::uint8_t* rhs, std::size_t size) noexcept
{
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < size; ++index)
        difference = static_cast<std::uint8_t>(difference | (lhs[index] ^ rhs[index]));
    return difference == 0;
}

inline bool hmac_sha256(const std::uint8_t* key, std::size_t key_size, const std::uint8_t* data,
                        std::size_t data_size, std::array<std::uint8_t, k_digest_bytes>& output) noexcept
{
    if ((!key && key_size != 0) || (!data && data_size != 0) || key_size > (std::numeric_limits<ULONG>::max)() ||
        data_size > (std::numeric_limits<ULONG>::max)())
        return false;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<std::uint8_t> object;
    ULONG object_size = 0;
    ULONG copied = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status))
        return false;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &copied, 0);
    if (!BCRYPT_SUCCESS(status) || copied != sizeof(object_size) || object_size == 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }
    try {
        object.resize(object_size);
    } catch (...) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }
    status = BCryptCreateHash(algorithm, &hash, object.data(), object_size, const_cast<PUCHAR>(key), static_cast<ULONG>(key_size), 0);
    if (BCRYPT_SUCCESS(status) && data_size != 0)
        status = BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(data_size), 0);
    if (BCRYPT_SUCCESS(status))
        status = BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0);
    if (hash)
        BCryptDestroyHash(hash);
    SecureZeroMemory(object.data(), object.size());
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return BCRYPT_SUCCESS(status);
}

inline bool sha256(const void* data, std::size_t size, sha256_digest_t& output) noexcept
{
    if ((!data && size != 0) || size > (std::numeric_limits<ULONG>::max)())
        return false;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<std::uint8_t> object;
    ULONG object_size = 0;
    ULONG copied = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
        return false;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &copied, 0);
    if (!BCRYPT_SUCCESS(status) || copied != sizeof(object_size) || object_size == 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }
    try {
        object.resize(object_size);
    } catch (...) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }
    status = BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0);
    if (BCRYPT_SUCCESS(status) && size != 0)
        status = BCryptHashData(hash, const_cast<PUCHAR>(static_cast<const std::uint8_t*>(data)), static_cast<ULONG>(size), 0);
    if (BCRYPT_SUCCESS(status))
        status = BCryptFinishHash(hash, output.bytes.data(), static_cast<ULONG>(output.bytes.size()), 0);
    if (hash)
        BCryptDestroyHash(hash);
    SecureZeroMemory(object.data(), object.size());
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return BCRYPT_SUCCESS(status);
}

inline bool make_session(session_material_t& output) noexcept
{
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, output.nonce.data(), static_cast<ULONG>(output.nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ||
        !BCRYPT_SUCCESS(BCryptGenRandom(nullptr, output.key.data(), static_cast<ULONG>(output.key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return false;
    return sha256(output.nonce.data(), output.nonce.size(), output.nonce_hash);
}

inline std::array<std::uint8_t, k_bootstrap_bytes> encode_bootstrap(const session_material_t& session,
                                                                      const sha256_digest_t& manifest_hash) noexcept
{
    std::array<std::uint8_t, k_bootstrap_bytes> output{};
    write_u32(output.data(), k_bootstrap_magic);
    write_u16(output.data() + 4, k_frame_version);
    write_u16(output.data() + 6, 0);
    std::memcpy(output.data() + 8, session.nonce.data(), session.nonce.size());
    std::memcpy(output.data() + 8 + k_digest_bytes, session.key.data(), session.key.size());
    std::memcpy(output.data() + 8 + k_digest_bytes + k_digest_bytes, manifest_hash.bytes.data(), manifest_hash.bytes.size());
    return output;
}

inline bool decode_bootstrap(const std::uint8_t* data, std::size_t size, session_material_t& session,
                             sha256_digest_t& manifest_hash) noexcept
{
    if (!data || size != k_bootstrap_bytes || read_u32(data) != k_bootstrap_magic || read_u16(data + 4) != k_frame_version ||
        read_u16(data + 6) != 0)
        return false;
    std::memcpy(session.nonce.data(), data + 8, session.nonce.size());
    std::memcpy(session.key.data(), data + 8 + k_digest_bytes, session.key.size());
    std::memcpy(manifest_hash.bytes.data(), data + 8 + k_digest_bytes + k_digest_bytes, manifest_hash.bytes.size());
    return sha256(session.nonce.data(), session.nonce.size(), session.nonce_hash);
}

inline bool write_all(HANDLE handle, const void* data, std::size_t size, DWORD& error) noexcept
{
    const auto* cursor = static_cast<const std::uint8_t*>(data);
    while (size != 0) {
        const DWORD chunk = static_cast<DWORD>((std::min)(size, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!WriteFile(handle, cursor, chunk, &written, nullptr) || written == 0) {
            error = GetLastError();
            return false;
        }
        cursor += written;
        size -= written;
    }
    error = ERROR_SUCCESS;
    return true;
}

inline bool read_all(HANDLE handle, void* data, std::size_t size, DWORD& error) noexcept
{
    auto* cursor = static_cast<std::uint8_t*>(data);
    while (size != 0) {
        const DWORD chunk = static_cast<DWORD>((std::min)(size, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD received = 0;
        if (!ReadFile(handle, cursor, chunk, &received, nullptr) || received == 0) {
            error = GetLastError();
            return false;
        }
        cursor += received;
        size -= received;
    }
    error = ERROR_SUCCESS;
    return true;
}

inline bool send_frame(HANDLE handle, const session_material_t& session, frame_kind_t kind, std::uint64_t sequence,
                       const std::uint8_t* payload, std::size_t payload_size, std::size_t maximum_payload,
                       DWORD& error) noexcept
{
    if ((!payload && payload_size != 0) || payload_size > maximum_payload || payload_size > (std::numeric_limits<std::uint32_t>::max)() ||
        sequence == 0) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    std::array<std::uint8_t, k_frame_header_bytes> header{};
    write_u32(header.data(), k_frame_magic);
    write_u16(header.data() + 4, k_frame_version);
    write_u16(header.data() + 6, static_cast<std::uint16_t>(kind));
    write_u64(header.data() + 8, sequence);
    write_u32(header.data() + 16, static_cast<std::uint32_t>(payload_size));
    std::memcpy(header.data() + 20, session.nonce_hash.bytes.data(), session.nonce_hash.bytes.size());
    std::vector<std::uint8_t> authenticated;
    try {
        authenticated.reserve(k_frame_header_without_tag_bytes + payload_size);
        authenticated.insert(authenticated.end(), header.begin(), header.begin() + static_cast<std::ptrdiff_t>(k_frame_header_without_tag_bytes));
        if (payload_size != 0)
            authenticated.insert(authenticated.end(), payload, payload + payload_size);
    } catch (...) {
        error = ERROR_NOT_ENOUGH_MEMORY;
        return false;
    }
    std::array<std::uint8_t, k_digest_bytes> tag{};
    if (!hmac_sha256(session.key.data(), session.key.size(), authenticated.data(), authenticated.size(), tag)) {
        SecureZeroMemory(authenticated.data(), authenticated.size());
        error = ERROR_CRC;
        return false;
    }
    std::memcpy(header.data() + k_frame_header_without_tag_bytes, tag.data(), tag.size());
    const bool header_written = write_all(handle, header.data(), header.size(), error);
    const bool payload_written = header_written && (payload_size == 0 || write_all(handle, payload, payload_size, error));
    SecureZeroMemory(authenticated.data(), authenticated.size());
    SecureZeroMemory(tag.data(), tag.size());
    return payload_written;
}

class frame_reader_t final {
public:
    read_state_t poll(HANDLE handle, const session_material_t& session, std::uint64_t expected_sequence,
                      std::size_t maximum_payload, frame_t& output, DWORD& error)
    {
        if (!fill(handle, header_.data(), header_size_, header_.size(), error))
            return read_state_t::failure;
        if (header_size_ != header_.size())
            return read_state_t::incomplete;
        if (!header_validated_) {
            if (!validate_header(session, expected_sequence, maximum_payload, error))
                return read_state_t::failure;
        }
        if (!fill(handle, payload_.data(), payload_size_read_, payload_.size(), error))
            return read_state_t::failure;
        if (payload_size_read_ != payload_.size())
            return read_state_t::incomplete;
        if (!authenticate(session, error))
            return read_state_t::failure;
        output.kind = kind_;
        output.sequence = sequence_;
        output.payload = std::move(payload_);
        reset();
        error = ERROR_SUCCESS;
        return read_state_t::complete;
    }

    frame_failure_t failure() const noexcept
    {
        return failure_;
    }

    bool has_partial_frame() const noexcept
    {
        return header_size_ != 0 || header_validated_ || payload_size_read_ != 0;
    }

    void reset() noexcept
    {
        SecureZeroMemory(header_.data(), header_.size());
        if (!payload_.empty())
            SecureZeroMemory(payload_.data(), payload_.size());
        payload_.clear();
        header_size_ = 0;
        payload_size_read_ = 0;
        sequence_ = 0;
        kind_ = frame_kind_t::decompiler_contract;
        header_validated_ = false;
        failure_ = frame_failure_t::none;
    }

private:
    bool fill(HANDLE handle, std::uint8_t* destination, std::size_t& current, std::size_t target, DWORD& error)
    {
        while (current < target) {
            DWORD available = 0;
            if (!PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr)) {
                error = GetLastError();
                failure_ = frame_failure_t::io;
                return false;
            }
            if (available == 0)
                break;
            const std::size_t wanted = (std::min)(target - current, static_cast<std::size_t>(available));
            DWORD read = 0;
            if (!ReadFile(handle, destination + current, static_cast<DWORD>(wanted), &read, nullptr) || read == 0) {
                error = GetLastError();
                failure_ = frame_failure_t::io;
                return false;
            }
            current += read;
        }
        error = ERROR_SUCCESS;
        return true;
    }

    bool validate_header(const session_material_t& session, std::uint64_t expected_sequence,
                         std::size_t maximum_payload, DWORD& error)
    {
        const auto magic = read_u32(header_.data());
        const auto version = read_u16(header_.data() + 4);
        const auto raw_kind = read_u16(header_.data() + 6);
        const auto payload_size = read_u32(header_.data() + 16);
        sequence_ = read_u64(header_.data() + 8);
        if (magic != k_frame_magic || version != k_frame_version ||
            raw_kind != static_cast<std::uint16_t>(frame_kind_t::decompiler_contract) || sequence_ == 0 ||
            expected_sequence == 0 || sequence_ > expected_sequence) {
            failure_ = frame_failure_t::malformed_header;
            error = ERROR_INVALID_DATA;
            return false;
        }
        if (payload_size > maximum_payload) {
            failure_ = frame_failure_t::oversize;
            error = ERROR_FILE_TOO_LARGE;
            return false;
        }
        if (!constant_time_equal(header_.data() + 20, session.nonce_hash.bytes.data(), session.nonce_hash.bytes.size())) {
            failure_ = frame_failure_t::nonce_mismatch;
            error = ERROR_ACCESS_DENIED;
            return false;
        }
        if (sequence_ < expected_sequence) {
            failure_ = frame_failure_t::replay;
            error = ERROR_INVALID_DATA;
            return false;
        }
        try {
            payload_.resize(payload_size);
        } catch (...) {
            failure_ = frame_failure_t::resource_exhausted;
            error = ERROR_NOT_ENOUGH_MEMORY;
            return false;
        }
        kind_ = static_cast<frame_kind_t>(raw_kind);
        header_validated_ = true;
        return true;
    }

    bool authenticate(const session_material_t& session, DWORD& error)
    {
        std::vector<std::uint8_t> authenticated;
        try {
            authenticated.reserve(k_frame_header_without_tag_bytes + payload_.size());
            authenticated.insert(authenticated.end(), header_.begin(), header_.begin() + static_cast<std::ptrdiff_t>(k_frame_header_without_tag_bytes));
            authenticated.insert(authenticated.end(), payload_.begin(), payload_.end());
        } catch (...) {
            failure_ = frame_failure_t::resource_exhausted;
            error = ERROR_NOT_ENOUGH_MEMORY;
            return false;
        }
        std::array<std::uint8_t, k_digest_bytes> tag{};
        const bool hashed = hmac_sha256(session.key.data(), session.key.size(), authenticated.data(), authenticated.size(), tag);
        const bool equal = hashed && constant_time_equal(tag.data(), header_.data() + k_frame_header_without_tag_bytes, tag.size());
        SecureZeroMemory(authenticated.data(), authenticated.size());
        SecureZeroMemory(tag.data(), tag.size());
        if (!equal) {
            failure_ = frame_failure_t::authentication_failed;
            error = ERROR_CRC;
            return false;
        }
        return true;
    }

    std::array<std::uint8_t, k_frame_header_bytes> header_{};
    std::vector<std::uint8_t> payload_;
    std::size_t header_size_ = 0;
    std::size_t payload_size_read_ = 0;
    std::uint64_t sequence_ = 0;
    frame_kind_t kind_ = frame_kind_t::decompiler_contract;
    bool header_validated_ = false;
    frame_failure_t failure_ = frame_failure_t::none;
};

inline sha256_digest_t protocol_hash()
{
    return stable_serialization_hash(k_protocol_hash_material);
}

}
