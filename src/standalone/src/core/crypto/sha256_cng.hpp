#pragma once

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <vector>

namespace aida::crypto {

using sha256_software_reference_fn = bool (*)(
    const std::uint8_t* data, std::size_t size,
    std::array<std::uint8_t, 32>& out) noexcept;

namespace detail {

inline BCRYPT_ALG_HANDLE sha256_cng_algorithm() noexcept {
    static BCRYPT_ALG_HANDLE cached = []() noexcept -> BCRYPT_ALG_HANDLE {
        BCRYPT_ALG_HANDLE opened = nullptr;
        const NTSTATUS status = BCryptOpenAlgorithmProvider(
            &opened, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
            return nullptr;
        return opened;
    }();
    return cached;
}

}

class sha256_cng_t final {
public:
    sha256_cng_t() noexcept = default;

    ~sha256_cng_t() noexcept { reset(); }

    sha256_cng_t(sha256_cng_t&& other) noexcept
        : hash_(other.hash_), object_(std::move(other.object_)) {
        other.hash_ = nullptr;
    }

    sha256_cng_t& operator=(sha256_cng_t&& other) noexcept {
        if (this != &other) {
            reset();
            hash_ = other.hash_;
            object_ = std::move(other.object_);
            other.hash_ = nullptr;
        }
        return *this;
    }

    sha256_cng_t(const sha256_cng_t&) = delete;
    sha256_cng_t& operator=(const sha256_cng_t&) = delete;

    static sha256_cng_t create() noexcept {
        sha256_cng_t instance;
        const BCRYPT_ALG_HANDLE algorithm = detail::sha256_cng_algorithm();
        if (algorithm == nullptr)
            return instance;
        DWORD object_size = 0;
        DWORD result_size = 0;
        NTSTATUS status = BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size), &result_size, 0);
        if (!BCRYPT_SUCCESS(status) || result_size != sizeof(object_size) ||
            object_size == 0 || object_size > 1024U * 1024U)
            return instance;
        try {
            instance.object_.resize(object_size);
        } catch (...) {
            instance.object_.clear();
            return instance;
        }
        BCRYPT_HASH_HANDLE raw_hash = nullptr;
        status = BCryptCreateHash(algorithm, &raw_hash, instance.object_.data(),
                                  static_cast<ULONG>(instance.object_.size()), nullptr, 0,
                                  0);
        if (!BCRYPT_SUCCESS(status)) {
            instance.object_.clear();
            return instance;
        }
        instance.hash_ = raw_hash;
        return instance;
    }

    bool is_valid() const noexcept { return hash_ != nullptr; }

    bool update(const std::uint8_t* data, std::size_t size) noexcept {
        if (hash_ == nullptr)
            return false;
        const std::uint8_t* cursor = data;
        while (size != 0) {
            const ULONG amount = static_cast<ULONG>((std::min)(
                size, static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));
            const NTSTATUS status = BCryptHashData(hash_, const_cast<PUCHAR>(cursor),
                                                   amount, 0);
            if (!BCRYPT_SUCCESS(status))
                return false;
            cursor += amount;
            size -= amount;
        }
        return true;
    }

    bool finish(std::array<std::uint8_t, 32>& out) noexcept {
        out.fill(0);
        if (hash_ == nullptr)
            return false;
        BCRYPT_HASH_HANDLE finishing = hash_;
        hash_ = nullptr;
        const NTSTATUS status = BCryptFinishHash(finishing, out.data(),
                                                 static_cast<ULONG>(out.size()), 0);
        BCryptDestroyHash(finishing);
        object_.clear();
        if (!BCRYPT_SUCCESS(status)) {
            out.fill(0);
            return false;
        }
        return true;
    }

private:
    void reset() noexcept {
        if (hash_ != nullptr) {
            BCryptDestroyHash(hash_);
            hash_ = nullptr;
        }
    }

    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<std::uint8_t> object_;
};

inline bool sha256_cng_digest(const void* data, std::size_t size,
                              std::array<std::uint8_t, 32>& out) noexcept {
    out.fill(0);
    sha256_cng_t hash = sha256_cng_t::create();
    if (!hash.is_valid())
        return false;
    if (!hash.update(static_cast<const std::uint8_t*>(data), size))
        return false;
    return hash.finish(out);
}

inline bool sha256_cng_self_test(
    sha256_software_reference_fn software_reference) noexcept {
    if (software_reference == nullptr)
        return false;
    static constexpr std::array<std::uint8_t, 32> kAbcExpected = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    static constexpr std::uint8_t kAbc[] = {0x61, 0x62, 0x63};
    std::array<std::uint8_t, 32> cng_digest{};
    if (!sha256_cng_digest(kAbc, sizeof(kAbc), cng_digest))
        return false;
    if (cng_digest != kAbcExpected)
        return false;
    std::array<std::uint8_t, 32> software_digest{};
    if (!software_reference(kAbc, sizeof(kAbc), software_digest))
        return false;
    if (software_digest != cng_digest)
        return false;
    constexpr std::size_t kPatternSize = 1U << 20;
    std::unique_ptr<std::uint8_t[]> pattern(new (std::nothrow) std::uint8_t[kPatternSize]);
    if (!pattern)
        return false;
    for (std::size_t index = 0; index < kPatternSize; ++index) {
        pattern[index] = static_cast<std::uint8_t>(
            (index * 31U + (index >> 8) + 7U) & 0xFFU);
    }
    if (!sha256_cng_digest(pattern.get(), kPatternSize, cng_digest))
        return false;
    if (!software_reference(pattern.get(), kPatternSize, software_digest))
        return false;
    return software_digest == cng_digest;
}

inline bool sha256_cng_available(
    sha256_software_reference_fn software_reference) noexcept {
    static const bool available = sha256_cng_self_test(software_reference);
    return available;
}

}
