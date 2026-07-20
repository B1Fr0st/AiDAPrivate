#include "evidence_hash.hpp"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

namespace aida::analysis::c03
{
namespace
{
    struct algorithm_closer_t
    {
        void operator()(void* value) const noexcept
        {
            if (value)
                BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(value), 0);
        }
    };

    struct hash_closer_t
    {
        void operator()(void* value) const noexcept
        {
            if (value)
                BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(value));
        }
    };

    using algorithm_handle_t = std::unique_ptr<void, algorithm_closer_t>;
    using hash_handle_t = std::unique_ptr<void, hash_closer_t>;

    evidence_hash_result_t failure(std::string error)
    {
        return {false, {}, std::move(error)};
    }

    std::string ntstatus_error(std::string_view operation, NTSTATUS status)
    {
        return std::string(operation) + " failed with NTSTATUS " + std::to_string(static_cast<long>(status));
    }

    class sha256_stream_t
    {
    public:
        bool open(std::string& error)
        {
            BCRYPT_ALG_HANDLE raw_algorithm = nullptr;
            NTSTATUS status = BCryptOpenAlgorithmProvider(&raw_algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
            if (!BCRYPT_SUCCESS(status)) {
                error = ntstatus_error("BCryptOpenAlgorithmProvider", status);
                return false;
            }
            algorithm_.reset(raw_algorithm);

            DWORD object_bytes = 0;
            DWORD result_bytes = 0;
            status = BCryptGetProperty(raw_algorithm, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes), &result_bytes, 0);
            if (!BCRYPT_SUCCESS(status) || result_bytes != sizeof(object_bytes) || object_bytes == 0) {
                error = BCRYPT_SUCCESS(status) ? "invalid SHA-256 object length" :
                    ntstatus_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH)", status);
                return false;
            }
            object_.resize(object_bytes);
            BCRYPT_HASH_HANDLE raw_hash = nullptr;
            status = BCryptCreateHash(raw_algorithm, &raw_hash, object_.data(),
                static_cast<ULONG>(object_.size()), nullptr, 0, 0);
            if (!BCRYPT_SUCCESS(status)) {
                error = ntstatus_error("BCryptCreateHash", status);
                return false;
            }
            hash_.reset(raw_hash);
            return true;
        }

        bool update(const std::uint8_t* data, std::size_t size, std::string& error)
        {
            while (size != 0) {
                const auto chunk = static_cast<ULONG>(std::min<std::size_t>(size,
                    std::numeric_limits<ULONG>::max()));
                const NTSTATUS status = BCryptHashData(static_cast<BCRYPT_HASH_HANDLE>(hash_.get()),
                    const_cast<PUCHAR>(data), chunk, 0);
                if (!BCRYPT_SUCCESS(status)) {
                    error = ntstatus_error("BCryptHashData", status);
                    return false;
                }
                data += chunk;
                size -= chunk;
            }
            return true;
        }

        evidence_hash_result_t finish()
        {
            std::array<std::uint8_t, 32> digest{};
            const NTSTATUS status = BCryptFinishHash(static_cast<BCRYPT_HASH_HANDLE>(hash_.get()),
                digest.data(), static_cast<ULONG>(digest.size()), 0);
            if (!BCRYPT_SUCCESS(status))
                return failure(ntstatus_error("BCryptFinishHash", status));
            static constexpr char digits[] = "0123456789abcdef";
            std::string hex;
            hex.resize(digest.size() * 2);
            for (std::size_t index = 0; index < digest.size(); ++index) {
                hex[index * 2] = digits[digest[index] >> 4];
                hex[index * 2 + 1] = digits[digest[index] & 0x0f];
            }
            SecureZeroMemory(digest.data(), digest.size());
            return {true, std::move(hex), {}};
        }

    private:
        algorithm_handle_t algorithm_;
        hash_handle_t hash_;
        std::vector<std::uint8_t> object_;
    };

    bool is_within_root(const std::filesystem::path& root, const std::filesystem::path& candidate)
    {
        std::error_code error;
        const auto relative = std::filesystem::relative(candidate, root, error);
        if (error || relative.empty() || relative.is_absolute())
            return false;
        const auto first = relative.begin();
        return first == relative.end() || *first != "..";
    }
}

bool is_canonical_sha256(std::string_view value) noexcept
{
    if (value.size() != 64 || std::all_of(value.begin(), value.end(), [](char character) { return character == '0'; }))
        return false;
    return std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9') ||
            (character >= 'a' && character <= 'f');
    });
}

evidence_hash_result_t sha256_evidence_bytes(const void* bytes, std::size_t size)
{
    if (!bytes && size != 0)
        return failure("SHA-256 input pointer is null");
    sha256_stream_t stream;
    std::string error;
    if (!stream.open(error) || !stream.update(static_cast<const std::uint8_t*>(bytes), size, error))
        return failure(std::move(error));
    return stream.finish();
}

evidence_hash_result_t sha256_evidence_text(std::string_view text)
{
    return sha256_evidence_bytes(text.data(), text.size());
}

evidence_hash_result_t sha256_evidence_file(const std::filesystem::path& path,
    std::uint64_t maximum_bytes)
{
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error) || error)
        return failure("evidence path is not a regular file");
    const auto size = std::filesystem::file_size(path, error);
    if (error)
        return failure("cannot query evidence file size");
    if (size > maximum_bytes)
        return failure("evidence file exceeds the configured byte limit");
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
        return failure("cannot open evidence file");
    sha256_stream_t hash;
    std::string hash_error;
    if (!hash.open(hash_error))
        return failure(std::move(hash_error));
    std::vector<std::uint8_t> buffer(1024 * 1024);
    std::uint64_t consumed = 0;
    while (stream) {
        stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto count = stream.gcount();
        if (count < 0)
            return failure("negative evidence read length");
        if (count == 0)
            break;
        consumed += static_cast<std::uint64_t>(count);
        if (consumed > maximum_bytes)
            return failure("evidence file exceeded the configured byte limit while reading");
        if (!hash.update(buffer.data(), static_cast<std::size_t>(count), hash_error))
            return failure(std::move(hash_error));
    }
    if (stream.bad())
        return failure("evidence file read failed");
    if (consumed != size)
        return failure("evidence file size changed while hashing");
    return hash.finish();
}

evidence_hash_result_t sha256_repository_evidence_file(const std::filesystem::path& repository_root,
    std::string_view relative_path, std::uint64_t maximum_bytes)
{
    if (relative_path.empty())
        return failure("evidence relative path is empty");
    const auto relative = std::filesystem::u8path(std::string(relative_path));
    if (relative.is_absolute() || relative.has_root_name())
        return failure("evidence path must be repository-relative");
    for (const auto& part : relative) {
        if (part == "..")
            return failure("evidence path traversal is forbidden");
    }
    std::error_code error;
    const auto root = std::filesystem::weakly_canonical(repository_root, error);
    if (error || !std::filesystem::is_directory(root))
        return failure("repository root is invalid");
    const auto candidate = std::filesystem::weakly_canonical(root / relative, error);
    if (error || !is_within_root(root, candidate))
        return failure("evidence path escapes the repository root");
    return sha256_evidence_file(candidate, maximum_bytes);
}

evidence_hash_result_t canonical_json_sha256(nlohmann::json value,
    std::string_view excluded_top_level_field)
{
    if (!excluded_top_level_field.empty()) {
        if (!value.is_object())
            return failure("canonical hash subject must be an object");
        value.erase(std::string(excluded_top_level_field));
    }
    return sha256_evidence_text(value.dump());
}

bool verify_canonical_receipt_hash(const nlohmann::json& receipt,
    std::string_view hash_field, std::string& error)
{
    if (!receipt.is_object() || !receipt.contains(std::string(hash_field)) ||
        !receipt.at(std::string(hash_field)).is_string()) {
        error = "receipt hash field is absent or not a string";
        return false;
    }
    const auto expected = receipt.at(std::string(hash_field)).get<std::string>();
    if (!is_canonical_sha256(expected)) {
        error = "receipt hash is not a canonical lowercase SHA-256";
        return false;
    }
    const auto actual = canonical_json_sha256(receipt, hash_field);
    if (!actual.ok) {
        error = actual.error;
        return false;
    }
    if (actual.sha256 != expected) {
        error = "receipt hash does not match the canonical receipt body";
        return false;
    }
    error.clear();
    return true;
}
}
