#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

#include "workspace_identity.hpp"

#include "byte_provider.hpp"
#include "checked_range.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <memory>
#include <string_view>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace aida::analysis {
namespace {

static_assert(sizeof(binary_id_t) == 32);

struct algorithm_closer_t {
    void operator()(void* handle) const noexcept {
        if (handle)
            BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(handle), 0);
    }
};

struct hash_closer_t {
    void operator()(void* handle) const noexcept {
        if (handle)
            BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(handle));
    }
};

using algorithm_handle_t = std::unique_ptr<void, algorithm_closer_t>;
using hash_handle_t = std::unique_ptr<void, hash_closer_t>;

workspace_error_t crypto_error(const char* operation, NTSTATUS status) {
    auto error = make_workspace_error(workspace_error_code_t::hash_failure,
                                      std::string(operation) + " failed", "sha256");
    error.provider_status = static_cast<std::int64_t>(status);
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

class sha256_builder_t {
public:
    static workspace_result_t<sha256_builder_t> create() {
        BCRYPT_ALG_HANDLE raw_algorithm = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&raw_algorithm, BCRYPT_SHA256_ALGORITHM,
                                                      nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
            return workspace_result_t<sha256_builder_t>::failure(
                crypto_error("BCryptOpenAlgorithmProvider", status));
        algorithm_handle_t algorithm(raw_algorithm);

        DWORD object_size = 0;
        DWORD result_size = 0;
        status = BCryptGetProperty(raw_algorithm, BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                                   &result_size, 0);
        if (!BCRYPT_SUCCESS(status))
            return workspace_result_t<sha256_builder_t>::failure(
                crypto_error("BCryptGetProperty", status));
        if (result_size != sizeof(object_size) || object_size == 0 ||
            object_size > 1024U * 1024U)
            return workspace_result_t<sha256_builder_t>::failure(
                make_workspace_error(workspace_error_code_t::hash_failure,
                                     "BCrypt returned an invalid SHA-256 object size",
                                     "sha256"));

        std::vector<std::uint8_t> object(object_size);
        BCRYPT_HASH_HANDLE raw_hash = nullptr;
        status = BCryptCreateHash(raw_algorithm, &raw_hash, object.data(), object_size,
                                  nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status))
            return workspace_result_t<sha256_builder_t>::failure(
                crypto_error("BCryptCreateHash", status));

        return workspace_result_t<sha256_builder_t>::success(
            sha256_builder_t(std::move(algorithm), hash_handle_t(raw_hash), std::move(object)));
    }

    sha256_builder_t(sha256_builder_t&&) noexcept = default;
    sha256_builder_t& operator=(sha256_builder_t&&) noexcept = default;
    sha256_builder_t(const sha256_builder_t&) = delete;
    sha256_builder_t& operator=(const sha256_builder_t&) = delete;

    workspace_result_t<void> update(const void* data, std::size_t size) {
        const auto* cursor = static_cast<const std::uint8_t*>(data);
        while (size != 0) {
            const auto chunk = static_cast<ULONG>(std::min<std::size_t>(
                size, static_cast<std::size_t>(std::numeric_limits<ULONG>::max())));
            const NTSTATUS status = BCryptHashData(
                static_cast<BCRYPT_HASH_HANDLE>(hash_.get()),
                const_cast<PUCHAR>(cursor), chunk, 0);
            if (!BCRYPT_SUCCESS(status))
                return workspace_result_t<void>::failure(crypto_error("BCryptHashData", status));
            cursor += chunk;
            size -= chunk;
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> update_u64(std::uint64_t value) {
        std::array<std::uint8_t, 8> encoded{};
        for (std::size_t index = 0; index < encoded.size(); ++index)
            encoded[index] = static_cast<std::uint8_t>(value >> (index * 8));
        return update(encoded.data(), encoded.size());
    }

    workspace_result_t<void> update_field(std::string_view value) {
        auto length_result = update_u64(static_cast<std::uint64_t>(value.size()));
        if (!length_result)
            return length_result;
        return update(value.data(), value.size());
    }

    workspace_result_t<void> update_digest(const sha256_digest_t& digest) {
        auto length_result = update_u64(digest.bytes.size());
        if (!length_result)
            return length_result;
        return update(digest.bytes.data(), digest.bytes.size());
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
        return workspace_result_t<sha256_digest_t>::success(digest);
    }

private:
    sha256_builder_t(algorithm_handle_t algorithm, hash_handle_t hash,
                     std::vector<std::uint8_t> object)
        : algorithm_(std::move(algorithm)), object_(std::move(object)), hash_(std::move(hash)) {}

    algorithm_handle_t algorithm_;
    std::vector<std::uint8_t> object_;
    hash_handle_t hash_;
};

workspace_result_t<std::wstring> utf8_to_wide(const std::string& text) {
    constexpr std::size_t maximum_utf8_path_bytes = 131072;
    if (text.empty() || text.size() > maximum_utf8_path_bytes ||
        text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return workspace_result_t<std::wstring>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "path length is invalid", "identity"));
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                           static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "path is not valid UTF-8", "identity");
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), wide.data(), needed) != needed) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "UTF-8 path conversion failed", "identity");
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    return workspace_result_t<std::wstring>::success(std::move(wide));
}

workspace_result_t<std::string> wide_to_utf8(const std::wstring& text) {
    if (text.empty())
        return workspace_result_t<std::string>::success({});
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "wide path length is invalid", "identity"));
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                                           static_cast<int>(text.size()), nullptr, 0,
                                           nullptr, nullptr);
    if (needed <= 0) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "path conversion to UTF-8 failed", "identity");
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    std::string utf8(static_cast<std::size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), utf8.data(), needed,
                            nullptr, nullptr) != needed) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "path conversion to UTF-8 failed", "identity");
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    return workspace_result_t<std::string>::success(std::move(utf8));
}

workspace_result_t<std::string> normalize_member_path(std::string path) {
    if (path.empty() || path.size() > 32768)
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "member path length is invalid", "identity"));
    std::replace(path.begin(), path.end(), '\\', '/');
    if (!path.empty() && path.front() == '/')
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "member path must be relative", "identity"));
    std::vector<std::string> parts;
    std::size_t cursor = 0;
    while (cursor <= path.size()) {
        const std::size_t next = path.find('/', cursor);
        std::string part = path.substr(cursor, next == std::string::npos ? std::string::npos
                                                                        : next - cursor);
        if (!part.empty() && part != ".") {
            if (part == "..")
                return workspace_result_t<std::string>::failure(
                    make_workspace_error(workspace_error_code_t::invalid_argument,
                                         "member path escapes its container", "identity"));
            auto valid_part = utf8_to_wide(part);
            if (!valid_part)
                return workspace_result_t<std::string>::failure(valid_part.error());
            parts.push_back(std::move(part));
        }
        if (next == std::string::npos)
            break;
        cursor = next + 1;
    }
    if (parts.empty())
        return workspace_result_t<std::string>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "member path has no components", "identity"));
    std::string normalized;
    for (const auto& part : parts) {
        if (!normalized.empty())
            normalized.push_back('/');
        normalized.append(part);
    }
    return workspace_result_t<std::string>::success(std::move(normalized));
}

workspace_result_t<binary_id_t> derive_binary_id(const workspace_identity_input_t& input,
                                                 const std::string& source,
                                                 const std::optional<std::string>& member) {
    auto builder_result = sha256_builder_t::create();
    if (!builder_result)
        return workspace_result_t<binary_id_t>::failure(builder_result.error());
    auto builder = builder_result.take_value();
    const bool legacy_pe = input.format == format_id_t::pe32 ||
                           input.format == format_id_t::pe32_plus;
    const std::array<std::uint8_t, 8> domain{{'A', 'i', 'D', 'A', 'W', 'S',
                                               static_cast<std::uint8_t>(legacy_pe ? 1U : 2U), 0}};
    auto result = builder.update(domain.data(), domain.size());
    if (!result)
        return workspace_result_t<binary_id_t>::failure(result.error());
    result = builder.update_u64(static_cast<std::uint64_t>(input.target_kind));
    if (!result)
        return workspace_result_t<binary_id_t>::failure(result.error());
    result = builder.update_digest(input.content_hash);
    if (!result)
        return workspace_result_t<binary_id_t>::failure(result.error());
    result = builder.update_field(source);
    if (!result)
        return workspace_result_t<binary_id_t>::failure(result.error());
    result = builder.update_field(member.value_or(std::string{}));
    if (!result)
        return workspace_result_t<binary_id_t>::failure(result.error());
    result = builder.update_digest(input.load_profile_hash);
    if (!result)
        return workspace_result_t<binary_id_t>::failure(result.error());
    if (!legacy_pe) {
        result = builder.update_u64(static_cast<std::uint64_t>(input.format));
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_u64(static_cast<std::uint64_t>(input.architecture));
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_u64(static_cast<std::uint64_t>(input.architecture_mode));
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_u64(static_cast<std::uint64_t>(input.abi));
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_u64(static_cast<std::uint64_t>(input.endian));
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_u64(input.image_base);
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
    }
    if (input.target_kind == target_kind_t::live_snapshot) {
        if (!input.process || !input.module)
            return workspace_result_t<binary_id_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "live identity requires process and module identity", "identity"));
        result = builder.update_u64(input.process->pid);
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_u64(input.process->creation_time_100ns);
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_field(input.process->normalized_process_path);
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_u64(input.module->base);
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_u64(input.module->size);
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_field(input.module->normalized_name);
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        result = builder.update_field(input.module->normalized_path);
        if (!result)
            return workspace_result_t<binary_id_t>::failure(result.error());
        if (input.module->content_hash) {
            result = builder.update_digest(*input.module->content_hash);
            if (!result)
                return workspace_result_t<binary_id_t>::failure(result.error());
        } else {
            result = builder.update_u64(0);
            if (!result)
                return workspace_result_t<binary_id_t>::failure(result.error());
        }
    }
    return builder.finish();
}

std::int64_t timepoint_ticks(std::chrono::steady_clock::time_point value) noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(value.time_since_epoch()).count();
}

}

bool binary_id_t::empty() const noexcept {
    std::uint8_t aggregate = 0;
    for (const auto value : bytes)
        aggregate |= value;
    return aggregate == 0;
}

std::string binary_id_t::to_hex() const {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string text(bytes.size() * 2, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        text[index * 2] = alphabet[bytes[index] >> 4];
        text[index * 2 + 1] = alphabet[bytes[index] & 0x0f];
    }
    return text;
}

std::optional<binary_id_t> binary_id_t::from_hex(const std::string& text) noexcept {
    if (text.size() != 64)
        return std::nullopt;
    binary_id_t result;
    auto nibble = [](char value) -> int {
        if (value >= '0' && value <= '9')
            return value - '0';
        if (value >= 'a' && value <= 'f')
            return value - 'a' + 10;
        if (value >= 'A' && value <= 'F')
            return value - 'A' + 10;
        return -1;
    };
    for (std::size_t index = 0; index < result.bytes.size(); ++index) {
        const int high = nibble(text[index * 2]);
        const int low = nibble(text[index * 2 + 1]);
        if (high < 0 || low < 0)
            return std::nullopt;
        result.bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return result;
}

bool binary_id_t::constant_time_equal(const binary_id_t& other) const noexcept {
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index)
        difference |= static_cast<std::uint8_t>(bytes[index] ^ other.bytes[index]);
    return difference == 0;
}

std::size_t binary_id_hash_t::operator()(const binary_id_t& id) const noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const auto value : id.bytes) {
        hash ^= value;
        hash *= 1099511628211ULL;
    }
    if constexpr (sizeof(std::size_t) < sizeof(hash))
        hash ^= hash >> 32;
    return static_cast<std::size_t>(hash);
}

const char* workspace_error_code_name(workspace_error_code_t code) noexcept {
    switch (code) {
    case workspace_error_code_t::none: return "NONE";
    case workspace_error_code_t::range_overflow: return "RANGE_OVERFLOW";
    case workspace_error_code_t::out_of_range: return "OUT_OF_RANGE";
    case workspace_error_code_t::file_changed: return "FILE_CHANGED";
    case workspace_error_code_t::malformed_pe: return "MALFORMED_PE";
    case workspace_error_code_t::unsupported_pe_arch: return "UNSUPPORTED_PE_ARCH";
    case workspace_error_code_t::cancelled: return "CANCELLED";
    case workspace_error_code_t::deadline_exceeded: return "DEADLINE_EXCEEDED";
    case workspace_error_code_t::stale_generation: return "STALE_GENERATION";
    case workspace_error_code_t::target_required: return "TARGET_REQUIRED";
    case workspace_error_code_t::target_conflict: return "TARGET_CONFLICT";
    case workspace_error_code_t::target_ambiguous: return "TARGET_AMBIGUOUS";
    case workspace_error_code_t::target_not_found: return "TARGET_NOT_FOUND";
    case workspace_error_code_t::target_stale: return "TARGET_STALE";
    case workspace_error_code_t::self_target_refused: return "SELF_TARGET_REFUSED";
    case workspace_error_code_t::live_target_bulk_analysis_unsupported: return "LIVE_TARGET_BULK_ANALYSIS_UNSUPPORTED";
    case workspace_error_code_t::revision_conflict: return "REVISION_CONFLICT";
    case workspace_error_code_t::persistence_failure: return "PERSISTENCE_FAILURE";
    case workspace_error_code_t::invalid_argument: return "INVALID_ARGUMENT";
    case workspace_error_code_t::io_failure: return "IO_FAILURE";
    case workspace_error_code_t::hash_failure: return "HASH_FAILURE";
    case workspace_error_code_t::provider_unavailable: return "PROVIDER_UNAVAILABLE";
    case workspace_error_code_t::duplicate_target: return "DUPLICATE_TARGET";
    case workspace_error_code_t::workspace_closing: return "WORKSPACE_CLOSING";
    case workspace_error_code_t::unsupported_address_space: return "UNSUPPORTED_ADDRESS_SPACE";
    case workspace_error_code_t::limit_exceeded: return "LIMIT_EXCEEDED";
    case workspace_error_code_t::decode_failure: return "DECODE_FAILURE";
    case workspace_error_code_t::integrity_failure: return "INTEGRITY_FAILURE";
    case workspace_error_code_t::analysis_in_progress: return "ANALYSIS_IN_PROGRESS";
    case workspace_error_code_t::service_conflict: return "SERVICE_CONFLICT";
    case workspace_error_code_t::substitution_rejected: return "SUBSTITUTION_REJECTED";
    case workspace_error_code_t::malformed_image: return "MALFORMED_IMAGE";
    case workspace_error_code_t::unsupported_format: return "UNSUPPORTED_FORMAT";
    case workspace_error_code_t::provider_binding_mismatch: return "PROVIDER_BINDING_MISMATCH";
    }
    return "UNKNOWN";
}

std::string workspace_error_t::stable_code() const {
    return workspace_error_code_name(code);
}

workspace_error_t make_workspace_error(workspace_error_code_t code, std::string message,
                                       std::string phase) {
    workspace_error_t error;
    error.code = code;
    error.message = std::move(message);
    error.phase = std::move(phase);
    return error;
}

bool cancellation_token_t::cancellation_requested() const noexcept {
    return state_ && state_->requested.load(std::memory_order_acquire);
}

bool cancellation_token_t::deadline_exceeded() const noexcept {
    if (!state_)
        return false;
    const auto ticks = state_->deadline_ticks.load(std::memory_order_acquire);
    return ticks != 0 && timepoint_ticks(std::chrono::steady_clock::now()) >= ticks;
}

bool cancellation_token_t::stop_requested() const noexcept {
    return cancellation_requested() || deadline_exceeded();
}

std::optional<std::chrono::steady_clock::time_point> cancellation_token_t::deadline() const noexcept {
    if (!state_)
        return std::nullopt;
    const auto ticks = state_->deadline_ticks.load(std::memory_order_acquire);
    if (ticks == 0)
        return std::nullopt;
    return std::chrono::steady_clock::time_point(std::chrono::nanoseconds(ticks));
}

cancellation_source_t::cancellation_source_t()
    : state_(std::make_shared<cancellation_token_t::state_t>()) {}

cancellation_source_t::cancellation_source_t(
    std::optional<std::chrono::steady_clock::time_point> deadline)
    : cancellation_source_t() {
    set_deadline(deadline);
}

cancellation_token_t cancellation_source_t::token() const noexcept {
    return cancellation_token_t(state_);
}

void cancellation_source_t::request_cancel() noexcept {
    state_->requested.store(true, std::memory_order_release);
}

void cancellation_source_t::set_deadline(
    std::optional<std::chrono::steady_clock::time_point> deadline) noexcept {
    state_->deadline_ticks.store(deadline ? timepoint_ticks(*deadline) : 0,
                                 std::memory_order_release);
}

workspace_identity_t::workspace_identity_t(
    binary_id_t binary_id, workspace_identity_input_t input,
    std::string normalized_source_path,
    std::optional<std::string> normalized_member_path,
    std::string safe_bin_name)
    : binary_id_(binary_id),
      bin_name_(std::move(safe_bin_name)),
      normalized_source_path_(std::move(normalized_source_path)),
      normalized_member_path_(std::move(normalized_member_path)),
      content_hash_(input.content_hash),
      load_profile_hash_(input.load_profile_hash),
      target_kind_(input.target_kind),
      format_(input.format),
      architecture_(input.architecture),
      architecture_mode_(input.architecture_mode),
      abi_(input.abi),
      endian_(input.endian),
      image_base_(input.image_base),
      process_(std::move(input.process)),
      module_(std::move(input.module)) {}

workspace_result_t<std::shared_ptr<const workspace_identity_t>>
make_workspace_identity(workspace_identity_input_t input) {
    if (input.content_hash.empty() || input.load_profile_hash.empty())
        return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "content and load-profile hashes are required", "identity"));
    auto source_result = normalize_utf8_path(input.source_path, input.target_kind == target_kind_t::static_file);
    if (!source_result)
        return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(source_result.error());
    std::optional<std::string> member;
    if (input.member_path) {
        auto member_result = normalize_member_path(*input.member_path);
        if (!member_result)
            return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(member_result.error());
        member = member_result.take_value();
    }
    if (input.format == format_id_t::pe32 &&
        input.architecture_mode == architecture_mode_t::unknown)
        input.architecture_mode = architecture_mode_t::x86_32;
    if (input.format == format_id_t::pe32_plus &&
        input.architecture_mode == architecture_mode_t::unknown)
        input.architecture_mode = architecture_mode_t::x86_64;
    const bool pe_identity = input.format == format_id_t::pe32 ||
                             input.format == format_id_t::pe32_plus;
    const bool pe_valid = (!pe_identity ||
        (input.endian == endian_t::little &&
         ((input.format == format_id_t::pe32 &&
           input.architecture == architecture_id_t::x86 &&
           input.architecture_mode == architecture_mode_t::x86_32 &&
           input.abi == abi_id_t::windows_x86) ||
          (input.format == format_id_t::pe32_plus &&
           input.architecture == architecture_id_t::x86_64 &&
           input.architecture_mode == architecture_mode_t::x86_64 &&
           input.abi == abi_id_t::windows_x64) ||
          (input.format == format_id_t::pe32_plus &&
           input.architecture == architecture_id_t::aarch64 &&
           input.architecture_mode == architecture_mode_t::aarch64 &&
           input.abi == abi_id_t::windows_arm64) ||
          (input.format == format_id_t::pe32_plus &&
           input.architecture == architecture_id_t::arm64ec &&
           input.architecture_mode == architecture_mode_t::aarch64 &&
           input.abi == abi_id_t::windows_arm64ec))));
    if (input.format == format_id_t::unknown || input.format > format_id_t::raw_code ||
        input.architecture == architecture_id_t::unknown ||
        input.architecture > architecture_id_t::dalvik_bytecode ||
        input.architecture_mode == architecture_mode_t::unknown ||
        input.architecture_mode > architecture_mode_t::dalvik ||
        input.abi == abi_id_t::unknown ||
        input.abi > abi_id_t::dalvik || input.endian > endian_t::big ||
        !workspace_architecture_mode_matches(input.architecture, input.architecture_mode) ||
        !pe_valid) {
        return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
            make_workspace_error(pe_identity ? workspace_error_code_t::unsupported_pe_arch
                                             : workspace_error_code_t::unsupported_format,
                                 "workspace format, architecture, mode, ABI, and endian are inconsistent",
                                 "identity"));
    }
    if (input.target_kind == target_kind_t::static_file) {
        if (input.process || input.module)
            return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "static identity cannot contain live process state",
                                     "identity"));
    } else if (input.target_kind == target_kind_t::live_snapshot) {
        if (!input.process || !input.module || input.process->pid == 0 ||
            input.process->creation_time_100ns == 0 || input.module->base == 0 ||
            input.module->size == 0 || input.module->normalized_name.empty() ||
            input.module->normalized_path.empty() ||
            (input.module->content_hash && input.module->content_hash->empty()))
            return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "live identity is incomplete", "identity"));
        auto process_path = normalize_utf8_path(input.process->normalized_process_path, false);
        auto folded_module_path = normalize_target_name(input.module->normalized_path);
        const bool nt_module_path =
            folded_module_path.rfind("\\device\\", 0) == 0 ||
            folded_module_path.rfind("\\systemroot\\", 0) == 0 ||
            folded_module_path.rfind("\\??\\", 0) == 0;
        auto module_path = nt_module_path
            ? workspace_result_t<std::string>::success(std::move(folded_module_path))
            : normalize_utf8_path(input.module->normalized_path, false);
        if (!process_path || !module_path)
            return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
                !process_path ? process_path.error() : module_path.error());
        input.process->normalized_process_path = process_path.take_value();
        input.module->normalized_path = module_path.take_value();
        auto module_name = utf8_to_wide(input.module->normalized_name);
        if (!module_name)
            return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
                module_name.error());
        input.module->normalized_name = normalize_target_name(input.module->normalized_name);
        if (input.module->normalized_name.empty() ||
            input.module->normalized_name.size() > 32768 ||
            source_result.value() != input.process->normalized_process_path ||
            input.image_base != input.module->base)
            return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "live identity source or module binding is inconsistent",
                                     "identity"));
        std::uint64_t module_end = 0;
        if (!checked_add_u64(input.module->base, input.module->size, module_end))
            return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "live module range overflowed", "identity"));
    } else {
        return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace target kind is invalid", "identity"));
    }
    std::string bin_name = input.bin_name;
    if (bin_name.empty()) {
        const auto slash = source_result.value().find_last_of("\\/");
        bin_name = slash == std::string::npos ? source_result.value()
                                               : source_result.value().substr(slash + 1);
    }
    if (bin_name.empty() || bin_name.size() > 32768)
        return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "binary name is invalid", "identity"));
    auto bin_name_utf8 = utf8_to_wide(bin_name);
    if (!bin_name_utf8)
        return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(
            bin_name_utf8.error());
    auto binary_id_result = derive_binary_id(input, source_result.value(), member);
    if (!binary_id_result)
        return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::failure(binary_id_result.error());
    auto identity = std::shared_ptr<const workspace_identity_t>(new workspace_identity_t(
        binary_id_result.take_value(), std::move(input), source_result.take_value(),
        std::move(member), std::move(bin_name)));
    return workspace_result_t<std::shared_ptr<const workspace_identity_t>>::success(std::move(identity));
}

workspace_result_t<sha256_digest_t> sha256_bytes(const void* data, std::size_t size,
                                                const cancellation_token_t& cancel) {
    if (size != 0 && !data)
        return workspace_result_t<sha256_digest_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "hash input is null", "sha256"));
    if (cancel.stop_requested())
        return workspace_result_t<sha256_digest_t>::failure(stop_error(cancel, "sha256"));
    auto builder_result = sha256_builder_t::create();
    if (!builder_result)
        return workspace_result_t<sha256_digest_t>::failure(builder_result.error());
    auto builder = builder_result.take_value();
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t completed = 0;
    constexpr std::size_t cancellation_chunk = 4U * 1024U * 1024U;
    while (completed < size) {
        if (cancel.stop_requested())
            return workspace_result_t<sha256_digest_t>::failure(stop_error(cancel, "sha256"));
        const auto amount = std::min(cancellation_chunk, size - completed);
        auto update_result = builder.update(bytes + completed, amount);
        if (!update_result)
            return workspace_result_t<sha256_digest_t>::failure(update_result.error());
        completed += amount;
    }
    return builder.finish();
}

workspace_result_t<sha256_digest_t> sha256_text(const std::string& text,
                                               const cancellation_token_t& cancel) {
    return sha256_bytes(text.data(), text.size(), cancel);
}

workspace_result_t<sha256_digest_t> sha256_provider(const byte_provider_t& provider,
                                                   const cancellation_token_t& cancel,
                                                   std::uint64_t chunk_size) {
    if (chunk_size == 0 || chunk_size > 64ULL * 1024ULL * 1024ULL)
        return workspace_result_t<sha256_digest_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "hash chunk size is outside the supported range", "sha256"));
    auto builder_result = sha256_builder_t::create();
    if (!builder_result)
        return workspace_result_t<sha256_digest_t>::failure(builder_result.error());
    auto builder = builder_result.take_value();
    std::uint64_t offset = 0;
    while (offset < provider.size()) {
        if (cancel.stop_requested())
            return workspace_result_t<sha256_digest_t>::failure(stop_error(cancel, "sha256"));
        const std::uint64_t remaining = provider.size() - offset;
        const std::uint64_t amount = std::min(chunk_size, remaining);
        auto lease_result = provider.lease(offset, amount, cancel);
        if (!lease_result)
            return workspace_result_t<sha256_digest_t>::failure(lease_result.error());
        const auto& view = lease_result.value();
        auto update_result = builder.update(view.data(), view.size());
        if (!update_result)
            return workspace_result_t<sha256_digest_t>::failure(update_result.error());
        offset += amount;
    }
    return builder.finish();
}

workspace_result_t<std::string> normalize_utf8_path(const std::string& path,
                                                    bool require_existing) {
    auto wide_result = utf8_to_wide(path);
    if (!wide_result)
        return workspace_result_t<std::string>::failure(wide_result.error());
    DWORD required = GetFullPathNameW(wide_result.value().c_str(), 0, nullptr, nullptr);
    if (required == 0) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to resolve full path", "identity");
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    std::wstring full(static_cast<std::size_t>(required), L'\0');
    const DWORD written = GetFullPathNameW(wide_result.value().c_str(), required,
                                           full.data(), nullptr);
    if (written == 0 || written >= required) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to resolve full path", "identity");
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    full.resize(written);
    const DWORD attributes = GetFileAttributesW(full.c_str());
    if (require_existing && attributes == INVALID_FILE_ATTRIBUTES) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "source path does not exist", "identity");
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        const DWORD long_required = GetLongPathNameW(full.c_str(), nullptr, 0);
        if (long_required != 0) {
            std::wstring long_path(static_cast<std::size_t>(long_required), L'\0');
            const DWORD long_written = GetLongPathNameW(full.c_str(), long_path.data(), long_required);
            if (long_written != 0 && long_written < long_required) {
                long_path.resize(long_written);
                full = std::move(long_path);
            }
        }
    }
    if (full.rfind(L"\\\\?\\UNC\\", 0) == 0)
        full = L"\\\\" + full.substr(8);
    else if (full.rfind(L"\\\\?\\", 0) == 0)
        full.erase(0, 4);
    std::replace(full.begin(), full.end(), L'/', L'\\');
    while (full.size() > 3 && full.back() == L'\\')
        full.pop_back();
    return wide_to_utf8(full);
}

std::string normalize_target_name(std::string name) {
    auto wide_result = utf8_to_wide(name);
    if (wide_result) {
        const auto& wide = wide_result.value();
        const int needed = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE,
                                         wide.data(), static_cast<int>(wide.size()),
                                         nullptr, 0, nullptr, nullptr, 0);
        if (needed > 0) {
            std::wstring lowercase(static_cast<std::size_t>(needed), L'\0');
            if (LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE,
                              wide.data(), static_cast<int>(wide.size()),
                              lowercase.data(), needed, nullptr, nullptr, 0) == needed) {
                auto utf8_result = wide_to_utf8(lowercase);
                if (utf8_result)
                    return utf8_result.take_value();
            }
        }
    }
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return name;
}

}
