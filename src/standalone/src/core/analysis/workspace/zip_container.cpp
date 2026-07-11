#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "zip_container.hpp"

#include "checked_range.hpp"
#include "jar_container.hpp"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "Normaliz.lib")

namespace aida::analysis {
namespace {

constexpr std::uint32_t zip_local_header_signature = 0x04034b50U;
constexpr std::uint32_t zip_central_header_signature = 0x02014b50U;
constexpr std::uint32_t zip_eocd_signature = 0x06054b50U;
constexpr std::uint32_t zip64_eocd_signature = 0x06064b50U;
constexpr std::uint32_t zip64_locator_signature = 0x07064b50U;
constexpr std::uint32_t zip_data_descriptor_signature = 0x08074b50U;
constexpr std::uint32_t zip_central_signature_signature = 0x05054b50U;
constexpr std::uint16_t zip64_extra_id = 0x0001U;
constexpr std::uint16_t unicode_path_extra_id = 0x7075U;
constexpr std::uint16_t zip_method_stored = 0U;
constexpr std::uint16_t zip_method_deflate = 8U;
constexpr std::uint16_t zip_flag_data_descriptor = 0x0008U;
constexpr std::uint16_t zip_flag_utf8 = 0x0800U;
constexpr std::uint16_t zip_allowed_stored_flags = zip_flag_data_descriptor | zip_flag_utf8;
constexpr std::uint16_t zip_allowed_deflate_flags = zip_allowed_stored_flags | 0x0006U;
constexpr std::uint64_t zip_eocd_fixed_size = 22U;
constexpr std::uint64_t zip64_locator_size = 20U;
constexpr std::uint64_t zip64_eocd_minimum_size = 56U;
constexpr std::uint64_t zip_central_header_size = 46U;
constexpr std::uint64_t zip_local_header_size = 30U;

std::uint64_t saturating_add(std::uint64_t lhs, std::uint64_t rhs) noexcept {
    return rhs > (std::numeric_limits<std::uint64_t>::max)() - lhs
        ? (std::numeric_limits<std::uint64_t>::max)()
        : lhs + rhs;
}

std::uint64_t saturating_multiply(std::uint64_t lhs,
                                  std::uint64_t rhs) noexcept {
    if (lhs != 0 && rhs > (std::numeric_limits<std::uint64_t>::max)() / lhs)
        return (std::numeric_limits<std::uint64_t>::max)();
    return lhs * rhs;
}

std::uint16_t read_u16_le(const std::uint8_t* value) noexcept {
    return static_cast<std::uint16_t>(value[0]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(value[1]) << 8U);
}

std::uint32_t read_u32_le(const std::uint8_t* value) noexcept {
    return static_cast<std::uint32_t>(value[0]) |
           (static_cast<std::uint32_t>(value[1]) << 8U) |
           (static_cast<std::uint32_t>(value[2]) << 16U) |
           (static_cast<std::uint32_t>(value[3]) << 24U);
}

std::uint64_t read_u64_le(const std::uint8_t* value) noexcept {
    return static_cast<std::uint64_t>(value[0]) |
           (static_cast<std::uint64_t>(value[1]) << 8U) |
           (static_cast<std::uint64_t>(value[2]) << 16U) |
           (static_cast<std::uint64_t>(value[3]) << 24U) |
           (static_cast<std::uint64_t>(value[4]) << 32U) |
           (static_cast<std::uint64_t>(value[5]) << 40U) |
           (static_cast<std::uint64_t>(value[6]) << 48U) |
           (static_cast<std::uint64_t>(value[7]) << 56U);
}

workspace_error_t zip_error(workspace_error_code_t code, std::string message,
                            std::string phase,
                            std::optional<std::uint64_t> offset = {},
                            std::optional<std::uint64_t> size = {}) {
    auto error = make_workspace_error(code, std::move(message), std::move(phase));
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t malformed_error(std::string message, std::string phase,
                                  std::optional<std::uint64_t> offset = {},
                                  std::optional<std::uint64_t> size = {}) {
    return zip_error(workspace_error_code_t::malformed_image, std::move(message),
                     std::move(phase), offset, size);
}

workspace_error_t integrity_error(std::string message,
                                  std::optional<std::uint64_t> offset = {},
                                  std::optional<std::uint64_t> size = {}) {
    return zip_error(workspace_error_code_t::integrity_failure, std::move(message),
                     "zip_member_integrity", offset, size);
}

workspace_error_t limit_error(std::string message, std::string phase,
                              std::uint64_t value, std::uint64_t limit) {
    auto error = zip_error(workspace_error_code_t::limit_exceeded, std::move(message),
                           std::move(phase));
    error.details.emplace_back("value", std::to_string(value));
    error.details.emplace_back("limit", std::to_string(limit));
    return error;
}

workspace_error_t allocation_error(std::string phase, std::uint64_t size) {
    auto error = zip_error(workspace_error_code_t::limit_exceeded,
                           "ZIP operation could not allocate its bounded buffer",
                           std::move(phase), {}, size);
    return error;
}

class work_guard_t final {
public:
    work_guard_t(const zip_container_limits_t& limits,
                 const cancellation_token_t& cancel)
        : limits_(limits), cancel_(cancel), started_(std::chrono::steady_clock::now()) {}

    workspace_result_t<void> poll(const char* phase) {
        if (cancel_.deadline_exceeded()) {
            auto error = zip_error(workspace_error_code_t::deadline_exceeded,
                                   "ZIP operation deadline exceeded", phase);
            error.deadline = true;
            return workspace_result_t<void>::failure(std::move(error));
        }
        if (cancel_.cancellation_requested()) {
            auto error = zip_error(workspace_error_code_t::cancelled,
                                   "ZIP operation cancelled", phase);
            error.cancellation = true;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const auto elapsed = std::chrono::steady_clock::now() - started_;
        if (elapsed > limits_.max_elapsed) {
            auto error = zip_error(workspace_error_code_t::deadline_exceeded,
                                   "ZIP operation elapsed-time limit exceeded", phase);
            error.deadline = true;
            error.details.emplace_back(
                "max_elapsed_ms", std::to_string(limits_.max_elapsed.count()));
            return workspace_result_t<void>::failure(std::move(error));
        }
        bytes_since_poll_ = 0;
        records_since_poll_ = 0;
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> consume(std::uint64_t amount, const char* phase) {
        if (amount > limits_.max_work_bytes - work_bytes_) {
            return workspace_result_t<void>::failure(limit_error(
                "ZIP operation exceeded its work-byte budget", phase,
                saturating_add(work_bytes_, amount), limits_.max_work_bytes));
        }
        work_bytes_ += amount;
        if (amount >= limits_.cancellation_poll_bytes - bytes_since_poll_)
            return poll(phase);
        bytes_since_poll_ += amount;
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> visit_record(const char* phase) {
        ++records_since_poll_;
        if (records_since_poll_ >= limits_.cancellation_poll_records)
            return poll(phase);
        return workspace_result_t<void>::success();
    }

    const zip_container_limits_t& limits() const noexcept {
        return limits_;
    }

private:
    const zip_container_limits_t& limits_;
    const cancellation_token_t& cancel_;
    std::chrono::steady_clock::time_point started_;
    std::uint64_t work_bytes_ = 0;
    std::uint64_t bytes_since_poll_ = 0;
    std::uint32_t records_since_poll_ = 0;
};

workspace_result_t<void> validate_limits(const zip_container_limits_t& limits) {
    const auto max_size_t = static_cast<std::uint64_t>(
        (std::numeric_limits<std::size_t>::max)());
    if (limits.max_archive_size < zip_eocd_fixed_size ||
        limits.max_member_count == 0 ||
        limits.max_member_count > max_size_t ||
        limits.max_central_directory_size == 0 ||
        limits.max_member_compressed_size == 0 ||
        limits.max_member_uncompressed_size == 0 ||
        limits.max_member_uncompressed_size > max_size_t ||
        limits.max_aggregate_compressed_size == 0 ||
        limits.max_aggregate_uncompressed_size == 0 ||
        limits.max_expansion_ratio == 0 ||
        limits.max_eocd_search_size < zip_eocd_fixed_size ||
        limits.max_eocd_search_size > 64ULL * 1024ULL * 1024ULL ||
        limits.max_zip64_eocd_size < zip64_eocd_minimum_size ||
        limits.max_work_bytes == 0 ||
        limits.max_io_chunk_size == 0 ||
        limits.max_io_chunk_size > static_cast<std::uint64_t>((std::numeric_limits<uInt>::max)()) ||
        limits.max_io_chunk_size > max_size_t ||
        limits.cancellation_poll_bytes == 0 ||
        limits.cancellation_poll_records == 0 ||
        limits.max_nesting_depth == 0 || limits.max_nesting_depth > 64 ||
        limits.max_path_components == 0 ||
        limits.max_normalized_path_size == 0 ||
        limits.max_normalized_path_size > 32768 ||
        limits.max_elapsed.count() <= 0) {
        return workspace_result_t<void>::failure(zip_error(
            workspace_error_code_t::invalid_argument,
            "ZIP container limits are invalid", "zip_limits"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_source_identity(
    const byte_provider_t& provider) {
    const auto& identity = provider.identity();
    if (identity.normalized_source.empty() || identity.size != provider.size())
        return workspace_result_t<void>::failure(zip_error(
            workspace_error_code_t::provider_binding_mismatch,
            "ZIP source identity does not match its provider", "zip_open"));
    if (!identity.member)
        return workspace_result_t<void>::success();
    const auto& member = *identity.member;
    std::uint64_t container_end = 0;
    if (member.normalized_member_path.empty() ||
        member.normalized_member_path.size() > 32768 ||
        member.normalized_member_path.front() == '/' ||
        member.normalized_member_path.find('\\') != std::string::npos ||
        member.normalized_member_path.find('\0') != std::string::npos ||
        member.depth == 0 || member.depth > 64 ||
        member.compressed_size == 0 ||
        member.uncompressed_size != provider.size() ||
        (!member.compressed &&
         member.compressed_size != member.uncompressed_size) ||
        !checked_add_u64(member.container_offset, member.compressed_size,
                         container_end))
        return workspace_result_t<void>::failure(zip_error(
            workspace_error_code_t::provider_binding_mismatch,
            "ZIP parent-member provenance is invalid", "zip_open"));
    std::size_t component_start = 0;
    while (component_start < member.normalized_member_path.size()) {
        const auto separator = member.normalized_member_path.find(
            '/', component_start);
        const auto component_end = separator == std::string::npos
            ? member.normalized_member_path.size() : separator;
        const auto component_size = component_end - component_start;
        if (component_size == 0 ||
            (component_size == 1 &&
             member.normalized_member_path[component_start] == '.') ||
            (component_size == 2 &&
             member.normalized_member_path[component_start] == '.' &&
             member.normalized_member_path[component_start + 1] == '.'))
            return workspace_result_t<void>::failure(zip_error(
                workspace_error_code_t::provider_binding_mismatch,
                "ZIP parent-member path provenance is invalid", "zip_open"));
        if (separator == std::string::npos)
            break;
        component_start = separator + 1;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> read_bounded(const byte_provider_t& provider,
                                      std::uint64_t offset, void* destination,
                                      std::uint64_t size, work_guard_t& work,
                                      const cancellation_token_t& cancel,
                                      const char* phase) {
    auto range = validate_span(offset, size, provider.size(), phase);
    if (!range)
        return workspace_result_t<void>::failure(std::move(range.error()));
    auto* output = static_cast<std::uint8_t*>(destination);
    std::uint64_t completed = 0;
    const std::uint64_t chunk_limit = (std::min)(
        work.limits().max_io_chunk_size, work.limits().cancellation_poll_bytes);
    while (completed < size) {
        const std::uint64_t chunk = (std::min)(chunk_limit, size - completed);
        auto consumed = work.consume(chunk, phase);
        if (!consumed)
            return consumed;
        std::uint64_t source_offset = 0;
        if (!checked_add_u64(offset, completed, source_offset))
            return workspace_result_t<void>::failure(malformed_error(
                "ZIP read offset overflowed", phase, offset, size));
        auto result = provider.read_exact(
            source_offset, output + static_cast<std::size_t>(completed), chunk, cancel);
        if (!result)
            return result;
        completed += chunk;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::vector<std::uint8_t>> read_vector_bounded(
    const byte_provider_t& provider, std::uint64_t offset, std::uint64_t size,
    work_guard_t& work, const cancellation_token_t& cancel, const char* phase) {
    std::size_t allocation = 0;
    if (!u64_to_size(size, allocation))
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            allocation_error(phase, size));
    std::vector<std::uint8_t> result(allocation);
    auto read = read_bounded(provider, offset, result.data(), size, work, cancel, phase);
    if (!read)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(std::move(read.error()));
    return workspace_result_t<std::vector<std::uint8_t>>::success(std::move(result));
}

template <std::size_t Size>
workspace_result_t<std::array<std::uint8_t, Size>> read_array_bounded(
    const byte_provider_t& provider, std::uint64_t offset, work_guard_t& work,
    const cancellation_token_t& cancel, const char* phase) {
    std::array<std::uint8_t, Size> result{};
    auto read = read_bounded(provider, offset, result.data(), Size, work, cancel, phase);
    if (!read)
        return workspace_result_t<std::array<std::uint8_t, Size>>::failure(
            std::move(read.error()));
    return workspace_result_t<std::array<std::uint8_t, Size>>::success(std::move(result));
}

workspace_result_t<std::wstring> decode_wide(const std::uint8_t* input,
                                             std::size_t size, UINT code_page,
                                             DWORD flags, const char* phase) {
    if (size == 0 || size > static_cast<std::size_t>(INT_MAX))
        return workspace_result_t<std::wstring>::failure(malformed_error(
            "ZIP member name byte length is invalid", phase, {}, size));
    const int source_size = static_cast<int>(size);
    const int required = MultiByteToWideChar(
        code_page, flags, reinterpret_cast<const char*>(input), source_size,
        nullptr, 0);
    if (required <= 0) {
        auto error = malformed_error("ZIP member name encoding is invalid", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    std::wstring output(static_cast<std::size_t>(required), L'\0');
    const int converted = MultiByteToWideChar(
        code_page, flags, reinterpret_cast<const char*>(input), source_size,
        output.data(), required);
    if (converted != required) {
        auto error = malformed_error("ZIP member name conversion failed", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    return workspace_result_t<std::wstring>::success(std::move(output));
}

workspace_result_t<std::wstring> normalize_wide(const std::wstring& input,
                                                NORM_FORM form,
                                                const char* phase) {
    if (input.empty() || input.size() > static_cast<std::size_t>(INT_MAX))
        return workspace_result_t<std::wstring>::failure(malformed_error(
            "ZIP member name cannot be normalized", phase));
    const int source_size = static_cast<int>(input.size());
    const int required = NormalizeString(form, input.data(), source_size, nullptr, 0);
    if (required <= 0) {
        auto error = malformed_error("ZIP member Unicode normalization failed", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    std::wstring output(static_cast<std::size_t>(required), L'\0');
    const int normalized = NormalizeString(
        form, input.data(), source_size, output.data(), required);
    if (normalized <= 0 || normalized > required) {
        auto error = malformed_error("ZIP member Unicode normalization failed", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    output.resize(static_cast<std::size_t>(normalized));
    return workspace_result_t<std::wstring>::success(std::move(output));
}

workspace_result_t<std::string> encode_utf8(const std::wstring& input,
                                            const char* phase) {
    if (input.empty() || input.size() > static_cast<std::size_t>(INT_MAX))
        return workspace_result_t<std::string>::failure(malformed_error(
            "ZIP member name cannot be encoded", phase));
    const int source_size = static_cast<int>(input.size());
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), source_size,
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        auto error = malformed_error("ZIP member UTF-8 encoding failed", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    std::string output(static_cast<std::size_t>(required), '\0');
    const int converted = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), source_size,
        output.data(), required, nullptr, nullptr);
    if (converted != required) {
        auto error = malformed_error("ZIP member UTF-8 encoding failed", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    return workspace_result_t<std::string>::success(std::move(output));
}

workspace_result_t<std::wstring> uppercase_invariant(const std::wstring& input,
                                                     const char* phase) {
    if (input.empty() || input.size() > static_cast<std::size_t>(INT_MAX))
        return workspace_result_t<std::wstring>::failure(malformed_error(
            "ZIP member name cannot be case mapped", phase));
    const int source_size = static_cast<int>(input.size());
    const int required = LCMapStringEx(
        LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE, input.data(), source_size,
        nullptr, 0, nullptr, nullptr, 0);
    if (required <= 0) {
        auto error = malformed_error("ZIP member case mapping failed", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    std::wstring output(static_cast<std::size_t>(required), L'\0');
    const int mapped = LCMapStringEx(
        LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE, input.data(), source_size,
        output.data(), required, nullptr, nullptr, 0);
    if (mapped <= 0 || mapped > required) {
        auto error = malformed_error("ZIP member case mapping failed", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    output.resize(static_cast<std::size_t>(mapped));
    return workspace_result_t<std::wstring>::success(std::move(output));
}

struct normalized_path_t {
    std::string path;
    std::string collision_key;
    std::uint32_t component_count = 0;
    bool directory_marker = false;
};

workspace_result_t<normalized_path_t> normalize_member_path(
    std::wstring decoded, const zip_container_limits_t& limits,
    const char* phase) {
    auto nfc_result = normalize_wide(decoded, NormalizationC, phase);
    if (!nfc_result)
        return workspace_result_t<normalized_path_t>::failure(
            std::move(nfc_result.error()));
    decoded = nfc_result.take_value();
    for (auto& value : decoded) {
        if (value == L'\\')
            value = L'/';
        if (value == L'\0' || value < L' ' || value == 0x7f)
            return workspace_result_t<normalized_path_t>::failure(malformed_error(
                "ZIP member path contains a forbidden control character", phase));
    }
    if (decoded.empty() || decoded.front() == L'/')
        return workspace_result_t<normalized_path_t>::failure(malformed_error(
            "ZIP member path is empty or absolute", phase));

    normalized_path_t result;
    result.directory_marker = decoded.back() == L'/';
    std::vector<std::wstring> components;
    std::size_t cursor = 0;
    while (cursor <= decoded.size()) {
        const std::size_t separator = decoded.find(L'/', cursor);
        const std::size_t end = separator == std::wstring::npos
            ? decoded.size() : separator;
        std::wstring component = decoded.substr(cursor, end - cursor);
        if (!component.empty() && component != L".") {
            if (component == L"..")
                return workspace_result_t<normalized_path_t>::failure(malformed_error(
                    "ZIP member path escapes its container", phase));
            if (component.back() == L'.' || component.back() == L' ' ||
                component.find(L':') != std::wstring::npos)
                return workspace_result_t<normalized_path_t>::failure(malformed_error(
                    "ZIP member path has an unsafe component", phase));
            components.push_back(std::move(component));
            if (components.size() > limits.max_path_components)
                return workspace_result_t<normalized_path_t>::failure(limit_error(
                    "ZIP member path nesting exceeds its limit", phase,
                    components.size(), limits.max_path_components));
        }
        if (separator == std::wstring::npos)
            break;
        cursor = separator + 1;
    }
    if (components.empty())
        return workspace_result_t<normalized_path_t>::failure(malformed_error(
            "ZIP member path has no usable component", phase));

    std::wstring normalized;
    for (std::size_t index = 0; index < components.size(); ++index) {
        if (index != 0)
            normalized.push_back(L'/');
        normalized.append(components[index]);
    }
    auto encoded_result = encode_utf8(normalized, phase);
    if (!encoded_result)
        return workspace_result_t<normalized_path_t>::failure(
            std::move(encoded_result.error()));
    result.path = encoded_result.take_value();
    if (result.path.size() > limits.max_normalized_path_size)
        return workspace_result_t<normalized_path_t>::failure(limit_error(
            "ZIP normalized member path exceeds its byte limit", phase,
            result.path.size(), limits.max_normalized_path_size));

    auto compatibility_result = normalize_wide(normalized, NormalizationKC, phase);
    if (!compatibility_result)
        return workspace_result_t<normalized_path_t>::failure(
            std::move(compatibility_result.error()));
    auto uppercase_result = uppercase_invariant(compatibility_result.value(), phase);
    if (!uppercase_result)
        return workspace_result_t<normalized_path_t>::failure(
            std::move(uppercase_result.error()));
    auto key_normalized_result = normalize_wide(
        uppercase_result.value(), NormalizationKC, phase);
    if (!key_normalized_result)
        return workspace_result_t<normalized_path_t>::failure(
            std::move(key_normalized_result.error()));
    auto key_result = encode_utf8(key_normalized_result.value(), phase);
    if (!key_result)
        return workspace_result_t<normalized_path_t>::failure(
            std::move(key_result.error()));
    result.collision_key = key_result.take_value();
    result.component_count = static_cast<std::uint32_t>(components.size());
    return workspace_result_t<normalized_path_t>::success(std::move(result));
}

struct extra_requirements_t {
    bool uncompressed_size = false;
    bool compressed_size = false;
    bool local_header_offset = false;
    bool disk_start = false;
};

struct extra_info_t {
    std::optional<std::uint64_t> uncompressed_size;
    std::optional<std::uint64_t> compressed_size;
    std::optional<std::uint64_t> local_header_offset;
    std::optional<std::uint32_t> disk_start;
    std::optional<std::vector<std::uint8_t>> unicode_path;
    bool has_zip64 = false;
};

std::uint32_t crc32_bytes(const std::uint8_t* data, std::size_t size) noexcept {
    uLong value = crc32(0L, Z_NULL, 0);
    std::size_t cursor = 0;
    while (cursor < size) {
        const auto chunk = static_cast<uInt>((std::min)(
            size - cursor,
            static_cast<std::size_t>((std::numeric_limits<uInt>::max)())));
        value = crc32(value, reinterpret_cast<const Bytef*>(data + cursor), chunk);
        cursor += chunk;
    }
    return static_cast<std::uint32_t>(value);
}

workspace_result_t<extra_info_t> parse_extra_fields(
    const std::vector<std::uint8_t>& extra,
    const std::vector<std::uint8_t>& raw_name,
    const extra_requirements_t& requirements, work_guard_t& work,
    const char* phase) {
    extra_info_t result;
    bool unicode_seen = false;
    std::size_t cursor = 0;
    while (cursor < extra.size()) {
        auto visited = work.visit_record(phase);
        if (!visited)
            return workspace_result_t<extra_info_t>::failure(
                std::move(visited.error()));
        if (extra.size() - cursor < 4)
            return workspace_result_t<extra_info_t>::failure(malformed_error(
                "ZIP extra field header is truncated", phase, cursor,
                extra.size() - cursor));
        const std::uint16_t identifier = read_u16_le(extra.data() + cursor);
        const std::uint16_t field_size = read_u16_le(extra.data() + cursor + 2);
        cursor += 4;
        if (field_size > extra.size() - cursor)
            return workspace_result_t<extra_info_t>::failure(malformed_error(
                "ZIP extra field payload is truncated", phase, cursor, field_size));
        const std::uint8_t* field = extra.data() + cursor;
        if (identifier == zip64_extra_id) {
            if (result.has_zip64)
                return workspace_result_t<extra_info_t>::failure(malformed_error(
                    "ZIP64 extra field is duplicated", phase));
            result.has_zip64 = true;
            std::size_t field_cursor = 0;
            const auto take_u64 = [&](std::optional<std::uint64_t>& destination)
                -> bool {
                if (field_size - field_cursor < 8)
                    return false;
                destination = read_u64_le(field + field_cursor);
                field_cursor += 8;
                return true;
            };
            if (requirements.uncompressed_size &&
                !take_u64(result.uncompressed_size))
                return workspace_result_t<extra_info_t>::failure(malformed_error(
                    "ZIP64 uncompressed size is missing", phase));
            if (requirements.compressed_size &&
                !take_u64(result.compressed_size))
                return workspace_result_t<extra_info_t>::failure(malformed_error(
                    "ZIP64 compressed size is missing", phase));
            if (requirements.local_header_offset &&
                !take_u64(result.local_header_offset))
                return workspace_result_t<extra_info_t>::failure(malformed_error(
                    "ZIP64 local-header offset is missing", phase));
            if (requirements.disk_start) {
                if (field_size - field_cursor < 4)
                    return workspace_result_t<extra_info_t>::failure(malformed_error(
                        "ZIP64 disk-start field is missing", phase));
                result.disk_start = read_u32_le(field + field_cursor);
            }
        } else if (identifier == unicode_path_extra_id) {
            if (unicode_seen)
                return workspace_result_t<extra_info_t>::failure(malformed_error(
                    "ZIP Unicode path extra field is duplicated", phase));
            unicode_seen = true;
            if (field_size < 5 || field[0] != 1)
                return workspace_result_t<extra_info_t>::failure(malformed_error(
                    "ZIP Unicode path extra field is invalid", phase));
            const std::uint32_t expected_crc = read_u32_le(field + 1);
            if (expected_crc != crc32_bytes(raw_name.data(), raw_name.size()))
                return workspace_result_t<extra_info_t>::failure(zip_error(
                    workspace_error_code_t::integrity_failure,
                    "ZIP Unicode path extra field CRC is invalid", phase));
            result.unicode_path = std::vector<std::uint8_t>(
                field + 5, field + field_size);
            if (result.unicode_path->empty())
                return workspace_result_t<extra_info_t>::failure(malformed_error(
                    "ZIP Unicode path extra field is empty", phase));
        }
        cursor += field_size;
    }
    if ((requirements.uncompressed_size && !result.uncompressed_size) ||
        (requirements.compressed_size && !result.compressed_size) ||
        (requirements.local_header_offset && !result.local_header_offset) ||
        (requirements.disk_start && !result.disk_start))
        return workspace_result_t<extra_info_t>::failure(malformed_error(
            "ZIP64 extra field does not satisfy required values", phase));
    return workspace_result_t<extra_info_t>::success(std::move(result));
}

workspace_result_t<normalized_path_t> resolve_member_path(
    const std::vector<std::uint8_t>& raw_name, std::uint16_t flags,
    const extra_info_t& extra, const zip_container_limits_t& limits,
    work_guard_t& work, const char* phase) {
    auto consumed = work.consume(raw_name.size(), phase);
    if (!consumed)
        return workspace_result_t<normalized_path_t>::failure(
            std::move(consumed.error()));
    const bool utf8 = (flags & zip_flag_utf8) != 0;
    auto decoded_result = decode_wide(
        raw_name.data(), raw_name.size(), utf8 ? CP_UTF8 : 437,
        utf8 ? MB_ERR_INVALID_CHARS : 0, phase);
    if (!decoded_result)
        return workspace_result_t<normalized_path_t>::failure(
            std::move(decoded_result.error()));
    std::wstring decoded = decoded_result.take_value();
    if (extra.unicode_path) {
        auto unicode_result = decode_wide(
            extra.unicode_path->data(), extra.unicode_path->size(), CP_UTF8,
            MB_ERR_INVALID_CHARS, phase);
        if (!unicode_result)
            return workspace_result_t<normalized_path_t>::failure(
                std::move(unicode_result.error()));
        if (utf8) {
            auto primary_nfc = normalize_wide(decoded, NormalizationC, phase);
            if (!primary_nfc)
                return workspace_result_t<normalized_path_t>::failure(
                    std::move(primary_nfc.error()));
            auto extra_nfc = normalize_wide(
                unicode_result.value(), NormalizationC, phase);
            if (!extra_nfc)
                return workspace_result_t<normalized_path_t>::failure(
                    std::move(extra_nfc.error()));
            if (primary_nfc.value() != extra_nfc.value())
                return workspace_result_t<normalized_path_t>::failure(zip_error(
                    workspace_error_code_t::integrity_failure,
                    "ZIP UTF-8 name conflicts with its Unicode path field", phase));
        }
        decoded = unicode_result.take_value();
    }
    return normalize_member_path(std::move(decoded), limits, phase);
}

struct eocd_t {
    std::uint16_t disk_number = 0;
    std::uint16_t central_disk = 0;
    std::uint16_t records_on_disk = 0;
    std::uint16_t record_count = 0;
    std::uint32_t central_size = 0;
    std::uint32_t central_offset = 0;
    std::uint64_t offset = 0;
};

struct zip64_eocd_t {
    std::uint64_t record_count = 0;
    std::uint64_t central_size = 0;
    std::uint64_t central_offset = 0;
    std::uint64_t offset = 0;
};

workspace_result_t<eocd_t> find_eocd(
    const byte_provider_t& provider, const zip_container_limits_t& limits,
    work_guard_t& work, const cancellation_token_t& cancel) {
    const std::uint64_t file_size = provider.size();
    if (file_size < zip_eocd_fixed_size)
        return workspace_result_t<eocd_t>::failure(malformed_error(
            "File is too small to contain a ZIP end record", "zip_eocd"));
    const std::uint64_t search_size = (std::min)(
        file_size, limits.max_eocd_search_size);
    const std::uint64_t search_offset = file_size - search_size;
    auto tail_result = read_vector_bounded(
        provider, search_offset, search_size, work, cancel, "zip_eocd");
    if (!tail_result)
        return workspace_result_t<eocd_t>::failure(
            std::move(tail_result.error()));
    auto tail = tail_result.take_value();
    std::optional<std::size_t> found;
    std::uint64_t scanned = 0;
    std::size_t cursor = tail.size() - static_cast<std::size_t>(zip_eocd_fixed_size) + 1;
    while (cursor != 0) {
        --cursor;
        ++scanned;
        if (scanned >= limits.cancellation_poll_bytes) {
            auto consumed = work.consume(scanned, "zip_eocd");
            if (!consumed)
                return workspace_result_t<eocd_t>::failure(
                    std::move(consumed.error()));
            scanned = 0;
        }
        if (read_u32_le(tail.data() + cursor) != zip_eocd_signature)
            continue;
        const std::uint16_t comment_size = read_u16_le(tail.data() + cursor + 20);
        const std::uint64_t candidate_end =
            static_cast<std::uint64_t>(cursor) + zip_eocd_fixed_size + comment_size;
        if (candidate_end == tail.size()) {
            found = cursor;
            break;
        }
    }
    if (scanned != 0) {
        auto consumed = work.consume(scanned, "zip_eocd");
        if (!consumed)
            return workspace_result_t<eocd_t>::failure(
                std::move(consumed.error()));
    }
    if (!found)
        return workspace_result_t<eocd_t>::failure(malformed_error(
            "ZIP end-of-central-directory record was not found", "zip_eocd"));
    const std::uint8_t* record = tail.data() + *found;
    eocd_t result;
    result.disk_number = read_u16_le(record + 4);
    result.central_disk = read_u16_le(record + 6);
    result.records_on_disk = read_u16_le(record + 8);
    result.record_count = read_u16_le(record + 10);
    result.central_size = read_u32_le(record + 12);
    result.central_offset = read_u32_le(record + 16);
    result.offset = search_offset + *found;
    return workspace_result_t<eocd_t>::success(std::move(result));
}

bool eocd_requires_zip64(const eocd_t& eocd) noexcept {
    return eocd.disk_number == 0xffffU || eocd.central_disk == 0xffffU ||
           eocd.records_on_disk == 0xffffU || eocd.record_count == 0xffffU ||
           eocd.central_size == 0xffffffffU ||
           eocd.central_offset == 0xffffffffU;
}

workspace_result_t<std::optional<zip64_eocd_t>> read_zip64_eocd(
    const byte_provider_t& provider, const eocd_t& eocd,
    const zip_container_limits_t& limits, work_guard_t& work,
    const cancellation_token_t& cancel) {
    const bool required = eocd_requires_zip64(eocd);
    if (eocd.offset < zip64_locator_size) {
        if (required)
            return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
                malformed_error("ZIP64 locator is missing", "zip64_eocd"));
        return workspace_result_t<std::optional<zip64_eocd_t>>::success(std::nullopt);
    }
    const std::uint64_t locator_offset = eocd.offset - zip64_locator_size;
    auto locator_result = read_array_bounded<20>(
        provider, locator_offset, work, cancel, "zip64_eocd");
    if (!locator_result)
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
            std::move(locator_result.error()));
    const auto locator = locator_result.take_value();
    if (read_u32_le(locator.data()) != zip64_locator_signature) {
        if (required)
            return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
                malformed_error("ZIP64 locator signature is missing", "zip64_eocd",
                                locator_offset, zip64_locator_size));
        return workspace_result_t<std::optional<zip64_eocd_t>>::success(std::nullopt);
    }
    const std::uint32_t eocd_disk = read_u32_le(locator.data() + 4);
    const std::uint64_t record_offset = read_u64_le(locator.data() + 8);
    const std::uint32_t disk_count = read_u32_le(locator.data() + 16);
    if (eocd_disk != 0 || disk_count != 1)
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
            malformed_error("Multi-disk ZIP64 containers are unsupported",
                            "zip64_eocd", locator_offset, zip64_locator_size));
    auto record_result = read_array_bounded<56>(
        provider, record_offset, work, cancel, "zip64_eocd");
    if (!record_result)
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
            std::move(record_result.error()));
    const auto record = record_result.take_value();
    if (read_u32_le(record.data()) != zip64_eocd_signature)
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
            malformed_error("ZIP64 end-record signature is invalid", "zip64_eocd",
                            record_offset, zip64_eocd_minimum_size));
    const std::uint64_t payload_size = read_u64_le(record.data() + 4);
    std::uint64_t total_size = 0;
    if (payload_size < 44)
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
            malformed_error("ZIP64 end record is truncated", "zip64_eocd",
                            record_offset, payload_size));
    if (!checked_add_u64(payload_size, 12, total_size))
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
            malformed_error("ZIP64 end-record size overflowed", "zip64_eocd",
                            record_offset, payload_size));
    if (total_size > limits.max_zip64_eocd_size)
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(limit_error(
            "ZIP64 end record exceeds its size limit", "zip64_eocd",
            total_size, limits.max_zip64_eocd_size));
    std::uint64_t record_end = 0;
    if (!checked_add_u64(record_offset, total_size, record_end) ||
        record_end != locator_offset)
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
            malformed_error("ZIP64 end-record range is inconsistent",
                            "zip64_eocd", record_offset, total_size));

    const std::uint16_t version_needed = read_u16_le(record.data() + 14);
    const std::uint32_t disk_number = read_u32_le(record.data() + 16);
    const std::uint32_t central_disk = read_u32_le(record.data() + 20);
    const std::uint64_t records_on_disk = read_u64_le(record.data() + 24);
    zip64_eocd_t result;
    result.record_count = read_u64_le(record.data() + 32);
    result.central_size = read_u64_le(record.data() + 40);
    result.central_offset = read_u64_le(record.data() + 48);
    result.offset = record_offset;
    if (version_needed < 45 || version_needed > 63)
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
            malformed_error("ZIP64 extraction version is invalid",
                            "zip64_eocd", record_offset, total_size));
    if (disk_number != 0 || central_disk != 0 ||
        records_on_disk != result.record_count)
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
            malformed_error("Multi-disk ZIP64 metadata is unsupported",
                            "zip64_eocd", record_offset, total_size));
    if ((eocd.disk_number != 0xffffU && eocd.disk_number != 0) ||
        (eocd.central_disk != 0xffffU && eocd.central_disk != 0) ||
        (eocd.records_on_disk != 0xffffU &&
         eocd.records_on_disk != records_on_disk) ||
        (eocd.record_count != 0xffffU &&
         eocd.record_count != result.record_count) ||
        (eocd.central_size != 0xffffffffU &&
         eocd.central_size != result.central_size) ||
        (eocd.central_offset != 0xffffffffU &&
         eocd.central_offset != result.central_offset))
        return workspace_result_t<std::optional<zip64_eocd_t>>::failure(
            malformed_error("ZIP64 and legacy end records disagree", "zip64_eocd"));
    return workspace_result_t<std::optional<zip64_eocd_t>>::success(
        std::optional<zip64_eocd_t>(std::move(result)));
}

workspace_result_t<void> validate_member_encoding(
    std::uint16_t version_needed, std::uint16_t flags,
    std::uint16_t compression_method, bool uses_zip64,
    std::uint64_t offset) {
    if (compression_method != zip_method_stored &&
        compression_method != zip_method_deflate) {
        auto error = zip_error(workspace_error_code_t::unsupported_format,
                               "ZIP member compression method is unsupported",
                               "zip_central_directory", offset);
        error.details.emplace_back("compression_method",
                                   std::to_string(compression_method));
        return workspace_result_t<void>::failure(std::move(error));
    }
    const std::uint16_t allowed = compression_method == zip_method_stored
        ? zip_allowed_stored_flags : zip_allowed_deflate_flags;
    if ((flags & static_cast<std::uint16_t>(~allowed)) != 0) {
        auto error = zip_error(workspace_error_code_t::unsupported_format,
                               "ZIP member uses encryption or unsupported flags",
                               "zip_central_directory", offset);
        error.details.emplace_back("flags", std::to_string(flags));
        return workspace_result_t<void>::failure(std::move(error));
    }
    std::uint16_t minimum_version = 10;
    if (compression_method == zip_method_deflate ||
        (flags & zip_flag_data_descriptor) != 0)
        minimum_version = 20;
    if (uses_zip64)
        minimum_version = 45;
    if (version_needed < minimum_version || version_needed > 63) {
        auto error = zip_error(workspace_error_code_t::unsupported_format,
                               "ZIP member extraction version is unsupported",
                               "zip_central_directory", offset);
        error.details.emplace_back("version_needed",
                                   std::to_string(version_needed));
        error.details.emplace_back("minimum_version",
                                   std::to_string(minimum_version));
        return workspace_result_t<void>::failure(std::move(error));
    }
    return workspace_result_t<void>::success();
}

bool expansion_ratio_exceeded(std::uint64_t output_size,
                              std::uint64_t input_size,
                              std::uint64_t ratio_limit) noexcept {
    if (output_size == 0)
        return false;
    if (input_size == 0)
        return true;
    const std::uint64_t quotient = output_size / input_size;
    const std::uint64_t remainder = output_size % input_size;
    return quotient > ratio_limit ||
           (quotient == ratio_limit && remainder != 0);
}

zip_member_kind_t classify_member_kind(std::uint16_t version_made_by,
                                       std::uint32_t external_attributes,
                                       bool directory_marker) noexcept {
    const std::uint8_t host = static_cast<std::uint8_t>(version_made_by >> 8U);
    const std::uint32_t unix_type = host == 3 || host == 19
        ? ((external_attributes >> 16U) & 0xf000U) : 0U;
    if (unix_type == 0xa000U)
        return zip_member_kind_t::symbolic_link;
    if (directory_marker || unix_type == 0x4000U ||
        (external_attributes & 0x10U) != 0)
        return zip_member_kind_t::directory;
    return zip_member_kind_t::regular_file;
}

struct parsed_member_t {
    zip_member_t member;
    std::vector<std::uint8_t> raw_name;
    bool zip64_sizes = false;
};

workspace_result_t<std::uint64_t> read_data_descriptor(
    const byte_provider_t& provider, const parsed_member_t& parsed,
    std::uint64_t descriptor_offset, std::uint64_t central_offset,
    work_guard_t& work, const cancellation_token_t& cancel) {
    if (descriptor_offset >= central_offset)
        return workspace_result_t<std::uint64_t>::failure(malformed_error(
            "ZIP data descriptor is missing", "zip_local_header",
            descriptor_offset));
    const std::uint64_t available = central_offset - descriptor_offset;
    const std::uint64_t read_size = (std::min)(available, 24ULL);
    if (read_size < 12)
        return workspace_result_t<std::uint64_t>::failure(malformed_error(
            "ZIP data descriptor is truncated", "zip_local_header",
            descriptor_offset, read_size));
    auto bytes_result = read_vector_bounded(
        provider, descriptor_offset, read_size, work, cancel,
        "zip_local_header");
    if (!bytes_result)
        return workspace_result_t<std::uint64_t>::failure(
            std::move(bytes_result.error()));
    const auto bytes = bytes_result.take_value();

    const auto match = [&](bool signature, bool zip64)
        -> std::optional<std::uint64_t> {
        const std::size_t prefix = signature ? 4U : 0U;
        const std::size_t required = prefix + 4U + (zip64 ? 16U : 8U);
        if (bytes.size() < required)
            return std::nullopt;
        if (signature && read_u32_le(bytes.data()) != zip_data_descriptor_signature)
            return std::nullopt;
        const std::uint8_t* value = bytes.data() + prefix;
        if (read_u32_le(value) != parsed.member.crc32)
            return std::nullopt;
        if (zip64) {
            if (read_u64_le(value + 4) != parsed.member.compressed_size ||
                read_u64_le(value + 12) != parsed.member.uncompressed_size)
                return std::nullopt;
        } else {
            if (parsed.member.compressed_size > 0xffffffffULL ||
                parsed.member.uncompressed_size > 0xffffffffULL ||
                read_u32_le(value + 4) != parsed.member.compressed_size ||
                read_u32_le(value + 8) != parsed.member.uncompressed_size)
                return std::nullopt;
        }
        return static_cast<std::uint64_t>(required);
    };

    const bool require_zip64 = parsed.zip64_sizes ||
        parsed.member.compressed_size > 0xffffffffULL ||
        parsed.member.uncompressed_size > 0xffffffffULL;
    if (require_zip64) {
        if (auto size = match(true, true))
            return workspace_result_t<std::uint64_t>::success(*size);
        if (auto size = match(false, true))
            return workspace_result_t<std::uint64_t>::success(*size);
    } else {
        if (auto size = match(true, false))
            return workspace_result_t<std::uint64_t>::success(*size);
        if (auto size = match(false, false))
            return workspace_result_t<std::uint64_t>::success(*size);
        if (parsed.member.version_needed >= 45) {
            if (auto size = match(true, true))
                return workspace_result_t<std::uint64_t>::success(*size);
            if (auto size = match(false, true))
                return workspace_result_t<std::uint64_t>::success(*size);
        }
    }
    return workspace_result_t<std::uint64_t>::failure(zip_error(
        workspace_error_code_t::integrity_failure,
        "ZIP data descriptor disagrees with the central directory",
        "zip_local_header", descriptor_offset, read_size));
}

workspace_result_t<void> validate_local_record(
    const byte_provider_t& provider, parsed_member_t& parsed,
    std::uint64_t central_offset, const zip_container_limits_t& limits,
    work_guard_t& work, const cancellation_token_t& cancel) {
    auto fixed_result = read_array_bounded<30>(
        provider, parsed.member.local_header_offset, work, cancel,
        "zip_local_header");
    if (!fixed_result)
        return workspace_result_t<void>::failure(
            std::move(fixed_result.error()));
    const auto fixed = fixed_result.take_value();
    if (read_u32_le(fixed.data()) != zip_local_header_signature)
        return workspace_result_t<void>::failure(malformed_error(
            "ZIP local-header signature is invalid", "zip_local_header",
            parsed.member.local_header_offset, zip_local_header_size));

    const std::uint16_t version_needed = read_u16_le(fixed.data() + 4);
    const std::uint16_t flags = read_u16_le(fixed.data() + 6);
    const std::uint16_t method = read_u16_le(fixed.data() + 8);
    const std::uint32_t local_crc = read_u32_le(fixed.data() + 14);
    const std::uint32_t compressed_field = read_u32_le(fixed.data() + 18);
    const std::uint32_t uncompressed_field = read_u32_le(fixed.data() + 22);
    const std::uint16_t name_size = read_u16_le(fixed.data() + 26);
    const std::uint16_t extra_size = read_u16_le(fixed.data() + 28);
    if (version_needed != parsed.member.version_needed ||
        flags != parsed.member.flags || method != parsed.member.compression_method)
        return workspace_result_t<void>::failure(zip_error(
            workspace_error_code_t::integrity_failure,
            "ZIP local and central headers disagree", "zip_local_header",
            parsed.member.local_header_offset, zip_local_header_size));

    std::uint64_t variable_size = 0;
    if (!checked_add_u64(name_size, extra_size, variable_size))
        return workspace_result_t<void>::failure(malformed_error(
            "ZIP local-header variable size overflowed", "zip_local_header",
            parsed.member.local_header_offset));
    std::uint64_t variable_offset = 0;
    if (!checked_add_u64(parsed.member.local_header_offset,
                         zip_local_header_size, variable_offset))
        return workspace_result_t<void>::failure(malformed_error(
            "ZIP local-header offset overflowed", "zip_local_header",
            parsed.member.local_header_offset));
    std::uint64_t data_offset = 0;
    if (!checked_add_u64(variable_offset, variable_size, data_offset) ||
        data_offset > central_offset)
        return workspace_result_t<void>::failure(malformed_error(
            "ZIP local-header range exceeds the file-data region",
            "zip_local_header", parsed.member.local_header_offset,
            zip_local_header_size + variable_size));
    auto variable_result = read_vector_bounded(
        provider, variable_offset, variable_size, work, cancel,
        "zip_local_header");
    if (!variable_result)
        return workspace_result_t<void>::failure(
            std::move(variable_result.error()));
    auto variable = variable_result.take_value();
    std::vector<std::uint8_t> local_name(
        variable.begin(), variable.begin() + name_size);
    if (local_name != parsed.raw_name)
        return workspace_result_t<void>::failure(zip_error(
            workspace_error_code_t::integrity_failure,
            "ZIP local and central member names disagree", "zip_local_header",
            parsed.member.local_header_offset));
    std::vector<std::uint8_t> local_extra(
        variable.begin() + name_size, variable.end());

    const bool descriptor = (flags & zip_flag_data_descriptor) != 0;
    extra_requirements_t requirements;
    requirements.uncompressed_size = uncompressed_field == 0xffffffffU;
    requirements.compressed_size = compressed_field == 0xffffffffU;
    auto extra_result = parse_extra_fields(
        local_extra, local_name, requirements, work, "zip_local_header");
    if (!extra_result)
        return workspace_result_t<void>::failure(
            std::move(extra_result.error()));
    const auto local_extra_info = extra_result.take_value();
    const bool local_uses_zip64 = local_extra_info.has_zip64 ||
        compressed_field == 0xffffffffU ||
        uncompressed_field == 0xffffffffU;
    if (local_uses_zip64 && version_needed < 45)
        return workspace_result_t<void>::failure(malformed_error(
            "ZIP64 local header has an invalid extraction version",
            "zip_local_header", parsed.member.local_header_offset));
    parsed.member.uses_zip64 = parsed.member.uses_zip64 || local_uses_zip64;
    if (local_extra_info.unicode_path) {
        auto local_path_result = resolve_member_path(
            local_name, flags, local_extra_info, limits, work,
            "zip_local_header");
        if (!local_path_result)
            return workspace_result_t<void>::failure(
                std::move(local_path_result.error()));
        if (local_path_result.value().path != parsed.member.normalized_path)
            return workspace_result_t<void>::failure(zip_error(
                workspace_error_code_t::integrity_failure,
                "ZIP local and central Unicode names disagree",
                "zip_local_header", parsed.member.local_header_offset));
    }

    if (!descriptor) {
        const std::uint64_t local_compressed = requirements.compressed_size
            ? *local_extra_info.compressed_size : compressed_field;
        const std::uint64_t local_uncompressed = requirements.uncompressed_size
            ? *local_extra_info.uncompressed_size : uncompressed_field;
        if (local_crc != parsed.member.crc32 ||
            local_compressed != parsed.member.compressed_size ||
            local_uncompressed != parsed.member.uncompressed_size)
            return workspace_result_t<void>::failure(zip_error(
                workspace_error_code_t::integrity_failure,
                "ZIP local-header sizes or CRC disagree with the central directory",
                "zip_local_header", parsed.member.local_header_offset));
    } else {
        const bool compressed_field_valid = compressed_field == 0 ||
            compressed_field == 0xffffffffU ||
            (parsed.member.compressed_size <= 0xffffffffULL &&
             compressed_field == parsed.member.compressed_size);
        const bool uncompressed_field_valid = uncompressed_field == 0 ||
            uncompressed_field == 0xffffffffU ||
            (parsed.member.uncompressed_size <= 0xffffffffULL &&
             uncompressed_field == parsed.member.uncompressed_size);
        const bool compressed_extra_valid = !local_extra_info.compressed_size ||
            *local_extra_info.compressed_size == 0 ||
            *local_extra_info.compressed_size == parsed.member.compressed_size;
        const bool uncompressed_extra_valid = !local_extra_info.uncompressed_size ||
            *local_extra_info.uncompressed_size == 0 ||
            *local_extra_info.uncompressed_size == parsed.member.uncompressed_size;
        if ((local_crc != 0 && local_crc != parsed.member.crc32) ||
            !compressed_field_valid || !uncompressed_field_valid ||
            !compressed_extra_valid || !uncompressed_extra_valid)
            return workspace_result_t<void>::failure(zip_error(
                workspace_error_code_t::integrity_failure,
                "ZIP local-header descriptor fields are inconsistent",
                "zip_local_header", parsed.member.local_header_offset));
    }

    std::uint64_t data_end = 0;
    if (!checked_add_u64(data_offset, parsed.member.compressed_size, data_end) ||
        data_end > central_offset)
        return workspace_result_t<void>::failure(malformed_error(
            "ZIP member data range exceeds the file-data region",
            "zip_local_header", data_offset, parsed.member.compressed_size));
    std::uint64_t record_end = data_end;
    if (descriptor) {
        auto descriptor_result = read_data_descriptor(
            provider, parsed, data_end, central_offset, work, cancel);
        if (!descriptor_result)
            return workspace_result_t<void>::failure(
                std::move(descriptor_result.error()));
        if (!checked_add_u64(data_end, descriptor_result.value(), record_end) ||
            record_end > central_offset)
            return workspace_result_t<void>::failure(malformed_error(
                "ZIP data-descriptor range exceeds the file-data region",
                "zip_local_header", data_end, descriptor_result.value()));
    }
    parsed.member.data_offset = data_offset;
    parsed.member.record_end_offset = record_end;
    return workspace_result_t<void>::success();
}

struct parsed_archive_t {
    std::vector<zip_member_t> members;
    std::unordered_map<std::string, std::size_t> member_by_name;
    bool uses_zip64 = false;
    std::uint32_t archive_depth = 0;
    std::uint64_t central_offset = 0;
    std::uint64_t central_size = 0;
    std::uint64_t aggregate_compressed_size = 0;
    std::uint64_t aggregate_uncompressed_size = 0;
    std::uint64_t aggregate_sparse_size = 0;
};

struct occupied_range_t {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    std::uint64_t ordinal = 0;
};

workspace_result_t<void> sort_occupied_ranges(
    std::vector<occupied_range_t>& ranges, work_guard_t& work) {
    if (ranges.size() < 2)
        return workspace_result_t<void>::success();
    std::vector<occupied_range_t> scratch(ranges.size());
    bool data_in_ranges = true;
    std::size_t width = 1;
    const auto precedes = [](const occupied_range_t& lhs,
                             const occupied_range_t& rhs) noexcept {
        if (lhs.begin != rhs.begin)
            return lhs.begin < rhs.begin;
        return lhs.end < rhs.end;
    };
    while (width < ranges.size()) {
        const auto& source = data_in_ranges ? ranges : scratch;
        auto& destination = data_in_ranges ? scratch : ranges;
        std::size_t left = 0;
        while (left < ranges.size()) {
            const std::size_t middle = left +
                (std::min)(width, ranges.size() - left);
            const std::size_t right = middle +
                (std::min)(width, ranges.size() - middle);
            std::size_t first = left;
            std::size_t second = middle;
            std::size_t output = left;
            while (first < middle || second < right) {
                auto visited = work.visit_record("zip_ranges");
                if (!visited)
                    return visited;
                if (second == right ||
                    (first < middle && precedes(source[first], source[second])))
                    destination[output++] = source[first++];
                else
                    destination[output++] = source[second++];
            }
            left = right;
        }
        data_in_ranges = !data_in_ranges;
        if (width > ranges.size() / 2)
            width = ranges.size();
        else
            width *= 2;
    }
    if (!data_in_ranges)
        ranges.swap(scratch);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> add_aggregate_value(
    std::uint64_t value, std::uint64_t limit, std::uint64_t& aggregate,
    const char* message) {
    if (value > limit - aggregate)
        return workspace_result_t<void>::failure(limit_error(
            message, "zip_central_directory",
            saturating_add(aggregate, value), limit));
    aggregate += value;
    return workspace_result_t<void>::success();
}

workspace_result_t<parsed_archive_t> parse_archive(
    const std::shared_ptr<const byte_provider_t>& provider,
    const zip_container_limits_t& limits, const cancellation_token_t& cancel) {
    work_guard_t work(limits, cancel);
    auto initial_poll = work.poll("zip_open");
    if (!initial_poll)
        return workspace_result_t<parsed_archive_t>::failure(
            std::move(initial_poll.error()));
    if (provider->size() < zip_eocd_fixed_size)
        return workspace_result_t<parsed_archive_t>::failure(malformed_error(
            "File is too small to be a ZIP container", "zip_open"));
    if (provider->size() > limits.max_archive_size)
        return workspace_result_t<parsed_archive_t>::failure(limit_error(
            "ZIP archive exceeds its size limit", "zip_open",
            provider->size(), limits.max_archive_size));
    auto source_identity_result = validate_source_identity(*provider);
    if (!source_identity_result)
        return workspace_result_t<parsed_archive_t>::failure(
            std::move(source_identity_result.error()));

    std::uint32_t archive_depth = 1;
    if (const auto& parent_member = provider->member_metadata()) {
        if (parent_member->depth == 0 || parent_member->depth >= 64)
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "ZIP parent provider has invalid member depth", "zip_open"));
        archive_depth = parent_member->depth + 1;
    }
    if (archive_depth > limits.max_nesting_depth)
        return workspace_result_t<parsed_archive_t>::failure(limit_error(
            "ZIP archive nesting exceeds its limit", "zip_open",
            archive_depth, limits.max_nesting_depth));

    auto eocd_result = find_eocd(*provider, limits, work, cancel);
    if (!eocd_result)
        return workspace_result_t<parsed_archive_t>::failure(
            std::move(eocd_result.error()));
    const eocd_t eocd = eocd_result.take_value();
    auto zip64_result = read_zip64_eocd(
        *provider, eocd, limits, work, cancel);
    if (!zip64_result)
        return workspace_result_t<parsed_archive_t>::failure(
            std::move(zip64_result.error()));
    const auto zip64 = zip64_result.take_value();
    if (!zip64 && (eocd.disk_number != 0 || eocd.central_disk != 0 ||
                   eocd.records_on_disk != eocd.record_count))
        return workspace_result_t<parsed_archive_t>::failure(malformed_error(
            "Multi-disk ZIP containers are unsupported", "zip_eocd"));

    const std::uint64_t central_offset = zip64
        ? zip64->central_offset : eocd.central_offset;
    const std::uint64_t central_size = zip64
        ? zip64->central_size : eocd.central_size;
    const std::uint64_t record_count = zip64
        ? zip64->record_count : eocd.record_count;
    const std::uint64_t metadata_offset = zip64
        ? zip64->offset : eocd.offset;
    if (record_count > limits.max_member_count)
        return workspace_result_t<parsed_archive_t>::failure(limit_error(
            "ZIP member count exceeds its limit", "zip_central_directory",
            record_count, limits.max_member_count));
    if (central_size > limits.max_central_directory_size)
        return workspace_result_t<parsed_archive_t>::failure(limit_error(
            "ZIP central directory exceeds its size limit",
            "zip_central_directory", central_size,
            limits.max_central_directory_size));
    if (record_count > central_size / zip_central_header_size ||
        record_count > central_offset / (zip_local_header_size + 1))
        return workspace_result_t<parsed_archive_t>::failure(malformed_error(
            "ZIP member count cannot fit its declared record ranges",
            "zip_central_directory", central_offset, central_size));
    std::uint64_t central_end = 0;
    if (!checked_add_u64(central_offset, central_size, central_end) ||
        central_end != metadata_offset || central_end > provider->size())
        return workspace_result_t<parsed_archive_t>::failure(malformed_error(
            "ZIP central-directory range is inconsistent",
            "zip_central_directory", central_offset, central_size));

    parsed_archive_t archive;
    archive.uses_zip64 = zip64.has_value();
    archive.archive_depth = archive_depth;
    archive.central_offset = central_offset;
    archive.central_size = central_size;
    archive.members.reserve(static_cast<std::size_t>(record_count));
    archive.member_by_name.reserve(static_cast<std::size_t>(record_count));
    std::unordered_map<std::string, std::uint64_t> collision_names;
    collision_names.reserve(static_cast<std::size_t>(record_count));

    std::vector<occupied_range_t> occupied;
    occupied.reserve(static_cast<std::size_t>(record_count));

    std::uint64_t cursor = central_offset;
    for (std::uint64_t ordinal = 0; ordinal < record_count; ++ordinal) {
        auto visited = work.visit_record("zip_central_directory");
        if (!visited)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(visited.error()));
        if (cursor > central_end || central_end - cursor < zip_central_header_size)
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "ZIP central-directory entry is truncated",
                "zip_central_directory", cursor));
        auto fixed_result = read_array_bounded<46>(
            *provider, cursor, work, cancel, "zip_central_directory");
        if (!fixed_result)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(fixed_result.error()));
        const auto fixed = fixed_result.take_value();
        if (read_u32_le(fixed.data()) != zip_central_header_signature)
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "ZIP central-directory signature is invalid",
                "zip_central_directory", cursor, zip_central_header_size));

        const std::uint16_t version_made_by = read_u16_le(fixed.data() + 4);
        const std::uint16_t version_needed = read_u16_le(fixed.data() + 6);
        const std::uint16_t flags = read_u16_le(fixed.data() + 8);
        const std::uint16_t method = read_u16_le(fixed.data() + 10);
        const std::uint32_t crc = read_u32_le(fixed.data() + 16);
        const std::uint32_t compressed_field = read_u32_le(fixed.data() + 20);
        const std::uint32_t uncompressed_field = read_u32_le(fixed.data() + 24);
        const std::uint16_t name_size = read_u16_le(fixed.data() + 28);
        const std::uint16_t extra_size = read_u16_le(fixed.data() + 30);
        const std::uint16_t comment_size = read_u16_le(fixed.data() + 32);
        const std::uint16_t disk_start_field = read_u16_le(fixed.data() + 34);
        const std::uint32_t external_attributes = read_u32_le(fixed.data() + 38);
        const std::uint32_t local_offset_field = read_u32_le(fixed.data() + 42);
        if (name_size == 0)
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "ZIP central-directory member name is empty",
                "zip_central_directory", cursor));

        std::uint64_t name_and_extra = 0;
        std::uint64_t entry_size = zip_central_header_size;
        if (!checked_add_u64(name_size, extra_size, name_and_extra) ||
            !checked_add_u64(entry_size, name_and_extra, entry_size) ||
            !checked_add_u64(entry_size, comment_size, entry_size) ||
            entry_size > central_end - cursor)
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "ZIP central-directory entry range is invalid",
                "zip_central_directory", cursor, entry_size));
        auto variable_result = read_vector_bounded(
            *provider, cursor + zip_central_header_size, name_and_extra,
            work, cancel, "zip_central_directory");
        if (!variable_result)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(variable_result.error()));
        auto variable = variable_result.take_value();
        std::vector<std::uint8_t> raw_name(
            variable.begin(), variable.begin() + name_size);
        std::vector<std::uint8_t> extra(
            variable.begin() + name_size, variable.end());

        extra_requirements_t requirements;
        requirements.uncompressed_size = uncompressed_field == 0xffffffffU;
        requirements.compressed_size = compressed_field == 0xffffffffU;
        requirements.local_header_offset = local_offset_field == 0xffffffffU;
        requirements.disk_start = disk_start_field == 0xffffU;
        auto extra_result = parse_extra_fields(
            extra, raw_name, requirements, work, "zip_central_directory");
        if (!extra_result)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(extra_result.error()));
        const auto extra_info = extra_result.take_value();

        parsed_member_t parsed;
        parsed.raw_name = std::move(raw_name);
        parsed.zip64_sizes = requirements.uncompressed_size ||
                             requirements.compressed_size;
        parsed.member.ordinal = ordinal;
        parsed.member.central_directory_offset = cursor;
        parsed.member.local_header_offset = requirements.local_header_offset
            ? *extra_info.local_header_offset : local_offset_field;
        parsed.member.compressed_size = requirements.compressed_size
            ? *extra_info.compressed_size : compressed_field;
        parsed.member.uncompressed_size = requirements.uncompressed_size
            ? *extra_info.uncompressed_size : uncompressed_field;
        parsed.member.crc32 = crc;
        parsed.member.external_attributes = external_attributes;
        parsed.member.archive_depth = archive_depth;
        parsed.member.version_needed = version_needed;
        parsed.member.flags = flags;
        parsed.member.compression_method = method;
        parsed.member.uses_zip64 = requirements.uncompressed_size ||
            requirements.compressed_size || requirements.local_header_offset ||
            requirements.disk_start || extra_info.has_zip64;
        parsed.member.uses_data_descriptor =
            (flags & zip_flag_data_descriptor) != 0;
        parsed.member.utf8_name = (flags & zip_flag_utf8) != 0;

        const std::uint32_t disk_start = requirements.disk_start
            ? *extra_info.disk_start : disk_start_field;
        if (disk_start != 0)
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "Multi-disk ZIP member is unsupported",
                "zip_central_directory", cursor));
        auto encoding_result = validate_member_encoding(
            version_needed, flags, method, parsed.member.uses_zip64, cursor);
        if (!encoding_result)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(encoding_result.error()));

        auto path_result = resolve_member_path(
            parsed.raw_name, flags, extra_info, limits, work,
            "zip_central_directory");
        if (!path_result)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(path_result.error()));
        auto path = path_result.take_value();
        parsed.member.normalized_path = std::move(path.path);
        parsed.member.path_component_count = path.component_count;
        parsed.member.kind = classify_member_kind(
            version_made_by, external_attributes, path.directory_marker);
        if (parsed.member.kind == zip_member_kind_t::symbolic_link &&
            path.directory_marker)
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "ZIP symbolic-link member has a directory path marker",
                "zip_central_directory", cursor));

        const auto exact_insert = archive.member_by_name.emplace(
            parsed.member.normalized_path, archive.members.size());
        if (!exact_insert.second) {
            auto error = zip_error(workspace_error_code_t::integrity_failure,
                                   "ZIP normalized member name is duplicated",
                                   "zip_central_directory", cursor);
            error.details.emplace_back("member", parsed.member.normalized_path);
            error.details.emplace_back("first_ordinal",
                std::to_string(
                    archive.members[exact_insert.first->second].ordinal));
            error.details.emplace_back("second_ordinal", std::to_string(ordinal));
            return workspace_result_t<parsed_archive_t>::failure(std::move(error));
        }
        const auto collision_insert = collision_names.emplace(
            path.collision_key, ordinal);
        if (!collision_insert.second) {
            auto error = zip_error(workspace_error_code_t::integrity_failure,
                                   "ZIP member names collide under case folding",
                                   "zip_central_directory", cursor);
            error.details.emplace_back("member", parsed.member.normalized_path);
            error.details.emplace_back(
                "first_ordinal", std::to_string(collision_insert.first->second));
            error.details.emplace_back("second_ordinal", std::to_string(ordinal));
            return workspace_result_t<parsed_archive_t>::failure(std::move(error));
        }

        if (parsed.member.compressed_size > limits.max_member_compressed_size)
            return workspace_result_t<parsed_archive_t>::failure(limit_error(
                "ZIP member compressed size exceeds its limit",
                "zip_central_directory", parsed.member.compressed_size,
                limits.max_member_compressed_size));
        if (parsed.member.uncompressed_size > limits.max_member_uncompressed_size)
            return workspace_result_t<parsed_archive_t>::failure(limit_error(
                "ZIP member uncompressed size exceeds its limit",
                "zip_central_directory", parsed.member.uncompressed_size,
                limits.max_member_uncompressed_size));
        if (parsed.member.compression_method == zip_method_stored &&
            parsed.member.compressed_size != parsed.member.uncompressed_size)
            return workspace_result_t<parsed_archive_t>::failure(zip_error(
                workspace_error_code_t::integrity_failure,
                "Stored ZIP member has unequal compressed and uncompressed sizes",
                "zip_central_directory", cursor));
        if (parsed.member.compression_method == zip_method_deflate &&
            parsed.member.compressed_size == 0)
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "Deflated ZIP member has no compressed stream",
                "zip_central_directory", cursor));
        if (expansion_ratio_exceeded(
                parsed.member.uncompressed_size, parsed.member.compressed_size,
                limits.max_expansion_ratio))
            return workspace_result_t<parsed_archive_t>::failure(limit_error(
                "ZIP member expansion ratio exceeds its limit",
                "zip_central_directory", parsed.member.uncompressed_size,
                saturating_multiply(parsed.member.compressed_size,
                                    limits.max_expansion_ratio)));
        if (parsed.member.kind == zip_member_kind_t::directory &&
            (parsed.member.compressed_size != 0 ||
             parsed.member.uncompressed_size != 0 ||
             parsed.member.compression_method != zip_method_stored ||
             parsed.member.crc32 != 0))
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "ZIP directory member carries file data",
                "zip_central_directory", cursor));

        auto aggregate_compressed = add_aggregate_value(
            parsed.member.compressed_size,
            limits.max_aggregate_compressed_size,
            archive.aggregate_compressed_size,
            "ZIP aggregate compressed size exceeds its limit");
        if (!aggregate_compressed)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(aggregate_compressed.error()));
        auto aggregate_uncompressed = add_aggregate_value(
            parsed.member.uncompressed_size,
            limits.max_aggregate_uncompressed_size,
            archive.aggregate_uncompressed_size,
            "ZIP aggregate output size exceeds its limit");
        if (!aggregate_uncompressed)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(aggregate_uncompressed.error()));
        if (expansion_ratio_exceeded(
                archive.aggregate_uncompressed_size,
                archive.aggregate_compressed_size,
                limits.max_expansion_ratio))
            return workspace_result_t<parsed_archive_t>::failure(limit_error(
                "ZIP aggregate expansion ratio exceeds its limit",
                "zip_central_directory",
                archive.aggregate_uncompressed_size,
                saturating_multiply(archive.aggregate_compressed_size,
                                    limits.max_expansion_ratio)));

        auto local_result = validate_local_record(
            *provider, parsed, central_offset, limits, work, cancel);
        if (!local_result)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(local_result.error()));
        parsed.member.provenance.normalized_member_path =
            parsed.member.normalized_path;
        parsed.member.provenance.container_offset = parsed.member.data_offset;
        parsed.member.provenance.compressed_size = parsed.member.compressed_size;
        parsed.member.provenance.uncompressed_size = parsed.member.uncompressed_size;
        parsed.member.provenance.ordinal = ordinal;
        parsed.member.provenance.depth = archive_depth;
        parsed.member.provenance.crc32 = parsed.member.crc32;
        parsed.member.provenance.compressed = method != zip_method_stored;

        occupied.push_back({parsed.member.local_header_offset,
                            parsed.member.record_end_offset, ordinal});
        archive.members.push_back(std::move(parsed.member));
        cursor += entry_size;
    }

    if (cursor < central_end) {
        const std::uint64_t remaining = central_end - cursor;
        if (remaining < 6)
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "ZIP central-directory trailer is truncated",
                "zip_central_directory", cursor, remaining));
        auto signature_result = read_array_bounded<6>(
            *provider, cursor, work, cancel, "zip_central_directory");
        if (!signature_result)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(signature_result.error()));
        const auto signature = signature_result.take_value();
        const std::uint16_t signature_size = read_u16_le(signature.data() + 4);
        if (read_u32_le(signature.data()) != zip_central_signature_signature ||
            remaining != 6ULL + signature_size)
            return workspace_result_t<parsed_archive_t>::failure(malformed_error(
                "ZIP central-directory trailer is invalid",
                "zip_central_directory", cursor, remaining));
        auto consumed = work.consume(signature_size, "zip_central_directory");
        if (!consumed)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(consumed.error()));
        cursor = central_end;
    }
    if (cursor != central_end)
        return workspace_result_t<parsed_archive_t>::failure(malformed_error(
            "ZIP central-directory size does not match its entries",
            "zip_central_directory", cursor));

    auto sorted = sort_occupied_ranges(occupied, work);
    if (!sorted)
        return workspace_result_t<parsed_archive_t>::failure(
            std::move(sorted.error()));
    std::uint64_t previous_end = 0;
    for (const auto& range : occupied) {
        auto visited = work.visit_record("zip_ranges");
        if (!visited)
            return workspace_result_t<parsed_archive_t>::failure(
                std::move(visited.error()));
        if (range.begin < previous_end || range.end < range.begin ||
            range.end > central_offset) {
            const std::uint64_t range_size = range.end >= range.begin
                ? range.end - range.begin : 0;
            auto error = zip_error(workspace_error_code_t::integrity_failure,
                                   "ZIP member physical ranges overlap",
                                   "zip_ranges", range.begin,
                                   range_size);
            error.details.emplace_back("ordinal", std::to_string(range.ordinal));
            return workspace_result_t<parsed_archive_t>::failure(std::move(error));
        }
        const std::uint64_t gap = range.begin - previous_end;
        if (gap > limits.max_single_sparse_gap)
            return workspace_result_t<parsed_archive_t>::failure(limit_error(
                "ZIP sparse gap exceeds its limit", "zip_ranges",
                gap, limits.max_single_sparse_gap));
        if (gap > limits.max_aggregate_sparse_size - archive.aggregate_sparse_size)
            return workspace_result_t<parsed_archive_t>::failure(limit_error(
                "ZIP aggregate sparse range exceeds its limit", "zip_ranges",
                saturating_add(archive.aggregate_sparse_size, gap),
                limits.max_aggregate_sparse_size));
        archive.aggregate_sparse_size += gap;
        previous_end = range.end;
    }
    if (previous_end > central_offset)
        return workspace_result_t<parsed_archive_t>::failure(malformed_error(
            "ZIP member ranges extend into the central directory", "zip_ranges"));
    const std::uint64_t trailing_gap = central_offset - previous_end;
    if (trailing_gap > limits.max_single_sparse_gap)
        return workspace_result_t<parsed_archive_t>::failure(limit_error(
            "ZIP trailing sparse gap exceeds its limit", "zip_ranges",
            trailing_gap, limits.max_single_sparse_gap));
    if (trailing_gap > limits.max_aggregate_sparse_size - archive.aggregate_sparse_size)
        return workspace_result_t<parsed_archive_t>::failure(limit_error(
            "ZIP aggregate sparse range exceeds its limit", "zip_ranges",
            saturating_add(archive.aggregate_sparse_size, trailing_gap),
            limits.max_aggregate_sparse_size));
    archive.aggregate_sparse_size += trailing_gap;

    auto final_poll = work.poll("zip_open");
    if (!final_poll)
        return workspace_result_t<parsed_archive_t>::failure(
            std::move(final_poll.error()));
    return workspace_result_t<parsed_archive_t>::success(std::move(archive));
}

workspace_result_t<std::vector<std::uint8_t>> allocate_output(
    std::uint64_t size, const char* phase) {
    std::size_t allocation = 0;
    if (!u64_to_size(size, allocation))
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            allocation_error(phase, size));
    return workspace_result_t<std::vector<std::uint8_t>>::success(
        std::vector<std::uint8_t>(allocation));
}

workspace_result_t<std::vector<std::uint8_t>> materialize_stored_member(
    const byte_provider_t& provider, const zip_member_t& member,
    work_guard_t& work, const cancellation_token_t& cancel) {
    auto range = validate_span(member.data_offset, member.compressed_size,
                               provider.size(), "zip_member_integrity");
    if (!range)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            std::move(range.error()));
    auto output_result = allocate_output(
        member.uncompressed_size, "zip_member_integrity");
    if (!output_result)
        return output_result;
    auto output = output_result.take_value();
    uLong crc = crc32(0L, Z_NULL, 0);
    std::uint64_t completed = 0;
    const std::uint64_t chunk_limit = (std::min)(
        work.limits().max_io_chunk_size,
        work.limits().cancellation_poll_bytes);
    while (completed < member.uncompressed_size) {
        const std::uint64_t chunk = (std::min)(
            chunk_limit, member.uncompressed_size - completed);
        auto input_work = work.consume(chunk, "zip_member_integrity");
        if (!input_work)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                std::move(input_work.error()));
        std::uint64_t source_offset = 0;
        if (!checked_add_u64(member.data_offset, completed, source_offset))
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                integrity_error("Stored ZIP member offset overflowed",
                                member.data_offset, member.compressed_size));
        auto read = provider.read_exact(
            source_offset,
            output.data() + static_cast<std::size_t>(completed),
            chunk, cancel);
        if (!read)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                std::move(read.error()));
        crc = crc32(
            crc,
            reinterpret_cast<const Bytef*>(
                output.data() + static_cast<std::size_t>(completed)),
            static_cast<uInt>(chunk));
        auto output_work = work.consume(chunk, "zip_member_integrity");
        if (!output_work)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                std::move(output_work.error()));
        completed += chunk;
    }
    if (static_cast<std::uint32_t>(crc) != member.crc32)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            integrity_error("Stored ZIP member CRC verification failed",
                            member.data_offset, member.compressed_size));
    return workspace_result_t<std::vector<std::uint8_t>>::success(
        std::move(output));
}

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
        if (status != Z_OK) {
            auto error = zip_error(
                status == Z_MEM_ERROR
                    ? workspace_error_code_t::limit_exceeded
                    : workspace_error_code_t::integrity_failure,
                "ZIP raw-DEFLATE initialization failed",
                "zip_member_integrity");
            error.provider_status = status;
            return workspace_result_t<void>::failure(std::move(error));
        }
        initialized_ = true;
        return workspace_result_t<void>::success();
    }

    z_stream& stream() noexcept {
        return stream_;
    }

private:
    z_stream stream_{};
    bool initialized_ = false;
};

workspace_result_t<std::vector<std::uint8_t>> materialize_deflated_member(
    const byte_provider_t& provider, const zip_member_t& member,
    work_guard_t& work, const cancellation_token_t& cancel) {
    auto range = validate_span(member.data_offset, member.compressed_size,
                               provider.size(), "zip_member_integrity");
    if (!range)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            std::move(range.error()));
    auto output_result = allocate_output(
        member.uncompressed_size, "zip_member_integrity");
    if (!output_result)
        return output_result;
    auto output = output_result.take_value();
    inflate_state_t inflater;
    auto initialized = inflater.initialize();
    if (!initialized)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            std::move(initialized.error()));

    z_stream& stream = inflater.stream();
    uLong crc = crc32(0L, Z_NULL, 0);
    std::uint64_t compressed_cursor = 0;
    std::uint64_t output_cursor = 0;
    bool stream_ended = false;
    std::array<std::uint8_t, 1> overflow_sink{};
    const std::uint64_t input_chunk_limit = (std::min)(
        work.limits().max_io_chunk_size,
        work.limits().cancellation_poll_bytes);

    while (compressed_cursor < member.compressed_size && !stream_ended) {
        const std::uint64_t chunk = (std::min)(
            input_chunk_limit, member.compressed_size - compressed_cursor);
        auto input_work = work.consume(chunk, "zip_member_integrity");
        if (!input_work)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                std::move(input_work.error()));
        std::uint64_t source_offset = 0;
        if (!checked_add_u64(member.data_offset, compressed_cursor, source_offset))
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                integrity_error("Deflated ZIP member offset overflowed",
                                member.data_offset, member.compressed_size));
        auto lease_result = provider.lease(source_offset, chunk, cancel);
        if (!lease_result)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                std::move(lease_result.error()));
        const auto input = lease_result.take_value();
        if (input.size() != chunk)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                integrity_error("Deflated ZIP member lease was incomplete",
                                source_offset, chunk));
        stream.next_in = const_cast<Bytef*>(
            reinterpret_cast<const Bytef*>(input.data()));
        stream.avail_in = static_cast<uInt>(chunk);

        while (!stream_ended) {
            const bool final_input_chunk =
                compressed_cursor + chunk == member.compressed_size;
            if (stream.avail_in == 0 && !final_input_chunk)
                break;
            const std::uint64_t output_remaining =
                member.uncompressed_size - output_cursor;
            const std::uint64_t output_capacity_u64 = output_remaining == 0
                ? 1ULL
                : (std::min)(
                    output_remaining,
                    (std::min)(work.limits().cancellation_poll_bytes,
                               static_cast<std::uint64_t>(
                                   (std::numeric_limits<uInt>::max)())));
            Bytef* output_pointer = output_remaining == 0
                ? reinterpret_cast<Bytef*>(overflow_sink.data())
                : reinterpret_cast<Bytef*>(
                    output.data() + static_cast<std::size_t>(output_cursor));
            stream.next_out = output_pointer;
            stream.avail_out = static_cast<uInt>(output_capacity_u64);
            const uInt input_before = stream.avail_in;
            const uInt output_before = stream.avail_out;
            const int status = inflate(&stream, Z_NO_FLUSH);
            const std::uint64_t input_consumed = input_before - stream.avail_in;
            const std::uint64_t output_produced = output_before - stream.avail_out;

            if (output_remaining == 0 && output_produced != 0)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    integrity_error(
                        "Deflated ZIP member exceeds its declared output size",
                        member.data_offset, member.compressed_size));
            if (output_produced != 0) {
                crc = crc32(
                    crc,
                    reinterpret_cast<const Bytef*>(
                        output.data() + static_cast<std::size_t>(output_cursor)),
                    static_cast<uInt>(output_produced));
                output_cursor += output_produced;
                auto output_work = work.consume(
                    output_produced, "zip_member_integrity");
                if (!output_work)
                    return workspace_result_t<std::vector<std::uint8_t>>::failure(
                        std::move(output_work.error()));
            }

            if (status == Z_STREAM_END) {
                const std::uint64_t member_consumed = compressed_cursor +
                    (chunk - stream.avail_in);
                if (member_consumed != member.compressed_size ||
                    stream.avail_in != 0 ||
                    output_cursor != member.uncompressed_size)
                    return workspace_result_t<std::vector<std::uint8_t>>::failure(
                        integrity_error(
                            "Deflated ZIP stream has trailing input or an incorrect output size",
                            member.data_offset, member.compressed_size));
                stream_ended = true;
                break;
            }
            if (status != Z_OK) {
                auto error = integrity_error(
                    "Deflated ZIP stream validation failed",
                    member.data_offset, member.compressed_size);
                error.provider_status = status;
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    std::move(error));
            }
            if (input_consumed == 0 && output_produced == 0)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    integrity_error("Deflated ZIP stream made no progress",
                                    member.data_offset,
                                    member.compressed_size));
            auto polled = work.poll("zip_member_integrity");
            if (!polled)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    std::move(polled.error()));
        }
        if (!stream_ended)
            compressed_cursor += chunk;
    }
    if (!stream_ended)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            integrity_error("Deflated ZIP stream ended before its terminator",
                            member.data_offset, member.compressed_size));
    if (output_cursor != member.uncompressed_size ||
        static_cast<std::uint32_t>(crc) != member.crc32)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            integrity_error("Deflated ZIP member size or CRC verification failed",
                            member.data_offset, member.compressed_size));
    return workspace_result_t<std::vector<std::uint8_t>>::success(
        std::move(output));
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

class zip_member_provider_t final : public byte_provider_t {
public:
    zip_member_provider_t(std::shared_ptr<const byte_provider_t> source,
                          std::shared_ptr<byte_provider_t> backing,
                          byte_provider_identity_t identity)
        : source_(std::move(source)), backing_(std::move(backing)),
          identity_(std::move(identity)) {}

    const byte_provider_identity_t& identity() const noexcept override {
        return identity_;
    }

    std::uint64_t size() const noexcept override {
        return identity_.size;
    }

    workspace_result_t<byte_view_t> lease(
        std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel) const override {
        return backing_->lease(offset, size, cancel);
    }

private:
    std::shared_ptr<const byte_provider_t> source_;
    std::shared_ptr<byte_provider_t> backing_;
    byte_provider_identity_t identity_;
};

workspace_result_t<std::shared_ptr<byte_provider_t>> materialize_member_provider(
    const std::shared_ptr<const byte_provider_t>& source,
    const zip_member_t& member, work_guard_t& work,
    const cancellation_token_t& cancel) {
    if (member.kind == zip_member_kind_t::directory)
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            zip_error(workspace_error_code_t::invalid_argument,
                      "ZIP directory member has no byte provider",
                      "zip_member_open"));
    workspace_result_t<std::vector<std::uint8_t>> bytes_result =
        member.compression_method == zip_method_stored
            ? materialize_stored_member(*source, member, work, cancel)
            : materialize_deflated_member(*source, member, work, cancel);
    if (!bytes_result)
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            std::move(bytes_result.error()));
    auto identity_component = encode_identity_component(member.normalized_path);
    auto memory_result = memory_provider_t::create(
        bytes_result.take_value(), "zip_member:" + identity_component);
    if (!memory_result)
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            std::move(memory_result.error()));
    std::shared_ptr<byte_provider_t> backing = memory_result.take_value();
    byte_provider_identity_t identity = source->identity();
    identity.normalized_source += "#member:" + identity_component;
    identity.size = member.uncompressed_size;
    identity.immutable_snapshot = true;
    identity.member = member.provenance;
    return workspace_result_t<std::shared_ptr<byte_provider_t>>::success(
        std::shared_ptr<byte_provider_t>(new zip_member_provider_t(
            source, std::move(backing), std::move(identity))));
}

}

struct zip_container_t::state_t {
    state_t(std::shared_ptr<const byte_provider_t> source_value,
            zip_container_limits_t limits_value, parsed_archive_t archive)
        : source(std::move(source_value)), limits(std::move(limits_value)),
          members(std::move(archive.members)),
          member_by_name(std::move(archive.member_by_name)),
          zip64(archive.uses_zip64), archive_depth(archive.archive_depth),
          central_offset(archive.central_offset), central_size(archive.central_size),
          aggregate_compressed(archive.aggregate_compressed_size),
          aggregate_uncompressed(archive.aggregate_uncompressed_size),
          aggregate_sparse(archive.aggregate_sparse_size), cache(members.size()) {}

    workspace_result_t<std::shared_ptr<byte_provider_t>> open_member(
        std::size_t member_index, work_guard_t& work,
        const cancellation_token_t& cancel) const {
        std::unique_lock<std::timed_mutex> lock(cache_mutex, std::defer_lock);
        while (!lock.try_lock_for(std::chrono::milliseconds(5))) {
            auto polled = work.poll("zip_member_open");
            if (!polled)
                return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
                    std::move(polled.error()));
        }
        if (cache[member_index])
            return workspace_result_t<std::shared_ptr<byte_provider_t>>::success(
                cache[member_index]);
        auto provider_result = materialize_member_provider(
            source, members[member_index], work, cancel);
        if (!provider_result)
            return provider_result;
        cache[member_index] = provider_result.value();
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::success(
            cache[member_index]);
    }

    std::shared_ptr<const byte_provider_t> source;
    zip_container_limits_t limits;
    std::vector<zip_member_t> members;
    std::unordered_map<std::string, std::size_t> member_by_name;
    bool zip64 = false;
    std::uint32_t archive_depth = 0;
    std::uint64_t central_offset = 0;
    std::uint64_t central_size = 0;
    std::uint64_t aggregate_compressed = 0;
    std::uint64_t aggregate_uncompressed = 0;
    std::uint64_t aggregate_sparse = 0;
    mutable std::timed_mutex cache_mutex;
    mutable std::vector<std::shared_ptr<byte_provider_t>> cache;
};

zip_container_t::zip_container_t(std::shared_ptr<state_t> state)
    : state_(std::move(state)) {}

workspace_result_t<std::shared_ptr<zip_container_t>> zip_container_t::open(
    std::shared_ptr<const byte_provider_t> provider,
    zip_container_limits_t limits, const cancellation_token_t& cancel) {
    if (!provider)
        return workspace_result_t<std::shared_ptr<zip_container_t>>::failure(
            zip_error(workspace_error_code_t::invalid_argument,
                      "ZIP source provider is null", "zip_open"));
    auto limits_result = validate_limits(limits);
    if (!limits_result)
        return workspace_result_t<std::shared_ptr<zip_container_t>>::failure(
            std::move(limits_result.error()));
    const std::uint64_t source_size = provider->size();
    try {
        auto archive_result = parse_archive(provider, limits, cancel);
        if (!archive_result)
            return workspace_result_t<std::shared_ptr<zip_container_t>>::failure(
                std::move(archive_result.error()));
        auto state = std::make_shared<state_t>(
            std::move(provider), std::move(limits), archive_result.take_value());
        return workspace_result_t<std::shared_ptr<zip_container_t>>::success(
            std::shared_ptr<zip_container_t>(
                new zip_container_t(std::move(state))));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<zip_container_t>>::failure(
            allocation_error("zip_open", source_size));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<zip_container_t>>::failure(
            allocation_error("zip_open", source_size));
    }
}

const byte_provider_identity_t& zip_container_t::source_identity() const noexcept {
    return state_->source->identity();
}

const std::shared_ptr<const byte_provider_t>&
zip_container_t::source_provider() const noexcept {
    return state_->source;
}

const zip_container_limits_t& zip_container_t::limits() const noexcept {
    return state_->limits;
}

const std::vector<zip_member_t>& zip_container_t::members() const noexcept {
    return state_->members;
}

const zip_member_t* zip_container_t::find_member(
    std::string_view normalized_path) const {
    if (normalized_path.empty() ||
        normalized_path.size() > state_->limits.max_normalized_path_size)
        return nullptr;
    const auto found = state_->member_by_name.find(std::string(normalized_path));
    if (found == state_->member_by_name.end())
        return nullptr;
    return &state_->members[found->second];
}

bool zip_container_t::uses_zip64() const noexcept {
    return state_->zip64;
}

std::uint32_t zip_container_t::archive_depth() const noexcept {
    return state_->archive_depth;
}

std::uint64_t zip_container_t::central_directory_offset() const noexcept {
    return state_->central_offset;
}

std::uint64_t zip_container_t::central_directory_size() const noexcept {
    return state_->central_size;
}

std::uint64_t zip_container_t::aggregate_compressed_size() const noexcept {
    return state_->aggregate_compressed;
}

std::uint64_t zip_container_t::aggregate_uncompressed_size() const noexcept {
    return state_->aggregate_uncompressed;
}

std::uint64_t zip_container_t::aggregate_sparse_size() const noexcept {
    return state_->aggregate_sparse;
}

workspace_result_t<std::shared_ptr<byte_provider_t>>
zip_container_t::open_member_provider(
    std::size_t member_index, const cancellation_token_t& cancel) const {
    if (member_index >= state_->members.size()) {
        auto error = zip_error(workspace_error_code_t::out_of_range,
                               "ZIP member index is out of range",
                               "zip_member_open");
        error.offset = member_index;
        error.details.emplace_back("member_count",
                                   std::to_string(state_->members.size()));
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            std::move(error));
    }
    if (state_->members[member_index].kind == zip_member_kind_t::directory)
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            zip_error(workspace_error_code_t::invalid_argument,
                      "ZIP directory member has no byte provider",
                      "zip_member_open"));
    try {
        work_guard_t work(state_->limits, cancel);
        auto polled = work.poll("zip_member_open");
        if (!polled)
            return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
                std::move(polled.error()));
        return state_->open_member(member_index, work, cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            allocation_error("zip_member_open",
                             state_->members[member_index].uncompressed_size));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            allocation_error("zip_member_open",
                             state_->members[member_index].uncompressed_size));
    } catch (const std::system_error& exception) {
        auto error = zip_error(workspace_error_code_t::service_conflict,
                               "ZIP member cache synchronization failed",
                               "zip_member_open");
        error.provider_status = exception.code().value();
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            std::move(error));
    }
}

workspace_result_t<std::shared_ptr<byte_provider_t>>
zip_container_t::open_member_provider(
    std::string_view normalized_path, const cancellation_token_t& cancel) const {
    if (normalized_path.empty() ||
        normalized_path.size() > state_->limits.max_normalized_path_size)
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            zip_error(workspace_error_code_t::invalid_argument,
                      "ZIP normalized member path is invalid",
                      "zip_member_open"));
    try {
        const auto found = state_->member_by_name.find(
            std::string(normalized_path));
        if (found == state_->member_by_name.end()) {
            auto error = zip_error(workspace_error_code_t::target_not_found,
                                   "ZIP member was not found",
                                   "zip_member_open");
            error.details.emplace_back("member", std::string(normalized_path));
            return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
                std::move(error));
        }
        return open_member_provider(found->second, cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            allocation_error("zip_member_open", normalized_path.size()));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            allocation_error("zip_member_open", normalized_path.size()));
    }
}

workspace_result_t<void> zip_container_t::verify_integrity(
    const cancellation_token_t& cancel) const {
    try {
        work_guard_t work(state_->limits, cancel);
        auto polled = work.poll("zip_verify_integrity");
        if (!polled)
            return polled;
        for (std::size_t index = 0; index < state_->members.size(); ++index) {
            auto visited = work.visit_record("zip_verify_integrity");
            if (!visited)
                return visited;
            if (state_->members[index].kind == zip_member_kind_t::directory)
                continue;
            auto provider_result = state_->open_member(index, work, cancel);
            if (!provider_result)
                return workspace_result_t<void>::failure(
                    std::move(provider_result.error()));
        }
        return work.poll("zip_verify_integrity");
    } catch (const std::bad_alloc&) {
        return workspace_result_t<void>::failure(allocation_error(
            "zip_verify_integrity", state_->aggregate_uncompressed));
    } catch (const std::length_error&) {
        return workspace_result_t<void>::failure(allocation_error(
            "zip_verify_integrity", state_->aggregate_uncompressed));
    } catch (const std::system_error& exception) {
        auto error = zip_error(workspace_error_code_t::service_conflict,
                               "ZIP integrity cache synchronization failed",
                               "zip_verify_integrity");
        error.provider_status = exception.code().value();
        return workspace_result_t<void>::failure(std::move(error));
    }
}

bool zip_container_t::integrity_verified() const {
    try {
        std::unique_lock<std::timed_mutex> lock(
            state_->cache_mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return false;
        for (std::size_t index = 0; index < state_->members.size(); ++index) {
            if (state_->members[index].kind != zip_member_kind_t::directory &&
                !state_->cache[index])
                return false;
        }
        return true;
    } catch (const std::system_error&) {
        return false;
    }
}

}
