#pragma once

#include "native_worker_protocol.hpp"

#include <windows.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::native_worker::runtime {

inline constexpr char k_provider_name[] = "aida-native-decompiler";
inline constexpr char k_provider_version[] = "1";
inline constexpr char k_worker_build_id[] = "aida-native-decompiler-worker-v1";
inline constexpr char k_worker_build_hash_material[] = "aida-native-decompiler-worker-build-v1";

struct startup_t {
    HANDLE read_handle = nullptr;
    HANDLE write_handle = nullptr;
    HANDLE snapshot_handle = nullptr;
    HANDLE identity_handle = nullptr;
    std::size_t snapshot_size = 0;
    wire::session_material_t session;
    sha256_digest_t manifest_hash;
    wire::frame_reader_t reader;
    std::uint64_t next_host_sequence = 1;
    std::uint64_t next_worker_sequence = 1;
};

inline bool parse_handle_argument(std::wstring_view argument, std::wstring_view name, HANDLE& value) noexcept
{
    const std::wstring prefix = std::wstring(name) + L"=";
    if (argument.substr(0, prefix.size()) != prefix || argument.size() == prefix.size())
        return false;
    const wchar_t* first = argument.data() + prefix.size();
    wchar_t* end = nullptr;
    errno = 0;
    const auto raw = _wcstoui64(first, &end, 10);
    if (errno != 0 || !end || end != argument.data() + argument.size() || raw == 0 || raw > (std::numeric_limits<std::uintptr_t>::max)())
        return false;
    value = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(raw));
    return true;
}

inline bool parse_size_argument(std::wstring_view argument, std::wstring_view name, std::size_t& value) noexcept
{
    const std::wstring prefix = std::wstring(name) + L"=";
    if (argument.substr(0, prefix.size()) != prefix || argument.size() == prefix.size())
        return false;
    const wchar_t* first = argument.data() + prefix.size();
    wchar_t* end = nullptr;
    errno = 0;
    const auto raw = _wcstoui64(first, &end, 10);
    if (errno != 0 || !end || end != argument.data() + argument.size() || raw == 0 || raw > (std::numeric_limits<std::size_t>::max)())
        return false;
    value = static_cast<std::size_t>(raw);
    return true;
}

inline bool parse_startup(int argc, wchar_t** argv, startup_t& output) noexcept
{
    bool marker = false;
    bool read = false;
    bool write = false;
    bool snapshot = false;
    bool identity = false;
    bool size = false;
    for (int index = 1; index < argc; ++index) {
        const std::wstring_view argument(argv[index] ? argv[index] : L"");
        if (argument == L"--aida-native-decompiler-worker") {
            marker = true;
            continue;
        }
        HANDLE value = nullptr;
        if (parse_handle_argument(argument, L"--read-handle", value)) {
            if (read)
                return false;
            output.read_handle = value;
            read = true;
            continue;
        }
        if (parse_handle_argument(argument, L"--write-handle", value)) {
            if (write)
                return false;
            output.write_handle = value;
            write = true;
            continue;
        }
        if (parse_handle_argument(argument, L"--snapshot-handle", value)) {
            if (snapshot)
                return false;
            output.snapshot_handle = value;
            snapshot = true;
            continue;
        }
        if (parse_handle_argument(argument, L"--identity-handle", value)) {
            if (identity)
                return false;
            output.identity_handle = value;
            identity = true;
            continue;
        }
        std::size_t parsed_size = 0;
        if (parse_size_argument(argument, L"--snapshot-size", parsed_size)) {
            if (size)
                return false;
            output.snapshot_size = parsed_size;
            size = true;
        }
    }
    return marker && read && write && snapshot && identity && size;
}

inline bool receive_bootstrap(startup_t& startup) noexcept
{
    std::array<std::uint8_t, wire::k_bootstrap_bytes> bootstrap{};
    DWORD error = ERROR_SUCCESS;
    const bool received = wire::read_all(startup.read_handle, bootstrap.data(), bootstrap.size(), error) &&
        wire::decode_bootstrap(bootstrap.data(), bootstrap.size(), startup.session, startup.manifest_hash);
    SecureZeroMemory(bootstrap.data(), bootstrap.size());
    return received;
}

inline std::optional<sha256_digest_t> executable_hash(HANDLE identity_handle)
{
    if (!identity_handle || identity_handle == INVALID_HANDLE_VALUE || GetFileType(identity_handle) != FILE_TYPE_DISK)
        return std::nullopt;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(identity_handle, &size) || size.QuadPart <= 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > 2ULL * 1024ULL * 1024ULL * 1024ULL)
        return std::nullopt;
    HANDLE mapping = CreateFileMappingW(identity_handle, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping)
        return std::nullopt;
    const void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(size.QuadPart));
    if (!view) {
        CloseHandle(mapping);
        return std::nullopt;
    }
    sha256_digest_t digest;
    const bool hashed = wire::sha256(view, static_cast<std::size_t>(size.QuadPart), digest);
    UnmapViewOfFile(view);
    CloseHandle(mapping);
    return hashed ? std::optional<sha256_digest_t>{digest} : std::nullopt;
}

inline decompiler_provider_identity_t provider_identity(const startup_t& startup)
{
    decompiler_provider_identity_t provider;
    provider.provider = decompiler_provider_id_t::ghidra_native;
    provider.provider_name = k_provider_name;
    provider.provider_version = k_provider_version;
    const auto hash = executable_hash(startup.identity_handle);
    if (hash)
        provider.provider_binary_hash = *hash;
    provider.worker_build_id = k_worker_build_id;
    provider.worker_build_hash = stable_serialization_hash(k_worker_build_hash_material);
    return provider;
}

inline bool send_message(startup_t& startup, const decompiler_worker_message_t& message, std::size_t maximum_frame_bytes) noexcept
{
    std::string payload;
    try {
        payload = serialize_decompiler_worker_message(message);
    } catch (...) {
        return false;
    }
    DWORD error = ERROR_SUCCESS;
    return wire::send_frame(startup.write_handle, startup.session, wire::frame_kind_t::decompiler_contract,
        startup.next_worker_sequence++, reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), maximum_frame_bytes, error);
}

inline decompiler_diagnostic_t failure_diagnostic(decompiler_diagnostic_code_t code, std::string key, bool retryable = false)
{
    decompiler_diagnostic_t result;
    result.severity = decompiler_diagnostic_severity_t::error;
    result.code = code;
    result.localization_key = std::move(key);
    result.confidence = 100;
    result.retryable = retryable;
    result.ordinal = 1;
    return result;
}

inline bool send_failure(startup_t& startup, std::uint64_t job_id, decompiler_diagnostic_code_t code,
                         std::string key, bool retryable = false)
{
    decompiler_worker_failure_message_t failure;
    failure.envelope.kind = decompiler_worker_message_kind_t::failure;
    failure.envelope.session_nonce_hash = startup.session.nonce_hash;
    failure.envelope.sequence = startup.next_worker_sequence;
    failure.job_id = job_id;
    failure.diagnostics.push_back(failure_diagnostic(code, std::move(key), retryable));
    return send_message(startup, decompiler_worker_message_t{std::move(failure)}, 8U * 1024U * 1024U);
}

inline bool send_hello(startup_t& startup, const decompiler_provider_identity_t& provider, const sha256_digest_t& manifest_hash)
{
    decompiler_worker_hello_t hello;
    hello.envelope.kind = decompiler_worker_message_kind_t::hello;
    hello.envelope.session_nonce_hash = startup.session.nonce_hash;
    hello.envelope.sequence = startup.next_worker_sequence;
    hello.provider = provider;
    hello.manifest_hash = manifest_hash;
    return send_message(startup, decompiler_worker_message_t{std::move(hello)}, 8U * 1024U * 1024U);
}

inline std::optional<decompiler_worker_job_request_t> receive_job(startup_t& startup, std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        wire::frame_t frame;
        DWORD error = ERROR_SUCCESS;
        const auto state = startup.reader.poll(startup.read_handle, startup.session, startup.next_host_sequence,
            8U * 1024U * 1024U, frame, error);
        if (state == wire::read_state_t::failure)
            return std::nullopt;
        if (state == wire::read_state_t::complete) {
            ++startup.next_host_sequence;
            const auto decoded = deserialize_decompiler_worker_message(
                std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()));
            if (!decoded.valid() || !decoded.value || !std::holds_alternative<decompiler_worker_job_request_t>(*decoded.value))
                return std::nullopt;
            const auto& job = std::get<decompiler_worker_job_request_t>(*decoded.value);
            const auto validation = validate_decompiler_worker_message(*decoded.value);
            if (!validation.valid() || job.envelope.sequence != frame.sequence || job.envelope.session_nonce_hash != startup.session.nonce_hash)
                return std::nullopt;
            return job;
        }
        Sleep(2);
    }
    return std::nullopt;
}

inline bool verify_snapshot(const startup_t& startup, const decompiler_worker_job_request_t& job)
{
    if (startup.snapshot_size == 0 || startup.snapshot_size > 256U * 1024U * 1024U || job.snapshot_hash.empty())
        return false;
    void* view = MapViewOfFile(startup.snapshot_handle, FILE_MAP_READ, 0, 0, startup.snapshot_size);
    if (!view)
        return false;
    sha256_digest_t hash;
    const bool valid = wire::sha256(view, startup.snapshot_size, hash) && hash == job.snapshot_hash;
    UnmapViewOfFile(view);
    return valid;
}

inline std::optional<decompiler_worker_cancel_request_t> receive_cancel(startup_t& startup, std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        wire::frame_t frame;
        DWORD error = ERROR_SUCCESS;
        const auto state = startup.reader.poll(startup.read_handle, startup.session, startup.next_host_sequence,
            8U * 1024U * 1024U, frame, error);
        if (state == wire::read_state_t::failure)
            return std::nullopt;
        if (state == wire::read_state_t::complete) {
            ++startup.next_host_sequence;
            const auto decoded = deserialize_decompiler_worker_message(
                std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()));
            if (!decoded.valid() || !decoded.value || !std::holds_alternative<decompiler_worker_cancel_request_t>(*decoded.value))
                return std::nullopt;
            const auto& cancel = std::get<decompiler_worker_cancel_request_t>(*decoded.value);
            const auto validation = validate_decompiler_worker_message(*decoded.value);
            if (!validation.valid() || cancel.envelope.sequence != frame.sequence || cancel.envelope.session_nonce_hash != startup.session.nonce_hash)
                return std::nullopt;
            return cancel;
        }
        Sleep(2);
    }
    return std::nullopt;
}

}
