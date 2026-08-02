#include "native_worker_host.hpp"

#include "decompiler_service.hpp"
#include "generation_snapshot_store.hpp"
#include "isolated_worker_codec.hpp"
#include "providers/dalvik_ssa.hpp"
#include "providers/cli_provider.hpp"
#include "providers/ghidra_ir_adapter.hpp"
#include "providers/jvm_ssa.hpp"
#include "../workspace/workspace_identity.hpp"
#include "../../../helpers/diag_log.hpp"

#include "../../../../workers/native_decompiler/native_worker_protocol.hpp"

#include <windows.h>
#include <aclapi.h>
#include <objbase.h>
#include <psapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <userenv.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <deque>
#include <exception>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")

namespace aida::analysis::native_worker {
namespace {

constexpr std::uint32_t k_manifest_max_string_bytes = 4096;
constexpr std::uint32_t k_manifest_max_arguments = 32;
constexpr std::size_t k_managed_runtime_max_files = 512;
constexpr std::size_t k_managed_runtime_manifest_max_bytes = 512U * 1024U;

class handle_t final {
public:
    handle_t() = default;
    explicit handle_t(HANDLE value) noexcept : value_(value) {}
    ~handle_t() { reset(); }

    handle_t(const handle_t&) = delete;
    handle_t& operator=(const handle_t&) = delete;

    handle_t(handle_t&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    handle_t& operator=(handle_t&& other) noexcept
    {
        if (this != &other)
            reset(std::exchange(other.value_, nullptr));
        return *this;
    }

    HANDLE get() const noexcept { return value_; }
    HANDLE release() noexcept { return std::exchange(value_, nullptr); }
    explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }

    void reset(HANDLE value = nullptr) noexcept
    {
        if (*this)
            CloseHandle(value_);
        value_ = value;
    }

private:
    HANDLE value_ = nullptr;
};

class manifest_writer_t final {
public:
    void u8(std::uint8_t value) { bytes_.push_back(static_cast<char>(value)); }

    void u32(std::uint32_t value)
    {
        std::array<std::uint8_t, sizeof(value)> bytes{};
        wire::write_u32(bytes.data(), value);
        bytes_.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    void string(const std::string& value)
    {
        u32(static_cast<std::uint32_t>(value.size()));
        bytes_.append(value);
    }

    void digest(const sha256_digest_t& value)
    {
        bytes_.append(reinterpret_cast<const char*>(value.bytes.data()), value.bytes.size());
    }

    std::string take() { return std::move(bytes_); }

private:
    std::string bytes_;
};

class manifest_reader_t final {
public:
    explicit manifest_reader_t(std::string_view bytes) : bytes_(bytes) {}

    bool u8(std::uint8_t& value)
    {
        if (remaining() < 1)
            return false;
        value = static_cast<std::uint8_t>(bytes_[offset_++]);
        return true;
    }

    bool u32(std::uint32_t& value)
    {
        if (remaining() < sizeof(value))
            return false;
        value = wire::read_u32(reinterpret_cast<const std::uint8_t*>(bytes_.data() + offset_));
        offset_ += sizeof(value);
        return true;
    }

    bool string(std::string& value)
    {
        std::uint32_t size = 0;
        if (!u32(size) || size > k_manifest_max_string_bytes || remaining() < size)
            return false;
        value.assign(bytes_.data() + offset_, size);
        offset_ += size;
        return true;
    }

    bool digest(sha256_digest_t& value)
    {
        if (remaining() < value.bytes.size())
            return false;
        std::memcpy(value.bytes.data(), bytes_.data() + offset_, value.bytes.size());
        offset_ += value.bytes.size();
        return true;
    }

    bool exhausted() const noexcept { return offset_ == bytes_.size(); }

private:
    std::size_t remaining() const noexcept { return bytes_.size() - offset_; }

    std::string_view bytes_;
    std::size_t offset_ = 0;
};

native_worker_diagnostic_t diagnostic(native_worker_diagnostic_code_t code, std::string phase, std::string detail,
                                      std::uint64_t job_id, std::uint64_t generation, DWORD error = ERROR_SUCCESS,
                                      bool retryable = false)
{
    native_worker_diagnostic_t result;
    result.code = code;
    result.phase = std::move(phase);
    result.detail = std::move(detail);
    result.job_id = job_id;
    result.worker_generation = generation;
    result.win32_error = error;
    result.retryable = retryable;
    return result;
}

void append_diagnostic(native_worker_execution_result_t& result, native_worker_diagnostic_code_t code,
                       std::string phase, std::string detail, DWORD error = ERROR_SUCCESS, bool retryable = false)
{
    result.diagnostics.push_back(diagnostic(code, std::move(phase), std::move(detail), 0,
        result.worker_generation, error, retryable));
}

std::optional<std::wstring> utf8_to_wide(const std::string& value)
{
    if (value.empty())
        return std::wstring{};
    if (value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        return std::nullopt;
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0)
        return std::nullopt;
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), required) != required)
        return std::nullopt;
    return result;
}

std::wstring strip_extended_prefix(std::wstring value)
{
    constexpr std::wstring_view prefix = L"\\\\?\\";
    constexpr std::wstring_view unc_prefix = L"UNC\\";
    if (value.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), value.begin())) {
        value.erase(0, prefix.size());
        if (value.size() >= unc_prefix.size() && std::equal(unc_prefix.begin(), unc_prefix.end(), value.begin(),
            [](wchar_t lhs, wchar_t rhs) { return towupper(lhs) == towupper(rhs); }))
            value.replace(0, unc_prefix.size(), L"\\\\");
    }
    return value;
}

std::optional<std::wstring> final_path(HANDLE handle)
{
    const DWORD required = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED);
    if (required == 0)
        return std::nullopt;
    std::wstring result(required, L'\0');
    const DWORD written = GetFinalPathNameByHandleW(handle, result.data(), required, FILE_NAME_NORMALIZED);
    if (written == 0 || written >= required)
        return std::nullopt;
    result.resize(written);
    return strip_extended_prefix(std::move(result));
}

bool path_within(const std::wstring& root, const std::wstring& candidate) noexcept
{
    if (candidate.size() < root.size() || _wcsnicmp(root.c_str(), candidate.c_str(), root.size()) != 0)
        return false;
    return candidate.size() == root.size() || root.back() == L'\\' || candidate[root.size()] == L'\\';
}

bool safe_relative_path(const std::string& text) noexcept
{
    const auto converted = utf8_to_wide(text);
    if (!converted || converted->empty())
        return false;
    std::filesystem::path path(*converted);
    if (path.is_absolute() || path.has_root_directory() || path.has_root_name())
        return false;
    for (const auto& part : path) {
        if (part.empty() || part == L"." || part == L"..")
            return false;
    }
    return true;
}

bool valid_manifest(const native_worker_manifest_t& manifest)
{
    if ((manifest.schema_version != k_native_worker_manifest_schema_version &&
         manifest.schema_version != k_managed_worker_manifest_schema_version) ||
        !safe_relative_path(manifest.worker_relative_path) ||
        manifest.worker_relative_path.size() > k_manifest_max_string_bytes || manifest.worker_relative_path.find('\0') != std::string::npos ||
        manifest.worker_binary_hash.empty() || manifest.provider.provider_name.empty() || manifest.provider.provider_version.empty() ||
        manifest.provider.worker_build_id.empty() || manifest.provider.provider_binary_hash.empty() || manifest.provider.worker_build_hash.empty() ||
        manifest.worker_protocol_version != k_decompiler_worker_protocol_version || manifest.worker_protocol_hash.empty() ||
        manifest.worker_protocol_hash != wire::protocol_hash() || manifest.capabilities != k_native_worker_capability_decompile ||
        manifest.startup_arguments.size() > k_manifest_max_arguments)
        return false;
    if (manifest.provider.provider_name.size() > k_manifest_max_string_bytes ||
        manifest.provider.provider_version.size() > k_manifest_max_string_bytes || manifest.provider.worker_build_id.size() > k_manifest_max_string_bytes ||
        manifest.provider.provider_name.find('\0') != std::string::npos || manifest.provider.provider_version.find('\0') != std::string::npos ||
        manifest.provider.worker_build_id.find('\0') != std::string::npos)
        return false;
    if (manifest.provider.provider == decompiler_provider_id_t::ghidra_native) {
        if (manifest.schema_version != k_native_worker_manifest_schema_version ||
            !manifest.managed_runtime_manifest_hash.empty() ||
            manifest.provider.provider_name != "aida-native-decompiler" ||
            manifest.provider.provider_binary_hash != manifest.worker_binary_hash)
            return false;
    } else if (manifest.provider.provider == decompiler_provider_id_t::ilspy_cli) {
        const auto expected_provider_hash = sha256_digest_t::from_hex(
            "bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345");
        const auto expected_worker_build_hash = sha256_digest_t::from_hex(
            "4dd8c0d095629437387a4b631fd9ac3c3cb8e840f6b7af277ccc2ad49d4bc3b7");
        if (manifest.schema_version != k_managed_worker_manifest_schema_version ||
            std::string_view(manifest.worker_relative_path) !=
                k_managed_worker_binary_artifact_relative_path ||
            manifest.managed_runtime_manifest_hash.empty() ||
            !manifest.startup_arguments.empty() || !expected_provider_hash ||
            !expected_worker_build_hash ||
            manifest.provider.provider_name != "ICSharpCode.Decompiler" ||
            manifest.provider.provider_version != "10.1.0.8386" ||
            manifest.provider.provider_binary_hash != *expected_provider_hash ||
            manifest.provider.worker_build_id !=
                "aida-managed-decompiler-worker-v3" ||
            manifest.provider.worker_build_hash != *expected_worker_build_hash)
            return false;
    } else {
        return false;
    }
    for (const auto& argument : manifest.startup_arguments) {
        if (argument.empty() || argument.size() > 1024 || argument.find('\0') != std::string::npos ||
            argument.rfind("--aida-native-decompiler-worker", 0) == 0 || argument.rfind("--read-handle", 0) == 0 ||
            argument.rfind("--write-handle", 0) == 0 || argument.rfind("--snapshot-handle", 0) == 0 ||
            argument.rfind("--snapshot-size", 0) == 0 || argument.rfind("--identity-handle", 0) == 0 ||
            argument.rfind("--module-handle", 0) == 0 || argument.rfind("--module-size", 0) == 0 ||
            argument.rfind("--runtime-manifest-hash", 0) == 0 ||
            !utf8_to_wide(argument))
            return false;
    }
    return true;
}

bool read_locked_file(const std::filesystem::path& path, std::size_t maximum_bytes, handle_t& handle,
                      std::vector<std::uint8_t>& output, DWORD& error)
{
    handle.reset(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!handle) {
        error = GetLastError();
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(handle.get(), &size) || size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > maximum_bytes) {
        error = size.QuadPart < 0 ? ERROR_FILE_INVALID : ERROR_FILE_TOO_LARGE;
        return false;
    }
    try {
        output.resize(static_cast<std::size_t>(size.QuadPart));
    } catch (...) {
        error = ERROR_NOT_ENOUGH_MEMORY;
        return false;
    }
    if (!output.empty() && !wire::read_all(handle.get(), output.data(), output.size(), error))
        return false;
    return true;
}

bool has_reparse_component(const std::filesystem::path& path, DWORD& error)
{
    std::filesystem::path current = path.root_path();
    for (const auto& component : path.relative_path()) {
        current /= component;
        const DWORD attributes = GetFileAttributesW(current.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            error = GetLastError();
            return true;
        }
        if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            error = ERROR_REPARSE_TAG_INVALID;
            return true;
        }
    }
    error = ERROR_SUCCESS;
    return false;
}

bool capture_regular_module_bytes(
    const std::filesystem::path& input,
    std::size_t maximum_bytes,
    const cancellation_token_t& cancel,
    std::vector<std::uint8_t>& output,
    DWORD& error)
{
    std::error_code filesystem_error;
    const auto normalized = std::filesystem::absolute(input, filesystem_error).lexically_normal();
    if (filesystem_error || normalized.empty() ||
        has_reparse_component(normalized, error)) {
        if (filesystem_error)
            error = ERROR_INVALID_NAME;
        return false;
    }
    handle_t file(CreateFileW(normalized.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!file) {
        error = GetLastError();
        return false;
    }
    FILE_ATTRIBUTE_TAG_INFO tag{};
    BY_HANDLE_FILE_INFORMATION before{};
    LARGE_INTEGER size{};
    if (!GetFileInformationByHandleEx(file.get(), FileAttributeTagInfo, &tag, sizeof(tag)) ||
        (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !GetFileInformationByHandle(file.get(), &before) ||
        !GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > maximum_bytes) {
        error = size.QuadPart > static_cast<LONGLONG>(maximum_bytes)
            ? ERROR_FILE_TOO_LARGE : ERROR_FILE_INVALID;
        return false;
    }
    const auto resolved = final_path(file.get());
    const auto expected = strip_extended_prefix(normalized.wstring());
    if (!resolved || _wcsicmp(resolved->c_str(), expected.c_str()) != 0) {
        error = ERROR_REPARSE_TAG_INVALID;
        return false;
    }
    try {
        output.resize(static_cast<std::size_t>(size.QuadPart));
    } catch (...) {
        error = ERROR_NOT_ENOUGH_MEMORY;
        return false;
    }
    std::size_t offset = 0;
    while (offset < output.size()) {
        if (cancel.stop_requested()) {
            SecureZeroMemory(output.data(), output.size());
            output.clear();
            error = cancel.deadline_exceeded() ? WAIT_TIMEOUT : ERROR_CANCELLED;
            return false;
        }
        const DWORD requested = static_cast<DWORD>((std::min<std::size_t>)(
            1U << 20, output.size() - offset));
        DWORD received = 0;
        if (!ReadFile(file.get(), output.data() + offset, requested, &received, nullptr) ||
            received != requested) {
            error = GetLastError();
            if (error == ERROR_SUCCESS)
                error = ERROR_HANDLE_EOF;
            SecureZeroMemory(output.data(), output.size());
            output.clear();
            return false;
        }
        offset += received;
    }
    BY_HANDLE_FILE_INFORMATION after{};
    LARGE_INTEGER final_size{};
    if (!GetFileInformationByHandle(file.get(), &after) ||
        !GetFileSizeEx(file.get(), &final_size) ||
        final_size.QuadPart != size.QuadPart ||
        before.dwVolumeSerialNumber != after.dwVolumeSerialNumber ||
        before.nFileIndexHigh != after.nFileIndexHigh ||
        before.nFileIndexLow != after.nFileIndexLow ||
        before.ftLastWriteTime.dwHighDateTime != after.ftLastWriteTime.dwHighDateTime ||
        before.ftLastWriteTime.dwLowDateTime != after.ftLastWriteTime.dwLowDateTime) {
        SecureZeroMemory(output.data(), output.size());
        output.clear();
        error = ERROR_FILE_INVALID;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

struct managed_runtime_file_t {
    std::string role;
    std::string relative_path;
    std::uint64_t size_bytes = 0;
    sha256_digest_t hash;
};

struct managed_runtime_package_t {
    sha256_digest_t manifest_hash;
    std::wstring dotnet_root;
    std::vector<handle_t> locked_files;
};

bool exact_fields(const nlohmann::json& value,
                  std::initializer_list<std::string_view> names)
{
    if (!value.is_object() || value.size() != names.size())
        return false;
    return std::all_of(names.begin(), names.end(), [&value](const auto name) {
        return value.contains(std::string(name));
    });
}

std::optional<std::uint64_t> json_u64(const nlohmann::json& value,
                                      const char* name)
{
    const auto found = value.find(name);
    if (found == value.end() || !found->is_number_unsigned())
        return std::nullopt;
    return found->get<std::uint64_t>();
}

std::optional<std::string> json_string(const nlohmann::json& value,
                                       const char* name,
                                       std::size_t maximum = k_manifest_max_string_bytes)
{
    const auto found = value.find(name);
    if (found == value.end() || !found->is_string())
        return std::nullopt;
    auto result = found->get<std::string>();
    if (result.empty() || result.size() > maximum ||
        result.find('\0') != std::string::npos)
        return std::nullopt;
    return result;
}

bool lowercase_digest_text(const std::string& value) noexcept
{
    return value.size() == 64 &&
        std::all_of(value.begin(), value.end(), [](const unsigned char byte) {
            return (byte >= '0' && byte <= '9') ||
                   (byte >= 'a' && byte <= 'f');
        });
}

std::string lowercase_path_key(std::string value)
{
    std::replace(value.begin(), value.end(), '\\', '/');
    std::transform(value.begin(), value.end(), value.begin(),
        [](const unsigned char byte) { return static_cast<char>(std::tolower(byte)); });
    return value;
}

bool parse_managed_runtime_file(const nlohmann::json& value,
                                bool application,
                                managed_runtime_file_t& result)
{
    if (!exact_fields(value, application
            ? std::initializer_list<std::string_view>{"role", "relative_path", "size_bytes", "sha256"}
            : std::initializer_list<std::string_view>{"relative_path", "size_bytes", "sha256"}))
        return false;
    if (application) {
        const auto role = json_string(value, "role", 64);
        if (!role)
            return false;
        result.role = *role;
    }
    const auto relative_path = json_string(value, "relative_path");
    const auto size = json_u64(value, "size_bytes");
    const auto hash_text = json_string(value, "sha256", 64);
    if (!relative_path || !size || *size == 0 || !hash_text ||
        !lowercase_digest_text(*hash_text) || !safe_relative_path(*relative_path))
        return false;
    const auto hash = sha256_digest_t::from_hex(*hash_text);
    if (!hash || hash->empty())
        return false;
    result.relative_path = *relative_path;
    std::replace(result.relative_path.begin(), result.relative_path.end(), '\\', '/');
    result.size_bytes = *size;
    result.hash = *hash;
    return true;
}

sha256_digest_t canonical_runtime_inventory_hash(
    std::vector<managed_runtime_file_t> files)
{
    std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
        const auto left_key = lowercase_path_key(left.relative_path);
        const auto right_key = lowercase_path_key(right.relative_path);
        return left_key == right_key
            ? left.relative_path < right.relative_path
            : left_key < right_key;
    });
    std::string material;
    for (std::size_t index = 0; index < files.size(); ++index) {
        if (index != 0)
            material.push_back('\n');
        material.append(files[index].relative_path);
        material.push_back('|');
        material.append(std::to_string(files[index].size_bytes));
        material.push_back('|');
        material.append(files[index].hash.to_hex());
    }
    return stable_serialization_hash(material);
}

std::optional<managed_runtime_package_t> verify_managed_runtime_package(
    const std::filesystem::path& approved_root,
    const std::wstring& approved_root_final,
    const sha256_digest_t& expected_hash,
    const sha256_digest_t& expected_provider_hash,
    native_worker_execution_result_t& result)
{
    try {
        const auto manifest_path = (approved_root / std::filesystem::path(
            std::string(k_managed_runtime_manifest_artifact_relative_path))).lexically_normal();
        const auto digest_path = (approved_root / std::filesystem::path(
            std::string(k_managed_runtime_manifest_digest_relative_path))).lexically_normal();
        DWORD error = ERROR_SUCCESS;
        handle_t manifest_handle;
        handle_t digest_handle;
        std::vector<std::uint8_t> manifest_bytes;
        std::vector<std::uint8_t> digest_bytes;
        if (has_reparse_component(manifest_path, error) ||
            has_reparse_component(digest_path, error) ||
            !read_locked_file(manifest_path, k_managed_runtime_manifest_max_bytes,
                manifest_handle, manifest_bytes, error) ||
            !read_locked_file(digest_path, 128, digest_handle, digest_bytes, error)) {
            append_diagnostic(result,
                native_worker_diagnostic_code_t::runtime_manifest_unavailable,
                "native_worker.managed_runtime.manifest",
                "managed runtime manifest or digest is unavailable", error);
            return std::nullopt;
        }
        const auto manifest_final = final_path(manifest_handle.get());
        const auto digest_final = final_path(digest_handle.get());
        if (!manifest_final || !digest_final ||
            !path_within(approved_root_final, *manifest_final) ||
            !path_within(approved_root_final, *digest_final)) {
            append_diagnostic(result,
                native_worker_diagnostic_code_t::runtime_manifest_unavailable,
                "native_worker.managed_runtime.binding",
                "managed runtime manifest escaped the approved package root",
                ERROR_ACCESS_DENIED);
            return std::nullopt;
        }
        sha256_digest_t actual_manifest_hash;
        if (!wire::sha256(manifest_bytes.data(), manifest_bytes.size(),
                actual_manifest_hash) || actual_manifest_hash != expected_hash) {
            append_diagnostic(result,
                native_worker_diagnostic_code_t::runtime_manifest_hash_mismatch,
                "native_worker.managed_runtime.manifest_hash",
                "managed runtime manifest hash does not match the worker identity",
                ERROR_CRC);
            return std::nullopt;
        }
        if (digest_bytes.size() != 65 || digest_bytes.back() != '\n') {
            append_diagnostic(result,
                native_worker_diagnostic_code_t::runtime_manifest_hash_mismatch,
                "native_worker.managed_runtime.digest",
                "managed runtime digest encoding is not canonical",
                ERROR_INVALID_DATA);
            return std::nullopt;
        }
        const std::string digest_text(
            reinterpret_cast<const char*>(digest_bytes.data()), 64);
        const auto parsed_digest = sha256_digest_t::from_hex(digest_text);
        if (!lowercase_digest_text(digest_text) || !parsed_digest ||
            *parsed_digest != actual_manifest_hash) {
            append_diagnostic(result,
                native_worker_diagnostic_code_t::runtime_manifest_hash_mismatch,
                "native_worker.managed_runtime.digest",
                "managed runtime digest does not match the manifest",
                ERROR_CRC);
            return std::nullopt;
        }
        const auto document = nlohmann::json::parse(manifest_bytes.begin(),
            manifest_bytes.end(), nullptr, true, true);
        SecureZeroMemory(manifest_bytes.data(), manifest_bytes.size());
        if (!exact_fields(document, {"schema", "schema_version",
                "source_contract_sha256", "target_framework", "runtime",
                "application", "launch", "inventory"}) ||
            document.at("schema") != "aida.c03.managed-runtime-manifest" ||
            document.at("schema_version") != 1 ||
            document.at("target_framework") != "net10.0")
            throw std::invalid_argument("managed runtime manifest header");
        const auto source_hash = json_string(document, "source_contract_sha256", 64);
        const auto source_digest = sha256_digest_t::from_hex(
            source_hash.value_or(std::string{}));
        if (!source_hash || !lowercase_digest_text(*source_hash) ||
            !source_digest || source_digest->empty())
            throw std::invalid_argument("managed runtime source identity");
        const auto& runtime = document.at("runtime");
        const auto& application = document.at("application");
        const auto& launch = document.at("launch");
        const auto& inventory = document.at("inventory");
        if (!exact_fields(runtime, {"framework", "version", "runtime_identifier",
                "relative_root", "exact_inventory", "file_count",
                "total_size_bytes", "canonical_inventory_sha256", "files"}) ||
            runtime.at("framework") != "Microsoft.NETCore.App" ||
            runtime.at("version") != "10.0.9" ||
            runtime.at("runtime_identifier") != "win-x64" ||
            runtime.at("relative_root") != "deps/dotnet" ||
            runtime.at("exact_inventory") != true ||
            !exact_fields(application, {"exact_inventory", "files"}) ||
            application.at("exact_inventory") != true ||
            !exact_fields(launch, {"executable_relative_path",
                "hostfxr_relative_path", "dotnet_root_relative_path",
                "multilevel_lookup", "roll_forward",
                "roll_forward_to_prerelease", "machine_runtime_fallback"}) ||
            launch.at("executable_relative_path") !=
                "deps/AiDA_ManagedDecompilerWorker.exe" ||
            launch.at("hostfxr_relative_path") !=
                "deps/dotnet/host/fxr/10.0.9/hostfxr.dll" ||
            launch.at("dotnet_root_relative_path") != "deps/dotnet" ||
            launch.at("multilevel_lookup") != false ||
            launch.at("roll_forward") != "Disable" ||
            launch.at("roll_forward_to_prerelease") != false ||
            launch.at("machine_runtime_fallback") != false ||
            !exact_fields(inventory, {"file_count", "total_size_bytes",
                "canonical_inventory_sha256"}) ||
            !runtime.at("files").is_array() ||
            !application.at("files").is_array())
            throw std::invalid_argument("managed runtime manifest contract");
        const auto runtime_count = json_u64(runtime, "file_count");
        const auto runtime_total = json_u64(runtime, "total_size_bytes");
        const auto runtime_inventory_text = json_string(runtime,
            "canonical_inventory_sha256", 64);
        const auto inventory_count = json_u64(inventory, "file_count");
        const auto inventory_total = json_u64(inventory, "total_size_bytes");
        const auto inventory_hash_text = json_string(inventory,
            "canonical_inventory_sha256", 64);
        if (!runtime_count || *runtime_count != 193 ||
            *runtime_count > k_managed_runtime_max_files || !runtime_total ||
            *runtime_total == 0 || !runtime_inventory_text ||
            !lowercase_digest_text(*runtime_inventory_text) || !inventory_count ||
            *inventory_count != 200 || !inventory_total || *inventory_total == 0 ||
            !inventory_hash_text || !lowercase_digest_text(*inventory_hash_text) ||
            runtime.at("files").size() != *runtime_count ||
            application.at("files").size() != 7)
            throw std::invalid_argument("managed runtime manifest inventory header");
        std::vector<managed_runtime_file_t> runtime_files;
        std::vector<managed_runtime_file_t> application_files;
        runtime_files.reserve(runtime.at("files").size());
        application_files.reserve(application.at("files").size());
        std::unordered_set<std::string> path_keys;
        std::uint64_t runtime_size = 0;
        std::uint64_t application_size = 0;
        for (const auto& encoded : runtime.at("files")) {
            managed_runtime_file_t file;
            if (!parse_managed_runtime_file(encoded, false, file) ||
                file.relative_path.rfind("deps/dotnet/", 0) != 0 ||
                !path_keys.insert(lowercase_path_key(file.relative_path)).second ||
                file.size_bytes > (std::numeric_limits<std::uint64_t>::max)() - runtime_size)
                throw std::invalid_argument("managed runtime file inventory");
            runtime_size += file.size_bytes;
            runtime_files.push_back(std::move(file));
        }
        const std::unordered_map<std::string, std::string> expected_application{
            {"apphost", "deps/AiDA_ManagedDecompilerWorker.exe"},
            {"assembly", "deps/AiDA_ManagedDecompilerWorker.dll"},
            {"deps", "deps/AiDA_ManagedDecompilerWorker.deps.json"},
            {"runtimeconfig", "deps/AiDA_ManagedDecompilerWorker.runtimeconfig.json"},
            {"provider", "deps/ICSharpCode.Decompiler.dll"}};
        std::unordered_map<std::string, std::size_t> roles;
        std::unordered_set<std::string> direct_dependencies;
        for (const auto& encoded : application.at("files")) {
            managed_runtime_file_t file;
            if (!parse_managed_runtime_file(encoded, true, file) ||
                !path_keys.insert(lowercase_path_key(file.relative_path)).second ||
                file.size_bytes > (std::numeric_limits<std::uint64_t>::max)() - application_size)
                throw std::invalid_argument("managed application file inventory");
            application_size += file.size_bytes;
            ++roles[file.role];
            if (file.role == "direct_dependency")
                direct_dependencies.insert(file.relative_path);
            else {
                const auto expected = expected_application.find(file.role);
                if (expected == expected_application.end() ||
                    file.relative_path != expected->second)
                    throw std::invalid_argument("managed application role identity");
            }
            if (file.role == "provider" && file.hash != expected_provider_hash)
                throw std::invalid_argument("managed provider manifest identity");
            application_files.push_back(std::move(file));
        }
        if (roles["apphost"] != 1 || roles["assembly"] != 1 ||
            roles["deps"] != 1 || roles["runtimeconfig"] != 1 ||
            roles["provider"] != 1 || roles["direct_dependency"] != 2 ||
            roles.size() != 6 || direct_dependencies !=
                std::unordered_set<std::string>{
                    "deps/System.Collections.Immutable.dll",
                    "deps/System.Reflection.Metadata.dll"} ||
            application_size >
                (std::numeric_limits<std::uint64_t>::max)() - runtime_size ||
            runtime_size != *runtime_total ||
            runtime_size + application_size != *inventory_total)
            throw std::invalid_argument("managed application inventory identity");
        const auto runtime_inventory_hash =
            canonical_runtime_inventory_hash(runtime_files);
        auto all_files = runtime_files;
        all_files.insert(all_files.end(), application_files.begin(),
            application_files.end());
        const auto complete_inventory_hash =
            canonical_runtime_inventory_hash(all_files);
        if (runtime_inventory_hash.to_hex() !=
                "8582bda52b66ad61651a2c9bc2c705cf10b038e374f87662045397c7966b02c9" ||
            runtime_inventory_hash.to_hex() != *runtime_inventory_text ||
            complete_inventory_hash.to_hex() != *inventory_hash_text)
            throw std::invalid_argument("managed runtime canonical inventory");
        managed_runtime_package_t package;
        package.manifest_hash = actual_manifest_hash;
        package.locked_files.reserve(all_files.size() + 2);
        package.locked_files.push_back(std::move(manifest_handle));
        package.locked_files.push_back(std::move(digest_handle));
        std::unordered_set<std::string> expected_runtime_paths;
        for (const auto& file : all_files) {
            const auto absolute = (approved_root /
                std::filesystem::path(file.relative_path)).lexically_normal();
            if (has_reparse_component(absolute, error))
                throw std::invalid_argument("managed runtime reparse path");
            handle_t locked;
            std::vector<std::uint8_t> bytes;
            if (!read_locked_file(absolute,
                    static_cast<std::size_t>((std::min<std::uint64_t>)(
                        file.size_bytes, (std::numeric_limits<std::size_t>::max)())),
                    locked, bytes, error) || bytes.size() != file.size_bytes)
                throw std::invalid_argument("managed runtime file unavailable");
            const auto resolved = final_path(locked.get());
            sha256_digest_t actual;
            const bool hashed = wire::sha256(bytes.data(), bytes.size(), actual);
            SecureZeroMemory(bytes.data(), bytes.size());
            if (!resolved || !path_within(approved_root_final, *resolved) ||
                !hashed || actual != file.hash)
                throw std::invalid_argument("managed runtime file identity");
            if (file.relative_path.rfind("deps/dotnet/", 0) == 0)
                expected_runtime_paths.insert(lowercase_path_key(file.relative_path));
            package.locked_files.push_back(std::move(locked));
        }
        const auto dotnet_root = (approved_root / std::filesystem::path(
            std::string(k_managed_dotnet_root_relative_path))).lexically_normal();
        if (has_reparse_component(dotnet_root, error))
            throw std::invalid_argument("managed runtime root reparse point");
        handle_t dotnet_root_handle(CreateFileW(dotnet_root.c_str(),
            FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        const auto dotnet_root_final = dotnet_root_handle
            ? final_path(dotnet_root_handle.get()) : std::nullopt;
        if (!dotnet_root_final ||
            !path_within(approved_root_final, *dotnet_root_final))
            throw std::invalid_argument("managed runtime root identity");
        std::error_code iteration_error;
        std::size_t observed_runtime_files = 0;
        for (std::filesystem::recursive_directory_iterator iterator(dotnet_root,
                 std::filesystem::directory_options::none, iteration_error), end;
             !iteration_error && iterator != end; iterator.increment(iteration_error)) {
            const DWORD attributes = GetFileAttributesW(iterator->path().c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw std::invalid_argument("managed runtime tree reparse point");
            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                continue;
            const auto relative = std::filesystem::relative(iterator->path(),
                approved_root, iteration_error).generic_string();
            if (iteration_error ||
                expected_runtime_paths.erase(lowercase_path_key(relative)) != 1)
                throw std::invalid_argument("managed runtime unlisted file");
            ++observed_runtime_files;
        }
        if (iteration_error || observed_runtime_files != runtime_files.size() ||
            !expected_runtime_paths.empty())
            throw std::invalid_argument("managed runtime exact inventory");
        package.dotnet_root = *dotnet_root_final;
        return package;
    } catch (const std::exception& exception) {
        append_diagnostic(result,
            native_worker_diagnostic_code_t::runtime_inventory_mismatch,
            "native_worker.managed_runtime.inventory",
            std::string("managed runtime package violates its exact app-local identity: ") +
                exception.what(),
            ERROR_INVALID_DATA);
        return std::nullopt;
    } catch (...) {
        append_diagnostic(result,
            native_worker_diagnostic_code_t::runtime_inventory_mismatch,
            "native_worker.managed_runtime.inventory",
            "managed runtime package violates its exact app-local identity",
            ERROR_INVALID_DATA);
        return std::nullopt;
    }
}

}

struct native_worker_verified_package_t {
    native_worker_manifest_t manifest;
    sha256_digest_t manifest_hash;
    std::wstring root_path;
    std::wstring worker_path;
    handle_t worker_file;
    std::optional<managed_runtime_package_t> managed_runtime;
};

namespace {

std::optional<native_worker_verified_package_t> verify_worker(
    const native_worker_launch_contract_t& contract,
    native_worker_execution_result_t& result)
{
    if (contract.approved_root.empty() || contract.manifest_path.empty() || contract.expected_manifest_hash.empty()) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request, "native_worker.verify", "launch contract is incomplete");
        return std::nullopt;
    }
    std::error_code ec;
    const auto root = std::filesystem::absolute(contract.approved_root, ec).lexically_normal();
    if (ec || !std::filesystem::is_directory(root, ec) || ec) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_path_rejected, "native_worker.root", "approved root is not a directory", ERROR_PATH_NOT_FOUND);
        return std::nullopt;
    }
    const DWORD root_attributes = GetFileAttributesW(root.c_str());
    if (root_attributes == INVALID_FILE_ATTRIBUTES || (root_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_path_rejected, "native_worker.root", "approved root is a reparse point", GetLastError());
        return std::nullopt;
    }
    handle_t root_handle(CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    const auto root_path = root_handle ? final_path(root_handle.get()) : std::nullopt;
    if (!root_path) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_path_rejected, "native_worker.root", "approved root could not be canonicalized", GetLastError());
        return std::nullopt;
    }
    const auto manifest_path = std::filesystem::absolute(contract.manifest_path, ec).lexically_normal();
    if (ec) {
        append_diagnostic(result, native_worker_diagnostic_code_t::manifest_unavailable, "native_worker.manifest", "manifest path cannot be normalized", ERROR_INVALID_NAME);
        return std::nullopt;
    }
    const DWORD manifest_attributes = GetFileAttributesW(manifest_path.c_str());
    if (manifest_attributes == INVALID_FILE_ATTRIBUTES || (manifest_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        append_diagnostic(result, native_worker_diagnostic_code_t::manifest_unavailable, "native_worker.manifest", "manifest path is not a regular file", GetLastError());
        return std::nullopt;
    }
    handle_t manifest_file;
    std::vector<std::uint8_t> manifest_bytes;
    DWORD error = ERROR_SUCCESS;
    if (!read_locked_file(manifest_path, 64U * 1024U, manifest_file, manifest_bytes, error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::manifest_unavailable, "native_worker.manifest", "manifest could not be read", error);
        return std::nullopt;
    }
    const auto manifest_final_path = final_path(manifest_file.get());
    if (!manifest_final_path || !path_within(*root_path, *manifest_final_path)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_path_rejected, "native_worker.manifest", "manifest is outside approved root", ERROR_ACCESS_DENIED);
        return std::nullopt;
    }
    sha256_digest_t manifest_hash;
    if (!wire::sha256(manifest_bytes.data(), manifest_bytes.size(), manifest_hash)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::manifest_unavailable, "native_worker.manifest_hash", "manifest hash calculation failed", ERROR_CRC);
        return std::nullopt;
    }
    if (manifest_hash != contract.expected_manifest_hash) {
        append_diagnostic(result, native_worker_diagnostic_code_t::manifest_hash_mismatch, "native_worker.manifest_hash", "manifest hash does not match the launch contract", ERROR_CRC);
        return std::nullopt;
    }
    native_worker_manifest_decode_t decoded = deserialize_native_worker_manifest(
        std::string(reinterpret_cast<const char*>(manifest_bytes.data()), manifest_bytes.size()));
    SecureZeroMemory(manifest_bytes.data(), manifest_bytes.size());
    if (!decoded.valid() || !decoded.value || !valid_manifest(*decoded.value)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::manifest_malformed, "native_worker.manifest_decode",
            decoded.error.empty() ? "manifest fields violate the launch contract" : decoded.error, ERROR_INVALID_DATA);
        return std::nullopt;
    }
    const auto worker_relative = utf8_to_wide(decoded.value->worker_relative_path);
    if (!worker_relative) {
        append_diagnostic(result, native_worker_diagnostic_code_t::manifest_malformed, "native_worker.worker_path", "worker path is not valid UTF-8", ERROR_INVALID_NAME);
        return std::nullopt;
    }
    const auto worker_path = (root / std::filesystem::path(*worker_relative)).lexically_normal();
    const DWORD worker_attributes = GetFileAttributesW(worker_path.c_str());
    if (worker_attributes == INVALID_FILE_ATTRIBUTES || (worker_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_path_rejected, "native_worker.worker_path", "worker is not a regular disk-backed file", GetLastError());
        return std::nullopt;
    }
    native_worker_verified_package_t verified;
    verified.manifest = std::move(*decoded.value);
    verified.manifest_hash = manifest_hash;
    verified.root_path = *root_path;
    std::vector<std::uint8_t> worker_bytes;
    if (!read_locked_file(worker_path, 2ULL * 1024ULL * 1024ULL * 1024ULL, verified.worker_file, worker_bytes, error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_path_rejected, "native_worker.worker_file", "worker file could not be locked and read", error);
        return std::nullopt;
    }
    const auto worker_final_path = final_path(verified.worker_file.get());
    if (!worker_final_path || !path_within(verified.root_path, *worker_final_path)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_path_rejected, "native_worker.worker_file", "worker resolves outside approved root", ERROR_ACCESS_DENIED);
        return std::nullopt;
    }
    sha256_digest_t worker_hash;
    const bool hashed = wire::sha256(worker_bytes.data(), worker_bytes.size(), worker_hash);
    SecureZeroMemory(worker_bytes.data(), worker_bytes.size());
    if (!hashed) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_hash_mismatch, "native_worker.worker_hash", "worker hash calculation failed", ERROR_CRC);
        return std::nullopt;
    }
    if (worker_hash != verified.manifest.worker_binary_hash) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_hash_mismatch, "native_worker.worker_hash", "worker hash does not match manifest", ERROR_CRC);
        return std::nullopt;
    }
    if (verified.manifest.provider.provider == decompiler_provider_id_t::ilspy_cli) {
        verified.managed_runtime = verify_managed_runtime_package(root,
            verified.root_path, verified.manifest.managed_runtime_manifest_hash,
            verified.manifest.provider.provider_binary_hash, result);
        if (!verified.managed_runtime)
            return std::nullopt;
    }
    verified.worker_path = *worker_final_path;
    result.manifest_hash = manifest_hash;
    return verified;
}

std::wstring quote_argument(const std::wstring& value)
{
    std::wstring result;
    result.push_back(L'"');
    std::size_t slash_count = 0;
    for (const wchar_t character : value) {
        if (character == L'\\') {
            ++slash_count;
            continue;
        }
        if (character == L'"')
            result.append(slash_count * 2 + 1, L'\\');
        else
            result.append(slash_count, L'\\');
        slash_count = 0;
        result.push_back(character);
    }
    result.append(slash_count * 2, L'\\');
    result.push_back(L'"');
    return result;
}

std::optional<std::wstring> canonical_host_local_app_data()
{
    PWSTR known_path = nullptr;
    const HRESULT status = SHGetKnownFolderPath(
        FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &known_path);
    if (FAILED(status) || !known_path) {
        if (known_path)
            CoTaskMemFree(known_path);
        DWORD error = HRESULT_FACILITY(status) == FACILITY_WIN32
            ? HRESULT_CODE(status)
            : ERROR_PATH_NOT_FOUND;
        if (error == ERROR_SUCCESS)
            error = ERROR_PATH_NOT_FOUND;
        SetLastError(error);
        return std::nullopt;
    }
    constexpr std::size_t maximum_path_characters = 32768;
    const std::size_t length = wcsnlen_s(known_path, maximum_path_characters);
    if (length == 0 || length == maximum_path_characters) {
        CoTaskMemFree(known_path);
        SetLastError(length == 0 ? ERROR_PATH_NOT_FOUND : ERROR_INVALID_DATA);
        return std::nullopt;
    }
    std::optional<std::wstring> result;
    try {
        result.emplace(known_path, length);
    } catch (const std::bad_alloc&) {
        CoTaskMemFree(known_path);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return std::nullopt;
    } catch (const std::length_error&) {
        CoTaskMemFree(known_path);
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return std::nullopt;
    }
    CoTaskMemFree(known_path);
    SetLastError(ERROR_SUCCESS);
    return result;
}

std::optional<std::vector<wchar_t>> minimal_environment(
    const std::optional<std::wstring>& dotnet_root)
{
    try {
        std::wstring system_root(32768, L'\0');
        const UINT written = GetWindowsDirectoryW(system_root.data(),
            static_cast<UINT>(system_root.size()));
        if (written == 0) {
            if (GetLastError() == ERROR_SUCCESS)
                SetLastError(ERROR_PATH_NOT_FOUND);
            return std::nullopt;
        }
        if (written >= static_cast<UINT>(system_root.size())) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return std::nullopt;
        }
        system_root.resize(written);
        if (dotnet_root && dotnet_root->empty()) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return std::nullopt;
        }
        const auto local_app_data = canonical_host_local_app_data();
        if (!local_app_data)
            return std::nullopt;
        std::wstring temp = *local_app_data;
        while (!temp.empty() && (temp.back() == L'\\' || temp.back() == L'/'))
            temp.pop_back();
        if (temp.empty()) {
            SetLastError(ERROR_PATH_NOT_FOUND);
            return std::nullopt;
        }
        temp.append(L"\\Temp");
        std::vector<std::wstring> entries{
            L"COMPlus_EnableDiagnostics=0",
            L"DOTNET_CLI_TELEMETRY_OPTOUT=1",
            L"DOTNET_EnableDiagnostics=0",
            L"DOTNET_MULTILEVEL_LOOKUP=0",
            L"DOTNET_NOLOGO=1",
            L"DOTNET_ROLL_FORWARD=Disable",
            L"DOTNET_ROLL_FORWARD_TO_PRERELEASE=0",
            L"DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
            L"LOCALAPPDATA=" + *local_app_data,
            L"PATH=" + system_root + L"\\System32",
            L"SystemRoot=" + system_root,
            L"TEMP=" + temp,
            L"TMP=" + temp,
            L"WINDIR=" + system_root};
        if (dotnet_root)
            entries.push_back(L"DOTNET_ROOT=" + *dotnet_root);
        std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
            return _wcsicmp(left.c_str(), right.c_str()) < 0;
        });
        std::wstring block;
        for (const auto& entry : entries) {
            block.append(entry);
            block.push_back(L'\0');
        }
        block.push_back(L'\0');
        SetLastError(ERROR_SUCCESS);
        return std::vector<wchar_t>(block.begin(), block.end());
    } catch (const std::bad_alloc&) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    } catch (const std::length_error&) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
    }
    return std::nullopt;
}

class app_container_t final {
public:
    app_container_t() = default;
    ~app_container_t()
    {
        if (sid_)
            FreeSid(sid_);
    }

    app_container_t(const app_container_t&) = delete;
    app_container_t& operator=(const app_container_t&) = delete;

    bool create(const sha256_digest_t& manifest_hash, DWORD& error)
    {
        const auto name_utf8 = std::string("AiDA.NativeWorker.") + manifest_hash.to_hex().substr(0, 32);
        const auto name = utf8_to_wide(name_utf8);
        if (!name) {
            error = ERROR_INVALID_NAME;
            return false;
        }
        HRESULT status = CreateAppContainerProfile(name->c_str(), name->c_str(), name->c_str(), nullptr, 0, &sid_);
        if (status == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
            status = DeriveAppContainerSidFromAppContainerName(name->c_str(), &sid_);
        if (FAILED(status) || !sid_) {
            error = HRESULT_FACILITY(status) == FACILITY_WIN32 ? HRESULT_CODE(status) : ERROR_ACCESS_DENIED;
            return false;
        }
        LPWSTR sid_string = nullptr;
        if (!ConvertSidToStringSidW(sid_, &sid_string) || !sid_string) {
            error = GetLastError();
            if (error == ERROR_SUCCESS)
                error = ERROR_INVALID_SID;
            return false;
        }
        PWSTR profile_path = nullptr;
        status = GetAppContainerFolderPath(sid_string, &profile_path);
        LocalFree(sid_string);
        if (FAILED(status) || !profile_path || profile_path[0] == L'\0') {
            if (profile_path)
                CoTaskMemFree(profile_path);
            error = HRESULT_FACILITY(status) == FACILITY_WIN32
                ? HRESULT_CODE(status)
                : ERROR_PATH_NOT_FOUND;
            if (error == ERROR_SUCCESS)
                error = ERROR_PATH_NOT_FOUND;
            return false;
        }
        CoTaskMemFree(profile_path);
        error = ERROR_SUCCESS;
        return true;
    }

    PSID sid() const noexcept { return sid_; }

private:
    PSID sid_ = nullptr;
};

constexpr ACCESS_MASK k_app_container_runtime_read_execute =
    FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
constexpr ACCESS_MASK k_app_container_runtime_directory_traverse =
    FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
constexpr ACCESS_MASK k_app_container_runtime_forbidden =
    FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
    FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
constexpr std::size_t k_ghidra_spec_mirror_file_count = 51;

std::mutex& app_container_runtime_acl_mutex()
{
    static std::mutex mutex;
    return mutex;
}

bool app_container_runtime_acl_satisfied(PACL acl, PSID app_container_sid,
                                         ACCESS_MASK required_access) noexcept
{
    if (!acl || !IsValidAcl(acl) || !app_container_sid ||
        !IsValidSid(app_container_sid) || required_access == 0 ||
        (required_access & k_app_container_runtime_forbidden) != 0)
        return false;
    ACCESS_MASK allowed = 0;
    ACCESS_MASK denied = 0;
    for (DWORD index = 0; index < acl->AceCount; ++index) {
        void* raw_ace = nullptr;
        if (!GetAce(acl, index, &raw_ace) || !raw_ace)
            return false;
        const auto* header = static_cast<const ACE_HEADER*>(raw_ace);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE &&
            header->AceType != ACCESS_DENIED_ACE_TYPE)
            continue;
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
        PSID ace_sid = const_cast<DWORD*>(&ace->SidStart);
        if (!IsValidSid(ace_sid) || !EqualSid(ace_sid, app_container_sid))
            continue;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE)
            allowed |= ace->Mask;
        else
            denied |= ace->Mask;
    }
    return (allowed & required_access) == required_access &&
        (denied & k_app_container_runtime_forbidden) ==
            k_app_container_runtime_forbidden &&
        (denied & required_access) == 0;
}

bool query_app_container_runtime_acl(HANDLE handle, PSID app_container_sid,
                                     ACCESS_MASK required_access,
                                     bool& satisfied, DWORD& error) noexcept
{
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD status = GetSecurityInfo(handle, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
        &descriptor);
    if (status != ERROR_SUCCESS || !descriptor) {
        if (descriptor)
            LocalFree(descriptor);
        error = status == ERROR_SUCCESS ? ERROR_INVALID_SECURITY_DESCR : status;
        return false;
    }
    satisfied = app_container_runtime_acl_satisfied(dacl, app_container_sid,
        required_access);
    LocalFree(descriptor);
    error = ERROR_SUCCESS;
    return true;
}

bool grant_app_container_runtime_acl(HANDLE handle, PSID app_container_sid,
                                     ACCESS_MASK required_access,
                                     DWORD& error) noexcept
{
    if (required_access == 0 ||
        (required_access & k_app_container_runtime_forbidden) != 0) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    PACL existing_dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD status = GetSecurityInfo(handle, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, &existing_dacl, nullptr,
        &descriptor);
    if (status != ERROR_SUCCESS || !descriptor || !existing_dacl) {
        if (descriptor)
            LocalFree(descriptor);
        error = status == ERROR_SUCCESS ? ERROR_INVALID_ACL : status;
        return false;
    }
    std::array<EXPLICIT_ACCESSW, 2> entries{};
    entries[0].grfAccessPermissions = k_app_container_runtime_forbidden;
    entries[0].grfAccessMode = DENY_ACCESS;
    entries[0].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&entries[0].Trustee, app_container_sid);
    entries[1].grfAccessPermissions = required_access;
    entries[1].grfAccessMode = GRANT_ACCESS;
    entries[1].grfInheritance = NO_INHERITANCE;
    BuildTrusteeWithSidW(&entries[1].Trustee, app_container_sid);
    PACL updated_dacl = nullptr;
    status = SetEntriesInAclW(static_cast<ULONG>(entries.size()), entries.data(),
        existing_dacl, &updated_dacl);
    if (status == ERROR_SUCCESS && updated_dacl) {
        status = SetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, updated_dacl, nullptr);
    } else if (status == ERROR_SUCCESS) {
        status = ERROR_INVALID_ACL;
    }
    if (updated_dacl)
        LocalFree(updated_dacl);
    LocalFree(descriptor);
    if (status != ERROR_SUCCESS) {
        error = status;
        return false;
    }
    bool satisfied = false;
    return query_app_container_runtime_acl(handle, app_container_sid,
        required_access, satisfied, error) && satisfied;
}

bool ensure_app_container_runtime_acl(HANDLE verified_handle,
                                      PSID app_container_sid,
                                      ACCESS_MASK required_access,
                                      DWORD& error) noexcept
{
    bool satisfied = false;
    if (!query_app_container_runtime_acl(verified_handle, app_container_sid,
            required_access, satisfied, error))
        return false;
    if (satisfied)
        return true;
    handle_t writable(ReOpenFile(verified_handle, READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ, 0));
    if (!writable) {
        error = GetLastError();
        return false;
    }
    return grant_app_container_runtime_acl(writable.get(), app_container_sid,
        required_access, error);
}

bool ensure_app_container_runtime_path_acl(const std::filesystem::path& path,
                                           const std::wstring& approved_root,
                                           bool directory,
                                           PSID app_container_sid,
                                           ACCESS_MASK required_access,
                                           DWORD& error)
{
    const DWORD flags = FILE_FLAG_OPEN_REPARSE_POINT |
        (directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL);
    handle_t readable(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, flags, nullptr));
    if (!readable) {
        error = GetLastError();
        return false;
    }
    FILE_ATTRIBUTE_TAG_INFO tag{};
    const auto resolved = final_path(readable.get());
    if (!GetFileInformationByHandleEx(readable.get(), FileAttributeTagInfo,
            &tag, sizeof(tag)) ||
        (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        ((tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
        !resolved || !path_within(approved_root, *resolved)) {
        error = ERROR_ACCESS_DENIED;
        return false;
    }
    bool satisfied = false;
    if (!query_app_container_runtime_acl(readable.get(), app_container_sid,
            required_access, satisfied, error))
        return false;
    if (satisfied)
        return true;
    readable.reset();
    handle_t writable(CreateFileW(path.c_str(),
        READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, flags, nullptr));
    if (!writable) {
        error = GetLastError();
        return false;
    }
    const auto writable_resolved = final_path(writable.get());
    if (!GetFileInformationByHandleEx(writable.get(), FileAttributeTagInfo,
            &tag, sizeof(tag)) ||
        (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        ((tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
        !writable_resolved || !path_within(approved_root, *writable_resolved)) {
        error = ERROR_ACCESS_DENIED;
        return false;
    }
    return grant_app_container_runtime_acl(writable.get(), app_container_sid,
        required_access, error);
}

bool collect_native_spec_acl_inventory(const native_worker_verified_package_t& verified,
                                       std::vector<std::filesystem::path>& files,
                                       std::array<std::filesystem::path, 2>& directories,
                                       DWORD& error)
{
    directories = {
        std::filesystem::path(verified.root_path) / L"ghidra_specs",
        std::filesystem::path(verified.root_path) / L"deps" / L"ghidra_specs"};
    std::vector<std::wstring> expected_names;
    files.clear();
    files.reserve(k_ghidra_spec_mirror_file_count * directories.size());
    for (std::size_t mirror = 0; mirror < directories.size(); ++mirror) {
        const DWORD attributes = GetFileAttributesW(directories[mirror].c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_ACCESS_DENIED;
            return false;
        }
        std::error_code ec;
        std::vector<std::wstring> names;
        for (std::filesystem::directory_iterator iterator(directories[mirror],
                 std::filesystem::directory_options::none, ec), end;
             !ec && iterator != end; iterator.increment(ec)) {
            const DWORD child_attributes = GetFileAttributesW(iterator->path().c_str());
            if (child_attributes == INVALID_FILE_ATTRIBUTES ||
                (child_attributes & (FILE_ATTRIBUTE_DIRECTORY |
                    FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
                error = child_attributes == INVALID_FILE_ATTRIBUTES
                    ? GetLastError() : ERROR_ACCESS_DENIED;
                return false;
            }
            names.push_back(iterator->path().filename().wstring());
            files.push_back(iterator->path());
        }
        if (ec || names.size() != k_ghidra_spec_mirror_file_count) {
            error = ec ? static_cast<DWORD>(ec.value()) : ERROR_INVALID_DATA;
            return false;
        }
        std::sort(names.begin(), names.end(), [](const auto& left, const auto& right) {
            const int insensitive = _wcsicmp(left.c_str(), right.c_str());
            return insensitive == 0 ? left < right : insensitive < 0;
        });
        if (mirror == 0)
            expected_names = std::move(names);
        else if (names != expected_names) {
            error = ERROR_INVALID_DATA;
            return false;
        }
    }
    error = ERROR_SUCCESS;
    return true;
}

bool ensure_app_container_runtime_access(const native_worker_verified_package_t& verified,
                                         PSID app_container_sid,
                                         DWORD& error)
{
    std::lock_guard lock(app_container_runtime_acl_mutex());
    const auto root = std::filesystem::path(verified.root_path).lexically_normal();
    auto ancestor = std::filesystem::path(verified.worker_path).parent_path().lexically_normal();
    if (root.empty() || ancestor.empty() ||
        !path_within(verified.root_path, ancestor.wstring())) {
        error = ERROR_ACCESS_DENIED;
        return false;
    }
    std::vector<std::filesystem::path> ancestors;
    while (true) {
        ancestors.push_back(ancestor);
        if (_wcsicmp(ancestor.c_str(), root.c_str()) == 0)
            break;
        const auto parent = ancestor.parent_path().lexically_normal();
        if (parent.empty() || _wcsicmp(parent.c_str(), ancestor.c_str()) == 0 ||
            !path_within(verified.root_path, parent.wstring())) {
            error = ERROR_ACCESS_DENIED;
            return false;
        }
        ancestor = parent;
    }
    std::reverse(ancestors.begin(), ancestors.end());
    for (const auto& directory : ancestors) {
        if (!ensure_app_container_runtime_path_acl(directory, verified.root_path,
                true, app_container_sid,
                k_app_container_runtime_directory_traverse, error))
            return false;
    }
    if (!ensure_app_container_runtime_acl(verified.worker_file.get(),
            app_container_sid, k_app_container_runtime_read_execute, error))
        return false;
    if (verified.manifest.provider.provider != decompiler_provider_id_t::ghidra_native)
        return true;
    std::vector<std::filesystem::path> files;
    std::array<std::filesystem::path, 2> directories;
    if (!collect_native_spec_acl_inventory(verified, files, directories, error))
        return false;
    for (const auto& directory : directories) {
        if (!ensure_app_container_runtime_path_acl(directory, verified.root_path,
                true, app_container_sid, k_app_container_runtime_read_execute,
                error))
            return false;
    }
    for (const auto& file : files) {
        if (!ensure_app_container_runtime_path_acl(file, verified.root_path,
                false, app_container_sid, k_app_container_runtime_read_execute,
                error))
            return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

class restricted_pipe_security_t final {
public:
    bool create(PSID app_container_sid, DWORD& error)
    {
        if (!app_container_sid || !IsValidSid(app_container_sid)) {
            error = ERROR_INVALID_SID;
            return false;
        }
        handle_t token;
        HANDLE raw_token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
            error = GetLastError();
            return false;
        }
        token.reset(raw_token);
        DWORD token_bytes = 0;
        if (GetTokenInformation(token.get(), TokenUser, nullptr, 0, &token_bytes) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || token_bytes < sizeof(TOKEN_USER)) {
            error = GetLastError();
            if (error == ERROR_SUCCESS)
                error = ERROR_INVALID_DATA;
            return false;
        }
        try {
            token_user_.resize(token_bytes);
        } catch (...) {
            error = ERROR_NOT_ENOUGH_MEMORY;
            return false;
        }
        if (!GetTokenInformation(token.get(), TokenUser, token_user_.data(), token_bytes, &token_bytes)) {
            error = GetLastError();
            return false;
        }
        const auto* token_user = reinterpret_cast<const TOKEN_USER*>(token_user_.data());
        if (!token_user->User.Sid || !IsValidSid(token_user->User.Sid)) {
            error = ERROR_INVALID_SID;
            return false;
        }
        const std::uint64_t acl_bytes = sizeof(ACL) +
            (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(token_user->User.Sid)) +
            (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(app_container_sid));
        if (acl_bytes > (std::numeric_limits<DWORD>::max)()) {
            error = ERROR_ARITHMETIC_OVERFLOW;
            return false;
        }
        try {
            acl_.resize(static_cast<std::size_t>(acl_bytes));
        } catch (...) {
            error = ERROR_NOT_ENOUGH_MEMORY;
            return false;
        }
        auto* acl = reinterpret_cast<PACL>(acl_.data());
        constexpr DWORD access = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | READ_CONTROL;
        if (!InitializeAcl(acl, static_cast<DWORD>(acl_.size()), ACL_REVISION) ||
            !AddAccessAllowedAceEx(acl, ACL_REVISION, 0, access, token_user->User.Sid) ||
            !AddAccessAllowedAceEx(acl, ACL_REVISION, 0, access, app_container_sid) ||
            !InitializeSecurityDescriptor(&descriptor_, SECURITY_DESCRIPTOR_REVISION) ||
            !SetSecurityDescriptorOwner(&descriptor_, token_user->User.Sid, FALSE) ||
            !SetSecurityDescriptorDacl(&descriptor_, TRUE, acl, FALSE) ||
            !SetSecurityDescriptorControl(&descriptor_, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
            error = GetLastError();
            return false;
        }
        attributes_.nLength = sizeof(attributes_);
        attributes_.lpSecurityDescriptor = &descriptor_;
        attributes_.bInheritHandle = TRUE;
        error = ERROR_SUCCESS;
        return true;
    }

    SECURITY_ATTRIBUTES* attributes() noexcept
    {
        return &attributes_;
    }

private:
    std::vector<std::uint8_t> token_user_;
    std::vector<std::uint8_t> acl_;
    SECURITY_DESCRIPTOR descriptor_{};
    SECURITY_ATTRIBUTES attributes_{};
};

bool configure_job(HANDLE job, const decompiler_profile_budget_t& profile, DWORD& error,
                   std::uint64_t session_cpu_backstop_ms = 0,
                   std::uint64_t session_envelope_max_memory_bytes = 0)
{
    const std::uint64_t effective_cpu_ms = session_cpu_backstop_ms != 0
        ? session_cpu_backstop_ms
        : profile.max_cpu_ms;
    const std::uint64_t memory_limit = session_envelope_max_memory_bytes != 0
        ? session_envelope_max_memory_bytes
        : profile.max_memory_bytes;
    if (memory_limit == 0 || effective_cpu_ms == 0 ||
        (session_cpu_backstop_ms != 0 && session_cpu_backstop_ms < profile.max_cpu_ms) ||
        (session_envelope_max_memory_bytes != 0 &&
            session_envelope_max_memory_bytes < profile.max_memory_bytes) ||
        memory_limit > static_cast<std::uint64_t>((std::numeric_limits<SIZE_T>::max)()) ||
        effective_cpu_ms > static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)() / 10000)) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
        JOB_OBJECT_LIMIT_PROCESS_MEMORY |
        JOB_OBJECT_LIMIT_JOB_MEMORY |
        JOB_OBJECT_LIMIT_PROCESS_TIME;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = static_cast<LONGLONG>(effective_cpu_ms * 10000);
    limits.ProcessMemoryLimit = static_cast<SIZE_T>(memory_limit);
    limits.JobMemoryLimit = static_cast<SIZE_T>(memory_limit);
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        error = GetLastError();
        return false;
    }
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
        JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | JOB_OBJECT_UILIMIT_EXITWINDOWS;
    if (!SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui))) {
        error = GetLastError();
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

bool create_snapshot_mapping(const native_worker_snapshot_t& snapshot, handle_t& child_mapping, DWORD& error)
{
    if (snapshot.shared_mapping_handle != nullptr &&
        snapshot.shared_mapping_size != 0 && snapshot.bytes &&
        snapshot.shared_mapping_size == snapshot.bytes->size()) {
        HANDLE raw_shared_mapping = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(),
                static_cast<HANDLE>(snapshot.shared_mapping_handle), GetCurrentProcess(),
                &raw_shared_mapping, FILE_MAP_READ, TRUE, 0)) {
            error = GetLastError();
            diag::log_tagged_fmt("dec_batch",
                "snapshot_shared_duplicate_failed gle=%lu fallback=private_mapping",
                static_cast<unsigned long>(error));
        } else {
            child_mapping.reset(raw_shared_mapping);
            error = ERROR_SUCCESS;
            return true;
        }
    }
    if (!snapshot.valid() || snapshot.bytes->empty() || snapshot.bytes->size() > (std::numeric_limits<DWORD>::max)()) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    const std::uint64_t size = snapshot.bytes->size();
    handle_t mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, static_cast<DWORD>(size >> 32U),
        static_cast<DWORD>(size), nullptr));
    if (!mapping) {
        error = GetLastError();
        return false;
    }
    void* view = MapViewOfFile(mapping.get(), FILE_MAP_WRITE, 0, 0, snapshot.bytes->size());
    if (!view) {
        error = GetLastError();
        return false;
    }
    std::memcpy(view, snapshot.bytes->data(), snapshot.bytes->size());
    if (!UnmapViewOfFile(view)) {
        error = GetLastError();
        return false;
    }
    HANDLE raw_child_mapping = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), mapping.get(), GetCurrentProcess(), &raw_child_mapping, FILE_MAP_READ, TRUE, 0)) {
        error = GetLastError();
        return false;
    }
    child_mapping.reset(raw_child_mapping);
    error = ERROR_SUCCESS;
    return true;
}

bool create_worker_identity_handle(HANDLE verified_worker_file, handle_t& child_identity, DWORD& error)
{
    if (!verified_worker_file || verified_worker_file == INVALID_HANDLE_VALUE) {
        error = ERROR_INVALID_HANDLE;
        return false;
    }
    HANDLE raw_identity = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), verified_worker_file, GetCurrentProcess(), &raw_identity,
            0, TRUE, DUPLICATE_SAME_ACCESS)) {
        error = GetLastError();
        return false;
    }
    child_identity.reset(raw_identity);
    error = ERROR_SUCCESS;
    return true;
}

struct worker_wait_observation_t {
    DWORD pipe_error = ERROR_SUCCESS;
    DWORD process_error = ERROR_SUCCESS;
    DWORD exit_code = STILL_ACTIVE;
    bool pipe_closed = false;
    bool process_exited = false;
    bool exit_code_available = false;
    bool native_protocol = false;
};

struct worker_instance_t {
    handle_t job;
    handle_t process;
    handle_t request_pipe;
    handle_t response_pipe;
    wire::session_material_t session;
    wire::frame_reader_t reader;
    std::uint64_t next_host_sequence = 1;
    std::uint64_t next_worker_sequence = 1;
    DWORD process_id = 0;
    bool native_protocol = false;
    worker_wait_observation_t wait_observation;
};

bool create_pipe_pair(handle_t& child_end, handle_t& parent_end, bool child_reads,
                      SECURITY_ATTRIBUTES* attributes, DWORD& error)
{
    if (!attributes || !attributes->lpSecurityDescriptor || !attributes->bInheritHandle) {
        error = ERROR_INVALID_SECURITY_DESCR;
        return false;
    }
    HANDLE first = nullptr;
    HANDLE second = nullptr;
    if (!CreatePipe(&first, &second, attributes, 0)) {
        error = GetLastError();
        return false;
    }
    if (child_reads) {
        child_end.reset(first);
        parent_end.reset(second);
    } else {
        parent_end.reset(first);
        child_end.reset(second);
    }
    if (!SetHandleInformation(parent_end.get(), HANDLE_FLAG_INHERIT, 0)) {
        error = GetLastError();
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

bool launch_worker(const native_worker_verified_package_t& verified,
                   const native_worker_execution_request_t& request,
                   const native_worker_host_limits_t& host_limits, worker_instance_t& worker,
                   native_worker_execution_result_t& result, std::uint64_t session_cpu_backstop_ms = 0,
                   std::uint64_t session_envelope_max_memory_bytes = 0)
{
    handle_t child_read;
    handle_t parent_write;
    handle_t child_write;
    handle_t parent_read;
    handle_t child_snapshot;
    handle_t child_identity;
    handle_t child_standard;
    DWORD error = ERROR_SUCCESS;
    app_container_t container;
    if (!container.create(verified.manifest_hash, error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::app_container_unavailable, "native_worker.app_container", "networkless AppContainer could not be established", error);
        return false;
    }
    if (!ensure_app_container_runtime_access(verified, container.sid(), error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected,
            "native_worker.runtime_acl",
            "verified worker runtime could not be restricted to manifest-bound AppContainer read and execute access",
            error);
        return false;
    }
    restricted_pipe_security_t pipe_security;
    if (!pipe_security.create(container.sid(), error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected, "native_worker.pipe_security", "restricted pipe security descriptor could not be established", error);
        return false;
    }
    if (!create_pipe_pair(child_read, parent_write, true, pipe_security.attributes(), error) ||
        !create_pipe_pair(child_write, parent_read, false, pipe_security.attributes(), error) ||
        !create_snapshot_mapping(request.snapshot, child_snapshot, error) ||
        !create_worker_identity_handle(verified.worker_file.get(), child_identity, error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected, "native_worker.handles", "restricted handle set could not be created", error);
        return false;
    }
    worker.job.reset(CreateJobObjectW(nullptr, nullptr));
    if (!worker.job || !configure_job(worker.job.get(), request.profile, error, session_cpu_backstop_ms,
            session_envelope_max_memory_bytes)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected, "native_worker.job", "job limits could not be applied", error);
        return false;
    }
    if (!wire::make_session(worker.session)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::bootstrap_failed, "native_worker.session", "session entropy could not be acquired", ERROR_CRC);
        return false;
    }
    const bool managed = verified.manifest.provider.provider ==
        decompiler_provider_id_t::ilspy_cli;
    worker.native_protocol = !managed;
    std::array<HANDLE, 5> inherited_handles{
        child_read.get(), child_write.get(), child_snapshot.get(), child_identity.get(), nullptr};
    std::size_t inherited_handle_count = 4;
    if (managed) {
        SECURITY_ATTRIBUTES standard_attributes{};
        standard_attributes.nLength = sizeof(standard_attributes);
        standard_attributes.bInheritHandle = TRUE;
        child_standard.reset(CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, &standard_attributes, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!child_standard) {
            error = GetLastError();
            append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected,
                "native_worker.standard_handles",
                "detached managed worker standard handles could not be isolated",
                error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error);
            return false;
        }
        inherited_handles[inherited_handle_count++] = child_standard.get();
    }
    std::uint64_t mitigation_policy = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
        PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE |
        PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON;
    if (!managed) {
        mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON |
            PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    }
    DWORD child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    HANDLE job_list[] = {worker.job.get()};
    SECURITY_CAPABILITIES capabilities{};
    capabilities.AppContainerSid = container.sid();
    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(nullptr, 5, 0, &attribute_size);
    std::vector<std::uint8_t> attributes;
    try {
        attributes.resize(attribute_size);
    } catch (...) {
        append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected, "native_worker.attributes", "attribute allocation failed", ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    auto* attribute_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(attribute_list, 5, 0, &attribute_size)) {
        error = GetLastError();
        SecureZeroMemory(attributes.data(), attributes.size());
        append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected, "native_worker.attributes", "process attribute initialization failed", error);
        return false;
    }
    if (!UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited_handles.data(),
            sizeof(HANDLE) * inherited_handle_count, nullptr, nullptr) ||
        !UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation_policy,
            sizeof(mitigation_policy), nullptr, nullptr) ||
        !UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy,
            sizeof(child_policy), nullptr, nullptr) ||
        !UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, job_list, sizeof(job_list), nullptr, nullptr) ||
        !UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities, sizeof(capabilities), nullptr, nullptr)) {
        error = GetLastError();
        DeleteProcThreadAttributeList(attribute_list);
        SecureZeroMemory(attributes.data(), attributes.size());
        append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected, "native_worker.attributes", "process security attributes were rejected", error);
        return false;
    }
    if (managed) {
        if (!request.managed_request || !verified.managed_runtime ||
            verified.managed_runtime->locked_files.size() != 202 ||
            verified.managed_runtime->manifest_hash !=
                verified.manifest.managed_runtime_manifest_hash ||
            request.managed_request->worker.runtime_manifest_hash !=
                verified.manifest.managed_runtime_manifest_hash) {
            DeleteProcThreadAttributeList(attribute_list);
            SecureZeroMemory(attributes.data(), attributes.size());
            append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected,
                "native_worker.managed_request",
                "managed worker request is not bound to the verified app-local runtime",
                ERROR_INVALID_DATA);
            return false;
        }
    }
    std::wstring command_line = quote_argument(verified.worker_path);
    command_line.append(managed
        ? L" --aida-managed-decompiler-worker"
        : L" --aida-native-decompiler-worker");
    command_line.append(L" --provider=");
    command_line.append(std::to_wstring(
        static_cast<std::uint32_t>(request.cache_key.provider.provider)));
    command_line.append(L" --read-handle=");
    command_line.append(std::to_wstring(reinterpret_cast<std::uintptr_t>(child_read.get())));
    command_line.append(L" --write-handle=");
    command_line.append(std::to_wstring(reinterpret_cast<std::uintptr_t>(child_write.get())));
    command_line.append(managed ? L" --module-handle=" : L" --snapshot-handle=");
    command_line.append(std::to_wstring(reinterpret_cast<std::uintptr_t>(child_snapshot.get())));
    command_line.append(managed ? L" --module-size=" : L" --snapshot-size=");
    command_line.append(std::to_wstring(request.snapshot.bytes->size()));
    command_line.append(L" --identity-handle=");
    command_line.append(std::to_wstring(reinterpret_cast<std::uintptr_t>(child_identity.get())));
    if (managed) {
        command_line.append(L" --runtime-manifest-hash=");
        command_line.append(utf8_to_wide(
            verified.manifest.managed_runtime_manifest_hash.to_hex()).value());
    }
    for (const auto& argument : verified.manifest.startup_arguments) {
        const auto wide = utf8_to_wide(argument);
        if (!wide) {
            DeleteProcThreadAttributeList(attribute_list);
            SecureZeroMemory(attributes.data(), attributes.size());
            append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected, "native_worker.arguments", "manifest argument is invalid UTF-8", ERROR_INVALID_DATA);
            return false;
        }
        command_line.push_back(L' ');
        command_line.append(quote_argument(*wide));
    }
    const auto environment = minimal_environment(managed
        ? std::optional<std::wstring>{verified.managed_runtime->dotnet_root}
        : std::nullopt);
    if (!environment) {
        DeleteProcThreadAttributeList(attribute_list);
        SecureZeroMemory(attributes.data(), attributes.size());
        append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected, "native_worker.environment", "minimal worker environment cannot be created", GetLastError());
        return false;
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    if (managed) {
        startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_standard.get();
        startup.StartupInfo.hStdOutput = child_standard.get();
        startup.StartupInfo.hStdError = child_standard.get();
    }
    startup.lpAttributeList = attribute_list;
    PROCESS_INFORMATION process{};
    const DWORD creation_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT |
        (managed ? DETACHED_PROCESS : CREATE_NO_WINDOW);
    const BOOL launched = CreateProcessW(verified.worker_path.c_str(), command_line.data(), nullptr, nullptr, TRUE,
        creation_flags, const_cast<wchar_t*>(environment->data()),
        verified.root_path.c_str(), &startup.StartupInfo, &process);
    error = launched ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(attribute_list);
    SecureZeroMemory(attributes.data(), attributes.size());
    SecureZeroMemory(command_line.data(), command_line.size() * sizeof(wchar_t));
    if (!launched) {
        append_diagnostic(result, native_worker_diagnostic_code_t::launch_failed, "native_worker.create_process", "restricted worker launch failed", error);
        return false;
    }
    CloseHandle(process.hThread);
    worker.process.reset(process.hProcess);
    worker.process_id = process.dwProcessId;
    worker.request_pipe = std::move(parent_write);
    worker.response_pipe = std::move(parent_read);
    child_read.reset();
    child_write.reset();
    child_snapshot.reset();
    child_identity.reset();
    child_standard.reset();
    const auto bootstrap = wire::encode_bootstrap(worker.session, verified.manifest_hash);
    if (!wire::write_all(worker.request_pipe.get(), bootstrap.data(), bootstrap.size(), error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::bootstrap_failed, "native_worker.bootstrap", "bootstrap could not be delivered", error, true);
        TerminateJobObject(worker.job.get(), ERROR_CANCELLED);
        return false;
    }
    return true;
}

void terminate_worker(worker_instance_t& worker, DWORD exit_code, native_worker_execution_result_t& result, bool replacement)
{
    bool termination_enforced = false;
    DWORD termination_error = ERROR_SUCCESS;
    if (worker.process) {
        const DWORD process_state = WaitForSingleObject(worker.process.get(), 0);
        if (process_state == WAIT_OBJECT_0)
            termination_enforced = true;
        else if (process_state == WAIT_FAILED)
            termination_error = GetLastError();
    }
    if (!termination_enforced && worker.job) {
        if (TerminateJobObject(worker.job.get(), exit_code))
            termination_enforced = true;
        else
            termination_error = GetLastError();
    }
    if (!termination_enforced && worker.process) {
        if (TerminateProcess(worker.process.get(), exit_code))
            termination_enforced = true;
        else
            termination_error = GetLastError();
    }
    worker.request_pipe.reset();
    worker.response_pipe.reset();
    worker.job.reset();
    worker.process.reset();
    result.worker_terminated = termination_enforced;
    result.worker_replaced = replacement;
    if (!termination_enforced)
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_failed,
            "native_worker.terminate", "worker termination could not be enforced",
            termination_error == ERROR_SUCCESS ? ERROR_PROCESS_ABORTED : termination_error, true);
    if (replacement)
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_replaced, "native_worker.replace",
            "worker generation was invalidated and will not be reused", exit_code, true);
    SecureZeroMemory(worker.session.key.data(), worker.session.key.size());
    SecureZeroMemory(worker.session.nonce.data(), worker.session.nonce.size());
}

bool same_provider(const decompiler_provider_identity_t& lhs, const decompiler_provider_identity_t& rhs) noexcept
{
    return lhs.provider == rhs.provider && lhs.provider_name == rhs.provider_name && lhs.provider_version == rhs.provider_version &&
        lhs.provider_binary_hash == rhs.provider_binary_hash && lhs.worker_build_id == rhs.worker_build_id &&
        lhs.worker_build_hash == rhs.worker_build_hash;
}

bool same_profile(const decompiler_profile_budget_t& lhs,
                  const decompiler_profile_budget_t& rhs) noexcept
{
    return lhs.schema_version == rhs.schema_version &&
        lhs.profile == rhs.profile &&
        lhs.max_wall_clock_ms == rhs.max_wall_clock_ms &&
        lhs.max_cpu_ms == rhs.max_cpu_ms &&
        lhs.max_memory_bytes == rhs.max_memory_bytes &&
        lhs.max_provider_ir_nodes == rhs.max_provider_ir_nodes &&
        lhs.max_hir_nodes == rhs.max_hir_nodes &&
        lhs.max_ast_nodes == rhs.max_ast_nodes &&
        lhs.max_semantic_queries == rhs.max_semantic_queries &&
        lhs.semantic_proofs_enabled == rhs.semantic_proofs_enabled;
}

const char* isolated_provider_name(const decompiler_provider_id_t provider) noexcept
{
    switch (provider) {
    case decompiler_provider_id_t::ghidra_native: return "aida-native-decompiler";
    case decompiler_provider_id_t::jvm_ssa: return "aida-jvm-ssa";
    case decompiler_provider_id_t::dalvik_ssa: return "aida-dalvik-ssa";
    case decompiler_provider_id_t::ilspy_cli: return "ICSharpCode.Decompiler";
    }
    return nullptr;
}

decompiler_provider_identity_t isolated_provider_identity(
    const decompiler_provider_identity_t& worker,
    const decompiler_provider_id_t provider)
{
    auto result = worker;
    result.provider = provider;
    if (const auto* name = isolated_provider_name(provider))
        result.provider_name = name;
    return result;
}

bool compatible_worker_provider(
    const decompiler_provider_identity_t& route,
    const decompiler_provider_identity_t& manifest) noexcept
{
    const auto* expected_name = isolated_provider_name(route.provider);
    return expected_name && route.provider_name == expected_name &&
        ((route.provider == decompiler_provider_id_t::ilspy_cli &&
          manifest.provider == decompiler_provider_id_t::ilspy_cli) ||
         (route.provider != decompiler_provider_id_t::ilspy_cli &&
          manifest.provider == decompiler_provider_id_t::ghidra_native)) &&
        route.provider_version == manifest.provider_version &&
        route.provider_binary_hash == manifest.provider_binary_hash &&
        route.worker_build_id == manifest.worker_build_id &&
        route.worker_build_hash == manifest.worker_build_hash;
}

bool same_language(const decompiler_language_identity_t& lhs, const decompiler_language_identity_t& rhs) noexcept
{
    return lhs.language_id == rhs.language_id && lhs.language_version == rhs.language_version &&
        lhs.compiler_spec_id == rhs.compiler_spec_id && lhs.language_spec_hash == rhs.language_spec_hash &&
        lhs.architecture == rhs.architecture && lhs.mode == rhs.mode && lhs.endian == rhs.endian;
}

bool send_contract(worker_instance_t& worker, const decompiler_worker_message_t& message,
                   const native_worker_host_limits_t& limits, DWORD& error)
{
    const std::string payload = serialize_decompiler_worker_message(message);
    return wire::send_frame(worker.request_pipe.get(), worker.session, wire::frame_kind_t::decompiler_contract,
        worker.next_host_sequence++, reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), limits.max_frame_bytes, error);
}

enum class terminal_wait_t : std::uint8_t {
    message,
    cancelled,
    deadline,
    exited,
    protocol_failure
};

enum class process_wait_state_t : std::uint8_t {
    running,
    exited,
    failure
};

bool terminal_pipe_error(DWORD error) noexcept
{
    return error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA ||
        error == ERROR_PIPE_NOT_CONNECTED || error == ERROR_HANDLE_EOF;
}

process_wait_state_t observe_process_exit(worker_instance_t& worker,
                                          DWORD timeout) noexcept
{
    const DWORD wait = WaitForSingleObject(worker.process.get(), timeout);
    if (wait == WAIT_TIMEOUT)
        return process_wait_state_t::running;
    if (wait == WAIT_FAILED) {
        worker.wait_observation.process_error = GetLastError();
        return process_wait_state_t::failure;
    }
    if (wait != WAIT_OBJECT_0) {
        worker.wait_observation.process_error = ERROR_INVALID_DATA;
        return process_wait_state_t::failure;
    }
    worker.wait_observation.process_exited = true;
    DWORD exit_code = STILL_ACTIVE;
    if (!GetExitCodeProcess(worker.process.get(), &exit_code)) {
        worker.wait_observation.process_error = GetLastError();
        return process_wait_state_t::exited;
    }
    worker.wait_observation.exit_code = exit_code;
    worker.wait_observation.exit_code_available = true;
    return process_wait_state_t::exited;
}

terminal_wait_t wait_for_message(worker_instance_t& worker, const native_worker_execution_request_t& request,
                                 const native_worker_host_limits_t& limits, std::chrono::steady_clock::time_point deadline,
                                 wire::frame_t& frame, DWORD& error)
{
    worker.wait_observation = {};
    worker.wait_observation.native_protocol = worker.native_protocol;
    while (true) {
        if (std::chrono::steady_clock::now() >= deadline)
            return terminal_wait_t::deadline;
        if (request.cancellation_requested) {
            bool cancelled = true;
            try {
                cancelled = request.cancellation_requested();
            } catch (...) {
                cancelled = true;
            }
            if (cancelled)
                return terminal_wait_t::cancelled;
        }
        const auto state = worker.reader.poll(worker.response_pipe.get(), worker.session, worker.next_worker_sequence,
            limits.max_frame_bytes, frame, error);
        if (state == wire::read_state_t::complete) {
            ++worker.next_worker_sequence;
            return terminal_wait_t::message;
        }
        if (state == wire::read_state_t::failure) {
            worker.wait_observation.pipe_error = error;
            worker.wait_observation.pipe_closed = terminal_pipe_error(error);
            const auto frame_failure = worker.reader.failure();
            const DWORD settle_timeout = worker.wait_observation.pipe_closed
                ? 100
                : 0;
            const auto process_state = observe_process_exit(worker, settle_timeout);
            if (frame_failure == wire::frame_failure_t::io &&
                worker.wait_observation.pipe_closed &&
                process_state == process_wait_state_t::exited &&
                !worker.reader.has_partial_frame()) {
                error = worker.wait_observation.exit_code_available
                    ? worker.wait_observation.exit_code
                    : worker.wait_observation.process_error;
                return terminal_wait_t::exited;
            }
            if (frame_failure == wire::frame_failure_t::io &&
                process_state == process_wait_state_t::failure)
                error = worker.wait_observation.process_error;
            else
                error = worker.wait_observation.pipe_error;
            return terminal_wait_t::protocol_failure;
        }
        const auto process_state = observe_process_exit(worker, 0);
        if (process_state == process_wait_state_t::failure) {
            error = worker.wait_observation.process_error;
            return terminal_wait_t::protocol_failure;
        }
        Sleep(static_cast<DWORD>((std::max)(std::int64_t{1}, limits.poll_interval.count())));
    }
}

std::string worker_status_hex(DWORD status)
{
    constexpr char digits[] = "0123456789ABCDEF";
    std::string result = "0x00000000";
    for (std::size_t index = 0; index < 8; ++index) {
        const auto shift = static_cast<unsigned>((7 - index) * 4);
        result[index + 2] = digits[(status >> shift) & 0xFU];
    }
    return result;
}

const char* native_worker_startup_exit_stage(DWORD exit_code) noexcept
{
    switch (exit_code) {
    case 2:
        return "startup_arguments_or_authenticated_bootstrap";
    case 3:
        return "worker_identity_hash_or_authenticated_hello_write";
    default:
        return nullptr;
    }
}

void append_wait_observation(std::string& detail,
                             const worker_wait_observation_t& observation)
{
    if (observation.pipe_error != ERROR_SUCCESS) {
        detail.append("; pipe_error=");
        detail.append(std::to_string(observation.pipe_error));
    }
    if (observation.process_exited)
        detail.append("; process_signaled=1");
    if (observation.exit_code_available) {
        detail.append("; exit_status=");
        detail.append(worker_status_hex(observation.exit_code));
        detail.push_back('(');
        detail.append(std::to_string(observation.exit_code));
        detail.push_back(')');
        if (const char* stage = observation.native_protocol
                ? native_worker_startup_exit_stage(observation.exit_code)
                : nullptr) {
            detail.append("; startup_stage=");
            detail.append(stage);
        }
    } else if (observation.process_error != ERROR_SUCCESS) {
        detail.append("; process_error=");
        detail.append(std::to_string(observation.process_error));
    }
}

void append_worker_exit(native_worker_execution_result_t& result,
                        const worker_instance_t& worker, std::string phase,
                        std::string detail)
{
    append_wait_observation(detail, worker.wait_observation);
    const DWORD status = worker.wait_observation.exit_code_available
        ? worker.wait_observation.exit_code
        : (worker.wait_observation.process_error != ERROR_SUCCESS
            ? worker.wait_observation.process_error
            : worker.wait_observation.pipe_error);
    append_diagnostic(result, native_worker_diagnostic_code_t::worker_crashed,
        std::move(phase), std::move(detail), status, true);
}

void append_protocol_failure(native_worker_execution_result_t& result, wire::frame_failure_t failure,
                             std::string phase, DWORD error,
                             const worker_wait_observation_t* observation = nullptr)
{
    native_worker_diagnostic_code_t code = native_worker_diagnostic_code_t::protocol_truncated;
    std::string detail = "worker frame could not be read completely";
    switch (failure) {
    case wire::frame_failure_t::malformed_header:
        code = native_worker_diagnostic_code_t::protocol_malformed;
        detail = "worker frame header has invalid magic, version, kind, or sequence";
        break;
    case wire::frame_failure_t::nonce_mismatch:
        code = native_worker_diagnostic_code_t::protocol_nonce_mismatch;
        detail = "worker frame nonce binding does not match the active session";
        break;
    case wire::frame_failure_t::replay:
        code = native_worker_diagnostic_code_t::protocol_replay;
        detail = "worker frame replays an accepted sequence";
        break;
    case wire::frame_failure_t::oversize:
        code = native_worker_diagnostic_code_t::protocol_oversize;
        detail = "worker frame payload exceeds the configured frame limit";
        break;
    case wire::frame_failure_t::authentication_failed:
        code = native_worker_diagnostic_code_t::protocol_authentication_failed;
        detail = "worker frame authentication tag is invalid";
        break;
    case wire::frame_failure_t::resource_exhausted:
        code = native_worker_diagnostic_code_t::protocol_malformed;
        detail = "worker frame resources could not be allocated within host limits";
        break;
    case wire::frame_failure_t::none:
    case wire::frame_failure_t::io:
        break;
    }
    if (observation)
        append_wait_observation(detail, *observation);
    append_diagnostic(result, code, std::move(phase), std::move(detail), error, true);
}

bool validate_envelope(const decompiler_worker_message_t& message, const wire::frame_t& frame,
                       const wire::session_material_t& session)
{
    const auto validation = validate_decompiler_worker_message(message);
    if (!validation.valid())
        return false;
    return std::visit([&](const auto& current) {
        return current.envelope.sequence == frame.sequence && current.envelope.session_nonce_hash == session.nonce_hash;
    }, message);
}

enum class managed_startup_frame_kind_t : std::uint8_t {
    invalid,
    hello,
    failure
};

struct managed_startup_frame_t {
    managed_startup_frame_kind_t kind = managed_startup_frame_kind_t::invalid;
    std::string stage;
    std::string code;
    bool retryable = false;
};

managed_startup_frame_t validate_managed_startup_frame(
    const wire::frame_t& frame,
    const wire::session_material_t& session,
    const native_worker_verified_package_t& verified)
{
    try {
        if (frame.kind != wire::frame_kind_t::decompiler_contract)
            return {};
        const auto value = nlohmann::json::parse(frame.payload.begin(), frame.payload.end(),
            nullptr, true, true);
        if (!value.is_object() || !value.contains("kind") ||
            value.at("schema") != "aida.c03.managed-cli.transport" ||
            value.at("schemaVersion") != 3 ||
            value.at("sequence") != frame.sequence ||
            value.at("sessionNonceHash") != session.nonce_hash.to_hex())
            return {};
        const auto kind = value.at("kind").get<std::string>();
        if (kind == "hello") {
            if (value.size() != 11 ||
                value.at("manifestHash") != verified.manifest_hash.to_hex() ||
                value.at("runtimeManifestHash") !=
                    verified.manifest.managed_runtime_manifest_hash.to_hex() ||
                value.at("workerBinaryHash") != verified.manifest.worker_binary_hash.to_hex() ||
                value.at("providerBinaryHash") != verified.manifest.provider.provider_binary_hash.to_hex() ||
                value.at("workerBuildId") != verified.manifest.provider.worker_build_id ||
                value.at("workerBuildHash") != verified.manifest.provider.worker_build_hash.to_hex())
                return {};
            return {managed_startup_frame_kind_t::hello, {}, {}, false};
        }
        if (kind != "startup_failure" || value.size() != 8 ||
            !value.at("stage").is_string() || !value.at("code").is_string() ||
            !value.at("retryable").is_boolean())
            return {};
        auto stage = value.at("stage").get<std::string>();
        auto code = value.at("code").get<std::string>();
        constexpr std::array<std::string_view, 5> stages{
            "transport", "runtime_identity", "module_mapping", "module_snapshot", "worker_identity"};
        constexpr std::array<std::string_view, 46> codes{
            "loaded_assembly_path", "framework_dependency_hash", "appcontainer_token_open",
            "appcontainer_token_size", "appcontainer_token_query",
            "appcontainer_sid", "appcontainer_profile", "appcontainer_profile_access",
            "appcontainer_localappdata", "appcontainer_temp", "appcontainer_environment",
            "environment_allowlist", "environment_policy", "windows_environment",
            "runtime_manifest_hash", "runtime_manifest_digest", "provider_hash",
            "runtime_integrity", "invalid_data", "bad_image", "access_denied",
            "io_failure", "resource_limit", "unexpected", "identity_not_established",
            "runtime_manifest_identity", "process_path_unavailable", "package_path_invalid",
            "package_root_invalid", "apphost_identity", "repository_dependency_root",
            "dotnet_root", "runtime_manifest_size", "framework_identity",
            "forbidden_host_override", "identity_reentry", "identity_unavailable",
            "package_root_unavailable", "identity_locks", "identity_changed",
            "package_root_changed", "runtime_file_unavailable", "runtime_directory_unavailable",
            "runtime_root_identity", "path_escape", "reparse_path"};
        const bool valid_stage = std::any_of(stages.begin(), stages.end(), [&stage](const auto candidate) {
            return candidate == std::string_view(stage);
        });
        const bool valid_code = std::any_of(codes.begin(), codes.end(), [&code](const auto candidate) {
            return candidate == std::string_view(code);
        });
        if (!valid_stage || !valid_code)
            return {};
        return {managed_startup_frame_kind_t::failure, std::move(stage),
            std::move(code), value.at("retryable").get<bool>()};
    } catch (...) {
        return {};
    }
}

bool send_managed_payload(
    worker_instance_t& worker,
    const std::string& payload,
    const native_worker_host_limits_t& limits,
    DWORD& error)
{
    return !payload.empty() && wire::send_frame(worker.request_pipe.get(), worker.session,
        wire::frame_kind_t::decompiler_contract, worker.next_host_sequence++,
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(),
        limits.max_frame_bytes, error);
}

bool valid_managed_terminal_payload(
    const wire::frame_t& frame,
    const managed_cli::request_t& request)
{
    try {
        if (frame.kind != wire::frame_kind_t::decompiler_contract)
            return false;
        const auto value = nlohmann::json::parse(frame.payload.begin(), frame.payload.end(),
            nullptr, true, true);
        const auto& source = value.at("moduleSource");
        if (!value.is_object() || value.at("schema") != "aida.c03.managed-cli.worker" ||
            value.at("schemaVersion") != managed_cli::k_managed_cli_worker_protocol_version ||
            value.at("sequence") != request.sequence ||
            value.at("requestId") != request.request_id || !source.is_object() ||
            source.size() != 4 ||
            source.at("logicalIdentity") != request.module_source.logical_identity ||
            source.at("moduleHash") != request.module_source.module_hash.to_hex() ||
            source.at("moduleSize") != request.module_source.module_size ||
            value.at("entityHash") != request.entity_hash.to_hex() ||
            value.at("workspaceGeneration") != request.workspace_generation ||
            value.at("typeGraphRevision") != request.type_graph_revision ||
            value.at("runtimeManifestHash") !=
                request.worker.runtime_manifest_hash.to_hex() ||
            value.at("contractHash") != request.contract_hash.to_hex() ||
            value.at("cacheIdentity") != request.cache_identity.to_hex() ||
            value.at("requestBindingHash") != request.request_binding_hash.to_hex())
            return false;
        const auto expected_source_kind = request.module_source.kind ==
            managed_cli::module_source_kind_t::regular_file
            ? "regular_file" : "embedded_member";
        if (source.at("kind") != expected_source_kind)
            return false;
        const auto kind = value.at("kind").get<std::string>();
        return kind == "result" || kind == "failure";
    } catch (...) {
        return false;
    }
}

std::chrono::steady_clock::time_point effective_deadline(const native_worker_execution_request_t& request)
{
    const auto profile_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(request.profile.max_wall_clock_ms);
    return request.deadline && *request.deadline < profile_deadline ? *request.deadline : profile_deadline;
}

bool send_cancel(worker_instance_t& worker, const native_worker_execution_request_t& request,
                 const native_worker_host_limits_t& limits, std::string reason)
{
    decompiler_worker_cancel_request_t cancellation;
    cancellation.envelope.kind = decompiler_worker_message_kind_t::cancel_request;
    cancellation.envelope.session_nonce_hash = worker.session.nonce_hash;
    cancellation.envelope.sequence = worker.next_host_sequence;
    cancellation.job_id = request.job_id;
    cancellation.stable_reason = std::move(reason);
    DWORD ignored = ERROR_SUCCESS;
    return send_contract(worker, decompiler_worker_message_t{std::move(cancellation)}, limits, ignored);
}

void append_worker_failure(native_worker_execution_result_t& result, const decompiler_worker_failure_message_t& failure)
{
    result.worker_diagnostics.insert(result.worker_diagnostics.end(), failure.diagnostics.begin(), failure.diagnostics.end());
}

std::string_view diagnostic_layer_name(const decompiler_coordinate_layer_t layer) noexcept
{
    switch (layer) {
    case decompiler_coordinate_layer_t::provider_ir:
        return "provider_ir";
    case decompiler_coordinate_layer_t::hir:
        return "hir";
    case decompiler_coordinate_layer_t::typed_ast:
        return "typed_ast";
    case decompiler_coordinate_layer_t::document:
        return "document";
    }
    return "invalid";
}

void append_worker_diagnostic_detail(std::string& detail, const decompiler_diagnostic_t& diagnostic)
{
    detail.append(": code=");
    detail.append(std::to_string(static_cast<std::uint16_t>(diagnostic.code)));
    detail.append(" severity=");
    detail.append(std::to_string(static_cast<std::uint8_t>(diagnostic.severity)));
    detail.append(" key=");
    detail.append(diagnostic.localization_key.data(),
        (std::min<std::size_t>)(diagnostic.localization_key.size(), 256U));
    detail.append(" ordinal=");
    detail.append(std::to_string(diagnostic.ordinal));
    detail.append(" confidence=");
    detail.append(std::to_string(diagnostic.confidence));
    detail.append(" retryable=");
    detail.push_back(diagnostic.retryable ? '1' : '0');
    detail.append(" argument_count=");
    detail.append(std::to_string(diagnostic.localization_arguments.size()));
    if (!diagnostic.coordinate)
        return;
    const auto& coordinate = *diagnostic.coordinate;
    detail.append(" layer=");
    detail.append(diagnostic_layer_name(coordinate.layer));
    detail.append(" generation=");
    detail.append(std::to_string(coordinate.workspace_generation));
    if (coordinate.address_range) {
        detail.append(" address=");
        detail.append(std::to_string(coordinate.address_range->begin.value));
        detail.push_back('-');
        detail.append(std::to_string(coordinate.address_range->end.value));
    }
    if (coordinate.token_range) {
        detail.append(" token=");
        detail.append(std::to_string(coordinate.token_range->begin));
        detail.push_back('-');
        detail.append(std::to_string(coordinate.token_range->end));
    }
    if (coordinate.instruction_range) {
        detail.append(" instruction=");
        detail.append(std::to_string(coordinate.instruction_range->first_instruction_id));
        detail.push_back('-');
        detail.append(std::to_string(coordinate.instruction_range->last_instruction_id));
    }
    if (coordinate.document_range) {
        detail.append(" document=");
        detail.append(std::to_string(coordinate.document_range->begin));
        detail.push_back('-');
        detail.append(std::to_string(coordinate.document_range->end));
    }
    if (coordinate.source_origin) {
        detail.append(" source_line=");
        detail.append(std::to_string(coordinate.source_origin->first_line));
        detail.push_back(':');
        detail.append(std::to_string(coordinate.source_origin->first_column));
        detail.push_back('-');
        detail.append(std::to_string(coordinate.source_origin->last_line));
        detail.push_back(':');
        detail.append(std::to_string(coordinate.source_origin->last_column));
    }
}

}

std::string serialize_native_worker_manifest(const native_worker_manifest_t& value)
{
    if (!valid_manifest(value))
        return {};
    manifest_writer_t writer;
    writer.u32(k_native_worker_manifest_magic);
    writer.u32(value.schema_version);
    writer.string(value.worker_relative_path);
    writer.digest(value.worker_binary_hash);
    writer.u8(static_cast<std::uint8_t>(value.provider.provider));
    writer.string(value.provider.provider_name);
    writer.string(value.provider.provider_version);
    writer.digest(value.provider.provider_binary_hash);
    writer.string(value.provider.worker_build_id);
    writer.digest(value.provider.worker_build_hash);
    writer.u32(value.worker_protocol_version);
    writer.digest(value.worker_protocol_hash);
    writer.u32(value.capabilities);
    writer.u32(static_cast<std::uint32_t>(value.startup_arguments.size()));
    for (const auto& argument : value.startup_arguments)
        writer.string(argument);
    if (value.schema_version == k_managed_worker_manifest_schema_version)
        writer.digest(value.managed_runtime_manifest_hash);
    return writer.take();
}

native_worker_manifest_decode_t deserialize_native_worker_manifest(const std::string& bytes)
{
    native_worker_manifest_decode_t result;
    manifest_reader_t reader(bytes);
    native_worker_manifest_t manifest;
    std::uint32_t magic = 0;
    std::uint8_t provider = 0;
    std::uint32_t argument_count = 0;
    if (!reader.u32(magic) || magic != k_native_worker_manifest_magic || !reader.u32(manifest.schema_version) ||
        !reader.string(manifest.worker_relative_path) || !reader.digest(manifest.worker_binary_hash) ||
        !reader.u8(provider) || !reader.string(manifest.provider.provider_name) || !reader.string(manifest.provider.provider_version) ||
        !reader.digest(manifest.provider.provider_binary_hash) || !reader.string(manifest.provider.worker_build_id) ||
        !reader.digest(manifest.provider.worker_build_hash) || !reader.u32(manifest.worker_protocol_version) ||
        !reader.digest(manifest.worker_protocol_hash) || !reader.u32(manifest.capabilities) || !reader.u32(argument_count) ||
        argument_count > k_manifest_max_arguments) {
        result.error = "native worker manifest is truncated or structurally invalid";
        return result;
    }
    manifest.provider.provider = static_cast<decompiler_provider_id_t>(provider);
    try {
        manifest.startup_arguments.reserve(argument_count);
    } catch (...) {
        result.error = "native worker manifest argument allocation failed";
        return result;
    }
    for (std::uint32_t index = 0; index < argument_count; ++index) {
        std::string argument;
        if (!reader.string(argument)) {
            result.error = "native worker manifest argument is truncated";
            return result;
        }
        manifest.startup_arguments.push_back(std::move(argument));
    }
    if (manifest.schema_version == k_managed_worker_manifest_schema_version &&
        !reader.digest(manifest.managed_runtime_manifest_hash)) {
        result.error = "managed worker manifest runtime identity is truncated";
        return result;
    }
    if (!reader.exhausted() || !valid_manifest(manifest)) {
        result.error = "native worker manifest fields violate the launch contract";
        return result;
    }
    result.value = std::move(manifest);
    return result;
}

sha256_digest_t native_worker_protocol_hash()
{
    return wire::protocol_hash();
}

std::optional<native_worker_snapshot_t> make_native_worker_snapshot(std::vector<std::uint8_t> bytes)
{
    if (bytes.empty())
        return std::nullopt;
    native_worker_snapshot_t result;
    try {
        result.bytes = std::make_shared<const std::vector<std::uint8_t>>(std::move(bytes));
    } catch (...) {
        return std::nullopt;
    }
    if (!wire::sha256(result.bytes->data(), result.bytes->size(), result.hash))
        return std::nullopt;
    return result;
}

workspace_result_t<managed_worker_snapshot_binding_t> capture_managed_worker_snapshot(
    const std::shared_ptr<const managed_cli::request_t>& request,
    std::size_t maximum_bytes,
    const cancellation_token_t& cancel)
{
    const auto failure = [](workspace_error_code_t code, std::string message,
                            std::string phase, DWORD win32_error = ERROR_SUCCESS) {
        auto error = make_workspace_error(code, std::move(message), std::move(phase));
        if (win32_error != ERROR_SUCCESS)
            error.win32_status = win32_error;
        return workspace_result_t<managed_worker_snapshot_binding_t>::failure(
            std::move(error));
    };
    if (!request || maximum_bytes == 0 ||
        maximum_bytes > managed_cli::k_managed_cli_maximum_module_bytes)
        return failure(workspace_error_code_t::invalid_argument,
            "managed CLI snapshot capture contract is invalid",
            "native_worker.managed_snapshot");
    if (cancel.stop_requested())
        return failure(cancel.deadline_exceeded()
                ? workspace_error_code_t::deadline_exceeded
                : workspace_error_code_t::cancelled,
            "managed CLI snapshot capture was cancelled",
            "native_worker.managed_snapshot");
    const auto bounded_maximum = static_cast<std::size_t>((std::min<std::uint64_t>)(
        maximum_bytes, request->profile.max_memory_bytes / 2U));
    if (bounded_maximum == 0)
        return failure(workspace_error_code_t::limit_exceeded,
            "managed CLI snapshot has no available memory budget",
            "native_worker.managed_snapshot");

    std::shared_ptr<const managed_cli::request_t> bound_request;
    if (request->module_source.kind == managed_cli::module_source_kind_t::regular_file) {
        const auto module_path = utf8_to_wide(request->module_source.filesystem_path);
        if (!module_path)
            return failure(workspace_error_code_t::invalid_argument,
                "managed CLI module path is not valid UTF-8",
                "native_worker.managed_snapshot.path", ERROR_INVALID_NAME);
        std::vector<std::uint8_t> bytes;
        DWORD capture_error = ERROR_SUCCESS;
        if (!capture_regular_module_bytes(*module_path, bounded_maximum, cancel,
                bytes, capture_error)) {
            const auto code = capture_error == ERROR_CANCELLED
                ? workspace_error_code_t::cancelled
                : capture_error == WAIT_TIMEOUT
                    ? workspace_error_code_t::deadline_exceeded
                    : capture_error == ERROR_FILE_TOO_LARGE
                        ? workspace_error_code_t::limit_exceeded
                        : workspace_error_code_t::integrity_failure;
            return failure(code,
                "managed CLI regular module could not be captured immutably",
                "native_worker.managed_snapshot.capture", capture_error);
        }
        auto bound = managed_cli::bind_module_snapshot(*request, std::move(bytes), cancel);
        if (!bound)
            return workspace_result_t<managed_worker_snapshot_binding_t>::failure(
                bound.error());
        try {
            bound_request = std::make_shared<const managed_cli::request_t>(
                bound.take_value());
        } catch (...) {
            return failure(workspace_error_code_t::limit_exceeded,
                "managed CLI bound request allocation failed",
                "native_worker.managed_snapshot.binding");
        }
    } else if (request->module_source.kind ==
               managed_cli::module_source_kind_t::embedded_member) {
        if (!request->module_snapshot || request->module_snapshot->empty() ||
            request->module_snapshot->size() > bounded_maximum)
            return failure(workspace_error_code_t::limit_exceeded,
                "managed CLI embedded module violates the snapshot budget",
                "native_worker.managed_snapshot.embedded");
        const auto validated = managed_cli::serialize_request(*request);
        if (!validated)
            return workspace_result_t<managed_worker_snapshot_binding_t>::failure(
                validated.error());
        bound_request = request;
    } else {
        return failure(workspace_error_code_t::invalid_argument,
            "managed CLI module source kind is invalid",
            "native_worker.managed_snapshot.source");
    }

    native_worker_snapshot_t snapshot;
    snapshot.bytes = bound_request->module_snapshot;
    snapshot.hash = bound_request->module_source.module_hash;
    if (!snapshot.bytes)
        return failure(workspace_error_code_t::integrity_failure,
            "managed CLI captured snapshot has no immutable bytes",
            "native_worker.managed_snapshot.verify");
    const auto verified_hash = sha256_bytes(
        snapshot.bytes->data(), snapshot.bytes->size(), cancel);
    if (!verified_hash)
        return workspace_result_t<managed_worker_snapshot_binding_t>::failure(
            verified_hash.error());
    if (!snapshot.valid() || snapshot.bytes->size() !=
            bound_request->module_source.module_size ||
        verified_hash.value() != snapshot.hash)
        return failure(workspace_error_code_t::integrity_failure,
            "managed CLI captured snapshot failed final verification",
            "native_worker.managed_snapshot.verify", ERROR_CRC);
    managed_worker_snapshot_binding_t result;
    result.snapshot = std::move(snapshot);
    result.request = std::move(bound_request);
    return workspace_result_t<managed_worker_snapshot_binding_t>::success(
        std::move(result));
}

workspace_result_t<packaged_native_worker_runtime_t> create_packaged_native_worker_runtime(
    std::filesystem::path runtime_root)
{
    const auto failure = [](workspace_error_code_t code, std::string message,
                            std::string phase, DWORD win32_error = ERROR_SUCCESS) {
        auto error = make_workspace_error(code, std::move(message), std::move(phase));
        if (win32_error != ERROR_SUCCESS)
            error.win32_status = win32_error;
        return workspace_result_t<packaged_native_worker_runtime_t>::failure(std::move(error));
    };
    try {
        if (runtime_root.empty()) {
            constexpr DWORD module_path_capacity = 32768;
            std::wstring module_path(module_path_capacity, L'\0');
            const DWORD written = GetModuleFileNameW(
                nullptr, module_path.data(), static_cast<DWORD>(module_path.size()));
            if (written == 0 || written >= module_path.size()) {
                return failure(workspace_error_code_t::provider_unavailable,
                    "native decompiler runtime root could not be discovered",
                    "native_worker.runtime.module", GetLastError());
            }
            module_path.resize(written);
            runtime_root = std::filesystem::path(std::move(module_path)).parent_path();
        }

        std::error_code ec;
        runtime_root = std::filesystem::absolute(runtime_root, ec).lexically_normal();
        if (ec || runtime_root.empty()) {
            return failure(workspace_error_code_t::invalid_argument,
                "native decompiler runtime root is invalid",
                "native_worker.runtime.root");
        }
        const DWORD root_attributes = GetFileAttributesW(runtime_root.c_str());
        if (root_attributes == INVALID_FILE_ATTRIBUTES ||
            (root_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (root_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            return failure(workspace_error_code_t::provider_unavailable,
                "native decompiler runtime root is unavailable or redirected",
                "native_worker.runtime.root", GetLastError());
        }

        const auto manifest_path = (runtime_root /
            std::filesystem::path(std::string(k_native_worker_manifest_artifact_relative_path))).lexically_normal();
        const auto digest_path = (runtime_root /
            std::filesystem::path(std::string(k_native_worker_manifest_digest_relative_path))).lexically_normal();
        const DWORD manifest_attributes = GetFileAttributesW(manifest_path.c_str());
        const DWORD digest_attributes = GetFileAttributesW(digest_path.c_str());
        if (manifest_attributes == INVALID_FILE_ATTRIBUTES ||
            digest_attributes == INVALID_FILE_ATTRIBUTES ||
            (manifest_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
            (digest_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            return failure(workspace_error_code_t::provider_unavailable,
                "native decompiler worker manifest package is unavailable",
                "native_worker.runtime.package", GetLastError());
        }

        handle_t manifest_file;
        handle_t digest_file;
        std::vector<std::uint8_t> manifest_bytes;
        std::vector<std::uint8_t> digest_bytes;
        DWORD error = ERROR_SUCCESS;
        if (!read_locked_file(manifest_path, 64U * 1024U, manifest_file, manifest_bytes, error)) {
            return failure(workspace_error_code_t::provider_unavailable,
                "native decompiler worker manifest could not be read",
                "native_worker.runtime.manifest", error);
        }
        if (!read_locked_file(digest_path, 4096U, digest_file, digest_bytes, error)) {
            return failure(workspace_error_code_t::provider_unavailable,
                "native decompiler worker manifest digest could not be read",
                "native_worker.runtime.digest", error);
        }
        const auto manifest_final = final_path(manifest_file.get());
        const auto digest_final = final_path(digest_file.get());
        const auto normalized_root = strip_extended_prefix(runtime_root.wstring());
        if (!manifest_final || !digest_final ||
            !path_within(normalized_root, *manifest_final) ||
            !path_within(normalized_root, *digest_final)) {
            return failure(workspace_error_code_t::integrity_failure,
                "native decompiler worker package escaped the approved runtime root",
                "native_worker.runtime.binding", ERROR_ACCESS_DENIED);
        }

        std::string digest_text(
            reinterpret_cast<const char*>(digest_bytes.data()), digest_bytes.size());
        const auto digest_hex_size = sha256_digest_t{}.bytes.size() * 2U;
        if (digest_text.size() != digest_hex_size + 1U ||
            digest_text.back() != '\n') {
            return failure(workspace_error_code_t::integrity_failure,
                "native decompiler worker manifest digest is malformed",
                "native_worker.runtime.digest");
        }
        digest_text.pop_back();
        if (!std::all_of(digest_text.begin(), digest_text.end(), [](const unsigned char value) {
                return (value >= '0' && value <= '9') ||
                       (value >= 'a' && value <= 'f');
            })) {
            return failure(workspace_error_code_t::integrity_failure,
                "native decompiler worker manifest digest is malformed",
                "native_worker.runtime.digest");
        }
        const auto expected_manifest_hash = sha256_digest_t::from_hex(digest_text);
        if (!expected_manifest_hash) {
            return failure(workspace_error_code_t::integrity_failure,
                "native decompiler worker manifest digest is invalid",
                "native_worker.runtime.digest");
        }
        sha256_digest_t manifest_hash;
        if (!wire::sha256(manifest_bytes.data(), manifest_bytes.size(), manifest_hash) ||
            manifest_hash != *expected_manifest_hash) {
            return failure(workspace_error_code_t::integrity_failure,
                "native decompiler worker manifest digest does not match the package",
                "native_worker.runtime.manifest_hash", ERROR_CRC);
        }
        const auto decoded = deserialize_native_worker_manifest(std::string(
            reinterpret_cast<const char*>(manifest_bytes.data()), manifest_bytes.size()));
        SecureZeroMemory(manifest_bytes.data(), manifest_bytes.size());
        if (!decoded.valid() || !decoded.value || !valid_manifest(*decoded.value) ||
            decoded.value->provider.provider != decompiler_provider_id_t::ghidra_native ||
            std::string_view(decoded.value->worker_relative_path) !=
                k_native_worker_binary_artifact_relative_path ||
            decoded.value->worker_protocol_hash != native_worker_protocol_hash()) {
            return failure(workspace_error_code_t::integrity_failure,
                "native decompiler worker manifest violates the production launch contract",
                "native_worker.runtime.manifest_contract");
        }

        const auto managed_manifest_path = (runtime_root /
            std::filesystem::path(std::string(k_managed_worker_manifest_artifact_relative_path))).lexically_normal();
        const auto managed_digest_path = (runtime_root /
            std::filesystem::path(std::string(k_managed_worker_manifest_digest_relative_path))).lexically_normal();
        const DWORD managed_manifest_attributes = GetFileAttributesW(managed_manifest_path.c_str());
        const DWORD managed_digest_attributes = GetFileAttributesW(managed_digest_path.c_str());
        if (managed_manifest_attributes == INVALID_FILE_ATTRIBUTES ||
            managed_digest_attributes == INVALID_FILE_ATTRIBUTES ||
            (managed_manifest_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
            (managed_digest_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            return failure(workspace_error_code_t::provider_unavailable,
                "managed decompiler worker manifest package is unavailable",
                "native_worker.runtime.managed_package", GetLastError());
        }
        handle_t managed_manifest_file;
        handle_t managed_digest_file;
        std::vector<std::uint8_t> managed_manifest_bytes;
        std::vector<std::uint8_t> managed_digest_bytes;
        if (!read_locked_file(managed_manifest_path, 64U * 1024U,
                managed_manifest_file, managed_manifest_bytes, error) ||
            !read_locked_file(managed_digest_path, 4096U,
                managed_digest_file, managed_digest_bytes, error)) {
            return failure(workspace_error_code_t::provider_unavailable,
                "managed decompiler worker manifest package could not be read",
                "native_worker.runtime.managed_manifest", error);
        }
        const auto managed_manifest_final = final_path(managed_manifest_file.get());
        const auto managed_digest_final = final_path(managed_digest_file.get());
        if (!managed_manifest_final || !managed_digest_final ||
            !path_within(normalized_root, *managed_manifest_final) ||
            !path_within(normalized_root, *managed_digest_final)) {
            return failure(workspace_error_code_t::integrity_failure,
                "managed decompiler worker package escaped the approved runtime root",
                "native_worker.runtime.managed_binding", ERROR_ACCESS_DENIED);
        }
        std::string managed_digest_text(
            reinterpret_cast<const char*>(managed_digest_bytes.data()),
            managed_digest_bytes.size());
        if (managed_digest_text.size() != digest_hex_size + 1U ||
            managed_digest_text.back() != '\n') {
            return failure(workspace_error_code_t::integrity_failure,
                "managed decompiler worker manifest digest is malformed",
                "native_worker.runtime.managed_digest");
        }
        managed_digest_text.pop_back();
        if (!std::all_of(managed_digest_text.begin(), managed_digest_text.end(),
                [](const unsigned char value) {
                    return (value >= '0' && value <= '9') ||
                           (value >= 'a' && value <= 'f');
                })) {
            return failure(workspace_error_code_t::integrity_failure,
                "managed decompiler worker manifest digest is malformed",
                "native_worker.runtime.managed_digest");
        }
        const auto expected_managed_manifest_hash =
            sha256_digest_t::from_hex(managed_digest_text);
        sha256_digest_t managed_manifest_hash;
        if (!expected_managed_manifest_hash ||
            !wire::sha256(managed_manifest_bytes.data(), managed_manifest_bytes.size(),
                managed_manifest_hash) ||
            managed_manifest_hash != *expected_managed_manifest_hash) {
            return failure(workspace_error_code_t::integrity_failure,
                "managed decompiler worker manifest digest does not match the package",
                "native_worker.runtime.managed_manifest_hash", ERROR_CRC);
        }
        const auto managed_decoded = deserialize_native_worker_manifest(std::string(
            reinterpret_cast<const char*>(managed_manifest_bytes.data()),
            managed_manifest_bytes.size()));
        SecureZeroMemory(managed_manifest_bytes.data(), managed_manifest_bytes.size());
        if (!managed_decoded.valid() || !managed_decoded.value ||
            !valid_manifest(*managed_decoded.value) ||
            managed_decoded.value->provider.provider != decompiler_provider_id_t::ilspy_cli ||
            std::string_view(managed_decoded.value->worker_relative_path) !=
                k_managed_worker_binary_artifact_relative_path ||
            managed_decoded.value->worker_protocol_hash != native_worker_protocol_hash()) {
            return failure(workspace_error_code_t::integrity_failure,
                "managed decompiler worker manifest violates the production launch contract",
                "native_worker.runtime.managed_manifest_contract");
        }

        native_worker_launch_contract_t launch_contract;
        launch_contract.approved_root = runtime_root;
        launch_contract.manifest_path = manifest_path;
        launch_contract.expected_manifest_hash = manifest_hash;
        native_worker_launch_contract_t managed_launch_contract;
        managed_launch_contract.approved_root = runtime_root;
        managed_launch_contract.manifest_path = managed_manifest_path;
        managed_launch_contract.expected_manifest_hash = managed_manifest_hash;
        native_worker_execution_result_t native_runtime_verification;
        auto verified_native = verify_worker(
            launch_contract, native_runtime_verification);
        if (!verified_native) {
            std::string detail =
                "native decompiler runtime failed package verification";
            if (!native_runtime_verification.diagnostics.empty()) {
                detail.append(": ");
                detail.append(native_runtime_verification.diagnostics.front().detail);
            }
            return failure(workspace_error_code_t::integrity_failure,
                std::move(detail), "native_worker.runtime.native", ERROR_CRC);
        }
        native_worker_execution_result_t managed_runtime_verification;
        auto verified_managed = verify_worker(
            managed_launch_contract, managed_runtime_verification);
        if (!verified_managed) {
            std::string detail = "managed decompiler app-local runtime failed package verification";
            if (!managed_runtime_verification.diagnostics.empty()) {
                detail.append(": ");
                detail.append(managed_runtime_verification.diagnostics.front().detail);
            }
            return failure(workspace_error_code_t::integrity_failure,
                std::move(detail),
                "native_worker.runtime.managed_runtime", ERROR_CRC);
        }
        std::shared_ptr<const native_worker_verified_package_t> native_package =
            std::make_shared<native_worker_verified_package_t>(
                std::move(*verified_native));
        std::shared_ptr<const native_worker_verified_package_t> managed_package =
            std::make_shared<native_worker_verified_package_t>(
                std::move(*verified_managed));
        auto host = std::shared_ptr<native_worker_host_t>(
            new native_worker_host_t(std::move(launch_contract), {},
                std::move(native_package)));
        auto managed_host = std::shared_ptr<native_worker_host_t>(
            new native_worker_host_t(std::move(managed_launch_contract), {},
                std::move(managed_package)));
        packaged_native_worker_runtime_t result;
        result.native_host = host;
        result.provider_host = std::make_shared<native_worker_provider_host_t>(
            host, std::move(managed_host));
        result.provider = decoded.value->provider;
        result.cli_provider = managed_decoded.value->provider;
        result.jvm_provider = isolated_provider_identity(
            decoded.value->provider, decompiler_provider_id_t::jvm_ssa);
        result.dalvik_provider = isolated_provider_identity(
            decoded.value->provider, decompiler_provider_id_t::dalvik_ssa);
        result.worker_protocol_hash = decoded.value->worker_protocol_hash;
        result.manifest_hash = manifest_hash;
        result.managed_manifest_hash = managed_manifest_hash;
        result.managed_runtime_manifest_hash =
            managed_decoded.value->managed_runtime_manifest_hash;
        result.worker_protocol_version = decoded.value->worker_protocol_version;
        return workspace_result_t<packaged_native_worker_runtime_t>::success(std::move(result));
    } catch (const std::bad_alloc&) {
        return failure(workspace_error_code_t::limit_exceeded,
            "native decompiler runtime allocation failed",
            "native_worker.runtime");
    } catch (...) {
        return failure(workspace_error_code_t::provider_unavailable,
            "native decompiler runtime initialization failed",
            "native_worker.runtime");
    }
}

bool native_worker_snapshot_t::valid() const noexcept
{
    return bytes && !bytes->empty() && !hash.empty();
}

native_worker_host_t::native_worker_host_t(native_worker_launch_contract_t contract, native_worker_host_limits_t limits)
    : contract_(std::move(contract)), limits_(limits)
{
    native_worker_execution_result_t verification;
    auto verified = verify_worker(contract_, verification);
    verification_diagnostics_ = std::move(verification.diagnostics);
    if (verified)
        verified_package_ = std::make_shared<native_worker_verified_package_t>(
            std::move(*verified));
}

native_worker_host_t::native_worker_host_t(
    native_worker_launch_contract_t contract,
    native_worker_host_limits_t limits,
    std::shared_ptr<const native_worker_verified_package_t> verified_package)
    : contract_(std::move(contract)), limits_(limits),
      verified_package_(std::move(verified_package))
{
    if (!verified_package_ ||
        verified_package_->manifest_hash != contract_.expected_manifest_hash) {
        verified_package_.reset();
        native_worker_execution_result_t verification;
        append_diagnostic(verification,
            native_worker_diagnostic_code_t::worker_identity_mismatch,
            "native_worker.verify",
            "preverified worker identity does not match the launch contract",
            ERROR_CRC);
        verification_diagnostics_ = std::move(verification.diagnostics);
    }
}

native_worker_host_t::~native_worker_host_t()
{
    stop();
}

native_worker_execution_result_t native_worker_host_t::execute(const native_worker_execution_request_t& input)
{
    native_worker_execution_result_t result;
    if (stopped_.load(std::memory_order_acquire)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::host_stopped, "native_worker.execute", "worker host is stopped");
        return result;
    }
    if (limits_.max_frame_bytes == 0 ||
        limits_.max_frame_bytes > k_decompiler_worker_result_frame_max_bytes ||
        limits_.max_snapshot_bytes == 0 ||
        limits_.max_concurrent_workers == 0 || limits_.startup_timeout.count() <= 0 ||
        limits_.cancellation_grace.count() < 0 || limits_.poll_interval.count() <= 0 || input.job_id == 0 ||
        !input.snapshot.valid() || input.snapshot.bytes->size() > limits_.max_snapshot_bytes ||
        input.snapshot.bytes->size() > input.profile.max_memory_bytes) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request, "native_worker.request", "worker request or host limits are invalid");
        return result;
    }
    const auto queue_deadline = effective_deadline(input);
    {
        std::unique_lock lock(state_mutex_);
        while (!stopped_.load(std::memory_order_acquire) &&
               active_workers_ >= limits_.max_concurrent_workers) {
            if ((input.cancellation_requested && input.cancellation_requested()) ||
                std::chrono::steady_clock::now() >= queue_deadline) {
                result.status = std::chrono::steady_clock::now() >= queue_deadline
                    ? native_worker_execution_status_t::deadline_exceeded
                    : native_worker_execution_status_t::cancelled;
                append_diagnostic(result,
                    result.status == native_worker_execution_status_t::deadline_exceeded
                        ? native_worker_diagnostic_code_t::deadline_exceeded
                        : native_worker_diagnostic_code_t::cancelled,
                    "native_worker.queue", "worker admission was cancelled before launch");
                return result;
            }
            const auto poll_deadline = std::min(
                queue_deadline,
                std::chrono::steady_clock::now() + limits_.poll_interval);
            state_wake_.wait_until(lock, poll_deadline);
        }
        if (stopped_.load(std::memory_order_acquire)) {
            append_diagnostic(result, native_worker_diagnostic_code_t::host_stopped,
                "native_worker.queue", "worker host stopped before admission");
            return result;
        }
        ++active_workers_;
    }
    struct active_worker_guard_t final {
        std::function<void()> release;
        ~active_worker_guard_t() { release(); }
    } active_guard{[this] {
        std::lock_guard lock(state_mutex_);
        --active_workers_;
        state_wake_.notify_all();
    }};
    native_worker_execution_request_t request = input;
    const auto external_cancel = input.cancellation_requested;
    request.cancellation_requested = [this, external_cancel] {
        return stopped_.load(std::memory_order_acquire) ||
               (external_cancel && external_cancel());
    };
    sha256_digest_t verified_snapshot_hash;
    if (!wire::sha256(request.snapshot.bytes->data(), request.snapshot.bytes->size(), verified_snapshot_hash) || verified_snapshot_hash != request.snapshot.hash) {
        append_diagnostic(result, native_worker_diagnostic_code_t::snapshot_invalid, "native_worker.snapshot", "snapshot hash is invalid", ERROR_CRC);
        return result;
    }
    result.snapshot_hash = verified_snapshot_hash;
    const auto cache_validation = validate_decompiler_pipeline_cache_key(request.cache_key);
    const auto profile_validation = validate_decompiler_profile(request.profile);
    if (!cache_validation.valid() || !profile_validation.valid() ||
        request.cache_key.worker_protocol_hash != native_worker_protocol_hash() ||
        request.cache_key.profile.profile != request.profile.profile ||
        request.cache_key.profile.max_wall_clock_ms != request.profile.max_wall_clock_ms ||
        request.cache_key.profile.max_cpu_ms != request.profile.max_cpu_ms ||
        request.cache_key.profile.max_memory_bytes != request.profile.max_memory_bytes ||
        request.cache_key.profile.max_provider_ir_nodes != request.profile.max_provider_ir_nodes ||
        request.cache_key.profile.max_hir_nodes != request.profile.max_hir_nodes ||
        request.cache_key.profile.max_ast_nodes != request.profile.max_ast_nodes ||
        request.cache_key.profile.max_semantic_queries != request.profile.max_semantic_queries ||
        request.cache_key.profile.semantic_proofs_enabled != request.profile.semantic_proofs_enabled) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request, "native_worker.contract", "cache key and profile do not form a valid bound request", ERROR_INVALID_DATA);
        return result;
    }
    const bool managed_route = request.cache_key.provider.provider ==
        decompiler_provider_id_t::ilspy_cli;
    if (request.request_printc_evidence &&
        request.cache_key.provider.provider != decompiler_provider_id_t::ghidra_native) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request,
            "native_worker.printc_contract",
            "PrintC evidence is restricted to the native Ghidra provider", ERROR_INVALID_DATA);
        return result;
    }
    if (managed_route) {
        if (!request.managed_request) {
            append_diagnostic(result,
                native_worker_diagnostic_code_t::invalid_request,
                "native_worker.managed_contract",
                "managed request is absent", ERROR_INVALID_DATA);
            return result;
        }
        const auto serialized = managed_cli::serialize_request(
            *request.managed_request);
        if (!serialized ||
            request.managed_request->entity != request.cache_key.entity ||
            request.managed_request->workspace_generation !=
                request.cache_key.workspace_generation ||
            request.managed_request->type_graph_revision !=
                request.cache_key.type_graph_revision ||
            !same_profile(request.managed_request->profile, request.profile) ||
            request.managed_request->module_source.module_size !=
                request.snapshot.bytes->size() ||
            request.managed_request->module_source.module_hash !=
                request.snapshot.hash ||
            request.managed_request->module_snapshot != request.snapshot.bytes ||
            request.managed_request->contract_hash !=
                managed_cli::managed_cli_contract_hash()) {
            append_diagnostic(result,
                native_worker_diagnostic_code_t::invalid_request,
                "native_worker.managed_contract",
                "managed request is not bound to the immutable snapshot and cache key",
                ERROR_INVALID_DATA);
            return result;
        }
    } else if (request.managed_request) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request,
            "native_worker.managed_contract",
            "native route cannot carry a managed request", ERROR_INVALID_DATA);
        return result;
    }
    const auto verified = verified_package_;
    if (!verified) {
        result.diagnostics = verification_diagnostics_;
        return result;
    }
    result.manifest_hash = verified->manifest_hash;
    if (!compatible_worker_provider(request.cache_key.provider, verified->manifest.provider)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_identity_mismatch,
            "native_worker.request_identity",
            "cache provider identity does not match the verified worker manifest",
            ERROR_CRC, true);
        return result;
    }
    result.worker_generation = worker_generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
    worker_instance_t worker;
    if (!launch_worker(*verified, request, limits_, worker, result)) {
        result.worker_process_id = worker.process_id;
        if (worker.process)
            terminate_worker(worker, ERROR_ACCESS_DENIED, result, true);
        return result;
    }
    result.worker_process_id = worker.process_id;
    const auto startup_timeout_deadline = std::chrono::steady_clock::now() + limits_.startup_timeout;
    const auto startup_deadline = (std::min)(startup_timeout_deadline, queue_deadline);
    wire::frame_t frame;
    DWORD error = ERROR_SUCCESS;
    const auto hello_wait = wait_for_message(worker, request, limits_, startup_deadline, frame, error);
    if (hello_wait != terminal_wait_t::message) {
        DWORD termination_code = ERROR_CANCELLED;
        if (hello_wait == terminal_wait_t::cancelled) {
            result.status = native_worker_execution_status_t::cancelled;
            append_diagnostic(result, native_worker_diagnostic_code_t::cancelled,
                "native_worker.hello", "worker startup was cancelled before an authenticated hello",
                ERROR_CANCELLED, true);
        } else if (hello_wait == terminal_wait_t::deadline) {
            result.status = native_worker_execution_status_t::deadline_exceeded;
            termination_code = WAIT_TIMEOUT;
            append_diagnostic(result, native_worker_diagnostic_code_t::deadline_exceeded, "native_worker.hello",
                queue_deadline <= startup_timeout_deadline
                    ? "request deadline expired before an authenticated worker hello"
                    : "worker did not provide an authenticated hello before the startup deadline",
                WAIT_TIMEOUT, true);
        } else if (hello_wait == terminal_wait_t::exited) {
            append_worker_exit(result, worker, "native_worker.hello",
                "worker exited before providing an authenticated hello");
        } else {
            append_protocol_failure(result, worker.reader.failure(), "native_worker.hello", error,
                &worker.wait_observation);
        }
        terminate_worker(worker, termination_code, result, true);
        return result;
    }
    if (verified->manifest.provider.provider == decompiler_provider_id_t::ilspy_cli) {
        const auto startup = validate_managed_startup_frame(frame, worker.session, *verified);
        if (startup.kind == managed_startup_frame_kind_t::failure) {
            std::string detail = "managed worker rejected startup: stage=";
            detail.append(startup.stage);
            detail.append(" code=");
            detail.append(startup.code);
            append_diagnostic(result, native_worker_diagnostic_code_t::worker_failed,
                "native_worker.managed_startup", std::move(detail),
                ERROR_INVALID_DATA, startup.retryable);
            terminate_worker(worker, ERROR_INVALID_DATA, result, true);
            return result;
        }
        if (!request.managed_request ||
            startup.kind != managed_startup_frame_kind_t::hello) {
            append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed,
                "native_worker.managed_hello",
                "managed worker hello violates the authenticated identity contract",
                ERROR_INVALID_DATA, true);
            terminate_worker(worker, ERROR_CRC, result, true);
            return result;
        }
        const auto serialized_request = managed_cli::serialize_request(*request.managed_request);
        if (!serialized_request || !send_managed_payload(
                worker, serialized_request.value(), limits_, error)) {
            append_diagnostic(result, native_worker_diagnostic_code_t::bootstrap_failed,
                "native_worker.managed_job",
                "managed worker request could not be validated or written",
                error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error, true);
            terminate_worker(worker, ERROR_CANCELLED, result, true);
            return result;
        }
        const auto deadline = effective_deadline(request);
        while (true) {
            const auto terminal = wait_for_message(worker, request, limits_, deadline, frame, error);
            if (terminal == terminal_wait_t::cancelled || terminal == terminal_wait_t::deadline) {
                const bool is_deadline = terminal == terminal_wait_t::deadline;
                const auto cancellation = managed_cli::serialize_cancellation(
                    *request.managed_request, request.managed_request->sequence + 1,
                    is_deadline ? "deadline_exceeded" : "cancelled");
                if (cancellation)
                    send_managed_payload(worker, cancellation.value(), limits_, error);
                const auto grace_deadline = std::chrono::steady_clock::now() + limits_.cancellation_grace;
                wire::frame_t ignored;
                wait_for_message(worker, native_worker_execution_request_t{}, limits_,
                    grace_deadline, ignored, error);
                result.status = is_deadline
                    ? native_worker_execution_status_t::deadline_exceeded
                    : native_worker_execution_status_t::cancelled;
                append_diagnostic(result,
                    is_deadline ? native_worker_diagnostic_code_t::deadline_exceeded
                                : native_worker_diagnostic_code_t::cancelled,
                    "native_worker.managed_cancel",
                    is_deadline ? "managed worker exceeded its deadline"
                                : "managed worker cancellation was requested",
                    ERROR_CANCELLED, true);
                terminate_worker(worker, ERROR_CANCELLED, result, true);
                return result;
            }
            if (terminal == terminal_wait_t::exited) {
                append_worker_exit(result, worker, "native_worker.managed_wait",
                    "managed worker exited before a terminal result");
                const DWORD exit_code = worker.wait_observation.exit_code_available
                    ? worker.wait_observation.exit_code : ERROR_PROCESS_ABORTED;
                terminate_worker(worker, exit_code, result, true);
                return result;
            }
            if (terminal == terminal_wait_t::protocol_failure) {
                append_protocol_failure(result, worker.reader.failure(),
                    "native_worker.managed_response", error, &worker.wait_observation);
                terminate_worker(worker, ERROR_CRC, result, true);
                return result;
            }
            if (!valid_managed_terminal_payload(frame, *request.managed_request)) {
                append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed,
                    "native_worker.managed_response",
                    "managed worker response is not bound to the active request",
                    ERROR_INVALID_DATA, true);
                terminate_worker(worker, ERROR_CRC, result, true);
                return result;
            }
            result.provider_artifacts.assign(
                reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size());
            result.provider_artifacts_hash = stable_serialization_hash(result.provider_artifacts);
            result.status = native_worker_execution_status_t::completed;
            terminate_worker(worker, ERROR_SUCCESS, result, false);
            return result;
        }
    }
    const auto decoded_hello = deserialize_decompiler_worker_message(
        std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()));
    if (!decoded_hello.valid() || !decoded_hello.value || !validate_envelope(*decoded_hello.value, frame, worker.session) ||
        !std::holds_alternative<decompiler_worker_hello_t>(*decoded_hello.value)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.hello", "worker hello violates the authenticated protocol", ERROR_INVALID_DATA, true);
        terminate_worker(worker, ERROR_CRC, result, true);
        return result;
    }
    const auto& hello = std::get<decompiler_worker_hello_t>(*decoded_hello.value);
    if (hello.manifest_hash != verified->manifest_hash ||
        !same_provider(hello.provider, request.cache_key.provider) ||
        !compatible_worker_provider(hello.provider, verified->manifest.provider)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_identity_mismatch, "native_worker.hello_identity", "worker identity does not match verified manifest", ERROR_CRC, true);
        terminate_worker(worker, ERROR_CRC, result, true);
        return result;
    }
    decompiler_worker_job_request_t job;
    job.envelope.kind = decompiler_worker_message_kind_t::job_request;
    job.envelope.session_nonce_hash = worker.session.nonce_hash;
    job.envelope.sequence = worker.next_host_sequence;
    job.job_id = request.job_id;
    job.cache_key = request.cache_key;
    job.profile = request.profile;
    job.snapshot_hash = request.snapshot.hash;
    job.request_printc_evidence = request.request_printc_evidence;
    if (!send_contract(worker, decompiler_worker_message_t{std::move(job)}, limits_, error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::bootstrap_failed, "native_worker.job", "job request could not be written", error, true);
        terminate_worker(worker, ERROR_CANCELLED, result, true);
        return result;
    }
    const auto deadline = effective_deadline(request);
    while (true) {
        const auto terminal = wait_for_message(worker, request, limits_, deadline, frame, error);
        if (terminal == terminal_wait_t::cancelled || terminal == terminal_wait_t::deadline) {
            const bool is_deadline = terminal == terminal_wait_t::deadline;
            send_cancel(worker, request, limits_, is_deadline ? "deadline_exceeded" : "cancelled");
            auto saved_cancel = request.cancellation_requested;
            request.cancellation_requested = [] { return false; };
            const auto grace_deadline = std::chrono::steady_clock::now() + limits_.cancellation_grace;
            while (std::chrono::steady_clock::now() < grace_deadline) {
                const auto grace_terminal = wait_for_message(worker, request, limits_, grace_deadline, frame, error);
                if (grace_terminal == terminal_wait_t::message) {
                    const auto decoded = deserialize_decompiler_worker_message(
                        std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()));
                    if (decoded.valid() && decoded.value && validate_envelope(*decoded.value, frame, worker.session)) {
                        if (std::holds_alternative<decompiler_worker_failure_message_t>(*decoded.value)) {
                            const auto& failure = std::get<decompiler_worker_failure_message_t>(*decoded.value);
                            if (failure.job_id == request.job_id)
                                append_worker_failure(result, failure);
                        }
                    }
                    break;
                }
                if (grace_terminal == terminal_wait_t::exited ||
                    grace_terminal == terminal_wait_t::deadline ||
                    grace_terminal == terminal_wait_t::protocol_failure)
                    break;
            }
            request.cancellation_requested = saved_cancel;
            result.status = is_deadline ? native_worker_execution_status_t::deadline_exceeded : native_worker_execution_status_t::cancelled;
            append_diagnostic(result, is_deadline ? native_worker_diagnostic_code_t::deadline_exceeded : native_worker_diagnostic_code_t::cancelled,
                "native_worker.cancel", is_deadline ? "worker exceeded its deadline" : "worker cancellation was requested", ERROR_CANCELLED, true);
            terminate_worker(worker, ERROR_CANCELLED, result, true);
            return result;
        }
        if (terminal == terminal_wait_t::exited) {
            append_worker_exit(result, worker, "native_worker.wait",
                "worker exited before a terminal result");
            const DWORD exit_code = worker.wait_observation.exit_code_available
                ? worker.wait_observation.exit_code : ERROR_PROCESS_ABORTED;
            terminate_worker(worker, exit_code, result, true);
            return result;
        }
        if (terminal == terminal_wait_t::protocol_failure) {
            append_protocol_failure(result, worker.reader.failure(), "native_worker.response", error,
                &worker.wait_observation);
            terminate_worker(worker, ERROR_CRC, result, true);
            return result;
        }
        const auto decoded = deserialize_decompiler_worker_message(
            std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()));
        if (!decoded.valid() || !decoded.value || !validate_envelope(*decoded.value, frame, worker.session)) {
            append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.response", "worker response cannot be decoded or validated", ERROR_INVALID_DATA, true);
            terminate_worker(worker, ERROR_CRC, result, true);
            return result;
        }
        if (std::holds_alternative<decompiler_worker_heartbeat_t>(*decoded.value)) {
            const auto& heartbeat = std::get<decompiler_worker_heartbeat_t>(*decoded.value);
            if (heartbeat.active_job_id != request.job_id) {
                append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.heartbeat", "heartbeat job identity does not match active job", ERROR_INVALID_DATA, true);
                terminate_worker(worker, ERROR_CRC, result, true);
                return result;
            }
            continue;
        }
        if (std::holds_alternative<decompiler_worker_failure_message_t>(*decoded.value)) {
            const auto& failure = std::get<decompiler_worker_failure_message_t>(*decoded.value);
            if (failure.job_id != request.job_id) {
                append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.failure", "failure job identity does not match active job", ERROR_INVALID_DATA, true);
                terminate_worker(worker, ERROR_CRC, result, true);
                return result;
            }
            append_worker_failure(result, failure);
            std::string detail = "worker returned typed failure diagnostics";
            if (!failure.diagnostics.empty())
                append_worker_diagnostic_detail(detail, failure.diagnostics.front());
            append_diagnostic(result, native_worker_diagnostic_code_t::worker_failed,
                "native_worker.failure", std::move(detail), ERROR_SUCCESS, false);
            result.status = native_worker_execution_status_t::failed;
            const bool replacement = std::any_of(failure.diagnostics.begin(), failure.diagnostics.end(),
                [](const decompiler_diagnostic_t& current) { return current.retryable; });
            terminate_worker(worker, replacement ? ERROR_RETRY : ERROR_SUCCESS, result, replacement);
            return result;
        }
        if (std::holds_alternative<decompiler_worker_document_message_t>(*decoded.value)) {
            const auto& document = std::get<decompiler_worker_document_message_t>(*decoded.value);
            const auto document_validation = validate_decompiler_document(document.document);
            if (document.job_id != request.job_id || !document_validation.valid() || !(document.document.entity == request.cache_key.entity) ||
                document.document.profile != request.profile.profile ||
                document.provider_artifacts.empty() || document.provider_artifacts_hash.empty() ||
                document.provider_artifacts.size() > k_decompiler_worker_provider_artifacts_max_bytes ||
                stable_serialization_hash(document.provider_artifacts) != document.provider_artifacts_hash ||
                document.printc_evidence.has_value() != request.request_printc_evidence ||
                (document.printc_evidence &&
                    (document.printc_evidence->empty() ||
                     document.printc_evidence->size() > k_decompiler_worker_printc_evidence_max_bytes ||
                     document.printc_evidence_hash.empty() ||
                     stable_serialization_hash(*document.printc_evidence) != document.printc_evidence_hash))) {
                append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.document", "worker document is not bound to the requested entity and profile", ERROR_INVALID_DATA, true);
                terminate_worker(worker, ERROR_CRC, result, true);
                return result;
            }
            result.document = document.document;
            result.provider_artifacts = document.provider_artifacts;
            result.provider_artifacts_hash = document.provider_artifacts_hash;
            result.printc_evidence = document.printc_evidence;
            result.printc_evidence_hash = document.printc_evidence_hash;
            result.status = native_worker_execution_status_t::completed;
            terminate_worker(worker, ERROR_SUCCESS, result, false);
            return result;
        }
        append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.response", "worker sent a message that is invalid in the active job state", ERROR_INVALID_DATA, true);
        terminate_worker(worker, ERROR_CRC, result, true);
        return result;
    }
}

void native_worker_host_t::stop() noexcept
{
    stopped_.store(true, std::memory_order_release);
    state_wake_.notify_all();
    std::unique_lock lock(state_mutex_);
    state_wake_.wait(lock, [this] { return active_workers_ == 0; });
}

std::uint64_t native_worker_host_t::worker_generation() const noexcept
{
    return worker_generation_.load(std::memory_order_acquire);
}

native_worker_provider_host_t::native_worker_provider_host_t(
    std::shared_ptr<native_worker_host_t> host,
    std::shared_ptr<native_worker_host_t> managed_host)
    : host_(std::move(host)), managed_host_(std::move(managed_host))
{
}

decompiler_provider_result_t map_worker_result_to_provider_result(
    const decompiler_provider_route_t& route,
    const decompiler_provider_request_t& request,
    const cancellation_token_t& cancel,
    const native_worker_execution_request_t& worker_request,
    native_worker_execution_result_t& worker_result,
    const std::chrono::steady_clock::time_point started)
{
    decompiler_provider_result_t result;
    result.diagnostics.insert(result.diagnostics.end(),
        worker_result.worker_diagnostics.begin(), worker_result.worker_diagnostics.end());
    for (const auto& source : worker_result.diagnostics) {
        decompiler_diagnostic_t diagnostic;
        diagnostic.severity = decompiler_diagnostic_severity_t::error;
        diagnostic.code = source.code == native_worker_diagnostic_code_t::deadline_exceeded
            ? decompiler_diagnostic_code_t::deadline_exceeded
            : source.code == native_worker_diagnostic_code_t::cancelled
                ? decompiler_diagnostic_code_t::cancelled
                : decompiler_diagnostic_code_t::worker_protocol_failure;
        diagnostic.localization_key = source.phase.empty()
            ? "decompiler.native_host.failure" : source.phase;
        diagnostic.localization_arguments = {
            source.detail,
            std::to_string(source.win32_error),
            std::to_string(source.worker_generation)};
        diagnostic.ordinal = static_cast<std::uint32_t>(result.diagnostics.size() + 1U);
        diagnostic.retryable = source.retryable;
        result.diagnostics.push_back(std::move(diagnostic));
    }
    switch (worker_result.status) {
    case native_worker_execution_status_t::completed:
        if ((worker_result.document ||
                route.descriptor.identity.provider == decompiler_provider_id_t::ilspy_cli) &&
            !worker_result.provider_artifacts.empty() &&
            worker_result.provider_artifacts_hash ==
                stable_serialization_hash(worker_result.provider_artifacts)) {
            try {
                decompiler_provider_artifacts_t provider_artifacts;
                bool managed_failure = false;
                std::vector<decompiler_diagnostic_t> decode_diagnostics;
                switch (route.descriptor.identity.provider) {
                case decompiler_provider_id_t::ghidra_native: {
                    auto decoded = ghidra_ir_adapter::deserialize_artifacts(
                        worker_result.provider_artifacts, decode_diagnostics);
                    if (decoded) {
                        provider_artifacts.provider_ir = std::move(decoded->provider_ir);
                        provider_artifacts.hir = std::move(decoded->hir);
                        provider_artifacts.type_graph = std::move(decoded->type_graph);
                        provider_artifacts.return_type_id = provider_artifacts.hir->return_type_id;
                    }
                    break;
                }
                case decompiler_provider_id_t::jvm_ssa: {
                    auto decoded = jvm_ssa::deserialize_jvm_ssa_result(
                        worker_result.provider_artifacts, decode_diagnostics);
                    if (decoded && decoded->succeeded() && decoded->provider_ir &&
                        decoded->hir && decoded->type_graph) {
                        provider_artifacts.provider_ir = std::move(*decoded->provider_ir);
                        provider_artifacts.hir = std::move(*decoded->hir);
                        provider_artifacts.type_graph = std::move(*decoded->type_graph);
                        provider_artifacts.return_type_id = provider_artifacts.hir->return_type_id;
                    }
                    break;
                }
                case decompiler_provider_id_t::dalvik_ssa: {
                    auto decoded = dalvik_ssa::deserialize_artifacts(
                        worker_result.provider_artifacts, decode_diagnostics);
                    if (decoded) {
                        provider_artifacts.provider_ir = std::move(decoded->provider_ir);
                        provider_artifacts.hir = std::move(decoded->hir);
                        provider_artifacts.type_graph = std::move(decoded->type_graph);
                        provider_artifacts.return_type_id = provider_artifacts.hir->return_type_id;
                    }
                    break;
                }
                case decompiler_provider_id_t::ilspy_cli:
                {
                    if (!worker_request.managed_request)
                        break;
                    auto decoded = managed_cli::deserialize_response(
                        *worker_request.managed_request,
                        worker_result.provider_artifacts, cancel);
                    if (!decoded) {
                        decompiler_diagnostic_t diagnostic;
                        diagnostic.severity = decompiler_diagnostic_severity_t::error;
                        diagnostic.code = decompiler_diagnostic_code_t::malformed_serialization;
                        diagnostic.localization_key = "decompiler.managed_host.response_decode";
                        auto decode_detail = decoded.error().message;
                        if (decode_detail.size() > 512U)
                            decode_detail.resize(512U);
                        diagnostic.localization_arguments = {
                            decoded.error().stable_code(), std::move(decode_detail)};
                        diagnostic.ordinal = static_cast<std::uint32_t>(result.diagnostics.size() + 1);
                        result.diagnostics.push_back(std::move(diagnostic));
                    } else if (decoded.value().failure) {
                        result.diagnostics.insert(result.diagnostics.end(),
                            decoded.value().failure->diagnostics.begin(),
                            decoded.value().failure->diagnostics.end());
                        managed_failure = true;
                    } else if (decoded.value().analysis) {
                        provider_artifacts.provider_ir =
                            std::move(decoded.value().analysis->provider_ir);
                        provider_artifacts.type_graph =
                            std::move(decoded.value().analysis->type_graph);
                        provider_artifacts.return_type_id =
                            decoded.value().analysis->return_type_id;
                    }
                    break;
                }
                }
                result.diagnostics.insert(result.diagnostics.end(),
                    decode_diagnostics.begin(), decode_diagnostics.end());
                if (managed_failure) {
                    result.status = decompiler_provider_execution_status_t::failed;
                    result.artifacts.reset();
                    break;
                }
                if (!validate_provider_ir(provider_artifacts.provider_ir).valid() ||
                    !validate_type_graph(provider_artifacts.type_graph).valid() ||
                    provider_artifacts.provider_ir.entity != request.cache_key.entity ||
                    provider_artifacts.type_graph.entity != request.cache_key.entity ||
                    !same_provider(provider_artifacts.provider_ir.provider, route.descriptor.identity) ||
                    !same_language(provider_artifacts.provider_ir.language, request.cache_key.language) ||
                    (provider_artifacts.hir &&
                        (!validate_hir_function(*provider_artifacts.hir).valid() ||
                         provider_artifacts.hir->entity != request.cache_key.entity ||
                         provider_artifacts.hir->provider_ir_hash !=
                             stable_serialization_hash(provider_artifacts.provider_ir) ||
                         provider_artifacts.hir->type_graph_revision !=
                             request.cache_key.type_graph_revision)) ||
                    (route.descriptor.identity.provider != decompiler_provider_id_t::ilspy_cli &&
                        !provider_artifacts.hir) ||
                    provider_artifacts.type_graph.revision != request.cache_key.type_graph_revision ||
                    provider_artifacts.return_type_id == 0)
                    throw std::invalid_argument("isolated provider artifacts failed binding");
                result.artifacts = std::move(provider_artifacts);
                if (worker_result.document)
                    result.attested_document = std::move(worker_result.document);
                result.authenticated_artifacts = true;
                result.status = decompiler_provider_execution_status_t::completed;
            } catch (const std::bad_alloc&) {
                result.status = decompiler_provider_execution_status_t::failed;
                result.artifacts.reset();
                result.attested_document.reset();
                result.authenticated_artifacts = false;
                decompiler_diagnostic_t diagnostic;
                diagnostic.severity = decompiler_diagnostic_severity_t::error;
                diagnostic.code = decompiler_diagnostic_code_t::resource_limit;
                diagnostic.localization_key = "decompiler.native_host.result_allocation";
                diagnostic.ordinal = static_cast<std::uint32_t>(result.diagnostics.size() + 1U);
                result.diagnostics.push_back(std::move(diagnostic));
            } catch (...) {
                result.status = decompiler_provider_execution_status_t::failed;
                result.artifacts.reset();
                result.attested_document.reset();
                result.authenticated_artifacts = false;
                decompiler_diagnostic_t diagnostic;
                diagnostic.severity = decompiler_diagnostic_severity_t::error;
                diagnostic.code = decompiler_diagnostic_code_t::malformed_serialization;
                diagnostic.localization_key = "decompiler.native_host.result_invalid";
                diagnostic.ordinal = static_cast<std::uint32_t>(result.diagnostics.size() + 1U);
                result.diagnostics.push_back(std::move(diagnostic));
            }
        } else {
            result.status = decompiler_provider_execution_status_t::failed;
            result.artifacts.reset();
        }
        break;
    case native_worker_execution_status_t::cancelled:
        result.status = decompiler_provider_execution_status_t::cancelled;
        result.artifacts.reset();
        break;
    case native_worker_execution_status_t::deadline_exceeded:
        result.status = decompiler_provider_execution_status_t::timed_out;
        result.artifacts.reset();
        break;
    case native_worker_execution_status_t::failed:
        result.status = std::any_of(worker_result.diagnostics.begin(), worker_result.diagnostics.end(),
            [](const native_worker_diagnostic_t& diagnostic) {
                return diagnostic.code == native_worker_diagnostic_code_t::worker_crashed;
            })
            ? decompiler_provider_execution_status_t::crashed
            : decompiler_provider_execution_status_t::failed;
        result.artifacts.reset();
        break;
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    result.elapsed_wall_clock_ms = static_cast<std::uint64_t>((std::max<std::int64_t>)(elapsed, 0));
    return result;
}

bool native_worker_provider_host_t::supports(
    const decompiler_provider_descriptor_t& descriptor) const noexcept
{
    if (!descriptor.isolated)
        return false;
    switch (descriptor.identity.provider) {
    case decompiler_provider_id_t::ghidra_native:
        return host_ && descriptor.entity_kind == decompiler_entity_kind_t::native_function;
    case decompiler_provider_id_t::jvm_ssa:
        return host_ && descriptor.entity_kind == decompiler_entity_kind_t::jvm_method;
    case decompiler_provider_id_t::dalvik_ssa:
        return host_ && descriptor.entity_kind == decompiler_entity_kind_t::dalvik_method;
    case decompiler_provider_id_t::ilspy_cli:
        return managed_host_ && descriptor.entity_kind == decompiler_entity_kind_t::cli_method;
    }
    return false;
}

decompiler_provider_result_t native_worker_provider_host_t::execute(
    const decompiler_provider_route_t& route,
    const decompiler_provider_request_t& request,
    const cancellation_token_t& cancel)
{
    const auto started = std::chrono::steady_clock::now();
    decompiler_provider_result_t result;
    if (!supports(route.descriptor) || !route.provider) {
        decompiler_diagnostic_t diagnostic;
        diagnostic.severity = decompiler_diagnostic_severity_t::error;
        diagnostic.code = decompiler_diagnostic_code_t::worker_protocol_failure;
        diagnostic.localization_key = "decompiler.native_host.route_rejected";
        diagnostic.ordinal = 1;
        result.diagnostics.push_back(std::move(diagnostic));
        return result;
    }
    if (cancel.stop_requested() || started >= request.deadline) {
        const bool timed_out = cancel.deadline_exceeded() || started >= request.deadline;
        result.status = timed_out ? decompiler_provider_execution_status_t::timed_out
                                  : decompiler_provider_execution_status_t::cancelled;
        decompiler_diagnostic_t diagnostic;
        diagnostic.severity = decompiler_diagnostic_severity_t::error;
        diagnostic.code = timed_out ? decompiler_diagnostic_code_t::deadline_exceeded
                                    : decompiler_diagnostic_code_t::cancelled;
        diagnostic.localization_key = timed_out
            ? "decompiler.native_host.deadline" : "decompiler.native_host.cancelled";
        diagnostic.ordinal = 1;
        result.diagnostics.push_back(std::move(diagnostic));
        return result;
    }

    if (request.cache_key.stage != decompiler_cache_stage_t::provider_ir ||
        !validate_decompiler_pipeline_cache_key(request.cache_key).valid() ||
        !same_provider(request.cache_key.provider, route.descriptor.identity)) {
        decompiler_diagnostic_t diagnostic;
        diagnostic.severity = decompiler_diagnostic_severity_t::error;
        diagnostic.code = decompiler_diagnostic_code_t::invalid_contract;
        diagnostic.localization_key = "decompiler.isolated_host.request_rejected";
        diagnostic.ordinal = 1;
        result.diagnostics.push_back(std::move(diagnostic));
        return result;
    }

    std::optional<native_worker_snapshot_t> snapshot;
    std::shared_ptr<const managed_cli::request_t> bound_managed_request;
    try {
        std::vector<std::uint8_t> bytes;
        switch (route.descriptor.identity.provider) {
        case decompiler_provider_id_t::ghidra_native: {
            const auto context = std::dynamic_pointer_cast<const ghidra_native_provider_context_t>(request.context);
            if (!context || !context->snapshot() || context->snapshot()->empty() ||
                context->snapshot_hash().empty())
                break;
            bytes.assign(context->snapshot()->begin(), context->snapshot()->end());
            snapshot = make_native_worker_snapshot(std::move(bytes));
            if (snapshot && snapshot->hash != context->snapshot_hash())
                snapshot.reset();
            break;
        }
        case decompiler_provider_id_t::jvm_ssa: {
            const auto context = std::dynamic_pointer_cast<const jvm_ssa_provider_context_t>(request.context);
            if (!context || !context->input() || context->input()->entity != request.cache_key.entity ||
                !same_provider(context->input()->provider, route.descriptor.identity) ||
                !same_language(context->input()->language, request.cache_key.language) ||
                context->input()->workspace_generation != request.cache_key.workspace_generation ||
                context->input()->type_graph_revision != request.cache_key.type_graph_revision)
                break;
            const auto serialized = jvm_ssa::serialize_jvm_method_input(*context->input());
            bytes.assign(serialized.begin(), serialized.end());
            snapshot = make_native_worker_snapshot(std::move(bytes));
            break;
        }
        case decompiler_provider_id_t::dalvik_ssa: {
            const auto context = std::dynamic_pointer_cast<const dalvik_ssa_provider_context_t>(request.context);
            if (!context || !context->capture() ||
                context->capture()->request.entity != request.cache_key.entity ||
                !same_provider(context->capture()->request.provider, route.descriptor.identity) ||
                !same_language(context->capture()->request.language, request.cache_key.language) ||
                context->capture()->request.workspace_generation != request.cache_key.workspace_generation ||
                context->capture()->request.type_graph_revision != request.cache_key.type_graph_revision)
                break;
            const auto serialized = dalvik_ssa::serialize_capture(*context->capture());
            bytes.assign(serialized.begin(), serialized.end());
            snapshot = make_native_worker_snapshot(std::move(bytes));
            break;
        }
        case decompiler_provider_id_t::ilspy_cli:
        {
            const auto context = std::dynamic_pointer_cast<const managed_cli_provider_context_t>(request.context);
            if (!context || !context->request() ||
                context->request()->entity != request.cache_key.entity ||
                context->request()->workspace_generation != request.cache_key.workspace_generation ||
                context->request()->type_graph_revision != request.cache_key.type_graph_revision ||
                !same_profile(context->request()->profile,
                    request.cache_key.profile) ||
                context->request()->worker.provider_version != route.descriptor.identity.provider_version ||
                context->request()->worker.decompiler_assembly_hash !=
                    route.descriptor.identity.provider_binary_hash ||
                context->request()->worker.worker_build_id != route.descriptor.identity.worker_build_id ||
                context->request()->worker.worker_build_hash != route.descriptor.identity.worker_build_hash)
                break;
            const auto maximum_module_bytes = static_cast<std::size_t>((std::min<std::uint64_t>)(
                managed_cli::k_managed_cli_maximum_module_bytes,
                request.cache_key.profile.max_memory_bytes / 2));
            const auto captured = capture_managed_worker_snapshot(
                context->request(), maximum_module_bytes, cancel);
            if (!captured)
                break;
            if (captured.value().request->entity != request.cache_key.entity ||
                captured.value().request->workspace_generation !=
                    request.cache_key.workspace_generation ||
                captured.value().request->type_graph_revision !=
                    request.cache_key.type_graph_revision ||
                !same_profile(captured.value().request->profile,
                    request.cache_key.profile)) {
                break;
            }
            snapshot = captured.value().snapshot;
            bound_managed_request = captured.value().request;
            break;
        }
        }
    } catch (...) {
        snapshot.reset();
    }
    if (!snapshot) {
        decompiler_diagnostic_t diagnostic;
        diagnostic.severity = decompiler_diagnostic_severity_t::error;
        diagnostic.code = decompiler_diagnostic_code_t::invalid_contract;
        diagnostic.localization_key = "decompiler.isolated_host.input_snapshot_rejected";
        diagnostic.ordinal = 1;
        result.diagnostics.push_back(std::move(diagnostic));
        return result;
    }

    auto job_id = next_job_id_.fetch_add(1, std::memory_order_acq_rel);
    if (job_id == 0)
        job_id = next_job_id_.fetch_add(1, std::memory_order_acq_rel);
    native_worker_execution_request_t worker_request;
    worker_request.job_id = job_id;
    worker_request.cache_key = request.cache_key;
    worker_request.profile = request.cache_key.profile;
    worker_request.snapshot = std::move(*snapshot);
    worker_request.deadline = request.deadline;
    worker_request.cancellation_requested = [cancel] {
        return cancel.stop_requested();
    };
    if (route.descriptor.identity.provider == decompiler_provider_id_t::ilspy_cli) {
        worker_request.managed_request = std::move(bound_managed_request);
    }
    auto worker_result = route.descriptor.identity.provider == decompiler_provider_id_t::ilspy_cli
        ? managed_host_->execute(worker_request)
        : host_->execute(worker_request);
    return map_worker_result_to_provider_result(route, request, cancel, worker_request, worker_result, started);
}

struct native_worker_host_t::session_state_t {
    worker_instance_t worker;
    sha256_digest_t snapshot_hash;
    std::uint64_t worker_generation = 0;
    std::uint32_t jobs_completed = 0;
    std::uint32_t max_jobs_per_session = 0;
    std::uint64_t cpu_backstop_ms = 0;
    std::uint64_t cpu_base_ms = 0;
    std::uint64_t memory_envelope_bytes = 0;
    std::chrono::steady_clock::time_point launched_steady;
    std::shared_ptr<std::atomic<bool>> preempt;
    bool healthy = true;
    bool slot_released = false;
};

namespace {

std::uint64_t session_cpu_backstop_for(std::uint32_t max_jobs_per_session, std::uint64_t max_cpu_ms) noexcept
{
    const std::uint64_t jobs = max_jobs_per_session != 0 ? max_jobs_per_session : 1;
    const std::uint64_t clamped_cpu = (std::min)(max_cpu_ms, k_decompiler_profile_max_cpu_ms);
    if (clamped_cpu > (std::numeric_limits<std::uint64_t>::max)() / jobs)
        return (std::numeric_limits<std::uint64_t>::max)();
    return jobs * clamped_cpu;
}

}

void native_worker_host_t::session_terminate(session_state_t& session, DWORD exit_code,
    native_worker_execution_result_t* result, bool replacement) noexcept
{
    native_worker_execution_result_t discarded;
    native_worker_execution_result_t& target = result ? *result : discarded;
    try {
        terminate_worker(session.worker, exit_code, target, replacement);
    } catch (...) {
    }
    if (!session.slot_released) {
        session.slot_released = true;
        std::lock_guard lock(state_mutex_);
        if (active_workers_ != 0)
            --active_workers_;
        state_wake_.notify_all();
    }
}

bool native_worker_host_t::session_launch(const native_worker_execution_request_t& input,
    std::uint32_t max_jobs_per_session, std::uint64_t session_envelope_max_memory_bytes,
    session_state_t& session, native_worker_execution_result_t& result)
{
    if (stopped_.load(std::memory_order_acquire)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::host_stopped, "native_worker.execute", "worker host is stopped");
        return false;
    }
    if (limits_.max_frame_bytes == 0 ||
        limits_.max_frame_bytes > k_decompiler_worker_result_frame_max_bytes ||
        limits_.max_snapshot_bytes == 0 ||
        limits_.max_concurrent_workers == 0 || limits_.startup_timeout.count() <= 0 ||
        limits_.cancellation_grace.count() < 0 || limits_.poll_interval.count() <= 0 || input.job_id == 0 ||
        max_jobs_per_session == 0 ||
        session_envelope_max_memory_bytes == 0 ||
        session_envelope_max_memory_bytes > k_decompiler_profile_max_memory_bytes ||
        session_envelope_max_memory_bytes < input.profile.max_memory_bytes ||
        !input.snapshot.valid() || input.snapshot.bytes->size() > limits_.max_snapshot_bytes ||
        input.snapshot.bytes->size() > session_envelope_max_memory_bytes) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request, "native_worker.request", "worker request or host limits are invalid");
        return false;
    }
    const auto queue_deadline = effective_deadline(input);
    {
        std::unique_lock lock(state_mutex_);
        while (!stopped_.load(std::memory_order_acquire) &&
               active_workers_ >= limits_.max_concurrent_workers) {
            if ((input.cancellation_requested && input.cancellation_requested()) ||
                std::chrono::steady_clock::now() >= queue_deadline) {
                result.status = std::chrono::steady_clock::now() >= queue_deadline
                    ? native_worker_execution_status_t::deadline_exceeded
                    : native_worker_execution_status_t::cancelled;
                append_diagnostic(result,
                    result.status == native_worker_execution_status_t::deadline_exceeded
                        ? native_worker_diagnostic_code_t::deadline_exceeded
                        : native_worker_diagnostic_code_t::cancelled,
                    "native_worker.queue", "worker admission was cancelled before launch");
                return false;
            }
            const auto poll_deadline = (std::min)(
                queue_deadline,
                std::chrono::steady_clock::now() + limits_.poll_interval);
            state_wake_.wait_until(lock, poll_deadline);
        }
        if (stopped_.load(std::memory_order_acquire)) {
            append_diagnostic(result, native_worker_diagnostic_code_t::host_stopped,
                "native_worker.queue", "worker host stopped before admission");
            return false;
        }
        ++active_workers_;
    }
    bool slot_held = true;
    const auto release_slot = [this, &slot_held] {
        if (!slot_held)
            return;
        slot_held = false;
        std::lock_guard lock(state_mutex_);
        if (active_workers_ != 0)
            --active_workers_;
        state_wake_.notify_all();
    };
    native_worker_execution_request_t request = input;
    const auto external_cancel = input.cancellation_requested;
    request.cancellation_requested = [this, external_cancel] {
        return stopped_.load(std::memory_order_acquire) ||
               (external_cancel && external_cancel());
    };
    sha256_digest_t verified_snapshot_hash;
    if (!wire::sha256(request.snapshot.bytes->data(), request.snapshot.bytes->size(), verified_snapshot_hash) || verified_snapshot_hash != request.snapshot.hash) {
        append_diagnostic(result, native_worker_diagnostic_code_t::snapshot_invalid, "native_worker.snapshot", "snapshot hash is invalid", ERROR_CRC);
        release_slot();
        return false;
    }
    result.snapshot_hash = verified_snapshot_hash;
    const auto cache_validation = validate_decompiler_pipeline_cache_key(request.cache_key);
    const auto profile_validation = validate_decompiler_profile(request.profile);
    if (!cache_validation.valid() || !profile_validation.valid() ||
        request.cache_key.worker_protocol_hash != native_worker_protocol_hash() ||
        request.cache_key.profile.profile != request.profile.profile ||
        request.cache_key.profile.max_wall_clock_ms != request.profile.max_wall_clock_ms ||
        request.cache_key.profile.max_cpu_ms != request.profile.max_cpu_ms ||
        request.cache_key.profile.max_memory_bytes != request.profile.max_memory_bytes ||
        request.cache_key.profile.max_provider_ir_nodes != request.profile.max_provider_ir_nodes ||
        request.cache_key.profile.max_hir_nodes != request.profile.max_hir_nodes ||
        request.cache_key.profile.max_ast_nodes != request.profile.max_ast_nodes ||
        request.cache_key.profile.max_semantic_queries != request.profile.max_semantic_queries ||
        request.cache_key.profile.semantic_proofs_enabled != request.profile.semantic_proofs_enabled) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request, "native_worker.contract", "cache key and profile do not form a valid bound request", ERROR_INVALID_DATA);
        release_slot();
        return false;
    }
    if (request.cache_key.provider.provider != decompiler_provider_id_t::ghidra_native ||
        request.managed_request) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request,
            "native_worker.session_route",
            "session launch is restricted to the native Ghidra provider", ERROR_INVALID_DATA);
        release_slot();
        return false;
    }
    const auto verified = verified_package_;
    if (!verified) {
        result.diagnostics = verification_diagnostics_;
        release_slot();
        return false;
    }
    result.manifest_hash = verified->manifest_hash;
    if (!compatible_worker_provider(request.cache_key.provider, verified->manifest.provider)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_identity_mismatch,
            "native_worker.request_identity",
            "cache provider identity does not match the verified worker manifest",
            ERROR_CRC, true);
        release_slot();
        return false;
    }
    session.worker_generation = worker_generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
    result.worker_generation = session.worker_generation;
    const std::uint64_t backstop = session_cpu_backstop_for(max_jobs_per_session, k_decompiler_profile_max_cpu_ms);
    if (!launch_worker(*verified, request, limits_, session.worker, result, backstop,
            session_envelope_max_memory_bytes)) {
        result.worker_process_id = session.worker.process_id;
        if (session.worker.process)
            terminate_worker(session.worker, ERROR_ACCESS_DENIED, result, true);
        release_slot();
        return false;
    }
    result.worker_process_id = session.worker.process_id;
    const auto startup_timeout_deadline = std::chrono::steady_clock::now() + limits_.startup_timeout;
    const auto startup_deadline = (std::min)(startup_timeout_deadline, queue_deadline);
    wire::frame_t frame;
    DWORD error = ERROR_SUCCESS;
    const auto hello_wait = wait_for_message(session.worker, request, limits_, startup_deadline, frame, error);
    if (hello_wait != terminal_wait_t::message) {
        DWORD termination_code = ERROR_CANCELLED;
        if (hello_wait == terminal_wait_t::cancelled) {
            result.status = native_worker_execution_status_t::cancelled;
            append_diagnostic(result, native_worker_diagnostic_code_t::cancelled,
                "native_worker.hello", "worker startup was cancelled before an authenticated hello",
                ERROR_CANCELLED, true);
        } else if (hello_wait == terminal_wait_t::deadline) {
            result.status = native_worker_execution_status_t::deadline_exceeded;
            termination_code = WAIT_TIMEOUT;
            append_diagnostic(result, native_worker_diagnostic_code_t::deadline_exceeded, "native_worker.hello",
                queue_deadline <= startup_timeout_deadline
                    ? "request deadline expired before an authenticated worker hello"
                    : "worker did not provide an authenticated hello before the startup deadline",
                WAIT_TIMEOUT, true);
        } else if (hello_wait == terminal_wait_t::exited) {
            append_worker_exit(result, session.worker, "native_worker.hello",
                "worker exited before providing an authenticated hello");
        } else {
            append_protocol_failure(result, session.worker.reader.failure(), "native_worker.hello", error,
                &session.worker.wait_observation);
        }
        terminate_worker(session.worker, termination_code, result, true);
        release_slot();
        return false;
    }
    const auto decoded_hello = deserialize_decompiler_worker_message(
        std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()));
    if (!decoded_hello.valid() || !decoded_hello.value || !validate_envelope(*decoded_hello.value, frame, session.worker.session) ||
        !std::holds_alternative<decompiler_worker_hello_t>(*decoded_hello.value)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.hello", "worker hello violates the authenticated protocol", ERROR_INVALID_DATA, true);
        terminate_worker(session.worker, ERROR_CRC, result, true);
        release_slot();
        return false;
    }
    const auto& hello = std::get<decompiler_worker_hello_t>(*decoded_hello.value);
    if (hello.manifest_hash != verified->manifest_hash ||
        !same_provider(hello.provider, request.cache_key.provider) ||
        !compatible_worker_provider(hello.provider, verified->manifest.provider)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_identity_mismatch, "native_worker.hello_identity", "worker identity does not match verified manifest", ERROR_CRC, true);
        terminate_worker(session.worker, ERROR_CRC, result, true);
        release_slot();
        return false;
    }
    session.snapshot_hash = verified_snapshot_hash;
    session.jobs_completed = 0;
    session.max_jobs_per_session = max_jobs_per_session;
    session.cpu_backstop_ms = backstop;
    session.cpu_base_ms = request.profile.max_cpu_ms;
    session.memory_envelope_bytes = session_envelope_max_memory_bytes;
    session.launched_steady = std::chrono::steady_clock::now();
    session.preempt.reset();
    session.healthy = true;
    session.slot_released = false;
    slot_held = false;
    diag::log_tagged_fmt("dec_batch",
        "pool_spawn worker_gen=%llu pid=%lu jobs_bound=%u cpu_backstop_ms=%llu snapshot_shared=%d snapshot_bytes=%llu",
        static_cast<unsigned long long>(session.worker_generation),
        static_cast<unsigned long>(session.worker.process_id),
        static_cast<unsigned int>(max_jobs_per_session),
        static_cast<unsigned long long>(backstop),
        request.snapshot.shared_mapping_handle != nullptr ? 1 : 0,
        static_cast<unsigned long long>(request.snapshot.bytes->size()));
    return true;
}

native_worker_execution_result_t native_worker_host_t::execute_on_session(
    session_state_t& session, const native_worker_execution_request_t& input)
{
    native_worker_execution_result_t result;
    result.worker_generation = session.worker_generation;
    result.worker_process_id = session.worker.process_id;
    result.snapshot_hash = session.snapshot_hash;
    const auto verified = verified_package_;
    if (verified)
        result.manifest_hash = verified->manifest_hash;
    if (stopped_.load(std::memory_order_acquire)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::host_stopped, "native_worker.execute", "worker host is stopped");
        session.healthy = false;
        return result;
    }
    if (!session.healthy || !session.worker.process || input.job_id == 0 ||
        input.snapshot.hash.empty() || input.snapshot.hash != session.snapshot_hash) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request,
            "native_worker.session_request", "session is not reusable for the requested job", ERROR_INVALID_DATA);
        session.healthy = false;
        session_terminate(session, ERROR_INVALID_DATA, &result, true);
        return result;
    }
    const auto cache_validation = validate_decompiler_pipeline_cache_key(input.cache_key);
    const auto profile_validation = validate_decompiler_profile(input.profile);
    if (!cache_validation.valid() || !profile_validation.valid() ||
        input.cache_key.worker_protocol_hash != native_worker_protocol_hash() ||
        input.cache_key.profile.profile != input.profile.profile ||
        input.cache_key.profile.max_wall_clock_ms != input.profile.max_wall_clock_ms ||
        input.cache_key.profile.max_cpu_ms != input.profile.max_cpu_ms ||
        input.cache_key.profile.max_memory_bytes != input.profile.max_memory_bytes ||
        input.cache_key.profile.max_provider_ir_nodes != input.profile.max_provider_ir_nodes ||
        input.cache_key.profile.max_hir_nodes != input.profile.max_hir_nodes ||
        input.cache_key.profile.max_ast_nodes != input.profile.max_ast_nodes ||
        input.cache_key.profile.max_semantic_queries != input.profile.max_semantic_queries ||
        input.cache_key.profile.semantic_proofs_enabled != input.profile.semantic_proofs_enabled) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request, "native_worker.contract", "cache key and profile do not form a valid bound request", ERROR_INVALID_DATA);
        session.healthy = false;
        session_terminate(session, ERROR_INVALID_DATA, &result, true);
        return result;
    }
    if (!verified ||
        input.cache_key.provider.provider != decompiler_provider_id_t::ghidra_native ||
        !compatible_worker_provider(input.cache_key.provider, verified->manifest.provider)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::worker_identity_mismatch,
            "native_worker.request_identity",
            "cache provider identity does not match the verified worker manifest",
            ERROR_CRC, true);
        session.healthy = false;
        session_terminate(session, ERROR_CRC, &result, true);
        return result;
    }
    if (input.profile.max_cpu_ms > session.cpu_base_ms) {
        const std::uint64_t backstop = session_cpu_backstop_for(session.max_jobs_per_session, input.profile.max_cpu_ms);
        if (backstop > session.cpu_backstop_ms) {
            DWORD error = ERROR_SUCCESS;
            if (!configure_job(session.worker.job.get(), input.profile, error, backstop,
                    session.memory_envelope_bytes)) {
                append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected,
                    "native_worker.session_job", "session CPU backstop could not be raised", error, true);
                session.healthy = false;
                session_terminate(session, ERROR_INVALID_DATA, &result, true);
                return result;
            }
            session.cpu_backstop_ms = backstop;
        }
        session.cpu_base_ms = input.profile.max_cpu_ms;
    }
    native_worker_execution_request_t request = input;
    const auto external_cancel = input.cancellation_requested;
    const auto preempt = session.preempt;
    request.cancellation_requested = [this, external_cancel, preempt] {
        return stopped_.load(std::memory_order_acquire) ||
               (preempt && preempt->load(std::memory_order_acquire)) ||
               (external_cancel && external_cancel());
    };
    decompiler_worker_job_request_t job;
    job.envelope.kind = decompiler_worker_message_kind_t::job_request;
    job.envelope.session_nonce_hash = session.worker.session.nonce_hash;
    job.envelope.sequence = session.worker.next_host_sequence;
    job.job_id = request.job_id;
    job.cache_key = request.cache_key;
    job.profile = request.profile;
    job.snapshot_hash = session.snapshot_hash;
    job.request_printc_evidence = request.request_printc_evidence;
    DWORD error = ERROR_SUCCESS;
    if (!send_contract(session.worker, decompiler_worker_message_t{std::move(job)}, limits_, error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::bootstrap_failed, "native_worker.job", "job request could not be written", error, true);
        session.healthy = false;
        session_terminate(session, ERROR_CANCELLED, &result, true);
        return result;
    }
    const auto deadline = effective_deadline(request);
    wire::frame_t frame;
    while (true) {
        const auto terminal = wait_for_message(session.worker, request, limits_, deadline, frame, error);
        if (terminal == terminal_wait_t::cancelled || terminal == terminal_wait_t::deadline) {
            const bool is_deadline = terminal == terminal_wait_t::deadline;
            send_cancel(session.worker, request, limits_, is_deadline ? "deadline_exceeded" : "cancelled");
            auto saved_cancel = request.cancellation_requested;
            request.cancellation_requested = [] { return false; };
            const auto grace_deadline = std::chrono::steady_clock::now() + limits_.cancellation_grace;
            while (std::chrono::steady_clock::now() < grace_deadline) {
                const auto grace_terminal = wait_for_message(session.worker, request, limits_, grace_deadline, frame, error);
                if (grace_terminal == terminal_wait_t::message) {
                    const auto decoded = deserialize_decompiler_worker_message(
                        std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()));
                    if (decoded.valid() && decoded.value && validate_envelope(*decoded.value, frame, session.worker.session)) {
                        if (std::holds_alternative<decompiler_worker_failure_message_t>(*decoded.value)) {
                            const auto& failure = std::get<decompiler_worker_failure_message_t>(*decoded.value);
                            if (failure.job_id == request.job_id)
                                append_worker_failure(result, failure);
                        }
                    }
                    break;
                }
                if (grace_terminal == terminal_wait_t::exited ||
                    grace_terminal == terminal_wait_t::deadline ||
                    grace_terminal == terminal_wait_t::protocol_failure)
                    break;
            }
            request.cancellation_requested = saved_cancel;
            result.status = is_deadline ? native_worker_execution_status_t::deadline_exceeded : native_worker_execution_status_t::cancelled;
            append_diagnostic(result, is_deadline ? native_worker_diagnostic_code_t::deadline_exceeded : native_worker_diagnostic_code_t::cancelled,
                "native_worker.cancel", is_deadline ? "worker exceeded its deadline" : "worker cancellation was requested", ERROR_CANCELLED, true);
            session.healthy = false;
            session_terminate(session, ERROR_CANCELLED, &result, true);
            return result;
        }
        if (terminal == terminal_wait_t::exited) {
            append_worker_exit(result, session.worker, "native_worker.wait",
                "worker exited before a terminal result");
            const DWORD exit_code = session.worker.wait_observation.exit_code_available
                ? session.worker.wait_observation.exit_code : ERROR_PROCESS_ABORTED;
            session.healthy = false;
            session_terminate(session, exit_code, &result, true);
            return result;
        }
        if (terminal == terminal_wait_t::protocol_failure) {
            append_protocol_failure(result, session.worker.reader.failure(), "native_worker.response", error,
                &session.worker.wait_observation);
            session.healthy = false;
            session_terminate(session, ERROR_CRC, &result, true);
            return result;
        }
        const auto decoded = deserialize_decompiler_worker_message(
            std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()));
        if (!decoded.valid() || !decoded.value || !validate_envelope(*decoded.value, frame, session.worker.session)) {
            append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.response", "worker response cannot be decoded or validated", ERROR_INVALID_DATA, true);
            session.healthy = false;
            session_terminate(session, ERROR_CRC, &result, true);
            return result;
        }
        if (std::holds_alternative<decompiler_worker_heartbeat_t>(*decoded.value)) {
            const auto& heartbeat = std::get<decompiler_worker_heartbeat_t>(*decoded.value);
            if (heartbeat.active_job_id != request.job_id) {
                append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.heartbeat", "heartbeat job identity does not match active job", ERROR_INVALID_DATA, true);
                session.healthy = false;
                session_terminate(session, ERROR_CRC, &result, true);
                return result;
            }
            continue;
        }
        if (std::holds_alternative<decompiler_worker_failure_message_t>(*decoded.value)) {
            const auto& failure = std::get<decompiler_worker_failure_message_t>(*decoded.value);
            if (failure.job_id != request.job_id) {
                append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.failure", "failure job identity does not match active job", ERROR_INVALID_DATA, true);
                session.healthy = false;
                session_terminate(session, ERROR_CRC, &result, true);
                return result;
            }
            append_worker_failure(result, failure);
            std::string detail = "worker returned typed failure diagnostics";
            if (!failure.diagnostics.empty())
                append_worker_diagnostic_detail(detail, failure.diagnostics.front());
            append_diagnostic(result, native_worker_diagnostic_code_t::worker_failed,
                "native_worker.failure", std::move(detail), ERROR_SUCCESS, false);
            result.status = native_worker_execution_status_t::failed;
            ++session.jobs_completed;
            const bool replacement = std::any_of(failure.diagnostics.begin(), failure.diagnostics.end(),
                [](const decompiler_diagnostic_t& current) { return current.retryable; });
            if (replacement) {
                session.healthy = false;
                session_terminate(session, ERROR_RETRY, &result, true);
            }
            return result;
        }
        if (std::holds_alternative<decompiler_worker_document_message_t>(*decoded.value)) {
            const auto& document = std::get<decompiler_worker_document_message_t>(*decoded.value);
            const auto document_validation = validate_decompiler_document(document.document);
            if (document.job_id != request.job_id || !document_validation.valid() || !(document.document.entity == request.cache_key.entity) ||
                document.document.profile != request.profile.profile ||
                document.provider_artifacts.empty() || document.provider_artifacts_hash.empty() ||
                document.provider_artifacts.size() > k_decompiler_worker_provider_artifacts_max_bytes ||
                stable_serialization_hash(document.provider_artifacts) != document.provider_artifacts_hash ||
                document.printc_evidence.has_value() != request.request_printc_evidence ||
                (document.printc_evidence &&
                    (document.printc_evidence->empty() ||
                     document.printc_evidence->size() > k_decompiler_worker_printc_evidence_max_bytes ||
                     document.printc_evidence_hash.empty() ||
                     stable_serialization_hash(*document.printc_evidence) != document.printc_evidence_hash))) {
                append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.document", "worker document is not bound to the requested entity and profile", ERROR_INVALID_DATA, true);
                session.healthy = false;
                session_terminate(session, ERROR_CRC, &result, true);
                return result;
            }
            result.document = document.document;
            result.provider_artifacts = document.provider_artifacts;
            result.provider_artifacts_hash = document.provider_artifacts_hash;
            result.printc_evidence = document.printc_evidence;
            result.printc_evidence_hash = document.printc_evidence_hash;
            result.status = native_worker_execution_status_t::completed;
            ++session.jobs_completed;
            return result;
        }
        append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.response", "worker sent a message that is invalid in the active job state", ERROR_INVALID_DATA, true);
        session.healthy = false;
        session_terminate(session, ERROR_CRC, &result, true);
        return result;
    }
}

std::shared_ptr<native_worker_host_t> native_worker_host_t::for_session_pool(std::size_t max_concurrent_workers) const
{
    if (!verified_package_ || max_concurrent_workers == 0)
        return {};
    native_worker_host_limits_t limits = limits_;
    limits.max_concurrent_workers = max_concurrent_workers;
    return std::shared_ptr<native_worker_host_t>(
        new native_worker_host_t(contract_, limits, verified_package_));
}

namespace {

struct worker_pool_key_t {
    std::string workspace_id;
    std::uint64_t generation = 0;
    sha256_digest_t snapshot_hash;
};

int digest_order(const sha256_digest_t& left, const sha256_digest_t& right) noexcept
{
    return std::memcmp(left.bytes.data(), right.bytes.data(), left.bytes.size());
}

bool operator<(const worker_pool_key_t& left, const worker_pool_key_t& right) noexcept
{
    if (left.workspace_id != right.workspace_id)
        return left.workspace_id < right.workspace_id;
    if (left.generation != right.generation)
        return left.generation < right.generation;
    return digest_order(left.snapshot_hash, right.snapshot_hash) < 0;
}

bool operator==(const worker_pool_key_t& left, const worker_pool_key_t& right) noexcept
{
    return left.workspace_id == right.workspace_id &&
        left.generation == right.generation &&
        digest_order(left.snapshot_hash, right.snapshot_hash) == 0;
}

worker_pool_key_t make_worker_pool_key(const decompiler_provider_request_t& request,
                                       const sha256_digest_t& snapshot_hash)
{
    worker_pool_key_t key;
    key.workspace_id = request.cache_key.workspace_id;
    key.generation = request.cache_key.workspace_generation;
    key.snapshot_hash = snapshot_hash;
    return key;
}

std::mutex g_native_worker_private_mutex;
std::uint64_t g_native_worker_private_ema = 0;
std::uint64_t g_native_worker_private_samples = 0;

void sample_native_worker_private_bytes(HANDLE process) noexcept
{
    if (process == nullptr)
        return;
    PROCESS_MEMORY_COUNTERS_EX counters{};
    if (!K32GetProcessMemoryInfo(process,
            reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&counters), sizeof(counters)))
        return;
    const std::uint64_t sample = static_cast<std::uint64_t>(counters.PagefileUsage);
    std::lock_guard lock(g_native_worker_private_mutex);
    if (g_native_worker_private_samples == 0 || g_native_worker_private_ema == 0) {
        g_native_worker_private_ema = sample;
    } else {
        const double folded = static_cast<double>(g_native_worker_private_ema) +
            (static_cast<double>(sample) - static_cast<double>(g_native_worker_private_ema)) / 8.0;
        g_native_worker_private_ema = folded <= 0.0 ? sample
            : static_cast<std::uint64_t>(folded);
    }
    ++g_native_worker_private_samples;
}

struct worker_session_record_t {
    std::unique_ptr<native_worker_host_t::session_state_t> session;
    worker_pool_key_t key;
    std::uint64_t ordinal = 0;
    bool busy = false;
    bool interactive = false;
    bool borrowed = false;
    bool preempted = false;
    std::shared_ptr<std::atomic<bool>> preempt;
};

decompiler_diagnostic_t pool_failure_diagnostic(decompiler_diagnostic_code_t code, std::string key)
{
    decompiler_diagnostic_t diagnostic;
    diagnostic.severity = decompiler_diagnostic_severity_t::error;
    diagnostic.code = code;
    diagnostic.localization_key = std::move(key);
    diagnostic.ordinal = 1;
    return diagnostic;
}

}

struct pooled_native_worker_provider_host_t::state_t {
    std::shared_ptr<decompiler_isolated_provider_host_t> fallback;
    std::shared_ptr<native_worker_host_t> host;
    native_worker_session_pool_config_t config;
    std::uint64_t session_envelope_max_memory_bytes = 0;
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::map<worker_pool_key_t, std::deque<std::shared_ptr<worker_session_record_t>>> idle;
    std::unordered_set<std::shared_ptr<worker_session_record_t>> busy;
    std::size_t total_sessions = 0;
    std::size_t batch_busy = 0;
    std::size_t interactive_busy = 0;
    std::uint64_t next_ordinal = 0;
    std::atomic<bool> stopped{false};
    std::atomic<std::uint64_t> next_job_id{1};

    bool session_alive(const std::shared_ptr<worker_session_record_t>& record) const noexcept
    {
        if (!record || !record->session || !record->session->healthy || !record->session->worker.process)
            return false;
        return WaitForSingleObject(record->session->worker.process.get(), 0) == WAIT_TIMEOUT;
    }

    bool recycle_due(const std::shared_ptr<worker_session_record_t>& record) const noexcept
    {
        if (!record || !record->session)
            return true;
        if (config.max_jobs_per_session != 0 &&
            record->session->jobs_completed >= config.max_jobs_per_session)
            return true;
        return config.max_session_lifetime.count() > 0 &&
            std::chrono::steady_clock::now() - record->session->launched_steady >= config.max_session_lifetime;
    }

    void retire_locked(const std::shared_ptr<worker_session_record_t>& record, const char* reason)
    {
        if (!record)
            return;
        if (record->session) {
            host->session_terminate(*record->session, ERROR_SUCCESS, nullptr, false);
            diag::log_tagged_fmt("dec_batch",
                "pool_recycle reason=%s worker_gen=%llu jobs_done=%u",
                reason ? reason : "retire",
                static_cast<unsigned long long>(record->session->worker_generation),
                static_cast<unsigned int>(record->session->jobs_completed));
        }
        if (total_sessions != 0)
            --total_sessions;
    }

    struct acquire_outcome_t {
        std::shared_ptr<worker_session_record_t> record;
        std::optional<decompiler_provider_result_t> failure;
    };

    acquire_outcome_t acquire(const worker_pool_key_t& key, bool interactive,
                              const native_worker_execution_request_t& request,
                              const cancellation_token_t& cancel,
                              const decompiler_provider_route_t& route,
                              const decompiler_provider_request_t& provider_request,
                              std::chrono::steady_clock::time_point started)
    {
        acquire_outcome_t outcome;
        const auto preempt_started = std::chrono::steady_clock::now();
        bool preempted_any = false;
        std::unique_lock lock(mutex);
        while (true) {
            if (stopped.load(std::memory_order_acquire)) {
                outcome.failure.emplace();
                outcome.failure->status = decompiler_provider_execution_status_t::failed;
                outcome.failure->diagnostics.push_back(pool_failure_diagnostic(
                    decompiler_diagnostic_code_t::worker_protocol_failure,
                    "decompiler.native_host.pool_stopped"));
                return outcome;
            }
            const auto idle_found = idle.find(key);
            if (idle_found != idle.end()) {
                auto& queue = idle_found->second;
                while (!queue.empty()) {
                    auto record = queue.front();
                    if (!session_alive(record) || recycle_due(record)) {
                        queue.pop_front();
                        retire_locked(record, !record->session || !record->session->healthy
                            ? "unhealthy" : "bounds");
                        continue;
                    }
                    auto preempt = std::make_shared<std::atomic<bool>>(false);
                    queue.pop_front();
                    record->busy = true;
                    record->interactive = interactive;
                    record->preempted = false;
                    try {
                        record->preempt = std::move(preempt);
                        record->session->preempt = record->preempt;
                        busy.insert(record);
                    } catch (...) {
                        record->busy = false;
                        record->preempt.reset();
                        if (record->session)
                            record->session->preempt.reset();
                        retire_locked(record, "reuse_insert_failed");
                        continue;
                    }
                    if (interactive)
                        ++interactive_busy;
                    else
                        ++batch_busy;
                    if (preempted_any) {
                        const auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - preempt_started).count();
                        diag::log_tagged_fmt("dec_batch",
                            "pool_preempt interactive_wait_ms=%lld slot=RECYCLED",
                            static_cast<long long>(wait_ms));
                    }
                    outcome.record = std::move(record);
                    return outcome;
                }
            }
            const std::size_t capacity = config.batch_slots + config.interactive_reserved_slots;
            const bool batch_borrow = !interactive && interactive_busy == 0 &&
                batch_busy >= config.batch_slots;
            const bool may_spawn = total_sessions < capacity &&
                (interactive || batch_busy < config.batch_slots || batch_borrow);
            if (may_spawn) {
                auto session = std::make_unique<native_worker_host_t::session_state_t>();
                ++total_sessions;
                if (interactive)
                    ++interactive_busy;
                else
                    ++batch_busy;
                lock.unlock();
                native_worker_execution_result_t launch_result;
                bool launched = false;
                std::exception_ptr launch_exception;
                try {
                    launched = host->session_launch(request, config.max_jobs_per_session,
                        session_envelope_max_memory_bytes, *session, launch_result);
                } catch (...) {
                    launch_exception = std::current_exception();
                }
                lock.lock();
                if (launch_exception || !launched) {
                    if (total_sessions != 0)
                        --total_sessions;
                    if (interactive)
                        --interactive_busy;
                    else
                        --batch_busy;
                    wake.notify_all();
                    if (launch_exception) {
                        diag::log_tagged_fmt("dec_batch",
                            "pool_launch_exception interactive=%d", interactive ? 1 : 0);
                        outcome.failure.emplace();
                        outcome.failure->status = decompiler_provider_execution_status_t::failed;
                        outcome.failure->diagnostics.push_back(pool_failure_diagnostic(
                            decompiler_diagnostic_code_t::worker_protocol_failure,
                            "decompiler.native_host.pool_launch"));
                        return outcome;
                    }
                    outcome.failure = map_worker_result_to_provider_result(
                        route, provider_request, cancel, request, launch_result, started);
                    return outcome;
                }
                std::shared_ptr<worker_session_record_t> record;
                try {
                    record = std::make_shared<worker_session_record_t>();
                    record->session = std::move(session);
                    record->key = key;
                    record->ordinal = ++next_ordinal;
                    record->busy = true;
                    record->interactive = interactive;
                    record->borrowed = batch_borrow;
                    record->preempt = std::make_shared<std::atomic<bool>>(false);
                    record->session->preempt = record->preempt;
                    busy.insert(record);
                } catch (...) {
                    if (record && record->session)
                        host->session_terminate(*record->session, ERROR_SUCCESS, nullptr, false);
                    else if (session)
                        host->session_terminate(*session, ERROR_SUCCESS, nullptr, false);
                    if (total_sessions != 0)
                        --total_sessions;
                    if (interactive)
                        --interactive_busy;
                    else
                        --batch_busy;
                    wake.notify_all();
                    throw;
                }
                if (preempted_any) {
                    const auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - preempt_started).count();
                    diag::log_tagged_fmt("dec_batch",
                        "pool_preempt interactive_wait_ms=%lld slot=FRESH",
                        static_cast<long long>(wait_ms));
                }
                outcome.record = std::move(record);
                return outcome;
            }
            if (interactive && !preempted_any) {
                std::shared_ptr<worker_session_record_t> victim;
                std::shared_ptr<worker_session_record_t> mismatched_victim;
                for (const auto& candidate : busy) {
                    if (!candidate || candidate->interactive || candidate->preempted)
                        continue;
                    auto& selected = candidate->key == key ? victim : mismatched_victim;
                    if (!selected || (candidate->borrowed && !selected->borrowed) ||
                        (candidate->borrowed == selected->borrowed && candidate->ordinal < selected->ordinal))
                        selected = candidate;
                }
                if (!victim)
                    victim = mismatched_victim;
                if (victim) {
                    victim->preempted = true;
                    if (victim->preempt)
                        victim->preempt->store(true, std::memory_order_release);
                    preempted_any = true;
                    diag::log_tagged_fmt("dec_batch",
                        "pool_preempt_victim ordinal=%llu key_match=%d",
                        static_cast<unsigned long long>(victim->ordinal),
                        victim->key == key ? 1 : 0);
                }
            }
            if (cancel.stop_requested() || std::chrono::steady_clock::now() >= provider_request.deadline) {
                const bool timed_out = cancel.deadline_exceeded() ||
                    std::chrono::steady_clock::now() >= provider_request.deadline;
                outcome.failure.emplace();
                outcome.failure->status = timed_out
                    ? decompiler_provider_execution_status_t::timed_out
                    : decompiler_provider_execution_status_t::cancelled;
                outcome.failure->diagnostics.push_back(pool_failure_diagnostic(
                    timed_out ? decompiler_diagnostic_code_t::deadline_exceeded
                              : decompiler_diagnostic_code_t::cancelled,
                    timed_out ? "decompiler.native_host.pool_deadline"
                              : "decompiler.native_host.pool_cancelled"));
                return outcome;
            }
            wake.wait_until(lock, (std::min)(provider_request.deadline,
                std::chrono::steady_clock::now() + std::chrono::milliseconds(10)));
        }
    }

    void release(const std::shared_ptr<worker_session_record_t>& record, bool reusable)
    {
        if (!record)
            return;
        if (record->session)
            sample_native_worker_private_bytes(record->session->worker.process.get());
        std::lock_guard lock(mutex);
        if (record->busy) {
            record->busy = false;
            busy.erase(record);
            if (record->interactive)
                --interactive_busy;
            else
                --batch_busy;
        }
        if (record->preempt)
            record->preempt.reset();
        if (record->session)
            record->session->preempt.reset();
        if (stopped.load(std::memory_order_acquire) || !reusable ||
            !session_alive(record) || recycle_due(record)) {
            retire_locked(record, stopped.load(std::memory_order_acquire)
                ? "stopped" : (!reusable ? "unhealthy" : "bounds"));
        } else {
            try {
                idle[record->key].push_back(record);
            } catch (...) {
                retire_locked(record, "idle_push_failed");
            }
        }
        wake.notify_all();
    }

    struct session_lease_guard_t {
        session_lease_guard_t(std::shared_ptr<state_t> owner,
                              std::shared_ptr<worker_session_record_t> leased) noexcept
            : host_state(std::move(owner)), record(std::move(leased)) {}
        session_lease_guard_t(const session_lease_guard_t&) = delete;
        session_lease_guard_t& operator=(const session_lease_guard_t&) = delete;
        ~session_lease_guard_t()
        {
            if (!host_state || !record)
                return;
            try {
                host_state->release(record, record->session && record->session->healthy);
            } catch (...) {
                diag::log_tagged_fmt("dec_batch", "pool_release_exception ordinal=%llu",
                    static_cast<unsigned long long>(record->ordinal));
            }
        }
        std::shared_ptr<state_t> host_state;
        std::shared_ptr<worker_session_record_t> record;
    };

    void stop_all() noexcept
    {
        try {
            stopped.store(true, std::memory_order_release);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
            std::unique_lock lock(mutex);
            for (const auto& record : busy) {
                if (!record)
                    continue;
                record->preempted = true;
                if (record->preempt)
                    record->preempt->store(true, std::memory_order_release);
            }
            for (auto& entry : idle) {
                for (auto& record : entry.second)
                    retire_locked(record, "stopped");
                entry.second.clear();
            }
            idle.clear();
            wake.notify_all();
            wake.wait_until(lock, deadline, [this] { return busy.empty(); });
        } catch (...) {
        }
    }
};

pooled_native_worker_provider_host_t::pooled_native_worker_provider_host_t(
    std::shared_ptr<decompiler_isolated_provider_host_t> fallback_host,
    std::shared_ptr<native_worker_host_t> session_host,
    native_worker_session_pool_config_t config)
    : state_(std::make_shared<state_t>())
{
    state_->fallback = std::move(fallback_host);
    state_->host = std::move(session_host);
    state_->config = config;
    if (state_->config.batch_slots == 0)
        state_->config.batch_slots = 1;
    if (state_->config.max_jobs_per_session == 0)
        state_->config.max_jobs_per_session = 8192;
    const auto policy = default_decompiler_profile_policy();
    state_->session_envelope_max_memory_bytes = (std::max)({policy.fast.max_memory_bytes,
        policy.balanced.max_memory_bytes, policy.thorough.max_memory_bytes});
    diag::log_tagged_fmt("dec_batch",
        "pool_session_envelope memory_bytes=%llu cpu_backstop_ms=%llu",
        static_cast<unsigned long long>(state_->session_envelope_max_memory_bytes),
        static_cast<unsigned long long>(k_decompiler_profile_max_cpu_ms));
}

pooled_native_worker_provider_host_t::~pooled_native_worker_provider_host_t()
{
    stop();
}

bool pooled_native_worker_provider_host_t::supports(
    const decompiler_provider_descriptor_t& descriptor) const noexcept
{
    if (!descriptor.isolated || !state_ || !state_->host)
        return false;
    if (descriptor.identity.provider == decompiler_provider_id_t::ghidra_native)
        return descriptor.entity_kind == decompiler_entity_kind_t::native_function &&
            !state_->stopped.load(std::memory_order_acquire);
    return state_->fallback && state_->fallback->supports(descriptor);
}

decompiler_provider_result_t pooled_native_worker_provider_host_t::execute(
    const decompiler_provider_route_t& route,
    const decompiler_provider_request_t& request,
    const cancellation_token_t& cancel)
{
    const auto started = std::chrono::steady_clock::now();
    decompiler_provider_result_t result;
    if (!state_ || !state_->host || !state_->fallback ||
        route.descriptor.identity.provider != decompiler_provider_id_t::ghidra_native) {
        if (state_ && state_->fallback)
            return state_->fallback->execute(route, request, cancel);
        result.diagnostics.push_back(pool_failure_diagnostic(
            decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.native_host.route_rejected"));
        return result;
    }
    if (!supports(route.descriptor) || !route.provider) {
        result.diagnostics.push_back(pool_failure_diagnostic(
            decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.native_host.route_rejected"));
        return result;
    }
    if (cancel.stop_requested() || started >= request.deadline) {
        const bool timed_out = cancel.deadline_exceeded() || started >= request.deadline;
        result.status = timed_out ? decompiler_provider_execution_status_t::timed_out
                                  : decompiler_provider_execution_status_t::cancelled;
        result.diagnostics.push_back(pool_failure_diagnostic(
            timed_out ? decompiler_diagnostic_code_t::deadline_exceeded
                      : decompiler_diagnostic_code_t::cancelled,
            timed_out ? "decompiler.native_host.deadline" : "decompiler.native_host.cancelled"));
        return result;
    }
    if (request.cache_key.stage != decompiler_cache_stage_t::provider_ir ||
        !validate_decompiler_pipeline_cache_key(request.cache_key).valid() ||
        !same_provider(request.cache_key.provider, route.descriptor.identity)) {
        result.diagnostics.push_back(pool_failure_diagnostic(
            decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.isolated_host.request_rejected"));
        return result;
    }
    const auto context = std::dynamic_pointer_cast<const ghidra_native_provider_context_t>(request.context);
    if (!context || !context->snapshot() || context->snapshot()->empty() ||
        context->snapshot_hash().empty() ||
        context->snapshot()->size() > state_->host->limits().max_snapshot_bytes) {
        result.diagnostics.push_back(pool_failure_diagnostic(
            decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.isolated_host.input_snapshot_rejected"));
        return result;
    }
    auto job_id = state_->next_job_id.fetch_add(1, std::memory_order_acq_rel);
    if (job_id == 0)
        job_id = state_->next_job_id.fetch_add(1, std::memory_order_acq_rel);
    native_worker_execution_request_t worker_request;
    worker_request.job_id = job_id;
    worker_request.cache_key = request.cache_key;
    worker_request.profile = request.cache_key.profile;
    native_worker_snapshot_t snapshot;
    snapshot.bytes = context->snapshot();
    snapshot.hash = context->snapshot_hash();
    if (const auto shared = generation_snapshot_store_t::instance().find(
            request.cache_key.workspace_generation, context->snapshot_hash())) {
        if (shared->mapping_handle != nullptr &&
            shared->mapping_size == context->snapshot()->size()) {
            snapshot.shared_mapping_owner = shared;
            snapshot.shared_mapping_handle = shared->mapping_handle;
            snapshot.shared_mapping_size = shared->mapping_size;
        }
    }
    worker_request.snapshot = std::move(snapshot);
    worker_request.deadline = request.deadline;
    worker_request.cancellation_requested = [cancel] {
        return cancel.stop_requested();
    };
    const auto key = make_worker_pool_key(request, context->snapshot_hash());
    auto acquired = state_->acquire(key, request.interactive, worker_request, cancel,
        route, request, started);
    if (!acquired.record) {
        if (acquired.failure)
            return std::move(*acquired.failure);
        result.diagnostics.push_back(pool_failure_diagnostic(
            decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.native_host.pool_acquire"));
        return result;
    }
    state_t::session_lease_guard_t lease(state_, acquired.record);
    native_worker_execution_result_t worker_result;
    try {
        worker_result = state_->host->execute_on_session(*acquired.record->session, worker_request);
    } catch (...) {
        if (acquired.record->session)
            acquired.record->session->healthy = false;
        throw;
    }
    return map_worker_result_to_provider_result(route, request, cancel, worker_request, worker_result, started);
}

void pooled_native_worker_provider_host_t::stop() noexcept
{
    if (state_)
        state_->stop_all();
}

std::optional<pooled_native_worker_provider_host_t::slot_class_t>
pooled_native_worker_provider_host_t::classify_interactive_dispatch() const noexcept
{
    const auto state = state_;
    if (!state || state->stopped.load(std::memory_order_acquire))
        return std::nullopt;
    std::lock_guard lock(state->mutex);
    return state->interactive_busy < state->config.interactive_reserved_slots
        ? std::optional<slot_class_t>(slot_class_t::reserved)
        : std::optional<slot_class_t>(slot_class_t::borrowed);
}

std::shared_ptr<decompiler_isolated_provider_host_t> create_pooled_native_worker_provider_host(
    const packaged_native_worker_runtime_t& runtime,
    native_worker_session_pool_config_t config)
{
    if (!runtime.provider_host || !runtime.native_host)
        return runtime.provider_host;
    if (config.batch_slots == 0)
        config.batch_slots = 1;
    const std::size_t capacity = config.batch_slots + config.interactive_reserved_slots + 1;
    auto session_host = runtime.native_host->for_session_pool(capacity);
    if (!session_host)
        return runtime.provider_host;
    diag::log_tagged_fmt("dec_batch",
        "pool_create batch_slots=%zu interactive_reserved=%zu max_jobs=%u max_lifetime_ms=%lld",
        config.batch_slots,
        config.interactive_reserved_slots,
        static_cast<unsigned int>(config.max_jobs_per_session),
        static_cast<long long>(config.max_session_lifetime.count()));
    return std::make_shared<pooled_native_worker_provider_host_t>(
        runtime.provider_host, std::move(session_host), config);
}

std::uint64_t native_worker_measured_private_bytes() noexcept
{
    std::lock_guard lock(g_native_worker_private_mutex);
    return g_native_worker_private_ema;
}

std::uint64_t native_worker_measured_private_samples() noexcept
{
    std::lock_guard lock(g_native_worker_private_mutex);
    return g_native_worker_private_samples;
}

}
