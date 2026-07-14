#include "native_worker_host.hpp"

#include "isolated_worker_codec.hpp"
#include "providers/dalvik_ssa.hpp"
#include "providers/cli_provider.hpp"
#include "providers/ghidra_ir_adapter.hpp"
#include "providers/jvm_ssa.hpp"
#include "../workspace/workspace_identity.hpp"

#include "../../../../workers/native_decompiler/native_worker_protocol.hpp"

#include <windows.h>
#include <aclapi.h>
#include <userenv.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <cwctype>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

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
        return left.relative_path < right.relative_path;
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
    } catch (...) {
        append_diagnostic(result,
            native_worker_diagnostic_code_t::runtime_inventory_mismatch,
            "native_worker.managed_runtime.inventory",
            "managed runtime package violates its exact app-local identity",
            ERROR_INVALID_DATA);
        return std::nullopt;
    }
}

struct verified_worker_t {
    native_worker_manifest_t manifest;
    sha256_digest_t manifest_hash;
    std::wstring root_path;
    std::wstring worker_path;
    handle_t worker_file;
    std::optional<managed_runtime_package_t> managed_runtime;
};

std::optional<verified_worker_t> verify_worker(const native_worker_launch_contract_t& contract,
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
    verified_worker_t verified;
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

std::optional<std::vector<wchar_t>> minimal_environment(
    const std::optional<std::wstring>& dotnet_root)
{
    std::wstring system_root(32768, L'\0');
    const UINT written = GetWindowsDirectoryW(system_root.data(),
        static_cast<UINT>(system_root.size()));
    if (written == 0 || written >= static_cast<UINT>(system_root.size()))
        return std::nullopt;
    system_root.resize(written);
    if (dotnet_root && (dotnet_root->empty() ||
        dotnet_root->find(L'=') != std::wstring::npos))
        return std::nullopt;
    std::vector<std::wstring> entries{
        L"COMPlus_EnableDiagnostics=0",
        L"DOTNET_CLI_TELEMETRY_OPTOUT=1",
        L"DOTNET_EnableDiagnostics=0",
        L"DOTNET_MULTILEVEL_LOOKUP=0",
        L"DOTNET_NOLOGO=1",
        L"DOTNET_ROLL_FORWARD=Disable",
        L"DOTNET_ROLL_FORWARD_TO_PRERELEASE=0",
        L"DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
        L"PATH=" + system_root + L"\\System32",
        L"SystemRoot=" + system_root,
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
    return std::vector<wchar_t>(block.begin(), block.end());
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
        error = ERROR_SUCCESS;
        return true;
    }

    PSID sid() const noexcept { return sid_; }

private:
    PSID sid_ = nullptr;
};

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

bool configure_job(HANDLE job, const decompiler_profile_budget_t& profile, DWORD& error)
{
    if (profile.max_memory_bytes == 0 || profile.max_cpu_ms == 0 ||
        profile.max_memory_bytes > static_cast<std::uint64_t>((std::numeric_limits<SIZE_T>::max)()) ||
        profile.max_cpu_ms > static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)() / 10000)) {
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
    limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = static_cast<LONGLONG>(profile.max_cpu_ms * 10000);
    limits.ProcessMemoryLimit = static_cast<SIZE_T>(profile.max_memory_bytes);
    limits.JobMemoryLimit = static_cast<SIZE_T>(profile.max_memory_bytes);
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

struct worker_instance_t {
    handle_t job;
    handle_t process;
    handle_t request_pipe;
    handle_t response_pipe;
    std::vector<handle_t> runtime_identity_locks;
    wire::session_material_t session;
    wire::frame_reader_t reader;
    std::uint64_t next_host_sequence = 1;
    std::uint64_t next_worker_sequence = 1;
    DWORD process_id = 0;
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

bool launch_worker(verified_worker_t& verified, const native_worker_execution_request_t& request,
                   const native_worker_host_limits_t& host_limits, worker_instance_t& worker,
                   native_worker_execution_result_t& result)
{
    handle_t child_read;
    handle_t parent_write;
    handle_t child_write;
    handle_t parent_read;
    handle_t child_snapshot;
    handle_t child_identity;
    DWORD error = ERROR_SUCCESS;
    app_container_t container;
    if (!container.create(verified.manifest_hash, error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::app_container_unavailable, "native_worker.app_container", "networkless AppContainer could not be established", error);
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
    if (!worker.job || !configure_job(worker.job.get(), request.profile, error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::launch_policy_rejected, "native_worker.job", "job limits could not be applied", error);
        return false;
    }
    if (!wire::make_session(worker.session)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::bootstrap_failed, "native_worker.session", "session entropy could not be acquired", ERROR_CRC);
        return false;
    }
    const bool managed = verified.manifest.provider.provider ==
        decompiler_provider_id_t::ilspy_cli;
    std::array<HANDLE, 4> inherited_handles{child_read.get(), child_write.get(), child_snapshot.get(), child_identity.get()};
    std::uint64_t mitigation_policy = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
        PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE |
        PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON;
    if (!managed)
        mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
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
            sizeof(HANDLE) * inherited_handles.size(), nullptr, nullptr) ||
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
    startup.lpAttributeList = attribute_list;
    PROCESS_INFORMATION process{};
    const BOOL launched = CreateProcessW(verified.worker_path.c_str(), command_line.data(), nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, const_cast<wchar_t*>(environment->data()),
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
    const auto bootstrap = wire::encode_bootstrap(worker.session, verified.manifest_hash);
    if (!wire::write_all(worker.request_pipe.get(), bootstrap.data(), bootstrap.size(), error)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::bootstrap_failed, "native_worker.bootstrap", "bootstrap could not be delivered", error, true);
        TerminateJobObject(worker.job.get(), ERROR_CANCELLED);
        return false;
    }
    if (verified.managed_runtime)
        worker.runtime_identity_locks = std::move(verified.managed_runtime->locked_files);
    return true;
}

void terminate_worker(worker_instance_t& worker, DWORD exit_code, native_worker_execution_result_t& result, bool replacement)
{
    if (worker.job)
        TerminateJobObject(worker.job.get(), exit_code);
    if (worker.process)
        WaitForSingleObject(worker.process.get(), 1000);
    result.worker_terminated = true;
    result.worker_replaced = replacement;
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

terminal_wait_t wait_for_message(worker_instance_t& worker, const native_worker_execution_request_t& request,
                                 const native_worker_host_limits_t& limits, std::chrono::steady_clock::time_point deadline,
                                 wire::frame_t& frame, DWORD& error)
{
    while (true) {
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
        if (std::chrono::steady_clock::now() >= deadline)
            return terminal_wait_t::deadline;
        const auto state = worker.reader.poll(worker.response_pipe.get(), worker.session, worker.next_worker_sequence,
            limits.max_frame_bytes, frame, error);
        if (state == wire::read_state_t::complete) {
            ++worker.next_worker_sequence;
            return terminal_wait_t::message;
        }
        if (state == wire::read_state_t::failure)
            return terminal_wait_t::protocol_failure;
        const DWORD wait = WaitForSingleObject(worker.process.get(), 0);
        if (wait == WAIT_OBJECT_0) {
            if (worker.reader.has_partial_frame()) {
                error = ERROR_HANDLE_EOF;
                return terminal_wait_t::protocol_failure;
            }
            return terminal_wait_t::exited;
        }
        if (wait == WAIT_FAILED) {
            error = GetLastError();
            return terminal_wait_t::protocol_failure;
        }
        Sleep(static_cast<DWORD>((std::max)(std::int64_t{1}, limits.poll_interval.count())));
    }
}

void append_protocol_failure(native_worker_execution_result_t& result, wire::frame_failure_t failure,
                             std::string phase, DWORD error)
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

bool validate_managed_hello(
    const wire::frame_t& frame,
    const wire::session_material_t& session,
    const verified_worker_t& verified)
{
    try {
        if (frame.kind != wire::frame_kind_t::decompiler_contract)
            return false;
        const auto value = nlohmann::json::parse(frame.payload.begin(), frame.payload.end(),
            nullptr, true, true);
        if (!value.is_object() || value.size() != 11 ||
            value.at("schema") != "aida.c03.managed-cli.transport" ||
            value.at("schemaVersion") != 3 || value.at("kind") != "hello" ||
            value.at("sequence") != frame.sequence ||
            value.at("sessionNonceHash") != session.nonce_hash.to_hex() ||
            value.at("manifestHash") != verified.manifest_hash.to_hex() ||
            value.at("runtimeManifestHash") !=
                verified.manifest.managed_runtime_manifest_hash.to_hex() ||
            value.at("workerBinaryHash") != verified.manifest.worker_binary_hash.to_hex() ||
            value.at("providerBinaryHash") != verified.manifest.provider.provider_binary_hash.to_hex() ||
            value.at("workerBuildId") != verified.manifest.provider.worker_build_id ||
            value.at("workerBuildHash") != verified.manifest.provider.worker_build_hash.to_hex())
            return false;
        return true;
    } catch (...) {
        return false;
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
        auto host = std::make_shared<native_worker_host_t>(std::move(launch_contract));
        native_worker_launch_contract_t managed_launch_contract;
        managed_launch_contract.approved_root = runtime_root;
        managed_launch_contract.manifest_path = managed_manifest_path;
        managed_launch_contract.expected_manifest_hash = managed_manifest_hash;
        native_worker_execution_result_t managed_runtime_verification;
        if (!verify_worker(managed_launch_contract, managed_runtime_verification)) {
            return failure(workspace_error_code_t::integrity_failure,
                "managed decompiler app-local runtime failed package verification",
                "native_worker.runtime.managed_runtime", ERROR_CRC);
        }
        auto managed_host = std::make_shared<native_worker_host_t>(
            std::move(managed_launch_contract));
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
    auto verified = verify_worker(contract_, result);
    if (!verified)
        return result;
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
    const auto startup_deadline = std::chrono::steady_clock::now() + limits_.startup_timeout;
    wire::frame_t frame;
    DWORD error = ERROR_SUCCESS;
    const auto hello_wait = wait_for_message(worker, native_worker_execution_request_t{}, limits_, startup_deadline, frame, error);
    if (hello_wait != terminal_wait_t::message) {
        if (hello_wait == terminal_wait_t::deadline) {
            append_diagnostic(result, native_worker_diagnostic_code_t::deadline_exceeded, "native_worker.hello",
                "worker did not provide an authenticated hello before the startup deadline", error, true);
        } else if (hello_wait == terminal_wait_t::exited) {
            append_diagnostic(result, native_worker_diagnostic_code_t::worker_crashed, "native_worker.hello",
                "worker exited before providing an authenticated hello", error, true);
        } else {
            append_protocol_failure(result, worker.reader.failure(), "native_worker.hello", error);
        }
        terminate_worker(worker, ERROR_CANCELLED, result, true);
        return result;
    }
    if (verified->manifest.provider.provider == decompiler_provider_id_t::ilspy_cli) {
        if (!request.managed_request ||
            !validate_managed_hello(frame, worker.session, *verified)) {
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
                DWORD exit_code = 0;
                GetExitCodeProcess(worker.process.get(), &exit_code);
                append_diagnostic(result, native_worker_diagnostic_code_t::worker_crashed,
                    "native_worker.managed_wait",
                    "managed worker exited before a terminal result", exit_code, true);
                terminate_worker(worker, exit_code, result, true);
                return result;
            }
            if (terminal == terminal_wait_t::protocol_failure) {
                append_protocol_failure(result, worker.reader.failure(),
                    "native_worker.managed_response", error);
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
    bool cancel_sent = false;
    while (true) {
        const auto terminal = wait_for_message(worker, request, limits_, deadline, frame, error);
        if (terminal == terminal_wait_t::cancelled || terminal == terminal_wait_t::deadline) {
            const bool is_deadline = terminal == terminal_wait_t::deadline;
            if (!cancel_sent) {
                send_cancel(worker, request, limits_, is_deadline ? "deadline_exceeded" : "cancelled");
                cancel_sent = true;
            }
            const auto grace_deadline = std::chrono::steady_clock::now() + limits_.cancellation_grace;
            wire::frame_t ignored;
            const auto grace = wait_for_message(worker, native_worker_execution_request_t{}, limits_, grace_deadline, ignored, error);
            if (grace == terminal_wait_t::message) {
                const auto decoded = deserialize_decompiler_worker_message(
                    std::string(reinterpret_cast<const char*>(ignored.payload.data()), ignored.payload.size()));
                if (decoded.valid() && decoded.value && validate_envelope(*decoded.value, ignored, worker.session) &&
                    std::holds_alternative<decompiler_worker_failure_message_t>(*decoded.value))
                    append_worker_failure(result, std::get<decompiler_worker_failure_message_t>(*decoded.value));
            }
            result.status = is_deadline ? native_worker_execution_status_t::deadline_exceeded : native_worker_execution_status_t::cancelled;
            append_diagnostic(result, is_deadline ? native_worker_diagnostic_code_t::deadline_exceeded : native_worker_diagnostic_code_t::cancelled,
                "native_worker.cancel", is_deadline ? "worker exceeded its deadline" : "worker cancellation was requested", ERROR_CANCELLED, true);
            terminate_worker(worker, ERROR_CANCELLED, result, true);
            return result;
        }
        if (terminal == terminal_wait_t::exited) {
            DWORD exit_code = 0;
            GetExitCodeProcess(worker.process.get(), &exit_code);
            append_diagnostic(result, native_worker_diagnostic_code_t::worker_crashed, "native_worker.wait", "worker exited before a terminal result", exit_code, true);
            terminate_worker(worker, exit_code, result, true);
            return result;
        }
        if (terminal == terminal_wait_t::protocol_failure) {
            append_protocol_failure(result, worker.reader.failure(), "native_worker.response", error);
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
            append_diagnostic(result, native_worker_diagnostic_code_t::worker_failed, "native_worker.failure", "worker returned typed failure diagnostics", ERROR_SUCCESS, false);
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
                        diagnostic.localization_arguments = {decoded.error().stable_code()};
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

}
