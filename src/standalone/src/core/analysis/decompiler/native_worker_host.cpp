#include "native_worker_host.hpp"

#include "../../../../workers/native_decompiler/native_worker_protocol.hpp"

#include <windows.h>
#include <aclapi.h>
#include <userenv.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cwctype>
#include <limits>
#include <string_view>
#include <system_error>
#include <utility>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

namespace aida::analysis::native_worker {
namespace {

constexpr std::uint32_t k_manifest_max_string_bytes = 4096;
constexpr std::uint32_t k_manifest_max_arguments = 32;

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
    if (manifest.schema_version != k_native_worker_manifest_schema_version || !safe_relative_path(manifest.worker_relative_path) ||
        manifest.worker_relative_path.size() > k_manifest_max_string_bytes || manifest.worker_relative_path.find('\0') != std::string::npos ||
        manifest.worker_binary_hash.empty() || manifest.provider.provider_name.empty() || manifest.provider.provider_version.empty() ||
        manifest.provider.worker_build_id.empty() || manifest.provider.provider_binary_hash.empty() || manifest.provider.worker_build_hash.empty() ||
        manifest.worker_protocol_version != k_decompiler_worker_protocol_version || manifest.worker_protocol_hash.empty() ||
        manifest.worker_protocol_hash != wire::protocol_hash() || manifest.capabilities != k_native_worker_capability_decompile ||
        manifest.startup_arguments.size() > k_manifest_max_arguments)
        return false;
    if (manifest.provider.provider != decompiler_provider_id_t::ghidra_native || manifest.provider.provider_name.size() > k_manifest_max_string_bytes ||
        manifest.provider.provider_version.size() > k_manifest_max_string_bytes || manifest.provider.worker_build_id.size() > k_manifest_max_string_bytes ||
        manifest.provider.provider_name.find('\0') != std::string::npos || manifest.provider.provider_version.find('\0') != std::string::npos ||
        manifest.provider.worker_build_id.find('\0') != std::string::npos || manifest.provider.provider_binary_hash != manifest.worker_binary_hash)
        return false;
    for (const auto& argument : manifest.startup_arguments) {
        if (argument.empty() || argument.size() > 1024 || argument.find('\0') != std::string::npos ||
            argument.rfind("--aida-native-decompiler-worker", 0) == 0 || argument.rfind("--read-handle", 0) == 0 ||
            argument.rfind("--write-handle", 0) == 0 || argument.rfind("--snapshot-handle", 0) == 0 ||
            argument.rfind("--snapshot-size", 0) == 0 || argument.rfind("--identity-handle", 0) == 0 ||
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

struct verified_worker_t {
    native_worker_manifest_t manifest;
    sha256_digest_t manifest_hash;
    std::wstring root_path;
    std::wstring worker_path;
    handle_t worker_file;
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

std::optional<std::vector<wchar_t>> minimal_environment()
{
    const DWORD required = GetEnvironmentVariableW(L"SystemRoot", nullptr, 0);
    if (required <= 1)
        return std::nullopt;
    std::wstring system_root(required - 1, L'\0');
    if (GetEnvironmentVariableW(L"SystemRoot", system_root.data(), required) != required - 1)
        return std::nullopt;
    std::wstring block = L"SystemRoot=" + system_root;
    block.push_back(L'\0');
    block.append(L"WINDIR=");
    block.append(system_root);
    block.push_back(L'\0');
    block.append(L"PATH=");
    block.append(system_root);
    block.append(L"\\System32");
    block.push_back(L'\0');
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
    UnmapViewOfFile(view);
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

bool launch_worker(const verified_worker_t& verified, const native_worker_execution_request_t& request,
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
    std::array<HANDLE, 4> inherited_handles{child_read.get(), child_write.get(), child_snapshot.get(), child_identity.get()};
    std::uint64_t mitigation_policy = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
        PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE |
        PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON |
        PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
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
    std::wstring command_line = quote_argument(verified.worker_path);
    command_line.append(L" --aida-native-decompiler-worker");
    command_line.append(L" --read-handle=");
    command_line.append(std::to_wstring(reinterpret_cast<std::uintptr_t>(child_read.get())));
    command_line.append(L" --write-handle=");
    command_line.append(std::to_wstring(reinterpret_cast<std::uintptr_t>(child_write.get())));
    command_line.append(L" --snapshot-handle=");
    command_line.append(std::to_wstring(reinterpret_cast<std::uintptr_t>(child_snapshot.get())));
    command_line.append(L" --snapshot-size=");
    command_line.append(std::to_wstring(request.snapshot.bytes->size()));
    command_line.append(L" --identity-handle=");
    command_line.append(std::to_wstring(reinterpret_cast<std::uintptr_t>(child_identity.get())));
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
    const auto environment = minimal_environment();
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

native_worker_execution_result_t native_worker_host_t::execute(const native_worker_execution_request_t& request)
{
    std::lock_guard lock(mutex_);
    native_worker_execution_result_t result;
    if (stopped_) {
        append_diagnostic(result, native_worker_diagnostic_code_t::host_stopped, "native_worker.execute", "worker host is stopped");
        return result;
    }
    if (limits_.max_frame_bytes == 0 || limits_.max_snapshot_bytes == 0 || limits_.startup_timeout.count() <= 0 ||
        limits_.cancellation_grace.count() < 0 || limits_.poll_interval.count() <= 0 || request.job_id == 0 ||
        !request.snapshot.valid() || request.snapshot.bytes->size() > limits_.max_snapshot_bytes ||
        request.snapshot.bytes->size() > request.profile.max_memory_bytes) {
        append_diagnostic(result, native_worker_diagnostic_code_t::invalid_request, "native_worker.request", "worker request or host limits are invalid");
        return result;
    }
    sha256_digest_t verified_snapshot_hash;
    if (!wire::sha256(request.snapshot.bytes->data(), request.snapshot.bytes->size(), verified_snapshot_hash) || verified_snapshot_hash != request.snapshot.hash) {
        append_diagnostic(result, native_worker_diagnostic_code_t::snapshot_invalid, "native_worker.snapshot", "snapshot hash is invalid", ERROR_CRC);
        return result;
    }
    result.snapshot_hash = verified_snapshot_hash;
    const auto cache_validation = validate_decompiler_pipeline_cache_key(request.cache_key);
    const auto profile_validation = validate_decompiler_profile(request.profile);
    if (!cache_validation.valid() || !profile_validation.valid() || request.cache_key.profile.profile != request.profile.profile ||
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
    auto verified = verify_worker(contract_, result);
    if (!verified)
        return result;
    result.worker_generation = ++worker_generation_;
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
    const auto decoded_hello = deserialize_decompiler_worker_message(
        std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()));
    if (!decoded_hello.valid() || !decoded_hello.value || !validate_envelope(*decoded_hello.value, frame, worker.session) ||
        !std::holds_alternative<decompiler_worker_hello_t>(*decoded_hello.value)) {
        append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.hello", "worker hello violates the authenticated protocol", ERROR_INVALID_DATA, true);
        terminate_worker(worker, ERROR_CRC, result, true);
        return result;
    }
    const auto& hello = std::get<decompiler_worker_hello_t>(*decoded_hello.value);
    if (hello.manifest_hash != verified->manifest_hash || !same_provider(hello.provider, verified->manifest.provider)) {
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
            if (document.job_id != request.job_id || !document_validation.valid() || document.document.entity != request.cache_key.entity ||
                document.document.profile != request.profile.profile) {
                append_diagnostic(result, native_worker_diagnostic_code_t::protocol_malformed, "native_worker.document", "worker document is not bound to the requested entity and profile", ERROR_INVALID_DATA, true);
                terminate_worker(worker, ERROR_CRC, result, true);
                return result;
            }
            result.document = document.document;
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
    std::lock_guard lock(mutex_);
    stopped_ = true;
}

std::uint64_t native_worker_host_t::worker_generation() const noexcept
{
    std::lock_guard lock(mutex_);
    return worker_generation_;
}

}
