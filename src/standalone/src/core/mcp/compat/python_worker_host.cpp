#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>

#include "python_worker_host.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <limits>
#include <memory>
#include <string_view>
#include <system_error>
#include <utility>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

namespace aida::standalone::mcp::compat {

namespace {

using python_worker::wire::digest_t;
using python_worker::wire::frame_t;
using python_worker::wire::frame_reader_t;
using python_worker::wire::read_state_t;
using python_worker::wire::session_material_t;

constexpr std::uint32_t k_manifest_magic = 0x4d575041U;
constexpr std::size_t k_manifest_max_bytes = 64U * 1024U;
constexpr std::size_t k_worker_max_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr std::size_t k_manifest_string_max_bytes = 4096;
constexpr std::uint32_t k_workspace_request_id_max = 1000000;

class handle_t final {
public:
    handle_t() = default;
    explicit handle_t(HANDLE value) noexcept : value_(value) {}
    ~handle_t() { reset(); }
    handle_t(const handle_t&) = delete;
    handle_t& operator=(const handle_t&) = delete;
    handle_t(handle_t&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    handle_t& operator=(handle_t&& other) noexcept {
        if (this != &other)
            reset(std::exchange(other.value_, nullptr));
        return *this;
    }
    HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
    HANDLE release() noexcept { return std::exchange(value_, nullptr); }
    void reset(HANDLE value = nullptr) noexcept {
        if (*this)
            CloseHandle(value_);
        value_ = value;
    }

private:
    HANDLE value_ = nullptr;
};

void append_diagnostic(python_worker_execution_result_t& result, python_worker_error_code_t code,
                       std::string phase, std::string detail, DWORD error = ERROR_SUCCESS,
                       bool replacement = false) {
    result.diagnostics.push_back({code, std::move(phase), std::move(detail), error, replacement});
}

std::optional<std::wstring> utf8_to_wide(std::string_view value) {
    if (value.empty() || value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        return std::nullopt;
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0)
        return std::nullopt;
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
            result.data(), required) != required)
        return std::nullopt;
    return result;
}

std::wstring strip_extended_prefix(std::wstring value) {
    constexpr std::wstring_view unc_prefix = L"\\\\?\\UNC\\";
    constexpr std::wstring_view path_prefix = L"\\\\?\\";
    if (value.size() >= unc_prefix.size() && _wcsnicmp(value.c_str(), unc_prefix.data(), unc_prefix.size()) == 0)
        value.replace(0, unc_prefix.size(), L"\\\\");
    else if (value.size() >= path_prefix.size() && _wcsnicmp(value.c_str(), path_prefix.data(), path_prefix.size()) == 0)
        value.erase(0, path_prefix.size());
    return value;
}

std::optional<std::wstring> final_path(HANDLE handle) {
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

bool path_within(const std::wstring& root, const std::wstring& candidate) noexcept {
    if (root.empty() || candidate.size() < root.size() || _wcsnicmp(root.c_str(), candidate.c_str(), root.size()) != 0)
        return false;
    return candidate.size() == root.size() || root.back() == L'\\' || candidate[root.size()] == L'\\';
}

bool safe_relative_path(std::string_view text) noexcept {
    const auto wide = utf8_to_wide(text);
    if (!wide || wide->empty())
        return false;
    std::filesystem::path path(*wide);
    if (path.is_absolute() || path.has_root_directory() || path.has_root_name())
        return false;
    for (const auto& part : path) {
        if (part.empty() || part == L"." || part == L"..")
            return false;
    }
    return true;
}

bool valid_limits(const python_worker_limits_t& limits) noexcept {
    return limits.max_script_bytes != 0 && limits.max_frame_bytes >= 1024 &&
        limits.max_output_bytes != 0 && limits.max_output_bytes <= limits.max_frame_bytes &&
        limits.max_workspace_response_bytes != 0 && limits.max_workspace_response_bytes <= limits.max_frame_bytes &&
        limits.max_workspace_requests != 0 && limits.startup_timeout.count() > 0 &&
        limits.cancellation_grace.count() >= 0 && limits.max_wall_clock.count() > 0 &&
        limits.max_cpu_ms != 0 && limits.max_memory_bytes != 0 &&
        limits.max_memory_bytes <= static_cast<std::uint64_t>((std::numeric_limits<SIZE_T>::max)()) &&
        limits.max_cpu_ms <= static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)() / 10000);
}

bool valid_manifest(const python_worker_manifest_t& manifest) {
    return manifest.schema_version == k_python_worker_manifest_schema_version &&
        safe_relative_path(manifest.worker_relative_path) &&
        manifest.worker_relative_path.size() <= k_manifest_string_max_bytes &&
        manifest.worker_relative_path.rfind("deps/", 0) == 0 &&
        manifest.worker_relative_path.find('\0') == std::string::npos &&
        manifest.worker_binary_hash.empty() == false &&
        manifest.protocol_hash == python_worker::wire::protocol_hash() &&
        manifest.capabilities == k_python_worker_capability_execute_file;
}

class manifest_writer_t final {
public:
    void u32(std::uint32_t value) {
        const auto position = data_.size();
        data_.resize(position + sizeof(value));
        python_worker::wire::write_u32(reinterpret_cast<std::uint8_t*>(data_.data()) + position, value);
    }

    void string(std::string_view value) {
        u32(static_cast<std::uint32_t>(value.size()));
        data_.append(value.data(), value.size());
    }

    void digest(const digest_t& value) {
        data_.append(reinterpret_cast<const char*>(value.bytes.data()), value.bytes.size());
    }

    std::string take() {
        return std::move(data_);
    }

private:
    std::string data_;
};

class manifest_reader_t final {
public:
    explicit manifest_reader_t(std::string_view value) : data_(reinterpret_cast<const std::uint8_t*>(value.data())), size_(value.size()) {}

    bool u32(std::uint32_t& value) noexcept {
        if (remaining() < sizeof(value))
            return false;
        value = python_worker::wire::read_u32(data_ + position_);
        position_ += sizeof(value);
        return true;
    }

    bool string(std::string& value) noexcept {
        std::uint32_t length = 0;
        if (!u32(length) || length == 0 || length > k_manifest_string_max_bytes || remaining() < length)
            return false;
        try {
            value.assign(reinterpret_cast<const char*>(data_ + position_), length);
        } catch (...) {
            return false;
        }
        position_ += length;
        return true;
    }

    bool digest(digest_t& value) noexcept {
        if (remaining() < value.bytes.size())
            return false;
        std::memcpy(value.bytes.data(), data_ + position_, value.bytes.size());
        position_ += value.bytes.size();
        return true;
    }

    bool exhausted() const noexcept {
        return position_ == size_;
    }

private:
    std::size_t remaining() const noexcept {
        return position_ <= size_ ? size_ - position_ : 0;
    }

    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t position_ = 0;
};

bool read_locked_file(const std::filesystem::path& path, std::size_t maximum_bytes, handle_t& handle,
                      std::vector<std::uint8_t>& output, DWORD& error) {
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
    std::size_t offset = 0;
    while (offset < output.size()) {
        const DWORD chunk = static_cast<DWORD>((std::min)(output.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD read = 0;
        if (!ReadFile(handle.get(), output.data() + offset, chunk, &read, nullptr) || read == 0) {
            error = GetLastError();
            return false;
        }
        offset += read;
    }
    error = ERROR_SUCCESS;
    return true;
}

struct verified_worker_t final {
    python_worker_manifest_t manifest;
    digest_t manifest_hash;
    std::wstring root_path;
    std::wstring worker_path;
    handle_t worker_file;
};

std::optional<verified_worker_t> verify_worker(const python_worker_launch_contract_t& contract,
                                                python_worker_execution_result_t& result) {
    if (contract.approved_root.empty() || contract.manifest_path.empty() || contract.expected_manifest_hash.empty()) {
        append_diagnostic(result, python_worker_error_code_t::invalid_request, "python_worker.verify", "launch contract is incomplete");
        return std::nullopt;
    }
    std::error_code ec;
    const auto root = std::filesystem::absolute(contract.approved_root, ec).lexically_normal();
    if (ec || !std::filesystem::is_directory(root, ec) || ec) {
        append_diagnostic(result, python_worker_error_code_t::worker_path_rejected, "python_worker.root", "approved root is not a directory", ERROR_PATH_NOT_FOUND);
        return std::nullopt;
    }
    const DWORD root_attributes = GetFileAttributesW(root.c_str());
    if (root_attributes == INVALID_FILE_ATTRIBUTES || (root_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        append_diagnostic(result, python_worker_error_code_t::worker_path_rejected, "python_worker.root", "approved root is a reparse point", GetLastError());
        return std::nullopt;
    }
    handle_t root_handle(CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    const auto root_path = root_handle ? final_path(root_handle.get()) : std::nullopt;
    if (!root_path) {
        append_diagnostic(result, python_worker_error_code_t::worker_path_rejected, "python_worker.root", "approved root cannot be canonicalized", GetLastError());
        return std::nullopt;
    }
    const auto manifest_path = std::filesystem::absolute(contract.manifest_path, ec).lexically_normal();
    if (ec || GetFileAttributesW(manifest_path.c_str()) == INVALID_FILE_ATTRIBUTES ||
        (GetFileAttributesW(manifest_path.c_str()) & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        append_diagnostic(result, python_worker_error_code_t::manifest_unavailable, "python_worker.manifest", "manifest is not a regular file", ERROR_INVALID_NAME);
        return std::nullopt;
    }
    handle_t manifest_file;
    std::vector<std::uint8_t> manifest_bytes;
    DWORD error = ERROR_SUCCESS;
    if (!read_locked_file(manifest_path, k_manifest_max_bytes, manifest_file, manifest_bytes, error)) {
        append_diagnostic(result, python_worker_error_code_t::manifest_unavailable, "python_worker.manifest", "manifest cannot be read", error);
        return std::nullopt;
    }
    const auto manifest_final_path = final_path(manifest_file.get());
    if (!manifest_final_path || !path_within(*root_path, *manifest_final_path)) {
        append_diagnostic(result, python_worker_error_code_t::worker_path_rejected, "python_worker.manifest", "manifest is outside approved root", ERROR_ACCESS_DENIED);
        return std::nullopt;
    }
    digest_t manifest_hash;
    if (!python_worker::wire::sha256(manifest_bytes.data(), manifest_bytes.size(), manifest_hash)) {
        append_diagnostic(result, python_worker_error_code_t::manifest_unavailable, "python_worker.manifest_hash", "manifest hash calculation failed", ERROR_CRC);
        return std::nullopt;
    }
    if (manifest_hash != contract.expected_manifest_hash) {
        append_diagnostic(result, python_worker_error_code_t::manifest_hash_mismatch, "python_worker.manifest_hash", "manifest hash does not match launch contract", ERROR_CRC);
        return std::nullopt;
    }
    const auto decoded = deserialize_python_worker_manifest(std::string(
        reinterpret_cast<const char*>(manifest_bytes.data()), manifest_bytes.size()));
    SecureZeroMemory(manifest_bytes.data(), manifest_bytes.size());
    if (!decoded.valid() || !decoded.value || !valid_manifest(*decoded.value)) {
        append_diagnostic(result, python_worker_error_code_t::manifest_malformed, "python_worker.manifest_decode",
            decoded.error.empty() ? "manifest fields violate worker contract" : decoded.error, ERROR_INVALID_DATA);
        return std::nullopt;
    }
    const auto worker_relative = utf8_to_wide(decoded.value->worker_relative_path);
    if (!worker_relative) {
        append_diagnostic(result, python_worker_error_code_t::manifest_malformed, "python_worker.worker_path", "worker path is invalid UTF-8", ERROR_INVALID_NAME);
        return std::nullopt;
    }
    const auto worker_path = (root / std::filesystem::path(*worker_relative)).lexically_normal();
    const DWORD worker_attributes = GetFileAttributesW(worker_path.c_str());
    if (worker_attributes == INVALID_FILE_ATTRIBUTES ||
        (worker_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        append_diagnostic(result, python_worker_error_code_t::worker_path_rejected, "python_worker.worker_file", "worker is not a regular disk-backed file", GetLastError());
        return std::nullopt;
    }
    verified_worker_t verified;
    verified.manifest = *decoded.value;
    verified.manifest_hash = manifest_hash;
    verified.root_path = *root_path;
    std::vector<std::uint8_t> worker_bytes;
    if (!read_locked_file(worker_path, k_worker_max_bytes, verified.worker_file, worker_bytes, error)) {
        append_diagnostic(result, python_worker_error_code_t::worker_path_rejected, "python_worker.worker_file", "worker cannot be locked and read", error);
        return std::nullopt;
    }
    const auto worker_final_path = final_path(verified.worker_file.get());
    if (!worker_final_path || !path_within(verified.root_path, *worker_final_path)) {
        append_diagnostic(result, python_worker_error_code_t::worker_path_rejected, "python_worker.worker_file", "worker resolves outside approved root", ERROR_ACCESS_DENIED);
        return std::nullopt;
    }
    digest_t worker_hash;
    const bool hashed = python_worker::wire::sha256(worker_bytes.data(), worker_bytes.size(), worker_hash);
    SecureZeroMemory(worker_bytes.data(), worker_bytes.size());
    if (!hashed || worker_hash != verified.manifest.worker_binary_hash) {
        append_diagnostic(result, python_worker_error_code_t::worker_hash_mismatch, "python_worker.worker_hash", "worker hash does not match manifest", ERROR_CRC);
        return std::nullopt;
    }
    std::wstring normalized = *worker_final_path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](wchar_t value) { return std::towlower(value); });
    if (normalized.find(L"camoufox") != std::wstring::npos) {
        append_diagnostic(result, python_worker_error_code_t::worker_path_rejected, "python_worker.worker_file", "Camoufox runtime cannot be used as analysis Python worker", ERROR_ACCESS_DENIED);
        return std::nullopt;
    }
    verified.worker_path = *worker_final_path;
    return verified;
}

std::wstring quote_argument(const std::wstring& value) {
    std::wstring result;
    result.push_back(L'"');
    std::size_t slash_count = 0;
    for (const wchar_t character : value) {
        if (character == L'\\') {
            ++slash_count;
            continue;
        }
        if (character == L'"')
            result.append(slash_count * 2U + 1U, L'\\');
        else
            result.append(slash_count, L'\\');
        slash_count = 0;
        result.push_back(character);
    }
    result.append(slash_count * 2U, L'\\');
    result.push_back(L'"');
    return result;
}

std::optional<std::vector<wchar_t>> minimal_environment() {
    const DWORD required = GetEnvironmentVariableW(L"SystemRoot", nullptr, 0);
    if (required <= 1)
        return std::nullopt;
    std::wstring system_root(required - 1U, L'\0');
    if (GetEnvironmentVariableW(L"SystemRoot", system_root.data(), required) != required - 1U)
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
    block.append(L"PYTHONHOME=");
    block.push_back(L'\0');
    block.append(L"PYTHONPATH=");
    block.push_back(L'\0');
    block.push_back(L'\0');
    return std::vector<wchar_t>(block.begin(), block.end());
}

class app_container_t final {
public:
    ~app_container_t() {
        if (sid_)
            FreeSid(sid_);
    }

    bool create(const digest_t& manifest_hash, DWORD& error) {
        const auto name = utf8_to_wide("AiDA.AnalysisPython." + manifest_hash.to_hex().substr(0, 32));
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
    bool create(PSID app_container_sid, DWORD& error) {
        if (!app_container_sid || !IsValidSid(app_container_sid)) {
            error = ERROR_INVALID_SID;
            return false;
        }
        HANDLE raw_token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
            error = GetLastError();
            return false;
        }
        handle_t token(raw_token);
        DWORD token_bytes = 0;
        if (GetTokenInformation(token.get(), TokenUser, nullptr, 0, &token_bytes) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || token_bytes < sizeof(TOKEN_USER)) {
            error = GetLastError();
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
        const auto* user = reinterpret_cast<const TOKEN_USER*>(token_user_.data());
        if (!user->User.Sid || !IsValidSid(user->User.Sid)) {
            error = ERROR_INVALID_SID;
            return false;
        }
        const auto bytes = sizeof(ACL) +
            (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(user->User.Sid)) +
            (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(app_container_sid));
        try {
            acl_.resize(bytes);
        } catch (...) {
            error = ERROR_NOT_ENOUGH_MEMORY;
            return false;
        }
        auto* acl = reinterpret_cast<PACL>(acl_.data());
        constexpr DWORD access = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | READ_CONTROL;
        if (!InitializeAcl(acl, static_cast<DWORD>(acl_.size()), ACL_REVISION) ||
            !AddAccessAllowedAceEx(acl, ACL_REVISION, 0, access, user->User.Sid) ||
            !AddAccessAllowedAceEx(acl, ACL_REVISION, 0, access, app_container_sid) ||
            !InitializeSecurityDescriptor(&descriptor_, SECURITY_DESCRIPTOR_REVISION) ||
            !SetSecurityDescriptorOwner(&descriptor_, user->User.Sid, FALSE) ||
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

    SECURITY_ATTRIBUTES* attributes() noexcept { return &attributes_; }

private:
    std::vector<std::uint8_t> token_user_;
    std::vector<std::uint8_t> acl_;
    SECURITY_DESCRIPTOR descriptor_{};
    SECURITY_ATTRIBUTES attributes_{};
};

bool create_pipe_pair(handle_t& child_end, handle_t& parent_end, bool child_reads,
                      SECURITY_ATTRIBUTES* attributes, DWORD& error) {
    HANDLE first = nullptr;
    HANDLE second = nullptr;
    if (!attributes || !attributes->lpSecurityDescriptor || !attributes->bInheritHandle ||
        !CreatePipe(&first, &second, attributes, 0)) {
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

bool configure_job(HANDLE job, const python_worker_limits_t& limits, DWORD& error) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION settings{};
    settings.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
        JOB_OBJECT_LIMIT_PROCESS_MEMORY |
        JOB_OBJECT_LIMIT_JOB_MEMORY |
        JOB_OBJECT_LIMIT_PROCESS_TIME;
    settings.BasicLimitInformation.ActiveProcessLimit = 1;
    settings.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = static_cast<LONGLONG>(limits.max_cpu_ms * 10000ULL);
    settings.ProcessMemoryLimit = static_cast<SIZE_T>(limits.max_memory_bytes);
    settings.JobMemoryLimit = static_cast<SIZE_T>(limits.max_memory_bytes);
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &settings, sizeof(settings))) {
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

struct worker_instance_t final {
    handle_t job;
    handle_t process;
    handle_t request_pipe;
    handle_t response_pipe;
    session_material_t session;
    frame_reader_t reader;
    std::uint64_t next_host_sequence = 1;
    std::uint64_t next_worker_sequence = 1;
    DWORD process_id = 0;
};

void terminate_worker(worker_instance_t& worker, DWORD exit_code, python_worker_execution_result_t& result,
                      bool replacement) {
    if (worker.job)
        TerminateJobObject(worker.job.get(), exit_code);
    if (worker.process)
        WaitForSingleObject(worker.process.get(), 1000);
    result.worker_terminated = true;
    result.worker_replaced = replacement;
    SecureZeroMemory(worker.session.key.data(), worker.session.key.size());
    SecureZeroMemory(worker.session.nonce.data(), worker.session.nonce.size());
}

bool launch_worker(const verified_worker_t& verified, const python_worker_limits_t& limits,
                   worker_instance_t& worker, python_worker_execution_result_t& result) {
    handle_t child_read;
    handle_t parent_write;
    handle_t child_write;
    handle_t parent_read;
    DWORD error = ERROR_SUCCESS;
    app_container_t container;
    if (!container.create(verified.manifest_hash, error)) {
        append_diagnostic(result, python_worker_error_code_t::launch_policy_rejected, "python_worker.app_container", "networkless AppContainer cannot be established", error);
        return false;
    }
    restricted_pipe_security_t pipe_security;
    if (!pipe_security.create(container.sid(), error) ||
        !create_pipe_pair(child_read, parent_write, true, pipe_security.attributes(), error) ||
        !create_pipe_pair(child_write, parent_read, false, pipe_security.attributes(), error)) {
        append_diagnostic(result, python_worker_error_code_t::launch_policy_rejected, "python_worker.handles", "restricted pipe handles cannot be created", error);
        return false;
    }
    worker.job.reset(CreateJobObjectW(nullptr, nullptr));
    if (!worker.job || !configure_job(worker.job.get(), limits, error)) {
        append_diagnostic(result, python_worker_error_code_t::launch_policy_rejected, "python_worker.job", "worker job limits cannot be applied", error);
        return false;
    }
    if (!python_worker::wire::make_session(worker.session)) {
        append_diagnostic(result, python_worker_error_code_t::bootstrap_failed, "python_worker.session", "session entropy cannot be acquired", ERROR_CRC);
        return false;
    }
    std::array<HANDLE, 2> inherited_handles{child_read.get(), child_write.get()};
    const std::uint64_t mitigation_policy = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
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
        append_diagnostic(result, python_worker_error_code_t::launch_policy_rejected, "python_worker.attributes", "attribute allocation failed", ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(list, 5, 0, &attribute_size) ||
        !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited_handles.data(),
            sizeof(HANDLE) * inherited_handles.size(), nullptr, nullptr) ||
        !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation_policy,
            sizeof(mitigation_policy), nullptr, nullptr) ||
        !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy,
            sizeof(child_policy), nullptr, nullptr) ||
        !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, job_list, sizeof(job_list), nullptr, nullptr) ||
        !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities, sizeof(capabilities), nullptr, nullptr)) {
        error = GetLastError();
        if (list)
            DeleteProcThreadAttributeList(list);
        SecureZeroMemory(attributes.data(), attributes.size());
        append_diagnostic(result, python_worker_error_code_t::launch_policy_rejected, "python_worker.attributes", "process security attributes were rejected", error);
        return false;
    }
    std::wstring command_line = quote_argument(verified.worker_path);
    command_line.append(L" --aida-analysis-python-worker --read-handle=");
    command_line.append(std::to_wstring(reinterpret_cast<std::uintptr_t>(child_read.get())));
    command_line.append(L" --write-handle=");
    command_line.append(std::to_wstring(reinterpret_cast<std::uintptr_t>(child_write.get())));
    const auto environment = minimal_environment();
    if (!environment) {
        DeleteProcThreadAttributeList(list);
        SecureZeroMemory(attributes.data(), attributes.size());
        append_diagnostic(result, python_worker_error_code_t::launch_policy_rejected, "python_worker.environment", "minimal worker environment cannot be created", GetLastError());
        return false;
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.lpAttributeList = list;
    PROCESS_INFORMATION process{};
    const BOOL launched = CreateProcessW(verified.worker_path.c_str(), command_line.data(), nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        const_cast<wchar_t*>(environment->data()), verified.root_path.c_str(), &startup.StartupInfo, &process);
    error = launched ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(list);
    SecureZeroMemory(attributes.data(), attributes.size());
    SecureZeroMemory(command_line.data(), command_line.size() * sizeof(wchar_t));
    if (!launched) {
        append_diagnostic(result, python_worker_error_code_t::launch_failed, "python_worker.create_process", "restricted worker launch failed", error);
        return false;
    }
    CloseHandle(process.hThread);
    worker.process.reset(process.hProcess);
    worker.process_id = process.dwProcessId;
    worker.request_pipe = std::move(parent_write);
    worker.response_pipe = std::move(parent_read);
    const auto bootstrap = python_worker::wire::encode_bootstrap(worker.session, verified.manifest_hash);
    if (!python_worker::wire::write_all(worker.request_pipe.get(), bootstrap.data(), bootstrap.size(), error)) {
        append_diagnostic(result, python_worker_error_code_t::bootstrap_failed, "python_worker.bootstrap", "bootstrap cannot be delivered", error, true);
        terminate_worker(worker, ERROR_CANCELLED, result, true);
        return false;
    }
    return true;
}

bool send_message(worker_instance_t& worker, const json& message, const python_worker_limits_t& limits, DWORD& error) {
    const std::string payload = message.dump();
    return python_worker::wire::send_frame(worker.request_pipe.get(), worker.session,
        python_worker::wire::frame_kind_t::control, worker.next_host_sequence++,
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), limits.max_frame_bytes, error);
}

enum class wait_state_t : std::uint8_t {
    message,
    cancelled,
    deadline,
    exited,
    protocol_failure
};

wait_state_t wait_for_message(worker_instance_t& worker, const python_worker_execution_request_t& request,
                              const python_worker_limits_t& limits,
                              std::chrono::steady_clock::time_point deadline, frame_t& frame, DWORD& error) {
    while (true) {
        if (request.cancellation && request.cancellation->load(std::memory_order_acquire))
            return wait_state_t::cancelled;
        if (std::chrono::steady_clock::now() >= deadline)
            return wait_state_t::deadline;
        const auto state = worker.reader.poll(worker.response_pipe.get(), worker.session,
            worker.next_worker_sequence, limits.max_frame_bytes, frame, error);
        if (state == read_state_t::complete) {
            ++worker.next_worker_sequence;
            return wait_state_t::message;
        }
        if (state == read_state_t::failure)
            return wait_state_t::protocol_failure;
        const DWORD process_state = WaitForSingleObject(worker.process.get(), 5);
        if (process_state == WAIT_OBJECT_0)
            return wait_state_t::exited;
        if (process_state == WAIT_FAILED) {
            error = GetLastError();
            return wait_state_t::protocol_failure;
        }
        Sleep(5);
    }
}

std::chrono::steady_clock::time_point effective_deadline(const python_worker_execution_request_t& request,
                                                          const python_worker_limits_t& limits) {
    const auto bounded = std::chrono::steady_clock::now() + limits.max_wall_clock;
    return request.deadline && *request.deadline < bounded ? *request.deadline : bounded;
}

bool json_string(const json& value, const char* name, std::size_t maximum, std::string& output) {
    const auto iterator = value.find(name);
    if (iterator == value.end() || !iterator->is_string())
        return false;
    output = iterator->get<std::string>();
    return output.size() <= maximum;
}

bool bounded_output(const json& message, const char* name, std::size_t limit, std::string& output) {
    if (!json_string(message, name, limit, output))
        return false;
    return output.find('\0') == std::string::npos;
}

bool send_cancellation(worker_instance_t& worker, const python_worker_execution_request_t& request,
                       const python_worker_limits_t& limits, std::string reason) {
    DWORD error = ERROR_SUCCESS;
    return send_message(worker, json{{"type", "cancel"}, {"job_id", request.job_id}, {"reason", std::move(reason)}}, limits, error);
}

bool script_path_and_source(const python_worker_launch_contract_t& contract, const python_worker_limits_t& limits,
                            const python_worker_execution_request_t& request, std::string& source,
                            python_worker_execution_result_t& result) {
    if (contract.approved_script_root.empty() || request.script_path.empty()) {
        append_diagnostic(result, python_worker_error_code_t::script_path_rejected, "python_worker.script", "script root or script path is empty");
        return false;
    }
    std::error_code ec;
    const auto root = std::filesystem::absolute(contract.approved_script_root, ec).lexically_normal();
    const auto script = std::filesystem::absolute(request.script_path, ec).lexically_normal();
    if (ec || !std::filesystem::is_directory(root, ec) || ec) {
        append_diagnostic(result, python_worker_error_code_t::script_path_rejected, "python_worker.script_root", "approved script root is unavailable", ERROR_PATH_NOT_FOUND);
        return false;
    }
    if (script.extension() != L".py") {
        append_diagnostic(result, python_worker_error_code_t::script_path_rejected, "python_worker.script", "script must use the .py extension", ERROR_INVALID_NAME);
        return false;
    }
    if (GetFileAttributesW(script.c_str()) == INVALID_FILE_ATTRIBUTES ||
        (GetFileAttributesW(script.c_str()) & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        append_diagnostic(result, python_worker_error_code_t::script_path_rejected, "python_worker.script", "script is not a regular file", GetLastError());
        return false;
    }
    handle_t root_handle(CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    const auto root_path = root_handle ? final_path(root_handle.get()) : std::nullopt;
    handle_t script_file;
    std::vector<std::uint8_t> bytes;
    DWORD error = ERROR_SUCCESS;
    if (!root_path || !read_locked_file(script, limits.max_script_bytes, script_file, bytes, error)) {
        append_diagnostic(result, error == ERROR_FILE_TOO_LARGE ? python_worker_error_code_t::script_too_large : python_worker_error_code_t::script_path_rejected,
            "python_worker.script", "script cannot be read within policy", error);
        return false;
    }
    const auto script_path = final_path(script_file.get());
    if (!script_path || !path_within(*root_path, *script_path)) {
        append_diagnostic(result, python_worker_error_code_t::script_path_rejected, "python_worker.script", "script resolves outside approved script root", ERROR_ACCESS_DENIED);
        return false;
    }
    if (bytes.empty() || std::find(bytes.begin(), bytes.end(), 0) != bytes.end()) {
        append_diagnostic(result, python_worker_error_code_t::script_encoding_invalid, "python_worker.script", "script is empty or contains NUL", ERROR_INVALID_DATA);
        return false;
    }
    source.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    SecureZeroMemory(bytes.data(), bytes.size());
    if (!utf8_to_wide(source)) {
        SecureZeroMemory(source.data(), source.size());
        source.clear();
        append_diagnostic(result, python_worker_error_code_t::script_encoding_invalid, "python_worker.script", "script must be valid UTF-8", ERROR_NO_UNICODE_TRANSLATION);
        return false;
    }
    return true;
}

python_worker_error_code_t protocol_error_for(python_worker::wire::frame_failure_t failure) {
    switch (failure) {
    case python_worker::wire::frame_failure_t::oversize:
        return python_worker_error_code_t::output_limit_exceeded;
    case python_worker::wire::frame_failure_t::none:
    case python_worker::wire::frame_failure_t::io:
    case python_worker::wire::frame_failure_t::malformed_header:
    case python_worker::wire::frame_failure_t::nonce_mismatch:
    case python_worker::wire::frame_failure_t::replay:
    case python_worker::wire::frame_failure_t::authentication_failed:
    case python_worker::wire::frame_failure_t::resource_exhausted:
        return python_worker_error_code_t::protocol_malformed;
    }
    return python_worker_error_code_t::protocol_malformed;
}

bool send_workspace_response(worker_instance_t& worker, const python_worker_execution_request_t& request,
                             const python_worker_limits_t& limits, const json& message,
                             std::uint32_t& request_count, python_worker_execution_result_t& result) {
    if (!message.is_object() || ++request_count > limits.max_workspace_requests ||
        !message.contains("request_id") || !message["request_id"].is_number_unsigned() ||
        message["request_id"].get<std::uint64_t>() > k_workspace_request_id_max ||
        !message.contains("operation") || !message["operation"].is_string()) {
        append_diagnostic(result, python_worker_error_code_t::workspace_api_denied, "python_worker.workspace_request", "workspace request violates the approved API contract", ERROR_INVALID_DATA, true);
        return false;
    }
    const std::string operation = message["operation"].get<std::string>();
    if (!python_workspace_operation_allowed(operation)) {
        append_diagnostic(result, python_worker_error_code_t::workspace_api_denied, "python_worker.workspace_request", "workspace operation is not approved", ERROR_ACCESS_DENIED, true);
        return false;
    }
    python_workspace_query_t query;
    query.operation = operation;
    query.arguments = message.value("arguments", json::object());
    if (!query.arguments.is_object()) {
        append_diagnostic(result, python_worker_error_code_t::workspace_api_denied, "python_worker.workspace_request", "workspace arguments must be an object", ERROR_INVALID_DATA, true);
        return false;
    }
    python_workspace_response_t response;
    if (operation == "metadata") {
        response.success = true;
        response.data = request.workspace_metadata;
    } else if (request.workspace_api) {
        response = request.workspace_api(query, request.cancellation);
    } else {
        response.success = false;
        response.error_code = "WORKSPACE_API_UNAVAILABLE";
        response.error_message = "approved workspace API is unavailable";
    }
    json outbound{{"type", "workspace_response"}, {"request_id", message["request_id"]}, {"success", response.success}};
    if (response.success)
        outbound["data"] = response.data;
    else {
        outbound["error_code"] = response.error_code.empty() ? "WORKSPACE_API_REJECTED" : response.error_code;
        outbound["error_message"] = response.error_message.empty() ? "approved workspace API rejected request" : response.error_message;
    }
    const std::string encoded = outbound.dump();
    if (encoded.size() > limits.max_workspace_response_bytes) {
        append_diagnostic(result, python_worker_error_code_t::workspace_api_failed, "python_worker.workspace_response", "workspace response exceeds output policy", ERROR_FILE_TOO_LARGE, true);
        return false;
    }
    DWORD error = ERROR_SUCCESS;
    if (!send_message(worker, outbound, limits, error)) {
        append_diagnostic(result, python_worker_error_code_t::workspace_api_failed, "python_worker.workspace_response", "workspace response cannot be delivered", error, true);
        return false;
    }
    return true;
}

}

std::string serialize_python_worker_manifest(const python_worker_manifest_t& value) {
    if (!valid_manifest(value))
        return {};
    manifest_writer_t writer;
    writer.u32(k_manifest_magic);
    writer.u32(value.schema_version);
    writer.string(value.worker_relative_path);
    writer.digest(value.worker_binary_hash);
    writer.digest(value.protocol_hash);
    writer.u32(value.capabilities);
    return writer.take();
}

python_worker_manifest_decode_t deserialize_python_worker_manifest(const std::string& value) {
    python_worker_manifest_decode_t result;
    manifest_reader_t reader(value);
    python_worker_manifest_t manifest;
    std::uint32_t magic = 0;
    if (!reader.u32(magic) || magic != k_manifest_magic || !reader.u32(manifest.schema_version) ||
        !reader.string(manifest.worker_relative_path) || !reader.digest(manifest.worker_binary_hash) ||
        !reader.digest(manifest.protocol_hash) || !reader.u32(manifest.capabilities) || !reader.exhausted() ||
        !valid_manifest(manifest)) {
        result.error = "analysis Python worker manifest is truncated or structurally invalid";
        return result;
    }
    result.value = std::move(manifest);
    return result;
}

bool python_workspace_operation_allowed(std::string_view operation) noexcept {
    return operation == "metadata" || operation == "read_bytes" || operation == "find" || operation == "list_functions";
}

bool python_worker_requires_replacement(python_worker_status_t status) noexcept {
    return status == python_worker_status_t::cancelled || status == python_worker_status_t::deadline_exceeded ||
        status == python_worker_status_t::worker_crashed || status == python_worker_status_t::protocol_failure ||
        status == python_worker_status_t::worker_failed;
}

python_worker_host_t::python_worker_host_t(python_worker_launch_contract_t contract, python_worker_limits_t limits)
    : contract_(std::move(contract)), limits_(limits) {}

python_worker_host_t::~python_worker_host_t() {
    stop();
}

python_worker_execution_result_t python_worker_host_t::execute(const python_worker_execution_request_t& request) {
    std::lock_guard lock(mutex_);
    python_worker_execution_result_t result;
    if (stopped_) {
        result.status = python_worker_status_t::host_stopped;
        result.error_code = "PYTHON_WORKER_HOST_STOPPED";
        append_diagnostic(result, python_worker_error_code_t::invalid_request, "python_worker.execute", "worker host is stopped");
        return result;
    }
    if (!valid_limits(limits_) || request.job_id == 0 || !request.workspace_metadata.is_object()) {
        result.error_code = "PYTHON_WORKER_INVALID_REQUEST";
        append_diagnostic(result, python_worker_error_code_t::invalid_request, "python_worker.request", "worker request or limits are invalid");
        return result;
    }
    if (!request.unsafe_approved) {
        result.error_code = "PYTHON_WORKER_UNSAFE_APPROVAL_REQUIRED";
        append_diagnostic(result, python_worker_error_code_t::unsafe_approval_required, "python_worker.approval", "explicit unsafe approval is required");
        return result;
    }
    if (request.cancellation && request.cancellation->load(std::memory_order_acquire)) {
        result.status = python_worker_status_t::cancelled;
        result.error_code = "PYTHON_WORKER_CANCELLED";
        result.worker_replaced = true;
        append_diagnostic(result, python_worker_error_code_t::cancelled, "python_worker.request", "request was cancelled before launch", ERROR_CANCELLED, true);
        return result;
    }
    std::string source;
    if (!script_path_and_source(contract_, limits_, request, source, result)) {
        result.error_code = "PYTHON_WORKER_SCRIPT_REJECTED";
        return result;
    }
    auto verified = verify_worker(contract_, result);
    if (!verified) {
        SecureZeroMemory(source.data(), source.size());
        result.error_code = "PYTHON_WORKER_MANIFEST_REJECTED";
        return result;
    }
    result.worker_generation = ++worker_generation_;
    worker_instance_t worker;
    if (!launch_worker(*verified, limits_, worker, result)) {
        SecureZeroMemory(source.data(), source.size());
        result.status = python_worker_status_t::worker_failed;
        result.error_code = "PYTHON_WORKER_LAUNCH_FAILED";
        return result;
    }
    result.worker_process_id = worker.process_id;
    const auto startup_deadline = std::chrono::steady_clock::now() + limits_.startup_timeout;
    frame_t frame;
    DWORD error = ERROR_SUCCESS;
    const auto hello_wait = wait_for_message(worker, python_worker_execution_request_t{}, limits_, startup_deadline, frame, error);
    if (hello_wait != wait_state_t::message) {
        result.status = hello_wait == wait_state_t::exited ? python_worker_status_t::worker_crashed : python_worker_status_t::protocol_failure;
        result.error_code = "PYTHON_WORKER_HELLO_FAILED";
        append_diagnostic(result, hello_wait == wait_state_t::exited ? python_worker_error_code_t::worker_crashed : python_worker_error_code_t::hello_failed,
            "python_worker.hello", "worker did not provide an authenticated hello", error, true);
        terminate_worker(worker, ERROR_CANCELLED, result, true);
        SecureZeroMemory(source.data(), source.size());
        return result;
    }
    const auto hello = json::parse(std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()), nullptr, false);
    bool hello_valid = !hello.is_discarded() && hello.is_object();
    if (hello_valid) {
        const auto hello_type = hello.find("type");
        const auto hello_worker = hello.find("worker");
        const auto hello_hash = hello.find("manifest_hash");
        hello_valid = hello_type != hello.end() && hello_worker != hello.end() && hello_hash != hello.end() &&
            hello_type->is_string() && hello_worker->is_string() && hello_hash->is_string() &&
            hello_type->get<std::string>() == "hello" && hello_worker->get<std::string>() == "analysis_python" &&
            hello_hash->get<std::string>() == verified->manifest_hash.to_hex();
    }
    if (!hello_valid) {
        result.status = python_worker_status_t::protocol_failure;
        result.error_code = "PYTHON_WORKER_HELLO_INVALID";
        append_diagnostic(result, python_worker_error_code_t::hello_failed, "python_worker.hello", "worker hello violates identity contract", ERROR_INVALID_DATA, true);
        terminate_worker(worker, ERROR_CRC, result, true);
        SecureZeroMemory(source.data(), source.size());
        return result;
    }
    json execution{{"type", "execute"}, {"job_id", request.job_id}, {"script", source},
        {"workspace", request.workspace_metadata}, {"max_output_bytes", limits_.max_output_bytes},
        {"max_workspace_requests", limits_.max_workspace_requests}};
    SecureZeroMemory(source.data(), source.size());
    if (!send_message(worker, execution, limits_, error)) {
        result.status = python_worker_status_t::protocol_failure;
        result.error_code = "PYTHON_WORKER_EXECUTE_DISPATCH_FAILED";
        append_diagnostic(result, python_worker_error_code_t::bootstrap_failed, "python_worker.execute", "execution request cannot be delivered", error, true);
        terminate_worker(worker, ERROR_CANCELLED, result, true);
        return result;
    }
    const auto deadline = effective_deadline(request, limits_);
    std::uint32_t workspace_requests = 0;
    while (true) {
        const auto state = wait_for_message(worker, request, limits_, deadline, frame, error);
        if (state == wait_state_t::cancelled || state == wait_state_t::deadline) {
            const bool deadline_exceeded = state == wait_state_t::deadline;
            send_cancellation(worker, request, limits_, deadline_exceeded ? "deadline_exceeded" : "cancelled");
            frame_t ignored;
            const auto grace = wait_for_message(worker, python_worker_execution_request_t{}, limits_,
                std::chrono::steady_clock::now() + limits_.cancellation_grace, ignored, error);
            result.status = deadline_exceeded ? python_worker_status_t::deadline_exceeded : python_worker_status_t::cancelled;
            result.error_code = deadline_exceeded ? "PYTHON_WORKER_DEADLINE_EXCEEDED" : "PYTHON_WORKER_CANCELLED";
            append_diagnostic(result, deadline_exceeded ? python_worker_error_code_t::deadline_exceeded : python_worker_error_code_t::cancelled,
                "python_worker.cancel", grace == wait_state_t::message ? "worker cancellation acknowledged" : "worker cancellation requires replacement",
                ERROR_CANCELLED, true);
            terminate_worker(worker, ERROR_CANCELLED, result, true);
            return result;
        }
        if (state == wait_state_t::exited) {
            DWORD exit_code = 0;
            GetExitCodeProcess(worker.process.get(), &exit_code);
            result.status = python_worker_status_t::worker_crashed;
            result.error_code = "PYTHON_WORKER_CRASHED";
            append_diagnostic(result, python_worker_error_code_t::worker_crashed, "python_worker.wait", "worker exited before terminal result", exit_code, true);
            terminate_worker(worker, exit_code, result, true);
            return result;
        }
        if (state == wait_state_t::protocol_failure) {
            result.status = python_worker_status_t::protocol_failure;
            result.error_code = "PYTHON_WORKER_PROTOCOL_FAILURE";
            append_diagnostic(result, protocol_error_for(worker.reader.failure()), "python_worker.response", "worker frame violated authenticated protocol", error, true);
            terminate_worker(worker, ERROR_CRC, result, true);
            return result;
        }
        const auto message = json::parse(std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()), nullptr, false);
        if (message.is_discarded() || !message.is_object() || !message.contains("type") || !message["type"].is_string()) {
            result.status = python_worker_status_t::protocol_failure;
            result.error_code = "PYTHON_WORKER_PROTOCOL_FAILURE";
            append_diagnostic(result, python_worker_error_code_t::protocol_malformed, "python_worker.response", "worker response is not a valid object", ERROR_INVALID_DATA, true);
            terminate_worker(worker, ERROR_CRC, result, true);
            return result;
        }
        const std::string type = message["type"].get<std::string>();
        if (type == "workspace_request") {
            if (!send_workspace_response(worker, request, limits_, message, workspace_requests, result)) {
                result.status = python_worker_status_t::worker_failed;
                result.error_code = "PYTHON_WORKER_WORKSPACE_API_REJECTED";
                terminate_worker(worker, ERROR_ACCESS_DENIED, result, true);
                return result;
            }
            continue;
        }
        if (type == "heartbeat")
            continue;
        if (type != "result" || !message.contains("job_id") || !message["job_id"].is_number_unsigned() ||
            message["job_id"].get<std::uint64_t>() != request.job_id) {
            result.status = python_worker_status_t::protocol_failure;
            result.error_code = "PYTHON_WORKER_PROTOCOL_FAILURE";
            append_diagnostic(result, python_worker_error_code_t::protocol_malformed, "python_worker.response", "worker sent an invalid terminal response", ERROR_INVALID_DATA, true);
            terminate_worker(worker, ERROR_CRC, result, true);
            return result;
        }
        if (!bounded_output(message, "result", limits_.max_output_bytes, result.result) ||
            !bounded_output(message, "stdout", limits_.max_output_bytes, result.stdout_text) ||
            !bounded_output(message, "stderr", limits_.max_output_bytes, result.stderr_text) ||
            result.result.size() + result.stdout_text.size() + result.stderr_text.size() > limits_.max_output_bytes) {
            result.status = python_worker_status_t::protocol_failure;
            result.error_code = "PYTHON_WORKER_OUTPUT_LIMIT_EXCEEDED";
            append_diagnostic(result, python_worker_error_code_t::output_limit_exceeded, "python_worker.result", "worker output exceeds the configured limit", ERROR_FILE_TOO_LARGE, true);
            terminate_worker(worker, ERROR_FILE_TOO_LARGE, result, true);
            return result;
        }
        const auto status = message.find("status");
        if (status == message.end() || !status->is_string()) {
            result.status = python_worker_status_t::protocol_failure;
            result.error_code = "PYTHON_WORKER_PROTOCOL_FAILURE";
            append_diagnostic(result, python_worker_error_code_t::protocol_malformed, "python_worker.result", "terminal status is missing or invalid", ERROR_INVALID_DATA, true);
            terminate_worker(worker, ERROR_CRC, result, true);
            return result;
        }
        const std::string terminal_status = status->get<std::string>();
        if (terminal_status == "ok") {
            result.status = python_worker_status_t::completed;
            result.error_code.clear();
            terminate_worker(worker, ERROR_SUCCESS, result, false);
            return result;
        }
        result.status = terminal_status == "cancelled" ? python_worker_status_t::cancelled : python_worker_status_t::worker_failed;
        const auto error_code = message.find("error_code");
        result.error_code = error_code != message.end() && error_code->is_string() && error_code->get<std::string>().size() <= 128
            ? error_code->get<std::string>()
            : terminal_status == "cancelled" ? "PYTHON_WORKER_CANCELLED" : "PYTHON_WORKER_SCRIPT_FAILED";
        append_diagnostic(result, terminal_status == "cancelled" ? python_worker_error_code_t::cancelled : python_worker_error_code_t::worker_crashed,
            "python_worker.result", "worker reported a terminal failure", ERROR_SUCCESS, true);
        terminate_worker(worker, ERROR_SUCCESS, result, true);
        return result;
    }
}

void python_worker_host_t::stop() noexcept {
    std::lock_guard lock(mutex_);
    stopped_ = true;
}

std::uint64_t python_worker_host_t::worker_generation() const noexcept {
    std::lock_guard lock(mutex_);
    return worker_generation_;
}

}
