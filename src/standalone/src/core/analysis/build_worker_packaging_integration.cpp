#include "build_worker_packaging_integration.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

namespace aida::analysis::c03 {

namespace {

using json = nlohmann::json;

struct stable_code_entry_t final {
    build_worker_error_code_t code;
    std::string_view name;
};

constexpr stable_code_entry_t k_stable_codes[] = {
    {build_worker_error_code_t::none, "none"},
    {build_worker_error_code_t::invalid_argument, "invalid_argument"},
    {build_worker_error_code_t::unsafe_path, "unsafe_path"},
    {build_worker_error_code_t::path_escape, "path_escape"},
    {build_worker_error_code_t::reparse_point, "reparse_point"},
    {build_worker_error_code_t::hardlink_forbidden, "hardlink_forbidden"},
    {build_worker_error_code_t::duplicate_entry, "duplicate_entry"},
    {build_worker_error_code_t::file_missing, "file_missing"},
    {build_worker_error_code_t::file_type_invalid, "file_type_invalid"},
    {build_worker_error_code_t::file_too_large, "file_too_large"},
    {build_worker_error_code_t::file_changed, "file_changed"},
    {build_worker_error_code_t::file_read_failed, "file_read_failed"},
    {build_worker_error_code_t::hash_failed, "hash_failed"},
    {build_worker_error_code_t::hash_mismatch, "hash_mismatch"},
    {build_worker_error_code_t::size_mismatch, "size_mismatch"},
    {build_worker_error_code_t::malformed_json, "malformed_json"},
    {build_worker_error_code_t::schema_mismatch, "schema_mismatch"},
    {build_worker_error_code_t::remote_reference_forbidden, "remote_reference_forbidden"},
    {build_worker_error_code_t::artifact_inventory_mismatch, "artifact_inventory_mismatch"},
    {build_worker_error_code_t::worker_inventory_mismatch, "worker_inventory_mismatch"},
    {build_worker_error_code_t::dependency_graph_invalid, "dependency_graph_invalid"},
    {build_worker_error_code_t::notice_missing, "notice_missing"},
    {build_worker_error_code_t::forbidden_link_detected, "forbidden_link_detected"},
    {build_worker_error_code_t::protocol_mismatch, "protocol_mismatch"},
    {build_worker_error_code_t::containment_policy_mismatch, "containment_policy_mismatch"},
    {build_worker_error_code_t::protector_receipt_invalid, "protector_receipt_invalid"},
    {build_worker_error_code_t::signature_receipt_invalid, "signature_receipt_invalid"},
    {build_worker_error_code_t::authenticode_verification_failed, "authenticode_verification_failed"},
    {build_worker_error_code_t::source_authority_invalid, "source_authority_invalid"},
    {build_worker_error_code_t::online_fetch_marker, "online_fetch_marker"},
    {build_worker_error_code_t::package_policy_violation, "package_policy_violation"},
    {build_worker_error_code_t::named_stream_forbidden, "named_stream_forbidden"},
    {build_worker_error_code_t::resource_file_limit, "resource_file_limit"},
    {build_worker_error_code_t::resource_directory_limit, "resource_directory_limit"},
    {build_worker_error_code_t::resource_entry_limit, "resource_entry_limit"},
    {build_worker_error_code_t::resource_depth_limit, "resource_depth_limit"},
    {build_worker_error_code_t::resource_path_limit, "resource_path_limit"},
    {build_worker_error_code_t::resource_file_bytes_limit, "resource_file_bytes_limit"},
    {build_worker_error_code_t::resource_total_bytes_limit, "resource_total_bytes_limit"},
    {build_worker_error_code_t::resource_stream_limit, "resource_stream_limit"},
    {build_worker_error_code_t::directory_cycle, "directory_cycle"},
    {build_worker_error_code_t::required_external_artifact_missing, "required_external_artifact_missing"},
    {build_worker_error_code_t::cancelled, "cancelled"},
    {build_worker_error_code_t::deadline_exceeded, "deadline_exceeded"},
    {build_worker_error_code_t::internal_error, "internal_error"},
};

std::string_view stable_name(build_worker_error_code_t code) noexcept {
    for (const auto& entry : k_stable_codes) {
        if (entry.code == code)
            return entry.name;
    }
    return "unknown";
}

build_worker_error_t error(build_worker_error_code_t code,
                           std::filesystem::path path = {},
                           std::string detail = {},
                           std::uint64_t expected = 0,
                           std::uint64_t actual = 0) {
    return {code, stable_name(code), std::move(path), std::move(detail), expected, actual};
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(character >= 'A' && character <= 'Z'
            ? character + ('a' - 'A')
            : character);
    });
    return value;
}

bool valid_sha256(std::string_view value) noexcept {
    if (value.size() != 64)
        return false;
    return std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9') ||
               (character >= 'a' && character <= 'f');
    });
}

bool fixed_time_equal(std::string_view left, std::string_view right) noexcept {
    if (left.size() != right.size())
        return false;
    unsigned char difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index)
        difference |= static_cast<unsigned char>(left[index] ^ right[index]);
    return difference == 0;
}

bool decode_sha256(std::string_view value, std::array<std::uint8_t, 32>& output) noexcept {
    if (!valid_sha256(value))
        return false;
    const auto nibble = [](char character) noexcept -> std::uint8_t {
        if (character >= '0' && character <= '9')
            return static_cast<std::uint8_t>(character - '0');
        return static_cast<std::uint8_t>(character - 'a' + 10);
    };
    for (std::size_t index = 0; index < output.size(); ++index)
        output[index] = static_cast<std::uint8_t>((nibble(value[index * 2]) << 4U) |
                                                  nibble(value[index * 2 + 1]));
    return true;
}

std::string hex_encode(const std::array<std::uint8_t, 32>& digest) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result(64, '0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        result[index * 2] = alphabet[digest[index] >> 4U];
        result[index * 2 + 1] = alphabet[digest[index] & 0x0fU];
    }
    return result;
}

struct file_evidence_t final {
    std::uint64_t size = 0;
    std::string sha256;
    std::string content;
    std::filesystem::path path;
    BY_HANDLE_FILE_INFORMATION identity{};
    std::shared_ptr<void> lock;
};

struct immutable_generation_context_t final {
    std::map<std::wstring, file_evidence_t> files;
    std::vector<std::shared_ptr<void>> directories;
};

thread_local immutable_generation_context_t* active_generation = nullptr;

struct package_verification_control_t final {
    const package_verification_request_t* request = nullptr;
    std::chrono::steady_clock::time_point deadline;
};

thread_local package_verification_control_t* active_verification_control = nullptr;

class package_verification_control_scope_t final {
public:
    explicit package_verification_control_scope_t(package_verification_control_t& control) noexcept
        : previous_(active_verification_control) {
        active_verification_control = &control;
    }

    ~package_verification_control_scope_t() {
        active_verification_control = previous_;
    }

    package_verification_control_scope_t(const package_verification_control_scope_t&) = delete;
    package_verification_control_scope_t& operator=(const package_verification_control_scope_t&) = delete;

private:
    package_verification_control_t* previous_ = nullptr;
};

build_worker_result_t<void> poll_verification_control(
    const std::filesystem::path& path = {}, std::string detail = {}) {
    if (!active_verification_control || !active_verification_control->request)
        return build_worker_result_t<void>::success();
    const auto& request = *active_verification_control->request;
    if (request.cancellation_requested) {
        try {
            if (request.cancellation_requested())
                return build_worker_result_t<void>::failure(
                    error(build_worker_error_code_t::cancelled, path, std::move(detail)));
        } catch (const std::exception& exception) {
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::internal_error, path, exception.what()));
        } catch (...) {
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::internal_error, path,
                      "cancellation_callback"));
        }
    }
    if (std::chrono::steady_clock::now() >= active_verification_control->deadline)
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::deadline_exceeded, path, std::move(detail)));
    return build_worker_result_t<void>::success();
}

class immutable_generation_scope_t final {
public:
    explicit immutable_generation_scope_t(immutable_generation_context_t& generation) noexcept
        : previous_(active_generation) {
        active_generation = &generation;
    }

    ~immutable_generation_scope_t() {
        active_generation = previous_;
    }

    immutable_generation_scope_t(const immutable_generation_scope_t&) = delete;
    immutable_generation_scope_t& operator=(const immutable_generation_scope_t&) = delete;

private:
    immutable_generation_context_t* previous_ = nullptr;
};

struct bcrypt_algorithm_t final {
    BCRYPT_ALG_HANDLE handle = nullptr;

    ~bcrypt_algorithm_t() {
        if (handle)
            BCryptCloseAlgorithmProvider(handle, 0);
    }
};

struct bcrypt_hash_t final {
    BCRYPT_HASH_HANDLE handle = nullptr;

    ~bcrypt_hash_t() {
        if (handle)
            BCryptDestroyHash(handle);
    }
};

struct win_handle_t final {
    HANDLE handle = INVALID_HANDLE_VALUE;

    ~win_handle_t() {
        if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
            CloseHandle(handle);
    }
};

struct find_handle_t final {
    HANDLE handle = INVALID_HANDLE_VALUE;

    ~find_handle_t() {
        if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
            FindClose(handle);
    }
};

struct certificate_store_t final {
    HCERTSTORE handle = nullptr;

    ~certificate_store_t() {
        if (handle)
            CertCloseStore(handle, 0);
    }
};

struct crypt_message_t final {
    HCRYPTMSG handle = nullptr;

    ~crypt_message_t() {
        if (handle)
            CryptMsgClose(handle);
    }
};

struct certificate_context_t final {
    PCCERT_CONTEXT context = nullptr;

    ~certificate_context_t() {
        if (context)
            CertFreeCertificateContext(context);
    }
};

build_worker_result_t<std::size_t> verify_stream_inventory(
    const std::filesystem::path& path) {
    WIN32_FIND_STREAM_DATA stream_data{};
    find_handle_t stream;
    stream.handle = FindFirstStreamW(path.c_str(), FindStreamInfoStandard, &stream_data, 0);
    if (stream.handle == INVALID_HANDLE_VALUE) {
        const DWORD last_error = GetLastError();
        return build_worker_result_t<std::size_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path,
                  "FindFirstStreamW", 0, last_error));
    }
    std::size_t count = 0;
    for (;;) {
        auto control = poll_verification_control(path, "stream_inventory");
        if (!control)
            return build_worker_result_t<std::size_t>::failure(control.error());
        ++count;
        if (count > k_default_stream_count_limit)
            return build_worker_result_t<std::size_t>::failure(
                error(build_worker_error_code_t::resource_stream_limit, path,
                      "stream_count", k_default_stream_count_limit, count));
        if (std::wstring_view(stream_data.cStreamName) != L"::$DATA")
            return build_worker_result_t<std::size_t>::failure(
                error(build_worker_error_code_t::named_stream_forbidden, path));
        if (!FindNextStreamW(stream.handle, &stream_data)) {
            const DWORD last_error = GetLastError();
            if (last_error == ERROR_HANDLE_EOF)
                break;
            return build_worker_result_t<std::size_t>::failure(
                error(build_worker_error_code_t::file_read_failed, path,
                      "FindNextStreamW", 0, last_error));
        }
    }
    return build_worker_result_t<std::size_t>::success(count);
}

build_worker_result_t<void> retain_locked_content(file_evidence_t& evidence) {
    if (!evidence.content.empty())
        return build_worker_result_t<void>::success();
    if (!evidence.lock || evidence.size == 0 ||
        evidence.size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::file_read_failed, evidence.path,
                  "immutable_generation_content"));
    const auto handle = static_cast<HANDLE>(evidence.lock.get());
    LARGE_INTEGER beginning{};
    if (!SetFilePointerEx(handle, beginning, nullptr, FILE_BEGIN))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::file_read_failed, evidence.path,
                  "SetFilePointerEx", 0, GetLastError()));
    evidence.content.resize(static_cast<std::size_t>(evidence.size));
    std::uint64_t total = 0;
    while (total < evidence.size) {
        auto control = poll_verification_control(evidence.path, "retained_content");
        if (!control)
            return build_worker_result_t<void>::failure(control.error());
        const DWORD requested = static_cast<DWORD>((std::min)(
            evidence.size - total,
            static_cast<std::uint64_t>((std::numeric_limits<DWORD>::max)())));
        DWORD received = 0;
        if (!ReadFile(handle, evidence.content.data() + static_cast<std::size_t>(total),
                      requested, &received, nullptr) || received == 0)
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::file_changed, evidence.path,
                      "ReadFile:immutable_generation", evidence.size, total));
        total += received;
    }
    return build_worker_result_t<void>::success();
}

build_worker_result_t<file_evidence_t> inspect_regular_file(
    const std::filesystem::path& path, std::uint64_t maximum_bytes, bool retain_content) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::file_missing, path, "GetFileAttributesW", 0, GetLastError()));
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::reparse_point, path));
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::file_type_invalid, path));
    auto streams = verify_stream_inventory(path);
    if (!streams)
        return build_worker_result_t<file_evidence_t>::failure(streams.error());
    if (active_generation) {
        const auto cached = active_generation->files.find(path.native());
        if (cached != active_generation->files.end()) {
            if (cached->second.size > maximum_bytes)
                return build_worker_result_t<file_evidence_t>::failure(
                    error(build_worker_error_code_t::file_too_large, path, {},
                          maximum_bytes, cached->second.size));
            if (retain_content) {
                auto retained = retain_locked_content(cached->second);
                if (!retained)
                    return build_worker_result_t<file_evidence_t>::failure(retained.error());
            }
            return build_worker_result_t<file_evidence_t>::success(cached->second);
        }
    }

    win_handle_t file;
    file.handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
                              FILE_FLAG_OPEN_REPARSE_POINT,
                              nullptr);
    if (file.handle == INVALID_HANDLE_VALUE)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path, "CreateFileW", 0, GetLastError()));

    FILE_ATTRIBUTE_TAG_INFO attribute_info{};
    if (!GetFileInformationByHandleEx(file.handle, FileAttributeTagInfo, &attribute_info,
                                      sizeof(attribute_info)))
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path,
                  "GetFileInformationByHandleEx", 0, GetLastError()));
    if ((attribute_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::reparse_point, path));
    if ((attribute_info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::file_type_invalid, path));

    BY_HANDLE_FILE_INFORMATION identity_before{};
    if (!GetFileInformationByHandle(file.handle, &identity_before))
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path,
                  "GetFileInformationByHandle", 0, GetLastError()));
    if (identity_before.nNumberOfLinks != 1)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::hardlink_forbidden, path,
                  "nNumberOfLinks", 1, identity_before.nNumberOfLinks));

    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file.handle, &length) || length.QuadPart < 0)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path, "GetFileSizeEx", 0, GetLastError()));
    const auto size = static_cast<std::uint64_t>(length.QuadPart);
    if (size == 0 || size > maximum_bytes)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::file_too_large, path, {}, maximum_bytes, size));

    bcrypt_algorithm_t algorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_SHA256_ALGORITHM,
                                                   nullptr, 0);
    if (status < 0)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::hash_failed, path, "BCryptOpenAlgorithmProvider", 0,
                  static_cast<std::uint32_t>(status)));

    DWORD object_size = 0;
    DWORD returned = 0;
    status = BCryptGetProperty(algorithm.handle, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                               &returned, 0);
    if (status < 0 || object_size == 0 ||
        returned != static_cast<DWORD>(sizeof(object_size)))
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::hash_failed, path, "BCryptGetProperty", 0,
                  static_cast<std::uint32_t>(status)));
    std::vector<std::uint8_t> hash_object(object_size);
    bcrypt_hash_t hash;
    status = BCryptCreateHash(algorithm.handle, &hash.handle, hash_object.data(), object_size,
                              nullptr, 0, 0);
    if (status < 0)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::hash_failed, path, "BCryptCreateHash", 0,
                  static_cast<std::uint32_t>(status)));

    file_evidence_t result;
    result.size = size;
    if (retain_content) {
        if (size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
            return build_worker_result_t<file_evidence_t>::failure(
                error(build_worker_error_code_t::file_too_large, path));
        result.content.reserve(static_cast<std::size_t>(size));
    }

    std::vector<std::uint8_t> buffer(1024U * 1024U);
    std::uint64_t total = 0;
    while (total < size) {
        auto control = poll_verification_control(path, "artifact_hash");
        if (!control)
            return build_worker_result_t<file_evidence_t>::failure(control.error());
        const DWORD requested = static_cast<DWORD>((std::min)(
            static_cast<std::uint64_t>(buffer.size()), size - total));
        DWORD received = 0;
        if (!ReadFile(file.handle, buffer.data(), requested, &received, nullptr) || received == 0)
            return build_worker_result_t<file_evidence_t>::failure(
                error(build_worker_error_code_t::file_changed, path, "ReadFile", size, total));
        status = BCryptHashData(hash.handle, buffer.data(), received, 0);
        if (status < 0)
            return build_worker_result_t<file_evidence_t>::failure(
                error(build_worker_error_code_t::hash_failed, path, "BCryptHashData", 0,
                      static_cast<std::uint32_t>(status)));
        if (retain_content)
            result.content.append(reinterpret_cast<const char*>(buffer.data()), received);
        total += received;
    }

    std::array<std::uint8_t, 32> digest{};
    status = BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (status < 0)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::hash_failed, path, "BCryptFinishHash", 0,
                  static_cast<std::uint32_t>(status)));
    BY_HANDLE_FILE_INFORMATION identity_after{};
    if (!GetFileInformationByHandle(file.handle, &identity_after) ||
        identity_before.dwVolumeSerialNumber != identity_after.dwVolumeSerialNumber ||
        identity_before.nFileIndexHigh != identity_after.nFileIndexHigh ||
        identity_before.nFileIndexLow != identity_after.nFileIndexLow ||
        identity_before.nFileSizeHigh != identity_after.nFileSizeHigh ||
        identity_before.nFileSizeLow != identity_after.nFileSizeLow ||
        identity_after.nNumberOfLinks != 1 ||
        identity_before.ftLastWriteTime.dwHighDateTime !=
            identity_after.ftLastWriteTime.dwHighDateTime ||
        identity_before.ftLastWriteTime.dwLowDateTime !=
            identity_after.ftLastWriteTime.dwLowDateTime)
        return build_worker_result_t<file_evidence_t>::failure(
            error(build_worker_error_code_t::file_changed, path,
                  "GetFileInformationByHandle"));
    result.sha256 = hex_encode(digest);
    result.path = path;
    result.identity = identity_after;
    result.lock = std::shared_ptr<void>(
        file.handle, [](void* handle) {
            if (handle && handle != INVALID_HANDLE_VALUE)
                CloseHandle(static_cast<HANDLE>(handle));
        });
    file.handle = INVALID_HANDLE_VALUE;
    if (active_generation) {
        auto inserted = active_generation->files.emplace(path.native(), std::move(result));
        if (!inserted.second)
            return build_worker_result_t<file_evidence_t>::failure(
                error(build_worker_error_code_t::internal_error, path,
                      "immutable_generation_duplicate"));
        return build_worker_result_t<file_evidence_t>::success(inserted.first->second);
    }
    return build_worker_result_t<file_evidence_t>::success(std::move(result));
}

build_worker_result_t<std::string> rehash_locked_generation_file(
    const file_evidence_t& evidence) {
    if (!evidence.lock || evidence.size == 0)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::internal_error, evidence.path,
                  "immutable_generation_hash_lock"));
    const auto handle = static_cast<HANDLE>(evidence.lock.get());
    LARGE_INTEGER beginning{};
    if (!SetFilePointerEx(handle, beginning, nullptr, FILE_BEGIN))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::file_read_failed, evidence.path,
                  "SetFilePointerEx:immutable_generation_hash", 0, GetLastError()));

    bcrypt_algorithm_t algorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_SHA256_ALGORITHM,
                                                   nullptr, 0);
    if (status < 0)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::hash_failed, evidence.path,
                  "BCryptOpenAlgorithmProvider:immutable_generation", 0,
                  static_cast<std::uint32_t>(status)));
    DWORD object_size = 0;
    DWORD returned = 0;
    status = BCryptGetProperty(algorithm.handle, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                               &returned, 0);
    if (status < 0 || object_size == 0 ||
        returned != static_cast<DWORD>(sizeof(object_size)))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::hash_failed, evidence.path,
                  "BCryptGetProperty:immutable_generation", 0,
                  static_cast<std::uint32_t>(status)));
    std::vector<std::uint8_t> hash_object(object_size);
    bcrypt_hash_t hash;
    status = BCryptCreateHash(algorithm.handle, &hash.handle, hash_object.data(), object_size,
                              nullptr, 0, 0);
    if (status < 0)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::hash_failed, evidence.path,
                  "BCryptCreateHash:immutable_generation", 0,
                  static_cast<std::uint32_t>(status)));

    std::vector<std::uint8_t> buffer(1024U * 1024U);
    std::uint64_t total = 0;
    while (total < evidence.size) {
        auto control = poll_verification_control(evidence.path, "immutable_hash");
        if (!control)
            return build_worker_result_t<std::string>::failure(control.error());
        const DWORD requested = static_cast<DWORD>((std::min)(
            static_cast<std::uint64_t>(buffer.size()), evidence.size - total));
        DWORD received = 0;
        if (!ReadFile(handle, buffer.data(), requested, &received, nullptr) || received == 0)
            return build_worker_result_t<std::string>::failure(
                error(build_worker_error_code_t::file_changed, evidence.path,
                      "ReadFile:immutable_generation_hash", evidence.size, total));
        status = BCryptHashData(hash.handle, buffer.data(), received, 0);
        if (status < 0)
            return build_worker_result_t<std::string>::failure(
                error(build_worker_error_code_t::hash_failed, evidence.path,
                      "BCryptHashData:immutable_generation", 0,
                      static_cast<std::uint32_t>(status)));
        total += received;
    }
    std::array<std::uint8_t, 32> digest{};
    status = BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (status < 0)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::hash_failed, evidence.path,
                  "BCryptFinishHash:immutable_generation", 0,
                  static_cast<std::uint32_t>(status)));
    return build_worker_result_t<std::string>::success(hex_encode(digest));
}

build_worker_result_t<void> revalidate_immutable_generation(
    const immutable_generation_context_t& generation) {
    for (const auto& entry : generation.files) {
        const auto& evidence = entry.second;
        auto control = poll_verification_control(evidence.path,
                                                 "immutable_revalidation");
        if (!control)
            return build_worker_result_t<void>::failure(control.error());
        if (!evidence.lock)
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::internal_error, evidence.path,
                      "immutable_generation_lock"));
        BY_HANDLE_FILE_INFORMATION identity{};
        const auto handle = static_cast<HANDLE>(evidence.lock.get());
        if (!GetFileInformationByHandle(handle, &identity))
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::file_read_failed, evidence.path,
                      "GetFileInformationByHandle:immutable_generation", 0,
                      GetLastError()));
        const auto& expected = evidence.identity;
        if (identity.dwVolumeSerialNumber != expected.dwVolumeSerialNumber ||
            identity.nFileIndexHigh != expected.nFileIndexHigh ||
            identity.nFileIndexLow != expected.nFileIndexLow ||
            identity.nFileSizeHigh != expected.nFileSizeHigh ||
            identity.nFileSizeLow != expected.nFileSizeLow ||
            identity.nNumberOfLinks != 1 || expected.nNumberOfLinks != 1 ||
            identity.ftLastWriteTime.dwHighDateTime !=
                expected.ftLastWriteTime.dwHighDateTime ||
            identity.ftLastWriteTime.dwLowDateTime !=
                expected.ftLastWriteTime.dwLowDateTime)
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::file_changed, evidence.path,
                      "immutable_generation_identity"));
        win_handle_t current;
        current.handle = CreateFileW(
            evidence.path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (current.handle == INVALID_HANDLE_VALUE)
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::file_changed, evidence.path,
                      "CreateFileW:immutable_generation_path", 0, GetLastError()));
        BY_HANDLE_FILE_INFORMATION current_identity{};
        if (!GetFileInformationByHandle(current.handle, &current_identity) ||
            current_identity.dwVolumeSerialNumber != expected.dwVolumeSerialNumber ||
            current_identity.nFileIndexHigh != expected.nFileIndexHigh ||
            current_identity.nFileIndexLow != expected.nFileIndexLow ||
            current_identity.nNumberOfLinks != 1)
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::file_changed, evidence.path,
                      "immutable_generation_path_identity"));
        auto streams = verify_stream_inventory(evidence.path);
        if (!streams)
            return build_worker_result_t<void>::failure(streams.error());
        auto current_hash = rehash_locked_generation_file(evidence);
        if (!current_hash)
            return build_worker_result_t<void>::failure(current_hash.error());
        if (!fixed_time_equal(current_hash.value(), evidence.sha256))
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::file_changed, evidence.path,
                      "immutable_generation_hash"));
    }
    return build_worker_result_t<void>::success();
}

build_worker_result_t<std::string> sha256_text(std::string_view text) {
    bcrypt_algorithm_t algorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_SHA256_ALGORITHM,
                                                   nullptr, 0);
    if (status < 0)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::hash_failed, {},
                  "BCryptOpenAlgorithmProvider:text", 0,
                  static_cast<std::uint32_t>(status)));
    DWORD object_size = 0;
    DWORD returned = 0;
    status = BCryptGetProperty(algorithm.handle, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                               &returned, 0);
    if (status < 0 || object_size == 0 ||
        returned != static_cast<DWORD>(sizeof(object_size)))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::hash_failed, {}, "BCryptGetProperty:text", 0,
                  static_cast<std::uint32_t>(status)));
    std::vector<std::uint8_t> hash_object(object_size);
    bcrypt_hash_t hash;
    status = BCryptCreateHash(algorithm.handle, &hash.handle, hash_object.data(), object_size,
                              nullptr, 0, 0);
    if (status < 0)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::hash_failed, {}, "BCryptCreateHash:text", 0,
                  static_cast<std::uint32_t>(status)));
    if (!text.empty()) {
        auto* data = reinterpret_cast<PUCHAR>(const_cast<char*>(text.data()));
        if (text.size() > static_cast<std::size_t>((std::numeric_limits<ULONG>::max)()))
            return build_worker_result_t<std::string>::failure(
                error(build_worker_error_code_t::file_too_large, {}, "SHA-256 text"));
        status = BCryptHashData(hash.handle, data, static_cast<ULONG>(text.size()), 0);
        if (status < 0)
            return build_worker_result_t<std::string>::failure(
                error(build_worker_error_code_t::hash_failed, {}, "BCryptHashData:text", 0,
                      static_cast<std::uint32_t>(status)));
    }
    std::array<std::uint8_t, 32> digest{};
    status = BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (status < 0)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::hash_failed, {}, "BCryptFinishHash:text", 0,
                  static_cast<std::uint32_t>(status)));
    return build_worker_result_t<std::string>::success(hex_encode(digest));
}

build_worker_result_t<std::filesystem::path> exact_existing_path(
    const std::filesystem::path& path, bool require_directory) {
    const auto& input = path.native();
    if (!path.is_absolute() || input.size() < 3 || input[1] != L':' ||
        input[0] < L'A' || input[0] > L'Z' || input[2] != L'\\' ||
        input.find(L'/') != std::wstring::npos || input.rfind(L"\\\\?\\", 0) == 0 ||
        (input.size() > 3 && input.back() == L'\\'))
        return build_worker_result_t<std::filesystem::path>::failure(
            error(build_worker_error_code_t::unsafe_path, path, "raw_absolute_path"));
    std::array<wchar_t, 32768> full_buffer{};
    const DWORD full_length = GetFullPathNameW(path.c_str(),
        static_cast<DWORD>(full_buffer.size()), full_buffer.data(), nullptr);
    if (full_length == 0 || full_length >= full_buffer.size() ||
        std::wstring_view(full_buffer.data(), full_length) !=
            std::wstring_view(input.data(), input.size()))
        return build_worker_result_t<std::filesystem::path>::failure(
            error(build_worker_error_code_t::unsafe_path, path, "normalized_absolute_path"));
    std::filesystem::path current = path.root_path();
    std::vector<std::filesystem::path> components;
    components.emplace_back(current);
    for (const auto& component : path.relative_path()) {
        const auto& text = component.native();
        if (text.empty() || text == L"." || text == L".." ||
            text.back() == L'.' || text.back() == L' ' || text.find(L':') != std::wstring::npos ||
            std::any_of(text.begin(), text.end(), [](const wchar_t character) {
                return character < 0x20 || character > 0x7e;
            }))
            return build_worker_result_t<std::filesystem::path>::failure(
                error(build_worker_error_code_t::unsafe_path, path, "path_component"));
        current /= component;
        components.emplace_back(current);
    }
    DWORD final_attributes = 0;
    for (const auto& component_path : components) {
        win_handle_t handle;
        handle.handle = CreateFileW(component_path.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle.handle == INVALID_HANDLE_VALUE)
            return build_worker_result_t<std::filesystem::path>::failure(
                error(build_worker_error_code_t::file_missing, component_path,
                      "CreateFileW:canonical", 0, GetLastError()));
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!GetFileInformationByHandleEx(handle.handle, FileAttributeTagInfo, &tag,
                                           sizeof(tag)))
            return build_worker_result_t<std::filesystem::path>::failure(
                error(build_worker_error_code_t::file_read_failed, component_path,
                      "FileAttributeTagInfo:canonical", 0, GetLastError()));
        if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || tag.ReparseTag != 0)
            return build_worker_result_t<std::filesystem::path>::failure(
                error(build_worker_error_code_t::reparse_point, component_path));
        std::array<wchar_t, 32768> final_buffer{};
        const DWORD final_length = GetFinalPathNameByHandleW(
            handle.handle, final_buffer.data(), static_cast<DWORD>(final_buffer.size()), 0);
        if (final_length == 0 || final_length >= final_buffer.size())
            return build_worker_result_t<std::filesystem::path>::failure(
                error(build_worker_error_code_t::file_read_failed, component_path,
                      "GetFinalPathNameByHandleW", 0, GetLastError()));
        std::wstring final_path(final_buffer.data(), final_length);
        if (final_path.rfind(L"\\\\?\\UNC\\", 0) == 0)
            return build_worker_result_t<std::filesystem::path>::failure(
                error(build_worker_error_code_t::unsafe_path, component_path,
                      "unc_path"));
        if (final_path.rfind(L"\\\\?\\", 0) == 0)
            final_path.erase(0, 4);
        auto expected = component_path.native();
        if (expected.size() == 2 && expected[1] == L':')
            expected.push_back(L'\\');
        if (final_path != expected)
            return build_worker_result_t<std::filesystem::path>::failure(
                error(build_worker_error_code_t::unsafe_path, component_path,
                      "canonical_case"));
        final_attributes = tag.FileAttributes;
    }
    if (require_directory != ((final_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0))
        return build_worker_result_t<std::filesystem::path>::failure(
            error(build_worker_error_code_t::file_type_invalid, path));
    return build_worker_result_t<std::filesystem::path>::success(path);
}

build_worker_result_t<std::filesystem::path> canonical_directory(
    const std::filesystem::path& path) {
    return exact_existing_path(path, true);
}

bool safe_relative_path(std::string_view value) noexcept {
    if (value.empty() || value.size() > k_default_relative_path_limit ||
        value.front() == '/' || value.back() == '/')
        return false;
    for (const unsigned char character : value) {
        if (character < 0x21U || character > 0x7eU || character == '\\' ||
            character == ':' || character == '<' || character == '>' ||
            character == '"' || character == '|' || character == '?' ||
            character == '*')
            return false;
    }
    std::size_t begin = 0;
    while (begin <= value.size()) {
        const auto end = value.find('/', begin);
        const auto part = value.substr(begin, end == std::string_view::npos
                                                ? value.size() - begin
                                                : end - begin);
        if (part.empty() || part == "." || part == ".." || part.back() == '.')
            return false;
        if (end == std::string_view::npos)
            break;
        begin = end + 1;
    }
    return true;
}

bool safe_identifier(std::string_view value) noexcept {
    if (value.empty() || value.size() > 256)
        return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return std::isalnum(character) != 0 || character == '_' || character == '.' ||
               character == '-';
    });
}

bool path_is_within(const std::filesystem::path& candidate,
                    const std::filesystem::path& root) {
    std::error_code error_code;
    const auto relative = std::filesystem::relative(candidate, root, error_code);
    if (error_code || relative.empty() || relative.is_absolute())
        return false;
    for (const auto& component : relative) {
        if (component == "..")
            return false;
    }
    return true;
}

build_worker_result_t<std::filesystem::path> resolve_regular_under_root(
    const std::filesystem::path& canonical_root, std::string_view relative) {
    if (!safe_relative_path(relative))
        return build_worker_result_t<std::filesystem::path>::failure(
            error(build_worker_error_code_t::unsafe_path, std::filesystem::u8path(relative)));
    std::filesystem::path current = canonical_root;
    const auto relative_path = std::filesystem::u8path(relative);
    for (const auto& component : relative_path) {
        current /= component;
        const DWORD attributes = GetFileAttributesW(current.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
            return build_worker_result_t<std::filesystem::path>::failure(
                error(build_worker_error_code_t::file_missing, current));
        if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            return build_worker_result_t<std::filesystem::path>::failure(
                error(build_worker_error_code_t::reparse_point, current));
    }
    const DWORD attributes = GetFileAttributesW(current.c_str());
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return build_worker_result_t<std::filesystem::path>::failure(
            error(build_worker_error_code_t::file_type_invalid, current));
    auto exact = exact_existing_path(current, false);
    if (!exact)
        return build_worker_result_t<std::filesystem::path>::failure(exact.error());
    std::error_code ec;
    const auto relative_check = std::filesystem::relative(current, canonical_root, ec);
    if (ec || relative_check.empty() || relative_check.is_absolute())
        return build_worker_result_t<std::filesystem::path>::failure(
            error(build_worker_error_code_t::path_escape, current));
    for (const auto& part : relative_check) {
        if (part == "..")
            return build_worker_result_t<std::filesystem::path>::failure(
                error(build_worker_error_code_t::path_escape, current));
    }
    return build_worker_result_t<std::filesystem::path>::success(current);
}

bool json_has_exact_keys(const json& value,
                         std::initializer_list<std::string_view> keys) {
    if (!value.is_object() || value.size() != keys.size())
        return false;
    for (const auto key : keys) {
        if (!value.contains(std::string(key)))
            return false;
    }
    return true;
}

bool json_contains_remote_reference(const json& value) {
    if (value.is_object()) {
        for (const auto& item : value.items()) {
            const auto key = lowercase(item.key());
            if (key == "$ref" || key == "$id" || key == "url" || key == "uri")
                return true;
            if (json_contains_remote_reference(item.value()))
                return true;
        }
        return false;
    }
    if (value.is_array()) {
        return std::any_of(value.begin(), value.end(), [](const json& item) {
            return json_contains_remote_reference(item);
        });
    }
    if (value.is_string()) {
        const auto text = lowercase(value.get<std::string>());
        return text.find("http://") != std::string::npos ||
               text.find("https://") != std::string::npos ||
               text.find("ftp://") != std::string::npos ||
               text.find("git://") != std::string::npos ||
               text.find("ssh://") != std::string::npos ||
               text.find("file://") != std::string::npos ||
               text.find("ws://") != std::string::npos ||
               text.find("wss://") != std::string::npos;
    }
    return false;
}

template <typename value_t>
bool json_scalar(const json& object, std::string_view key, value_t& output) {
    const auto iterator = object.find(std::string(key));
    if (iterator == object.end())
        return false;
    try {
        output = iterator->get<value_t>();
        return true;
    } catch (...) {
        return false;
    }
}

build_worker_result_t<json> parse_json_file(const std::filesystem::path& path,
                                            std::uint64_t maximum_bytes,
                                            std::string_view expected_sha256 = {}) {
    auto evidence = inspect_regular_file(path, maximum_bytes, true);
    if (!evidence)
        return build_worker_result_t<json>::failure(evidence.error());
    if (!expected_sha256.empty() &&
        (!valid_sha256(expected_sha256) ||
         !fixed_time_equal(evidence.value().sha256, expected_sha256)))
        return build_worker_result_t<json>::failure(
            error(build_worker_error_code_t::hash_mismatch, path,
                  evidence.value().sha256));
    try {
        auto value = json::parse(evidence.value().content, nullptr, true, true);
        if (json_contains_remote_reference(value))
            return build_worker_result_t<json>::failure(
                error(build_worker_error_code_t::remote_reference_forbidden, path));
        return build_worker_result_t<json>::success(std::move(value));
    } catch (const std::exception& exception) {
        return build_worker_result_t<json>::failure(
            error(build_worker_error_code_t::malformed_json, path, exception.what()));
    }
}

bool forbidden_link_token(std::string_view input) noexcept {
    std::string text(input);
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    for (const auto forbidden : k_forbidden_link_tokens) {
        std::size_t offset = 0;
        while ((offset = text.find(forbidden, offset)) != std::string::npos) {
            const auto identifier = [](char character) {
                return (character >= 'a' && character <= 'z') ||
                       (character >= '0' && character <= '9');
            };
            const bool left = offset == 0 || !identifier(text[offset - 1]);
            const auto right_offset = offset + forbidden.size();
            const bool right = right_offset == text.size() || !identifier(text[right_offset]);
            if (left && right)
                return true;
            ++offset;
        }
    }
    return false;
}

bool offline_authenticode_valid(const std::filesystem::path& path, LONG& status) {
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path.c_str();

    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL |
                             WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    status = WinVerifyTrust(nullptr, &policy, &trust_data);
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &trust_data);
    return status == ERROR_SUCCESS;
}

build_worker_result_t<std::string> authenticode_signer_sha256(
    const std::filesystem::path& path) {
    certificate_store_t store;
    crypt_message_t message;
    DWORD encoding = 0;
    DWORD content_type = 0;
    DWORD format_type = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content_type,
                          &format_type, &store.handle, &message.handle, nullptr))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::authenticode_verification_failed, path,
                  "CryptQueryObject", 0, GetLastError()));

    DWORD signer_size = 0;
    if (!CryptMsgGetParam(message.handle, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_size) ||
        signer_size < static_cast<DWORD>(sizeof(CMSG_SIGNER_INFO)) ||
        signer_size > 1024U * 1024U)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::authenticode_verification_failed, path,
                  "CryptMsgGetParam:size", 0, GetLastError()));
    std::vector<std::uint8_t> signer_buffer(signer_size);
    if (!CryptMsgGetParam(message.handle, CMSG_SIGNER_INFO_PARAM, 0,
                          signer_buffer.data(), &signer_size))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::authenticode_verification_failed, path,
                  "CryptMsgGetParam:value", 0, GetLastError()));
    const auto* signer = reinterpret_cast<const CMSG_SIGNER_INFO*>(signer_buffer.data());
    CERT_INFO certificate_info{};
    certificate_info.Issuer = signer->Issuer;
    certificate_info.SerialNumber = signer->SerialNumber;
    certificate_context_t certificate;
    certificate.context = CertFindCertificateInStore(
        store.handle, encoding, 0, CERT_FIND_SUBJECT_CERT, &certificate_info, nullptr);
    if (!certificate.context)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::authenticode_verification_failed, path,
                  "CertFindCertificateInStore", 0, GetLastError()));
    std::array<std::uint8_t, 32> digest{};
    DWORD digest_size = static_cast<DWORD>(digest.size());
    if (!CertGetCertificateContextProperty(certificate.context, CERT_SHA256_HASH_PROP_ID,
                                           digest.data(), &digest_size) ||
        digest_size != static_cast<DWORD>(digest.size()))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::authenticode_verification_failed, path,
                  "CertGetCertificateContextProperty", digest.size(), digest_size));
    return build_worker_result_t<std::string>::success(hex_encode(digest));
}

struct artifact_t final {
    std::string id;
    std::string kind;
    std::string relative_path;
    std::uint64_t size = 0;
    std::string sha256;
    std::string owner;
    std::vector<std::string> license_ids;
    std::filesystem::path path;
};

bool json_string_array(const json& value, std::vector<std::string>& output,
                       std::size_t maximum = 4096) {
    if (!value.is_array() || value.size() > maximum)
        return false;
    output.clear();
    output.reserve(value.size());
    std::unordered_set<std::string> unique;
    unique.reserve(value.size());
    for (const auto& item : value) {
        if (!item.is_string())
            return false;
        auto text = item.get<std::string>();
        if (text.empty() || text.size() > 4096 || !unique.emplace(text).second)
            return false;
        output.push_back(std::move(text));
    }
    return true;
}

bool bool_true(const json& object, std::string_view key) {
    const auto iterator = object.find(std::string(key));
    return iterator != object.end() && iterator->is_boolean() && iterator->get<bool>();
}

bool bool_false(const json& object, std::string_view key) {
    const auto iterator = object.find(std::string(key));
    return iterator != object.end() && iterator->is_boolean() && !iterator->get<bool>();
}

const artifact_t* artifact_by_path(
    const std::unordered_map<std::string, artifact_t>& artifacts,
    std::string_view relative_path) noexcept {
    for (const auto& entry : artifacts) {
        if (entry.second.relative_path == relative_path)
            return &entry.second;
    }
    return nullptr;
}

build_worker_result_t<void> verify_manifest_digest(const artifact_t& manifest,
                                                    const artifact_t& digest,
                                                    std::uint64_t maximum_bytes) {
    auto evidence = inspect_regular_file(digest.path, maximum_bytes, true);
    if (!evidence)
        return build_worker_result_t<void>::failure(evidence.error());
    if (digest.kind != "manifest_digest" ||
        !fixed_time_equal(evidence.value().content, manifest.sha256 + "\n"))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::hash_mismatch, digest.path,
                  "detached manifest digest"));
    return build_worker_result_t<void>::success();
}

struct packaged_inventory_entry_t final {
    std::string relative_path;
    std::uint64_t size = 0;
    std::string sha256;
};

build_worker_result_t<std::string> canonical_packaged_inventory(
    std::vector<packaged_inventory_entry_t> entries) {
    std::sort(entries.begin(), entries.end(),
              [](const auto& left, const auto& right) {
                  return left.relative_path < right.relative_path;
              });
    std::string material;
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        if (index != 0)
            material.push_back('\n');
        material.append(entry.relative_path);
        material.push_back('|');
        material.append(std::to_string(entry.size));
        material.push_back('|');
        material.append(entry.sha256);
    }
    return sha256_text(material);
}

build_worker_result_t<std::string> verify_managed_runtime_manifest(
    const artifact_t& manifest_artifact, const artifact_t& digest_artifact,
    const std::unordered_map<std::string, artifact_t>& artifacts,
    std::uint64_t maximum_bytes) {
    auto digest = verify_manifest_digest(manifest_artifact, digest_artifact, maximum_bytes);
    if (!digest)
        return build_worker_result_t<std::string>::failure(digest.error());
    auto parsed = parse_json_file(manifest_artifact.path, maximum_bytes,
                                  manifest_artifact.sha256);
    if (!parsed)
        return build_worker_result_t<std::string>::failure(parsed.error());
    const auto& value = parsed.value();
    if (!json_has_exact_keys(value, {"schema", "schema_version", "source_contract_sha256",
                                     "target_framework", "runtime", "application",
                                     "launch", "inventory"}))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest_artifact.path,
                  "managed runtime manifest keys"));
    std::string schema;
    std::string contract;
    std::string framework;
    std::uint32_t version = 0;
    if (!json_scalar(value, "schema", schema) ||
        schema != "aida.c03.managed-runtime-manifest" ||
        !json_scalar(value, "schema_version", version) || version != 1 ||
        !json_scalar(value, "source_contract_sha256", contract) ||
        !fixed_time_equal(contract,
            "2ee04cc5ed3c0fdbe1dac2f59ff2ac0e0fd5b4595c042aadb9abfbbd8153c4de") ||
        !json_scalar(value, "target_framework", framework) || framework != "net10.0")
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest_artifact.path,
                  "managed runtime authority"));

    const auto& runtime = value["runtime"];
    std::string runtime_framework;
    std::string runtime_version;
    std::string runtime_identifier;
    std::string relative_root;
    std::string runtime_canonical;
    std::uint64_t runtime_total = 0;
    std::uint32_t runtime_count = 0;
    if (!json_has_exact_keys(runtime, {"framework", "version", "runtime_identifier",
                                      "relative_root", "exact_inventory", "file_count",
                                      "total_size_bytes", "canonical_inventory_sha256",
                                      "files"}) ||
        !json_scalar(runtime, "framework", runtime_framework) ||
        runtime_framework != "Microsoft.NETCore.App" ||
        !json_scalar(runtime, "version", runtime_version) || runtime_version != "10.0.9" ||
        !json_scalar(runtime, "runtime_identifier", runtime_identifier) ||
        runtime_identifier != "win-x64" ||
        !json_scalar(runtime, "relative_root", relative_root) ||
        relative_root != "deps/dotnet" || !bool_true(runtime, "exact_inventory") ||
        !json_scalar(runtime, "file_count", runtime_count) || runtime_count != 193 ||
        !json_scalar(runtime, "total_size_bytes", runtime_total) ||
        runtime_total != 80344570ULL ||
        !json_scalar(runtime, "canonical_inventory_sha256", runtime_canonical) ||
        !fixed_time_equal(runtime_canonical,
            "8582bda52b66ad61651a2c9bc2c705cf10b038e374f87662045397c7966b02c9") ||
        !runtime["files"].is_array() || runtime["files"].size() != runtime_count)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest_artifact.path,
                  "managed runtime inventory"));

    std::vector<packaged_inventory_entry_t> runtime_entries;
    std::vector<packaged_inventory_entry_t> complete_entries;
    std::unordered_set<std::string> inventory_paths;
    std::uint64_t observed_runtime_total = 0;
    for (const auto& item : runtime["files"]) {
        packaged_inventory_entry_t entry;
        if (!json_has_exact_keys(item, {"relative_path", "size_bytes", "sha256"}) ||
            !json_scalar(item, "relative_path", entry.relative_path) ||
            !safe_relative_path(entry.relative_path) ||
            entry.relative_path.rfind("deps/dotnet/", 0) != 0 ||
            !json_scalar(item, "size_bytes", entry.size) || entry.size == 0 ||
            !json_scalar(item, "sha256", entry.sha256) || !valid_sha256(entry.sha256) ||
            !inventory_paths.emplace(entry.relative_path).second)
            return build_worker_result_t<std::string>::failure(
                error(build_worker_error_code_t::artifact_inventory_mismatch,
                      manifest_artifact.path, "managed runtime entry"));
        const auto* artifact = artifact_by_path(artifacts, entry.relative_path);
        if (!artifact || artifact->kind != "worker_runtime" ||
            artifact->owner != "managed_cli_decompiler" || artifact->size != entry.size ||
            !fixed_time_equal(artifact->sha256, entry.sha256))
            return build_worker_result_t<std::string>::failure(
                error(build_worker_error_code_t::artifact_inventory_mismatch,
                      std::filesystem::u8path(entry.relative_path), "managed runtime binding"));
        if (entry.size > (std::numeric_limits<std::uint64_t>::max)() - observed_runtime_total)
            return build_worker_result_t<std::string>::failure(
                error(build_worker_error_code_t::file_too_large, manifest_artifact.path));
        observed_runtime_total += entry.size;
        runtime_entries.push_back(entry);
        complete_entries.push_back(std::move(entry));
    }
    auto runtime_digest = canonical_packaged_inventory(runtime_entries);
    if (!runtime_digest)
        return build_worker_result_t<std::string>::failure(runtime_digest.error());
    if (observed_runtime_total != runtime_total ||
        !fixed_time_equal(runtime_digest.value(), runtime_canonical))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::hash_mismatch, manifest_artifact.path,
                  "managed runtime canonical inventory"));

    const auto& application = value["application"];
    if (!json_has_exact_keys(application, {"exact_inventory", "files"}) ||
        !bool_true(application, "exact_inventory") || !application["files"].is_array() ||
        application["files"].size() != 7)
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest_artifact.path,
                  "managed application inventory"));
    const std::map<std::string, std::string_view> expected_application{
        {"deps/AiDA_ManagedDecompilerWorker.exe", "apphost"},
        {"deps/AiDA_ManagedDecompilerWorker.dll", "assembly"},
        {"deps/AiDA_ManagedDecompilerWorker.deps.json", "deps"},
        {"deps/AiDA_ManagedDecompilerWorker.runtimeconfig.json", "runtimeconfig"},
        {"deps/ICSharpCode.Decompiler.dll", "provider"},
        {"deps/System.Collections.Immutable.dll", "direct_dependency"},
        {"deps/System.Reflection.Metadata.dll", "direct_dependency"},
    };
    std::uint64_t complete_total = observed_runtime_total;
    for (const auto& item : application["files"]) {
        packaged_inventory_entry_t entry;
        std::string role;
        if (!json_has_exact_keys(item, {"role", "relative_path", "size_bytes", "sha256"}) ||
            !json_scalar(item, "role", role) ||
            !json_scalar(item, "relative_path", entry.relative_path) ||
            expected_application.find(entry.relative_path) == expected_application.end() ||
            expected_application.at(entry.relative_path) != role ||
            !json_scalar(item, "size_bytes", entry.size) || entry.size == 0 ||
            !json_scalar(item, "sha256", entry.sha256) || !valid_sha256(entry.sha256) ||
            !inventory_paths.emplace(entry.relative_path).second)
            return build_worker_result_t<std::string>::failure(
                error(build_worker_error_code_t::artifact_inventory_mismatch,
                      manifest_artifact.path, "managed application entry"));
        const auto* artifact = artifact_by_path(artifacts, entry.relative_path);
        const auto expected_kind = role == "apphost" ? "worker_executable" : "worker_runtime";
        if (!artifact || artifact->kind != expected_kind ||
            artifact->owner != "managed_cli_decompiler" || artifact->size != entry.size ||
            !fixed_time_equal(artifact->sha256, entry.sha256))
            return build_worker_result_t<std::string>::failure(
                error(build_worker_error_code_t::artifact_inventory_mismatch,
                      std::filesystem::u8path(entry.relative_path), "managed application binding"));
        if (entry.size > (std::numeric_limits<std::uint64_t>::max)() - complete_total)
            return build_worker_result_t<std::string>::failure(
                error(build_worker_error_code_t::file_too_large, manifest_artifact.path));
        complete_total += entry.size;
        complete_entries.push_back(std::move(entry));
    }

    const auto& launch = value["launch"];
    std::string executable_path;
    std::string hostfxr_path;
    std::string dotnet_root;
    std::string roll_forward;
    if (!json_has_exact_keys(launch, {"executable_relative_path", "hostfxr_relative_path",
                                      "dotnet_root_relative_path", "multilevel_lookup",
                                      "roll_forward", "roll_forward_to_prerelease",
                                      "machine_runtime_fallback"}) ||
        !json_scalar(launch, "executable_relative_path", executable_path) ||
        executable_path != "deps/AiDA_ManagedDecompilerWorker.exe" ||
        !json_scalar(launch, "hostfxr_relative_path", hostfxr_path) ||
        hostfxr_path != "deps/dotnet/host/fxr/10.0.9/hostfxr.dll" ||
        !json_scalar(launch, "dotnet_root_relative_path", dotnet_root) ||
        dotnet_root != "deps/dotnet" || !bool_false(launch, "multilevel_lookup") ||
        !json_scalar(launch, "roll_forward", roll_forward) || roll_forward != "Disable" ||
        !bool_false(launch, "roll_forward_to_prerelease") ||
        !bool_false(launch, "machine_runtime_fallback"))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::containment_policy_mismatch,
                  manifest_artifact.path, "managed launch isolation"));

    const auto& inventory = value["inventory"];
    std::uint32_t complete_count = 0;
    std::uint64_t declared_total = 0;
    std::string complete_canonical;
    if (!json_has_exact_keys(inventory, {"file_count", "total_size_bytes",
                                         "canonical_inventory_sha256"}) ||
        !json_scalar(inventory, "file_count", complete_count) || complete_count != 200 ||
        !json_scalar(inventory, "total_size_bytes", declared_total) ||
        declared_total != complete_total ||
        !json_scalar(inventory, "canonical_inventory_sha256", complete_canonical) ||
        !valid_sha256(complete_canonical))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest_artifact.path,
                  "managed complete inventory"));
    auto complete_digest = canonical_packaged_inventory(std::move(complete_entries));
    if (!complete_digest)
        return build_worker_result_t<std::string>::failure(complete_digest.error());
    if (!fixed_time_equal(complete_digest.value(), complete_canonical))
        return build_worker_result_t<std::string>::failure(
            error(build_worker_error_code_t::hash_mismatch, manifest_artifact.path,
                  "managed complete canonical inventory"));
    return build_worker_result_t<std::string>::success(manifest_artifact.sha256);
}

build_worker_result_t<void> verify_ghidra_spec_manifest(
    const artifact_t& manifest_artifact, const artifact_t& digest_artifact,
    const std::unordered_map<std::string, artifact_t>& artifacts,
    std::uint64_t maximum_bytes) {
    auto digest = verify_manifest_digest(manifest_artifact, digest_artifact, maximum_bytes);
    if (!digest)
        return digest;
    auto parsed = parse_json_file(manifest_artifact.path, maximum_bytes,
                                  manifest_artifact.sha256);
    if (!parsed)
        return build_worker_result_t<void>::failure(parsed.error());
    const auto& value = parsed.value();
    std::string schema;
    std::string contract;
    std::uint32_t version = 0;
    if (!json_has_exact_keys(value, {"schema", "schema_version", "source_contract_sha256",
                                     "producer", "specifications"}) ||
        !json_scalar(value, "schema", schema) ||
        schema != "aida.c03.ghidra-spec-manifest" ||
        !json_scalar(value, "schema_version", version) || version != 1 ||
        !json_scalar(value, "source_contract_sha256", contract) ||
        !fixed_time_equal(contract,
            "880c588da681d62451d3dd5f901abc7cb86491a128a7793c8738f9bd7917f0b7"))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest_artifact.path,
                  "Ghidra specification authority"));
    const auto& producer = value["producer"];
    std::string producer_id;
    std::string producer_hash;
    if (!json_has_exact_keys(producer, {"id", "executable_sha256", "approved_input_root",
                                        "approved_generator_root"}) ||
        !json_scalar(producer, "id", producer_id) || producer_id != "ghidra_sleigh_compiler" ||
        !json_scalar(producer, "executable_sha256", producer_hash) ||
        !valid_sha256(producer_hash) || !bool_true(producer, "approved_input_root") ||
        !bool_true(producer, "approved_generator_root"))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::source_authority_invalid,
                  manifest_artifact.path, "Ghidra specification producer"));
    const auto& specifications = value["specifications"];
    std::uint32_t file_count = 0;
    std::string generation;
    std::string canonical;
    if (!json_has_exact_keys(specifications, {"file_count", "mirrors", "exact_inventory",
                                              "generation_id", "canonical_inventory_sha256",
                                              "files"}) ||
        !json_scalar(specifications, "file_count", file_count) || file_count != 51 ||
        !specifications["mirrors"].is_array() || specifications["mirrors"].size() != 2 ||
        specifications["mirrors"][0] != "ghidra_specs" ||
        specifications["mirrors"][1] != "deps/ghidra_specs" ||
        !bool_true(specifications, "exact_inventory") ||
        !json_scalar(specifications, "generation_id", generation) || !valid_sha256(generation) ||
        !json_scalar(specifications, "canonical_inventory_sha256", canonical) ||
        !valid_sha256(canonical) || !specifications["files"].is_array() ||
        specifications["files"].size() != file_count)
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest_artifact.path,
                  "Ghidra specification inventory"));
    constexpr std::array<std::string_view, 51> expected_names{
        "x86-64.sla", "x86.sla", "ARM7_le.sla", "ARM7_be.sla", "AARCH64.sla",
        "AARCH64BE.sla", "mips32le.sla", "mips32be.sla", "mips64le.sla",
        "mips64be.sla", "ppc_32_le.sla", "ppc_32_be.sla", "ppc_64_le.sla",
        "ppc_64_be.sla", "riscv.ilp32d.sla", "riscv.lp64d.sla", "x86-64.pspec",
        "x86-64-win.cspec", "x86-64-gcc.cspec", "x86.pspec", "x86win.cspec",
        "x86gcc.cspec", "x86-16-real.pspec", "x86-16.cspec", "x86.ldefs",
        "ARMt.pspec", "ARM.cspec", "ARM_win.cspec", "ARM.ldefs", "AARCH64.pspec",
        "AARCH64.cspec", "AARCH64_win.cspec", "AARCH64.ldefs", "mips32.pspec",
        "mips64.pspec", "mips32le.cspec", "mips32be.cspec", "mips64le.cspec",
        "mips64be.cspec", "mips.ldefs", "ppc_32.pspec", "ppc_64.pspec",
        "ppc_32.cspec", "ppc_64_le.cspec", "ppc_64_be.cspec", "ppc.ldefs",
        "RV32.pspec", "RV64.pspec", "riscv32-fp.cspec", "riscv64-fp.cspec",
        "riscv.ldefs",
    };
    std::unordered_set<std::string> names;
    std::size_t expected_name_index = 0;
    std::string canonical_rows;
    for (const auto& item : specifications["files"]) {
        std::string name;
        std::string kind;
        std::string hash;
        std::uint64_t size = 0;
        if (!json_has_exact_keys(item, {"name", "kind", "size_bytes", "sha256"}) ||
            !json_scalar(item, "name", name) || expected_name_index >= expected_names.size() ||
            name != expected_names[expected_name_index++] || !safe_relative_path(name) ||
            name.find('/') != std::string::npos || !names.emplace(name).second ||
            !json_scalar(item, "kind", kind) ||
            (kind != "sla" && kind != "pspec" && kind != "cspec" && kind != "ldefs") ||
            name.size() <= kind.size() + 1 ||
            name.compare(name.size() - kind.size(), kind.size(), kind) != 0 ||
            !json_scalar(item, "size_bytes", size) || size == 0 ||
            !json_scalar(item, "sha256", hash) || !valid_sha256(hash))
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::artifact_inventory_mismatch,
                      manifest_artifact.path, "Ghidra specification entry"));
        for (const auto mirror : {"ghidra_specs/", "deps/ghidra_specs/"}) {
            const auto relative = std::string(mirror) + name;
            const auto* artifact = artifact_by_path(artifacts, relative);
            if (!artifact || artifact->kind != "resource" ||
                artifact->owner != "native_decompiler" || artifact->size != size ||
                !fixed_time_equal(artifact->sha256, hash))
                return build_worker_result_t<void>::failure(
                    error(build_worker_error_code_t::artifact_inventory_mismatch,
                          std::filesystem::u8path(relative), "Ghidra mirror binding"));
        }
        canonical_rows.append(name).push_back('\t');
        canonical_rows.append(kind).push_back('\t');
        canonical_rows.append(std::to_string(size)).push_back('\t');
        canonical_rows.append(hash).push_back('\n');
    }
    if (expected_name_index != expected_names.size() || names.size() != expected_names.size())
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::artifact_inventory_mismatch,
                  manifest_artifact.path, "Ghidra specification name set"));
    auto observed_canonical = sha256_text(canonical_rows);
    if (!observed_canonical)
        return build_worker_result_t<void>::failure(observed_canonical.error());
    const auto generation_material = std::string("aida.c03.ghidra-spec-generation.v1\n") +
        contract + "\n" + producer_hash + "\n" + observed_canonical.value() + "\n";
    auto observed_generation = sha256_text(generation_material);
    if (!observed_generation)
        return build_worker_result_t<void>::failure(observed_generation.error());
    if (!fixed_time_equal(observed_canonical.value(), canonical) ||
        !fixed_time_equal(observed_generation.value(), generation))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::hash_mismatch, manifest_artifact.path,
                  "Ghidra specification generation"));
    return build_worker_result_t<void>::success();
}

build_worker_result_t<void> verify_worker_acl_receipt(
    const artifact_t& receipt, const artifact_t& worker_manifest,
    std::string_view expected_policy, std::uint64_t expected_path_count,
    std::uint64_t maximum_bytes) {
    auto parsed = parse_json_file(receipt.path, maximum_bytes, receipt.sha256);
    if (!parsed)
        return build_worker_result_t<void>::failure(parsed.error());
    const auto& value = parsed.value();
    std::string schema;
    std::string policy;
    std::string profile;
    std::string sid;
    std::string manifest_hash;
    std::uint32_t version = 0;
    std::uint64_t path_count = 0;
    if (!json_has_exact_keys(value, {"schema", "schema_version", "policy",
                                     "app_container_profile", "app_container_sid",
                                     "worker_manifest_sha256", "protected_parent_required",
                                     "access", "path_count", "verified"}) ||
        !json_scalar(value, "schema", schema) ||
        schema != "aida.c03.worker-runtime-acl-receipt" ||
        !json_scalar(value, "schema_version", version) || version != 1 ||
        !json_scalar(value, "policy", policy) || policy != expected_policy ||
        !json_scalar(value, "app_container_profile", profile) ||
        !json_scalar(value, "app_container_sid", sid) ||
        !json_scalar(value, "worker_manifest_sha256", manifest_hash) ||
        !fixed_time_equal(manifest_hash, worker_manifest.sha256) ||
        profile != "AiDA.NativeWorker." + worker_manifest.sha256.substr(0, 32) ||
        sid.rfind("S-1-15-2-", 0) != 0 || !bool_true(value, "protected_parent_required") ||
        !json_scalar(value, "path_count", path_count) || path_count != expected_path_count ||
        !bool_true(value, "verified"))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::containment_policy_mismatch, receipt.path,
                  "worker ACL receipt"));
    const auto& access = value["access"];
    if (!json_has_exact_keys(access, {"read_execute", "write", "delete",
                                      "change_permissions", "take_ownership"}) ||
        !bool_true(access, "read_execute") || !bool_false(access, "write") ||
        !bool_false(access, "delete") || !bool_false(access, "change_permissions") ||
        !bool_false(access, "take_ownership"))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::containment_policy_mismatch, receipt.path,
                  "worker ACL access"));
    return build_worker_result_t<void>::success();
}

build_worker_result_t<void> verify_protector_receipt(
    const artifact_t& receipt, const artifact_t& executable,
    std::string_view expected_tool_sha256, std::string_view expected_verifier_sha256,
    std::string_view expected_signer_policy_sha256,
    std::string_view expected_signing_provider_sha256,
    std::string_view expected_profile,
    const std::function<bool(const std::filesystem::path&, std::string_view)>& verifier,
    std::uint64_t maximum_bytes) {
    auto control = poll_verification_control(executable.path, "protector_receipt");
    if (!control)
        return build_worker_result_t<void>::failure(control.error());
    auto parsed = parse_json_file(receipt.path, maximum_bytes);
    if (!parsed)
        return build_worker_result_t<void>::failure(parsed.error());
    const auto& value = parsed.value();
    if (!json_has_exact_keys(value, {"schema", "schema_version", "status",
                                     "artifact_relative_path", "artifact_sha256",
                                     "artifact_size_bytes", "tool_sha256", "verifier_sha256",
                                     "signer_policy_sha256", "signing_provider_sha256",
                                     "profile", "post_process",
                                     "production_flags"}))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::protector_receipt_invalid, receipt.path));
    std::string schema;
    std::string status;
    std::string relative;
    std::string digest;
    std::string tool_digest;
    std::string verifier_digest;
    std::string signer_policy_digest;
    std::string signing_provider_digest;
    std::string profile;
    std::uint32_t version = 0;
    std::uint64_t size = 0;
    if (!json_scalar(value, "schema", schema) || schema != "aida.protector.receipt" ||
        !json_scalar(value, "schema_version", version) || version != 4 ||
        !json_scalar(value, "status", status) || status != "passed" ||
        !json_scalar(value, "artifact_relative_path", relative) ||
        !json_scalar(value, "artifact_sha256", digest) ||
        !json_scalar(value, "artifact_size_bytes", size) ||
        !json_scalar(value, "tool_sha256", tool_digest) || !valid_sha256(tool_digest) ||
        !json_scalar(value, "verifier_sha256", verifier_digest) || !valid_sha256(verifier_digest) ||
        !json_scalar(value, "signer_policy_sha256", signer_policy_digest) ||
        !valid_sha256(signer_policy_digest) ||
        !json_scalar(value, "signing_provider_sha256", signing_provider_digest) ||
        !valid_sha256(signing_provider_digest) ||
        !json_scalar(value, "profile", profile) || profile != expected_profile ||
        !fixed_time_equal(tool_digest, expected_tool_sha256) ||
        !fixed_time_equal(verifier_digest, expected_verifier_sha256) ||
        !fixed_time_equal(signer_policy_digest, expected_signer_policy_sha256) ||
        !fixed_time_equal(signing_provider_digest, expected_signing_provider_sha256) ||
        relative != executable.relative_path || !fixed_time_equal(digest, executable.sha256) ||
        size != executable.size)
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::protector_receipt_invalid, receipt.path));
    const auto& post = value["post_process"];
    std::uint64_t protection_checks_total = 0;
    std::uint64_t protection_checks_passed = 0;
    std::uint64_t coff_symbol_table_pointer = 0;
    std::uint64_t coff_symbol_count = 0;
    std::uint64_t debug_directory_entries = 0;
    std::uint64_t codeview_records = 0;
    std::uint64_t unscrubbed_debug_paths = 0;
    std::uint64_t rich_signature_count = 0;
    std::uint64_t dans_signature_count = 0;
    if (!json_has_exact_keys(post, {"protection_checks_total", "protection_checks_passed",
                                    "coff_symbol_table_pointer", "coff_symbol_count",
                                    "debug_directory_entries", "codeview_records",
                                    "unscrubbed_debug_paths", "rich_signature_count",
                                    "dans_signature_count", "pe_headers_complete",
                                    "debug_directory_complete"}) ||
        !json_scalar(post, "protection_checks_total", protection_checks_total) ||
        protection_checks_total == 0 ||
        !json_scalar(post, "protection_checks_passed", protection_checks_passed) ||
        protection_checks_passed != protection_checks_total ||
        !json_scalar(post, "coff_symbol_table_pointer", coff_symbol_table_pointer) ||
        coff_symbol_table_pointer != 0 ||
        !json_scalar(post, "coff_symbol_count", coff_symbol_count) ||
        coff_symbol_count != 0 ||
        !json_scalar(post, "debug_directory_entries", debug_directory_entries) ||
        debug_directory_entries > 4096 ||
        !json_scalar(post, "codeview_records", codeview_records) ||
        codeview_records > debug_directory_entries ||
        !json_scalar(post, "unscrubbed_debug_paths", unscrubbed_debug_paths) ||
        unscrubbed_debug_paths != 0 ||
        !json_scalar(post, "rich_signature_count", rich_signature_count) ||
        rich_signature_count != 0 ||
        !json_scalar(post, "dans_signature_count", dans_signature_count) ||
        dans_signature_count != 0 ||
        !bool_true(post, "pe_headers_complete") ||
        !bool_true(post, "debug_directory_complete"))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::protector_receipt_invalid, receipt.path));
    std::vector<std::string> flags;
    if (!json_string_array(value["production_flags"], flags, 32))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::protector_receipt_invalid, receipt.path));
    const std::set<std::string> required{"/Qspectre", "/sdl", "/guard:cf",
                                         "/guard:ehcont", "/guard:xfg"};
    const std::set<std::string> actual(flags.begin(), flags.end());
    if (actual != required)
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::protector_receipt_invalid, receipt.path));
    control = poll_verification_control(executable.path, "protector_verifier_enter");
    if (!control)
        return build_worker_result_t<void>::failure(control.error());
    bool verified = false;
    try {
        verified = verifier(executable.path, profile);
    } catch (...) {
        verified = false;
    }
    control = poll_verification_control(executable.path, "protector_verifier_exit");
    if (!control)
        return build_worker_result_t<void>::failure(control.error());
    if (!verified)
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::protector_receipt_invalid,
                  executable.path, "direct_protector_verifier"));
    return build_worker_result_t<void>::success();
}

build_worker_result_t<void> verify_signature_receipt(
    const artifact_t& receipt, const artifact_t& executable,
    std::string_view expected_verifier_sha256,
    std::string_view expected_signer_policy_sha256,
    std::string_view expected_signing_provider_sha256,
    const std::vector<std::string>& authorized_signers,
    const std::function<std::optional<package_signature_identity_t>(
        const std::filesystem::path&)>& verifier,
    std::uint64_t maximum_bytes) {
    auto control = poll_verification_control(executable.path, "signature_receipt");
    if (!control)
        return build_worker_result_t<void>::failure(control.error());
    auto parsed = parse_json_file(receipt.path, maximum_bytes);
    if (!parsed)
        return build_worker_result_t<void>::failure(parsed.error());
    const auto& value = parsed.value();
    if (!json_has_exact_keys(value, {"schema", "schema_version", "status",
                                     "artifact_relative_path", "artifact_sha256",
                                     "artifact_size_bytes", "verification_mode",
                                     "signer_thumbprint_sha256", "verifier_sha256",
                                     "signer_policy_sha256", "signing_provider_sha256",
                                     "chain_status", "timestamp_status",
                                     "timestamp_validation", "timestamp_filetime"}))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::signature_receipt_invalid, receipt.path));
    std::string schema;
    std::string status;
    std::string relative;
    std::string digest;
    std::string mode;
    std::string thumbprint;
    std::string verifier_digest;
    std::string signer_policy_digest;
    std::string signing_provider_digest;
    std::string chain;
    std::string timestamp;
    std::string timestamp_validation;
    std::uint32_t version = 0;
    std::uint64_t size = 0;
    std::uint64_t timestamp_filetime = 0;
    if (!json_scalar(value, "schema", schema) || schema != "aida.signature.receipt" ||
        !json_scalar(value, "schema_version", version) || version != 4 ||
        !json_scalar(value, "status", status) || status != "verified" ||
        !json_scalar(value, "artifact_relative_path", relative) ||
        !json_scalar(value, "artifact_sha256", digest) ||
        !json_scalar(value, "artifact_size_bytes", size) ||
        !json_scalar(value, "verification_mode", mode) || mode != "wintrust_offline" ||
        !json_scalar(value, "signer_thumbprint_sha256", thumbprint) || !valid_sha256(thumbprint) ||
        !json_scalar(value, "verifier_sha256", verifier_digest) || !valid_sha256(verifier_digest) ||
        !fixed_time_equal(verifier_digest, expected_verifier_sha256) ||
        !json_scalar(value, "signer_policy_sha256", signer_policy_digest) ||
        !valid_sha256(signer_policy_digest) ||
        !fixed_time_equal(signer_policy_digest, expected_signer_policy_sha256) ||
        !json_scalar(value, "signing_provider_sha256", signing_provider_digest) ||
        !valid_sha256(signing_provider_digest) ||
        !fixed_time_equal(signing_provider_digest, expected_signing_provider_sha256) ||
        !json_scalar(value, "chain_status", chain) || chain != "trusted" ||
        !json_scalar(value, "timestamp_status", timestamp) || timestamp != "trusted" ||
        !json_scalar(value, "timestamp_validation", timestamp_validation) ||
        timestamp_validation != "wintrust_provider_counter_signer" ||
        !json_scalar(value, "timestamp_filetime", timestamp_filetime) ||
        timestamp_filetime == 0 ||
        relative != executable.relative_path || !fixed_time_equal(digest, executable.sha256) ||
        size != executable.size)
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::signature_receipt_invalid, receipt.path));
    if (!std::binary_search(authorized_signers.begin(), authorized_signers.end(), thumbprint))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::signature_receipt_invalid,
                  receipt.path, "unauthorized_signer_thumbprint_sha256"));
    control = poll_verification_control(executable.path, "signature_verifier_enter");
    if (!control)
        return build_worker_result_t<void>::failure(control.error());
    std::optional<package_signature_identity_t> actual;
    try {
        actual = verifier(executable.path);
    } catch (...) {
        actual.reset();
    }
    control = poll_verification_control(executable.path, "signature_verifier_exit");
    if (!control)
        return build_worker_result_t<void>::failure(control.error());
    if (!actual)
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::signature_receipt_invalid,
                  receipt.path, "signature_verifier_result"));
    if (!actual->trusted_timestamp || actual->trusted_timestamp_filetime == 0)
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::signature_receipt_invalid,
                  receipt.path, "trusted_timestamp"));
    if (!std::binary_search(authorized_signers.begin(), authorized_signers.end(),
                            actual->signer_thumbprint_sha256))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::signature_receipt_invalid,
                  receipt.path, "unauthorized_actual_signer_thumbprint_sha256"));
    if (!fixed_time_equal(actual->signer_thumbprint_sha256, thumbprint) ||
        actual->trusted_timestamp_filetime != timestamp_filetime)
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::signature_receipt_invalid,
                  receipt.path, "signer_receipt_identity_mismatch"));
    return build_worker_result_t<void>::success();
}

class byte_reader_t final {
public:
    explicit byte_reader_t(std::string_view bytes) noexcept : bytes_(bytes) {}

    bool read_u8(std::uint8_t& value) noexcept {
        if (offset_ == bytes_.size())
            return false;
        value = static_cast<std::uint8_t>(bytes_[offset_++]);
        return true;
    }

    bool read_u32(std::uint32_t& value) noexcept {
        if (bytes_.size() - offset_ < sizeof(value))
            return false;
        const auto* data = reinterpret_cast<const unsigned char*>(bytes_.data() + offset_);
        value = static_cast<std::uint32_t>(data[0]) |
                (static_cast<std::uint32_t>(data[1]) << 8U) |
                (static_cast<std::uint32_t>(data[2]) << 16U) |
                (static_cast<std::uint32_t>(data[3]) << 24U);
        offset_ += sizeof(value);
        return true;
    }

    bool read_bytes(std::uint8_t* output, std::size_t size) noexcept {
        if (static_cast<std::size_t>(size) > bytes_.size() - offset_)
            return false;
        std::copy_n(reinterpret_cast<const std::uint8_t*>(bytes_.data() + offset_),
                    size, output);
        offset_ += size;
        return true;
    }

    bool read_string(std::string& value) {
        std::uint32_t size = 0;
        if (!read_u32(size) || size == 0 || size > 4096 ||
            static_cast<std::size_t>(size) > bytes_.size() - offset_)
            return false;
        value.assign(bytes_.data() + offset_, size);
        offset_ += size;
        return value.find('\0') == std::string::npos;
    }

    bool exhausted() const noexcept { return offset_ == bytes_.size(); }

private:
    std::string_view bytes_;
    std::size_t offset_ = 0;
};

build_worker_result_t<void> verify_worker_manifest_binary(
    const artifact_t& manifest, const artifact_t& digest, const artifact_t& executable,
    std::uint32_t expected_magic, std::uint32_t expected_schema,
    std::uint8_t expected_provider, std::uint32_t expected_binary_protocol,
    std::string_view expected_binary_protocol_sha256, std::string_view expected_provider_name,
    std::string_view expected_provider_version, std::string_view expected_worker_build_id,
    std::string_view expected_worker_build_sha256,
    std::string_view expected_provider_binary_sha256, bool provider_binary_is_worker,
    std::string_view expected_managed_runtime_manifest_sha256,
    std::uint64_t maximum_bytes) {
    auto manifest_bytes = inspect_regular_file(manifest.path, maximum_bytes, true);
    if (!manifest_bytes)
        return build_worker_result_t<void>::failure(manifest_bytes.error());
    byte_reader_t reader(manifest_bytes.value().content);
    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    std::string worker_path;
    std::array<std::uint8_t, 32> worker_hash{};
    std::array<std::uint8_t, 32> expected_worker_hash{};
    std::array<std::uint8_t, 32> protocol_hash{};
    std::array<std::uint8_t, 32> expected_protocol_hash{};
    std::array<std::uint8_t, 32> expected_worker_build_hash{};
    std::array<std::uint8_t, 32> expected_provider_binary_hash{};
    if (!reader.read_u32(magic) || !reader.read_u32(version))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest.path));
    if (magic != expected_magic || version != expected_schema)
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest.path,
                  "worker manifest header", expected_schema, version));
    if (!reader.read_string(worker_path) ||
        worker_path != executable.relative_path ||
        !reader.read_bytes(worker_hash.data(), worker_hash.size()) ||
        !decode_sha256(executable.sha256, expected_worker_hash) ||
        !std::equal(worker_hash.begin(), worker_hash.end(), expected_worker_hash.begin()) ||
        !decode_sha256(expected_binary_protocol_sha256, expected_protocol_hash))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest.path,
                  "worker manifest identity"));

    if (expected_magic == 0x464d574eU) {
        std::uint8_t provider = 0;
        std::string provider_name;
        std::string provider_version;
        std::array<std::uint8_t, 32> provider_binary_hash{};
        std::string worker_build_id;
        std::array<std::uint8_t, 32> worker_build_hash{};
        std::uint32_t protocol = 0;
        std::uint32_t capabilities = 0;
        std::uint32_t argument_count = 0;
        std::array<std::uint8_t, 32> managed_runtime_manifest_hash{};
        std::array<std::uint8_t, 32> expected_managed_runtime_manifest_hash{};
        if (!reader.read_u8(provider) || provider != expected_provider ||
            !reader.read_string(provider_name) ||
            std::string_view(provider_name) != expected_provider_name ||
            !reader.read_string(provider_version) ||
            std::string_view(provider_version) != expected_provider_version ||
            !reader.read_bytes(provider_binary_hash.data(), provider_binary_hash.size()) ||
            (provider_binary_is_worker
                 ? !std::equal(provider_binary_hash.begin(), provider_binary_hash.end(),
                               expected_worker_hash.begin())
                 : (!decode_sha256(expected_provider_binary_sha256,
                                   expected_provider_binary_hash) ||
                    !std::equal(provider_binary_hash.begin(), provider_binary_hash.end(),
                                expected_provider_binary_hash.begin()))) ||
            !reader.read_string(worker_build_id) ||
            std::string_view(worker_build_id) != expected_worker_build_id ||
            !reader.read_bytes(worker_build_hash.data(), worker_build_hash.size()) ||
            !decode_sha256(expected_worker_build_sha256, expected_worker_build_hash) ||
            !std::equal(worker_build_hash.begin(), worker_build_hash.end(),
                        expected_worker_build_hash.begin()) ||
            !reader.read_u32(protocol) ||
            protocol != expected_binary_protocol ||
            !reader.read_bytes(protocol_hash.data(), protocol_hash.size()) ||
            !std::equal(protocol_hash.begin(), protocol_hash.end(),
                        expected_protocol_hash.begin()) ||
            !reader.read_u32(capabilities) || capabilities != 1 ||
            !reader.read_u32(argument_count) || argument_count != 0 ||
            (expected_schema == 3 &&
             (!reader.read_bytes(managed_runtime_manifest_hash.data(),
                                 managed_runtime_manifest_hash.size()) ||
              !decode_sha256(expected_managed_runtime_manifest_sha256,
                             expected_managed_runtime_manifest_hash) ||
              !std::equal(managed_runtime_manifest_hash.begin(),
                          managed_runtime_manifest_hash.end(),
                          expected_managed_runtime_manifest_hash.begin()))) ||
            (expected_schema != 3 && !expected_managed_runtime_manifest_sha256.empty()) ||
            !reader.exhausted())
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::protocol_mismatch, manifest.path));
    } else if (expected_magic == 0x4d575041U) {
        std::uint32_t capabilities = 0;
        if (!reader.read_bytes(protocol_hash.data(), protocol_hash.size()) ||
            !std::equal(protocol_hash.begin(), protocol_hash.end(),
                        expected_protocol_hash.begin()) ||
            !reader.read_u32(capabilities) || capabilities != 1 || !reader.exhausted())
            return build_worker_result_t<void>::failure(
                error(build_worker_error_code_t::protocol_mismatch, manifest.path));
    } else {
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::schema_mismatch, manifest.path));
    }
    auto digest_bytes = inspect_regular_file(digest.path, 256, true);
    if (!digest_bytes)
        return build_worker_result_t<void>::failure(digest_bytes.error());
    if (!fixed_time_equal(digest_bytes.value().content, manifest.sha256 + "\n"))
        return build_worker_result_t<void>::failure(
            error(build_worker_error_code_t::hash_mismatch, digest.path));
    return build_worker_result_t<void>::success();
}

bool unexpected_customer_file(std::string_view relative) {
    if (!safe_relative_path(relative))
        return true;
    const auto lower = lowercase(std::string(relative));
    constexpr std::string_view forbidden_extensions[]{
        ".a", ".asm", ".bash", ".bat", ".c", ".c++", ".cc", ".cmake", ".cmd", ".cpp",
        ".cppm", ".cs", ".csproj", ".cxx", ".def", ".exp", ".fs", ".fsproj", ".go",
        ".gradle", ".h", ".hh", ".hpp", ".hxx", ".ilk", ".in", ".inc", ".inl", ".ipp",
        ".ixx", ".java", ".kt", ".kts", ".lib", ".m", ".make", ".map", ".mk", ".mm",
        ".natvis", ".nupkg", ".nuspec", ".obj", ".pdb", ".props", ".ps1", ".psd1",
        ".psm1", ".pth", ".py", ".pyc", ".pyo", ".pyz", ".rc", ".rc2", ".rs", ".s",
        ".sh", ".sln", ".snupkg", ".spec", ".swift", ".targets", ".tpp", ".vb",
        ".vbproj", ".vcxproj", ".vcxproj.filters", ".whl", ".zig", ".zsh"
    };
    constexpr std::string_view forbidden_names[]{
        "build", "build.bazel", "cmakelists.txt", "gnumakefile", "makefile",
        "meson.build", "workspace", "workspace.bazel"
    };
    constexpr std::string_view forbidden_directories[]{
        "c03-safe-headless", "camoufox-reverse-mcp", "camoufox_reverse_mcp",
        "library-packs", "metadata", "packs", "sdk", "templates"
    };
    constexpr std::string_view stock_browsers[]{
        "chrome", "chrome.exe", "msedge", "msedge.exe", "stock-firefox", "stock-firefox.exe"
    };
    const auto ascii_alphanumeric = [](char character) noexcept {
        return (character >= 'a' && character <= 'z') ||
               (character >= '0' && character <= '9');
    };
    const auto policy_name_match = [&](std::string_view segment,
                                       std::string_view forbidden) noexcept {
        return segment == forbidden ||
               (segment.size() > forbidden.size() &&
                segment.compare(0, forbidden.size(), forbidden) == 0 &&
                !ascii_alphanumeric(segment[forbidden.size()]));
    };
    const auto forbidden_extension = [&](std::string_view segment) {
        for (const auto extension : forbidden_extensions) {
            std::size_t offset = 0;
            while (offset < segment.size()) {
                const auto match = segment.find(extension, offset);
                if (match == std::string_view::npos)
                    break;
                const auto after = match + extension.size();
                if (after == segment.size() || !ascii_alphanumeric(segment[after]))
                    return true;
                offset = match + 1;
            }
        }
        return false;
    };
    std::string_view remaining(lower);
    std::string_view leaf;
    while (!remaining.empty()) {
        const auto separator = remaining.find('/');
        const auto segment = remaining.substr(0, separator);
        const auto dot = segment.find('.');
        const auto device_base = segment.substr(0, dot);
        const bool reserved_device = device_base == "con" || device_base == "prn" ||
            device_base == "aux" || device_base == "nul" ||
            (device_base.size() == 4 &&
             (device_base.compare(0, 3, "com") == 0 ||
              device_base.compare(0, 3, "lpt") == 0) &&
             device_base[3] >= '1' && device_base[3] <= '9');
        const bool forbidden_name = std::any_of(
            std::begin(forbidden_names), std::end(forbidden_names),
            [&](std::string_view value) { return policy_name_match(segment, value); });
        const bool forbidden_directory = std::any_of(
            std::begin(forbidden_directories), std::end(forbidden_directories),
            [&](std::string_view value) { return policy_name_match(segment, value); });
        const bool metadata_wrapper = policy_name_match(segment, ".dist-info") ||
            policy_name_match(segment, ".egg-info") ||
            segment.find(".dist-info") != std::string_view::npos ||
            segment.find(".egg-info") != std::string_view::npos;
        if (reserved_device || forbidden_name || forbidden_directory || metadata_wrapper ||
            forbidden_extension(segment))
            return true;
        leaf = segment;
        if (separator == std::string_view::npos)
            break;
        remaining.remove_prefix(separator + 1);
    }
    return std::any_of(std::begin(stock_browsers), std::end(stock_browsers),
                       [&](std::string_view value) {
                           return policy_name_match(leaf, value);
                       });
}

struct directory_identity_t final {
    DWORD volume = 0;
    std::uint64_t file = 0;

    bool operator<(const directory_identity_t& other) const noexcept {
        return volume < other.volume || (volume == other.volume && file < other.file);
    }
};

build_worker_result_t<directory_identity_t> inspect_directory_identity(
    const std::filesystem::path& path) {
    win_handle_t directory;
    directory.handle = CreateFileW(
        path.c_str(), FILE_READ_ATTRIBUTES,
        active_generation ? FILE_SHARE_READ
                          : FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (directory.handle == INVALID_HANDLE_VALUE)
        return build_worker_result_t<directory_identity_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path,
                  "CreateFileW:directory", 0, GetLastError()));
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(directory.handle, FileAttributeTagInfo, &tag,
                                      sizeof(tag)))
        return build_worker_result_t<directory_identity_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path,
                  "FileAttributeTagInfo:directory", 0, GetLastError()));
    if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return build_worker_result_t<directory_identity_t>::failure(
            error(build_worker_error_code_t::reparse_point, path));
    if ((tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        return build_worker_result_t<directory_identity_t>::failure(
            error(build_worker_error_code_t::file_type_invalid, path));
    BY_HANDLE_FILE_INFORMATION identity{};
    if (!GetFileInformationByHandle(directory.handle, &identity))
        return build_worker_result_t<directory_identity_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path,
                  "GetFileInformationByHandle:directory", 0, GetLastError()));
    auto streams = verify_stream_inventory(path);
    if (!streams)
        return build_worker_result_t<directory_identity_t>::failure(streams.error());
    if (active_generation) {
        active_generation->directories.emplace_back(
            directory.handle, [](void* handle) {
                if (handle && handle != INVALID_HANDLE_VALUE)
                    CloseHandle(static_cast<HANDLE>(handle));
            });
        directory.handle = INVALID_HANDLE_VALUE;
    }
    return build_worker_result_t<directory_identity_t>::success({
        identity.dwVolumeSerialNumber,
        (static_cast<std::uint64_t>(identity.nFileIndexHigh) << 32U) |
            identity.nFileIndexLow});
}

build_worker_result_t<std::uint64_t> inspect_file_size_only(
    const std::filesystem::path& path) {
    if (active_generation) {
        auto evidence = inspect_regular_file(path, k_default_artifact_limit, false);
        if (!evidence)
            return build_worker_result_t<std::uint64_t>::failure(evidence.error());
        return build_worker_result_t<std::uint64_t>::success(evidence.value().size);
    }
    win_handle_t file;
    file.handle = CreateFileW(
        path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file.handle == INVALID_HANDLE_VALUE)
        return build_worker_result_t<std::uint64_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path,
                  "CreateFileW:size", 0, GetLastError()));
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(file.handle, FileAttributeTagInfo, &tag, sizeof(tag)))
        return build_worker_result_t<std::uint64_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path,
                  "FileAttributeTagInfo:size", 0, GetLastError()));
    if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return build_worker_result_t<std::uint64_t>::failure(
            error(build_worker_error_code_t::reparse_point, path));
    if ((tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return build_worker_result_t<std::uint64_t>::failure(
            error(build_worker_error_code_t::file_type_invalid, path));
    BY_HANDLE_FILE_INFORMATION identity{};
    if (!GetFileInformationByHandle(file.handle, &identity))
        return build_worker_result_t<std::uint64_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path,
                  "GetFileInformationByHandle:size", 0, GetLastError()));
    if (identity.nNumberOfLinks != 1)
        return build_worker_result_t<std::uint64_t>::failure(
            error(build_worker_error_code_t::hardlink_forbidden, path,
                  "nNumberOfLinks", 1, identity.nNumberOfLinks));
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.handle, &size) || size.QuadPart < 0)
        return build_worker_result_t<std::uint64_t>::failure(
            error(build_worker_error_code_t::file_read_failed, path,
                  "GetFileSizeEx:size", 0, GetLastError()));
    auto streams = verify_stream_inventory(path);
    if (!streams)
        return build_worker_result_t<std::uint64_t>::failure(streams.error());
    return build_worker_result_t<std::uint64_t>::success(
        static_cast<std::uint64_t>(size.QuadPart));
}

struct bounded_package_inventory_t final {
    std::vector<std::string> files;
    std::size_t directories = 0;
    std::size_t entries = 0;
    std::size_t path_bytes = 0;
    std::size_t stream_inventories = 0;
    std::uint64_t bytes = 0;
};

build_worker_result_t<bounded_package_inventory_t> enumerate_package_tree(
    const std::filesystem::path& root, const package_verification_request_t& request) {
    bounded_package_inventory_t result;
    result.directories = 1;
    result.stream_inventories = 1;
    auto root_identity = inspect_directory_identity(root);
    if (!root_identity)
        return build_worker_result_t<bounded_package_inventory_t>::failure(
            root_identity.error());
    std::set<directory_identity_t> directory_identities;
    directory_identities.emplace(root_identity.value());
    struct pending_directory_t final {
        std::filesystem::path path;
        std::size_t depth = 0;
    };
    std::queue<pending_directory_t> pending;
    std::set<std::string> folded_paths;
    pending.push({root, 0});
    while (!pending.empty()) {
        auto control = poll_verification_control(root, "tree_queue");
        if (!control)
            return build_worker_result_t<bounded_package_inventory_t>::failure(
                control.error());
        auto current = std::move(pending.front());
        pending.pop();
        struct discovered_entry_t final {
            std::filesystem::path path;
            std::string relative;
        };
        std::vector<discovered_entry_t> discovered;
        std::error_code iteration_error;
        std::filesystem::directory_iterator iterator(
            current.path, std::filesystem::directory_options::none, iteration_error);
        const std::filesystem::directory_iterator end;
        if (iteration_error)
            return build_worker_result_t<bounded_package_inventory_t>::failure(
                error(build_worker_error_code_t::file_read_failed, current.path,
                      iteration_error.message()));
        for (; iterator != end; iterator.increment(iteration_error)) {
            control = poll_verification_control(current.path, "tree_enumeration");
            if (!control)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    control.error());
            if (iteration_error)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::file_read_failed, current.path,
                          iteration_error.message()));
            ++result.entries;
            if (result.entries > request.maximum_total_entry_count)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::resource_entry_limit, root,
                          "total_entries", request.maximum_total_entry_count,
                          result.entries));
            const auto relative = iterator->path().lexically_relative(root);
            if (relative.empty() || relative.is_absolute())
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::path_escape, iterator->path()));
            std::string text;
            try {
                text = relative.generic_u8string();
            } catch (const std::exception& exception) {
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::unsafe_path, iterator->path(),
                          exception.what()));
            }
            if (text.size() > request.maximum_relative_path_bytes)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::resource_path_limit, iterator->path(),
                          "relative_path_bytes", request.maximum_relative_path_bytes,
                          text.size()));
            std::string absolute_text;
            try {
                absolute_text = iterator->path().generic_u8string();
            } catch (const std::exception& exception) {
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::unsafe_path, iterator->path(),
                          exception.what()));
            }
            const auto remaining_path_bytes =
                request.maximum_inventory_path_bytes - result.path_bytes;
            if (text.size() > remaining_path_bytes ||
                absolute_text.size() > remaining_path_bytes - text.size())
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::resource_path_limit, root,
                          "inventory_path_bytes", request.maximum_inventory_path_bytes,
                          result.path_bytes + text.size()));
            result.path_bytes += text.size() + absolute_text.size();
            discovered.push_back({iterator->path(), std::move(text)});
        }
        if (iteration_error)
            return build_worker_result_t<bounded_package_inventory_t>::failure(
                error(build_worker_error_code_t::file_read_failed, current.path,
                      iteration_error.message()));
        std::sort(discovered.begin(), discovered.end(),
                  [](const auto& left, const auto& right) {
                      return left.relative < right.relative;
                  });
        for (auto& entry : discovered) {
            control = poll_verification_control(entry.path, "tree_entry");
            if (!control)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    control.error());
            const DWORD attributes = GetFileAttributesW(entry.path.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::file_read_failed, entry.path,
                          "GetFileAttributesW", 0, GetLastError()));
            if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::reparse_point, entry.path));
            if (unexpected_customer_file(entry.relative))
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::package_policy_violation,
                          entry.path));
            if (!folded_paths.emplace(lowercase(entry.relative)).second)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::duplicate_entry, entry.path,
                          "case-colliding path"));
            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                ++result.directories;
                ++result.stream_inventories;
                if (result.directories > request.maximum_directory_count)
                    return build_worker_result_t<bounded_package_inventory_t>::failure(
                        error(build_worker_error_code_t::resource_directory_limit,
                              entry.path, "directories",
                              request.maximum_directory_count, result.directories));
                const auto depth = current.depth + 1;
                if (depth > request.maximum_depth)
                    return build_worker_result_t<bounded_package_inventory_t>::failure(
                        error(build_worker_error_code_t::resource_depth_limit,
                              entry.path, "depth", request.maximum_depth, depth));
                auto identity = inspect_directory_identity(entry.path);
                if (!identity)
                    return build_worker_result_t<bounded_package_inventory_t>::failure(
                        identity.error());
                if (!directory_identities.emplace(identity.value()).second)
                    return build_worker_result_t<bounded_package_inventory_t>::failure(
                        error(build_worker_error_code_t::directory_cycle,
                              entry.path));
                pending.push({std::move(entry.path), depth});
                continue;
            }
            ++result.stream_inventories;
            if (result.files.size() >= request.maximum_file_count)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::resource_file_limit,
                          entry.path, "files", request.maximum_file_count,
                          result.files.size() + 1));
            auto size = inspect_file_size_only(entry.path);
            if (!size)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    size.error());
            if (size.value() > request.maximum_artifact_bytes)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::resource_file_bytes_limit,
                          entry.path, "file_bytes", request.maximum_artifact_bytes,
                          size.value()));
            if (size.value() > request.maximum_total_artifact_bytes - result.bytes)
                return build_worker_result_t<bounded_package_inventory_t>::failure(
                    error(build_worker_error_code_t::resource_total_bytes_limit,
                          entry.path, "aggregate_bytes",
                          request.maximum_total_artifact_bytes,
                          result.bytes + size.value()));
            result.bytes += size.value();
            result.files.emplace_back(std::move(entry.relative));
        }
    }
    std::sort(result.files.begin(), result.files.end());
    if (std::adjacent_find(result.files.begin(), result.files.end()) != result.files.end())
        return build_worker_result_t<bounded_package_inventory_t>::failure(
            error(build_worker_error_code_t::duplicate_entry, root));
    return build_worker_result_t<bounded_package_inventory_t>::success(std::move(result));
}

}

bool customer_package_relative_path_allowed(std::string_view value) noexcept {
    return !unexpected_customer_file(value);
}

build_worker_error_t build_worker_packaging_integration_t::make_error(
    build_worker_error_code_t code, std::filesystem::path path, std::string detail,
    std::uint64_t expected, std::uint64_t actual) {
    return error(code, std::move(path), std::move(detail), expected, actual);
}

build_worker_result_t<deny_link_check_result_t>
build_worker_packaging_integration_t::check_deny_links(
    const deny_link_check_request_t& request) const {
    if (request.target_name.empty())
        return build_worker_result_t<deny_link_check_result_t>::failure(
            make_error(build_worker_error_code_t::invalid_argument));
    deny_link_check_result_t result;
    const std::array<const std::vector<std::string>*, 3> lists{
        &request.direct_links, &request.interface_links, &request.transitive_links
    };
    for (const auto* list : lists) {
        if (list->size() > 65536)
            return build_worker_result_t<deny_link_check_result_t>::failure(
                make_error(build_worker_error_code_t::invalid_argument));
        for (const auto& link : *list) {
            ++result.inspected;
            if (forbidden_link_token(link))
                return build_worker_result_t<deny_link_check_result_t>::failure(
                    make_error(build_worker_error_code_t::forbidden_link_detected, {},
                               request.target_name + ":" + link));
        }
    }
    deny_link_checks_.fetch_add(1, std::memory_order_release);
    return build_worker_result_t<deny_link_check_result_t>::success(result);
}

build_worker_result_t<package_verification_result_t>
build_worker_packaging_integration_t::verify_distribution_package(
    const package_verification_request_t& request) const {
    if (request.package_root.empty() || request.manifest_path.empty() ||
        request.maximum_manifest_bytes == 0 || request.maximum_receipt_bytes == 0 ||
        request.maximum_artifact_bytes == 0 || request.maximum_total_artifact_bytes == 0 ||
        request.maximum_file_count == 0 || request.maximum_directory_count == 0 ||
        request.maximum_total_entry_count == 0 || request.maximum_depth == 0 ||
        request.maximum_relative_path_bytes == 0 ||
        request.maximum_inventory_path_bytes == 0 ||
        request.deadline.count() <= 0 || request.deadline.count() > 7200000 ||
        !request.protector_verifier || !request.signature_verifier ||
        request.authorized_signer_thumbprints_sha256.empty() ||
        request.authorized_signer_thumbprints_sha256.size() > 16 ||
        request.maximum_manifest_bytes > k_default_manifest_limit ||
        request.maximum_receipt_bytes > k_default_receipt_limit ||
        request.maximum_artifact_bytes > k_default_artifact_limit ||
        request.maximum_total_artifact_bytes > k_default_package_total_limit ||
        request.maximum_file_count > k_default_file_count_limit ||
        request.maximum_directory_count > k_default_directory_count_limit ||
        request.maximum_total_entry_count > k_default_total_entry_count_limit ||
        request.maximum_depth > k_default_depth_limit ||
        request.maximum_relative_path_bytes > k_default_relative_path_limit ||
        request.maximum_inventory_path_bytes > k_default_inventory_path_bytes_limit)
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::invalid_argument));
    if (!valid_sha256(request.expected_manifest_sha256) ||
        !valid_sha256(request.expected_source_authority_sha256) ||
        !valid_sha256(request.expected_protector_tool_sha256) ||
        !valid_sha256(request.expected_protector_verifier_sha256) ||
        !valid_sha256(request.expected_signature_verifier_sha256) ||
        !valid_sha256(request.expected_signer_policy_sha256) ||
        !valid_sha256(request.expected_signing_provider_sha256) ||
        !std::is_sorted(request.authorized_signer_thumbprints_sha256.begin(),
                        request.authorized_signer_thumbprints_sha256.end()) ||
        std::adjacent_find(request.authorized_signer_thumbprints_sha256.begin(),
                           request.authorized_signer_thumbprints_sha256.end()) !=
            request.authorized_signer_thumbprints_sha256.end() ||
        !std::all_of(request.authorized_signer_thumbprints_sha256.begin(),
                     request.authorized_signer_thumbprints_sha256.end(),
                     [](const auto& value) { return valid_sha256(value); }))
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::invalid_argument, request.manifest_path));

    package_verification_control_t verification_control{
        &request, std::chrono::steady_clock::now() + request.deadline};
    [[maybe_unused]] const package_verification_control_scope_t verification_control_scope(
        verification_control);
    auto initial_control = poll_verification_control(request.package_root,
                                                     "verification_start");
    if (!initial_control)
        return build_worker_result_t<package_verification_result_t>::failure(
            initial_control.error());

    immutable_generation_context_t immutable_generation;
    [[maybe_unused]] const immutable_generation_scope_t immutable_generation_scope(
        immutable_generation);
    auto root_result = canonical_directory(request.package_root);
    if (!root_result)
        return build_worker_result_t<package_verification_result_t>::failure(root_result.error());
    const auto package_root = root_result.value();
    auto exact_manifest = exact_existing_path(request.manifest_path, false);
    if (!exact_manifest)
        return build_worker_result_t<package_verification_result_t>::failure(
            exact_manifest.error());
    auto manifest_evidence = inspect_regular_file(request.manifest_path,
                                                   request.maximum_manifest_bytes, true);
    if (!manifest_evidence)
        return build_worker_result_t<package_verification_result_t>::failure(
            manifest_evidence.error());
    if (!fixed_time_equal(manifest_evidence.value().sha256,
                          request.expected_manifest_sha256))
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::hash_mismatch, request.manifest_path,
                       manifest_evidence.value().sha256));
    std::error_code manifest_path_error;
    const auto canonical_manifest = std::filesystem::canonical(
        request.manifest_path, manifest_path_error);
    if (manifest_path_error || path_is_within(canonical_manifest, package_root))
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::package_policy_violation,
                       request.manifest_path, "distribution manifest must be detached"));

    json manifest;
    try {
        manifest = json::parse(manifest_evidence.value().content, nullptr, true, true);
    } catch (const std::exception& exception) {
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::malformed_json, request.manifest_path,
                       exception.what()));
    }
    if (json_contains_remote_reference(manifest))
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::remote_reference_forbidden,
                       request.manifest_path));
    if (!json_has_exact_keys(manifest, {"schema", "schema_version", "generator",
                                        "source_authority_sha256", "distribution", "artifacts",
                                        "workers", "dependencies", "customer_sidecars"}))
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::schema_mismatch, request.manifest_path));
    std::string schema;
    std::uint32_t schema_version = 0;
    std::string source_authority_sha256;
    if (!json_scalar(manifest, "schema", schema) ||
        std::string_view(schema) != k_distribution_manifest_schema ||
        !json_scalar(manifest, "schema_version", schema_version) ||
        schema_version != k_distribution_manifest_schema_version ||
        !json_scalar(manifest, "source_authority_sha256", source_authority_sha256) ||
        !valid_sha256(source_authority_sha256) ||
        !fixed_time_equal(source_authority_sha256,
                          request.expected_source_authority_sha256))
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::schema_mismatch, request.manifest_path));

    const auto& generator = manifest["generator"];
    std::string preset;
    std::string digest_algorithm;
    if (!json_has_exact_keys(generator, {"preset", "no_network_fetch", "offline_only",
                                         "manifest_digest_algorithm"}) ||
        !json_scalar(generator, "preset", preset) ||
        std::string_view(preset) != k_canonical_preset ||
        !bool_true(generator, "no_network_fetch") || !bool_true(generator, "offline_only") ||
        !json_scalar(generator, "manifest_digest_algorithm", digest_algorithm) ||
        digest_algorithm != "sha256")
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::package_policy_violation,
                       request.manifest_path));

    const auto& distribution = manifest["distribution"];
    std::string layout;
    if (!json_has_exact_keys(distribution, {"disk_backed", "protected",
                                            "arc_license_gates_required", "acl_restricted_ipc",
                                            "raw_standalone_download_forbidden",
                                            "fileless_launch_forbidden", "exact_inventory",
                                            "package_layout"}) ||
        !bool_true(distribution, "disk_backed") || !bool_true(distribution, "protected") ||
        !bool_true(distribution, "arc_license_gates_required") ||
        !bool_true(distribution, "acl_restricted_ipc") ||
        !bool_true(distribution, "raw_standalone_download_forbidden") ||
        !bool_true(distribution, "fileless_launch_forbidden") ||
        !bool_true(distribution, "exact_inventory") ||
        !json_scalar(distribution, "package_layout", layout) || layout != "self-contained")
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::package_policy_violation,
                       request.manifest_path));

    const auto& artifact_array = manifest["artifacts"];
    if (!artifact_array.is_array() || artifact_array.empty())
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::artifact_inventory_mismatch,
                       request.manifest_path));
    if (artifact_array.size() > request.maximum_file_count)
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::resource_file_limit,
                       request.manifest_path, "manifest_files",
                       request.maximum_file_count, artifact_array.size()));
    std::unordered_map<std::string, artifact_t> artifacts;
    std::unordered_set<std::string> paths;
    std::set<std::string> folded_paths;
    std::uint64_t total_bytes = 0;
    std::size_t notice_count = 0;
    const std::set<std::string_view> artifact_kinds{
        "application", "application_runtime", "worker_executable", "worker_runtime",
        "worker_manifest", "resource_manifest", "manifest_digest", "acl_receipt",
        "build_receipt", "protector_receipt", "signature_receipt", "browser",
        "reverse_mcp", "license", "notice", "dependency", "resource", "build_evidence"
    };
    for (const auto& value : artifact_array) {
        auto control = poll_verification_control(package_root, "artifact_inventory");
        if (!control)
            return build_worker_result_t<package_verification_result_t>::failure(
                control.error());
        if (!json_has_exact_keys(value, {"id", "kind", "relative_path", "size_bytes",
                                         "sha256", "owner", "license_ids"}))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::schema_mismatch, request.manifest_path));
        artifact_t artifact;
        if (!json_scalar(value, "id", artifact.id) || !safe_identifier(artifact.id) ||
            !json_scalar(value, "kind", artifact.kind) ||
            artifact_kinds.find(std::string_view(artifact.kind)) == artifact_kinds.end() ||
            !json_scalar(value, "relative_path", artifact.relative_path) ||
            !json_scalar(value, "size_bytes", artifact.size) || artifact.size == 0 ||
            !json_scalar(value, "sha256", artifact.sha256) || !valid_sha256(artifact.sha256) ||
            !json_scalar(value, "owner", artifact.owner) || !safe_identifier(artifact.owner) ||
            !json_string_array(value["license_ids"], artifact.license_ids, 128))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::schema_mismatch, request.manifest_path));
        if (!std::all_of(artifact.license_ids.begin(), artifact.license_ids.end(),
                         [](const std::string& value) { return safe_identifier(value); }))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::schema_mismatch, request.manifest_path));
        if (!artifacts.emplace(artifact.id, artifact).second ||
            !paths.emplace(artifact.relative_path).second ||
            !folded_paths.emplace(lowercase(artifact.relative_path)).second)
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::duplicate_entry,
                           std::filesystem::u8path(artifact.relative_path)));
        if (unexpected_customer_file(artifact.relative_path))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::package_policy_violation,
                           std::filesystem::u8path(artifact.relative_path)));
        if (artifact.size > request.maximum_artifact_bytes)
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::resource_file_bytes_limit,
                           std::filesystem::u8path(artifact.relative_path), "file_bytes",
                           request.maximum_artifact_bytes, artifact.size));
        if (artifact.size > request.maximum_total_artifact_bytes - total_bytes)
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::resource_total_bytes_limit,
                           package_root, "aggregate_bytes",
                           request.maximum_total_artifact_bytes,
                           total_bytes + artifact.size));
        auto resolved = resolve_regular_under_root(package_root, artifact.relative_path);
        if (!resolved)
            return build_worker_result_t<package_verification_result_t>::failure(resolved.error());
        auto evidence = inspect_regular_file(resolved.value(), request.maximum_artifact_bytes, false);
        if (!evidence)
            return build_worker_result_t<package_verification_result_t>::failure(evidence.error());
        if (evidence.value().size != artifact.size)
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::size_mismatch, resolved.value(), {},
                           artifact.size, evidence.value().size));
        if (!fixed_time_equal(evidence.value().sha256, artifact.sha256))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::hash_mismatch, resolved.value(),
                           evidence.value().sha256));
        total_bytes += evidence.value().size;
        artifacts[artifact.id].path = resolved.value();
        if (artifact.kind == "notice" || artifact.kind == "license")
            ++notice_count;
    }

    auto bounded_inventory = enumerate_package_tree(package_root, request);
    if (!bounded_inventory)
        return build_worker_result_t<package_verification_result_t>::failure(
            bounded_inventory.error());
    std::unordered_set<std::string> actual_paths(
        bounded_inventory.value().files.begin(), bounded_inventory.value().files.end());
    if (actual_paths != paths || bounded_inventory.value().bytes != total_bytes)
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::artifact_inventory_mismatch, package_root,
                       "bounded exact inventory", paths.size(), actual_paths.size()));

    const auto production_link_graph = artifacts.find("production-link-graph");
    if (production_link_graph == artifacts.end() ||
        production_link_graph->second.kind != "build_evidence" ||
        production_link_graph->second.relative_path !=
            "deps/evidence/production-link-graph.json" ||
        production_link_graph->second.owner != "standalone")
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::artifact_inventory_mismatch,
                       package_root, "production link graph evidence"));
    auto production_link_document = parse_json_file(
        production_link_graph->second.path, request.maximum_receipt_bytes,
        production_link_graph->second.sha256);
    if (!production_link_document)
        return build_worker_result_t<package_verification_result_t>::failure(
            production_link_document.error());
    const auto& link_document = production_link_document.value();
    std::string link_schema;
    std::uint32_t link_schema_version = 0;
    std::string link_configuration;
    std::string link_integration_host;
    std::vector<std::string> link_denylist;
    std::vector<std::string> link_roots;
    std::vector<std::string> link_targets;
    std::vector<std::string> link_edges;
    std::vector<std::string> link_host_edges;
    std::vector<std::string> link_host_exemptions;
    std::uint64_t manifest_root_count = 0;
    std::uint64_t direct_root_count = 0;
    std::uint64_t strict_root_count = 0;
    if (!json_has_exact_keys(link_document,
                             {"schema", "schema_version", "configuration", "denylist",
                              "manifest_root_count", "direct_root_count",
                              "strict_root_count",
                              "strict_roots", "strict_targets", "strict_edges",
                              "integration_host", "host_direct_edges",
                              "host_preexisting_exemptions"}) ||
        !json_scalar(link_document, "schema", link_schema) ||
        link_schema != "aida.c03.production-link-graph.v3" ||
        !json_scalar(link_document, "schema_version", link_schema_version) ||
        link_schema_version != 3 ||
        !json_scalar(link_document, "configuration", link_configuration) ||
        link_configuration.size() > 128 ||
        !json_string_array(link_document["denylist"], link_denylist, 4) ||
        link_denylist != std::vector<std::string>({"lief", "lmdb", "unicorn", "remill"}) ||
        !json_scalar(link_document, "manifest_root_count", manifest_root_count) ||
        manifest_root_count != 56 ||
        !json_scalar(link_document, "direct_root_count", direct_root_count) ||
        direct_root_count != 15 ||
        !json_scalar(link_document, "strict_root_count", strict_root_count) ||
        !json_string_array(link_document["strict_roots"], link_roots, 4096) ||
        strict_root_count != link_roots.size() || strict_root_count < 77 ||
        !json_string_array(link_document["strict_targets"], link_targets, 65536) ||
        !json_string_array(link_document["strict_edges"], link_edges, 65536) ||
        !json_scalar(link_document, "integration_host", link_integration_host) ||
        link_integration_host != "AiDAStandalone" ||
        !json_string_array(link_document["host_direct_edges"], link_host_edges, 65536) ||
        !json_string_array(link_document["host_preexisting_exemptions"],
                           link_host_exemptions, 16) ||
        link_host_exemptions != std::vector<std::string>({
            "AiDAStandalone|LINK_LIBRARIES|unicorn"}) ||
        link_targets.empty() || link_edges.empty() || link_host_edges.empty() ||
        !std::is_sorted(link_roots.begin(), link_roots.end()) ||
        !std::is_sorted(link_targets.begin(), link_targets.end()) ||
        !std::is_sorted(link_edges.begin(), link_edges.end()) ||
        !std::is_sorted(link_host_edges.begin(), link_host_edges.end()) ||
        !std::is_sorted(link_host_exemptions.begin(), link_host_exemptions.end()))
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::schema_mismatch,
                       production_link_graph->second.path,
                       "production link graph contract"));
    const std::set<std::string_view> link_properties{
        "LINK_LIBRARIES", "LINK_INTERFACE_LIBRARIES", "INTERFACE_LINK_LIBRARIES",
        "INTERFACE_LINK_LIBRARIES_DIRECT", "IMPORTED_LINK_INTERFACE_LIBRARIES",
        "IMPORTED_LINK_INTERFACE_LIBRARIES_DEBUG",
        "IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE",
        "IMPORTED_LINK_INTERFACE_LIBRARIES_RELWITHDEBINFO",
        "IMPORTED_LINK_INTERFACE_LIBRARIES_MINSIZEREL",
        "IMPORTED_LINK_DEPENDENT_LIBRARIES",
        "IMPORTED_LINK_DEPENDENT_LIBRARIES_DEBUG",
        "IMPORTED_LINK_DEPENDENT_LIBRARIES_RELEASE",
        "IMPORTED_LINK_DEPENDENT_LIBRARIES_RELWITHDEBINFO",
        "IMPORTED_LINK_DEPENDENT_LIBRARIES_MINSIZEREL"};
    const auto validate_link_edge = [&](const std::string& edge,
                                         std::string_view required_source,
                                         bool allow_preexisting_host_exemption) {
        const auto first = edge.find('|');
        const auto second = first == std::string::npos ? std::string::npos :
            edge.find('|', first + 1);
        if (first == 0 || second == std::string::npos || second == first + 1 ||
            second + 1 >= edge.size() || edge.find('|', second + 1) != std::string::npos)
            return false;
        const auto source = std::string_view(edge).substr(0, first);
        if ((!required_source.empty() && source != required_source) ||
            (required_source.empty() &&
             !std::binary_search(link_targets.begin(), link_targets.end(),
                                 std::string(source))) ||
            link_properties.find(std::string_view(edge).substr(
                first + 1, second - first - 1)) == link_properties.end())
            return false;
        if (!forbidden_link_token(std::string_view(edge).substr(second + 1)))
            return true;
        return (allow_preexisting_host_exemption || source == "AiDAStandalone") &&
            std::binary_search(link_host_exemptions.begin(),
                               link_host_exemptions.end(), edge);
    };
    for (const auto& edge : link_edges) {
        if (!validate_link_edge(edge, {}, false))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::forbidden_link_detected,
                           production_link_graph->second.path, edge));
    }
    for (const auto& edge : link_host_edges) {
        if (!validate_link_edge(edge, link_integration_host, true))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::forbidden_link_detected,
                           production_link_graph->second.path, edge));
    }
    const bool production_link_graph_verified =
        !link_edges.empty() && !link_host_edges.empty() &&
        std::binary_search(link_roots.begin(), link_roots.end(), "AiDAStandalone") &&
        std::binary_search(link_roots.begin(), link_roots.end(),
                           "aida_c03_safe_headless_runtime") &&
        std::binary_search(link_roots.begin(), link_roots.end(),
                           "aida_c03_auth_preview_implementation") &&
        std::binary_search(link_roots.begin(), link_roots.end(),
                           "aida_c03_b14_native_decompiler_worker") &&
        std::binary_search(link_roots.begin(), link_roots.end(),
                           "aida_c03_package_verifier") &&
        std::all_of(link_roots.begin(), link_roots.end(),
                    [&](const auto& root) {
                        return std::binary_search(link_targets.begin(), link_targets.end(), root);
                    }) &&
        std::all_of(link_host_exemptions.begin(), link_host_exemptions.end(),
                    [&](const auto& exemption) {
                        return std::binary_search(link_host_edges.begin(),
                                                  link_host_edges.end(), exemption);
                    });
    if (!production_link_graph_verified)
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::schema_mismatch,
                       production_link_graph->second.path,
                       "production link graph root closure"));
    if (request.verification_checkpoint) {
        try {
            request.verification_checkpoint(
                package_verification_checkpoint_t::immutable_generation_captured);
        } catch (const std::exception& exception) {
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::internal_error, package_root,
                           exception.what()));
        } catch (...) {
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::internal_error, package_root,
                           "immutable_generation_checkpoint"));
        }
    }

    const auto managed_runtime_manifest = artifacts.find("managed-runtime-manifest");
    const auto managed_runtime_digest = artifacts.find("managed-runtime-manifest-digest");
    const auto ghidra_manifest = artifacts.find("ghidra-spec-manifest");
    const auto ghidra_digest = artifacts.find("ghidra-spec-manifest-digest");
    if (managed_runtime_manifest == artifacts.end() ||
        managed_runtime_digest == artifacts.end() ||
        ghidra_manifest == artifacts.end() || ghidra_digest == artifacts.end() ||
        managed_runtime_manifest->second.kind != "resource_manifest" ||
        managed_runtime_manifest->second.owner != "managed_cli_decompiler" ||
        managed_runtime_digest->second.owner != "managed_cli_decompiler" ||
        ghidra_manifest->second.kind != "resource_manifest" ||
        ghidra_manifest->second.owner != "native_decompiler" ||
        ghidra_digest->second.owner != "native_decompiler")
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::artifact_inventory_mismatch,
                       request.manifest_path, "worker resource manifest inventory"));
    auto managed_runtime = verify_managed_runtime_manifest(
        managed_runtime_manifest->second, managed_runtime_digest->second, artifacts,
        request.maximum_receipt_bytes);
    if (!managed_runtime)
        return build_worker_result_t<package_verification_result_t>::failure(
            managed_runtime.error());
    auto ghidra_specs = verify_ghidra_spec_manifest(
        ghidra_manifest->second, ghidra_digest->second, artifacts,
        request.maximum_receipt_bytes);
    if (!ghidra_specs)
        return build_worker_result_t<package_verification_result_t>::failure(
            ghidra_specs.error());

    std::size_t camoufox_files = 0;
    std::size_t customer_notice_files = 0;
    for (const auto& artifact : artifacts) {
        auto control = poll_verification_control(artifact.second.path,
                                                 "artifact_verification");
        if (!control)
            return build_worker_result_t<package_verification_result_t>::failure(
                control.error());
        if (artifact.second.relative_path.rfind(
                "deps/camoufox-135.0.1-beta.24-win.x86_64/", 0) == 0) {
            if (artifact.second.kind != "browser" || artifact.second.owner != "camoufox")
                return build_worker_result_t<package_verification_result_t>::failure(
                    make_error(build_worker_error_code_t::package_policy_violation,
                               artifact.second.path, "Camoufox exact-tree classification"));
            ++camoufox_files;
        }
        if (artifact.second.relative_path.rfind("notices/", 0) == 0) {
            if (artifact.second.kind != "notice" && artifact.second.kind != "license")
                return build_worker_result_t<package_verification_result_t>::failure(
                    make_error(build_worker_error_code_t::notice_missing,
                               artifact.second.path, "customer notice classification"));
            ++customer_notice_files;
        }
    }
    if (camoufox_files != 502 || customer_notice_files != 26)
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::artifact_inventory_mismatch,
                       package_root, "exact sidecar tree cardinality", 528,
                        camoufox_files + customer_notice_files));

    std::size_t acl_receipts = 0;
    std::size_t protector_receipts = 0;
    std::size_t signature_receipts = 0;
    const auto standalone = artifacts.find("standalone-executable");
    const auto standalone_protector = artifacts.find("standalone-protector");
    const auto standalone_signature = artifacts.find("standalone-signature");
    if (standalone == artifacts.end() || standalone_protector == artifacts.end() ||
        standalone_signature == artifacts.end() || standalone->second.kind != "application" ||
        standalone->second.relative_path != "AiDAStandalone.exe" ||
        standalone->second.owner != "standalone" ||
        standalone_protector->second.kind != "protector_receipt" ||
        standalone_protector->second.owner != "standalone" ||
        standalone_signature->second.kind != "signature_receipt" ||
        standalone_signature->second.owner != "standalone")
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::artifact_inventory_mismatch,
                       package_root, "protected standalone artifact inventory"));
    auto standalone_protector_check = verify_protector_receipt(
        standalone_protector->second, standalone->second,
        request.expected_protector_tool_sha256,
        request.expected_protector_verifier_sha256,
        request.expected_signer_policy_sha256,
        request.expected_signing_provider_sha256, "standalone-no-imports",
        request.protector_verifier, request.maximum_receipt_bytes);
    if (!standalone_protector_check)
        return build_worker_result_t<package_verification_result_t>::failure(
            standalone_protector_check.error());
    ++protector_receipts;
    auto standalone_signature_check = verify_signature_receipt(
        standalone_signature->second, standalone->second,
        request.expected_signature_verifier_sha256,
        request.expected_signer_policy_sha256,
        request.expected_signing_provider_sha256,
        request.authorized_signer_thumbprints_sha256,
        request.signature_verifier, request.maximum_receipt_bytes);
    if (!standalone_signature_check)
        return build_worker_result_t<package_verification_result_t>::failure(
            standalone_signature_check.error());
    ++signature_receipts;

    const auto& dependency_array = manifest["dependencies"];
    if (!dependency_array.is_array() || dependency_array.size() != 30)
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::dependency_graph_invalid,
                        request.manifest_path));
    struct dependency_t final {
        std::string version;
        std::string usage;
        std::string license;
        std::vector<std::string> artifact_ids;
        std::vector<std::string> notice_ids;
        std::vector<std::string> dependencies;
    };
    std::unordered_map<std::string, dependency_t> dependencies;
    for (const auto& value : dependency_array) {
        auto control = poll_verification_control(package_root, "dependency_inventory");
        if (!control)
            return build_worker_result_t<package_verification_result_t>::failure(
                control.error());
        if (!json_has_exact_keys(value, {"id", "version", "usage", "license",
                                         "artifact_ids", "notice_artifact_ids",
                                         "dependencies"}))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid,
                           request.manifest_path));
        std::string id;
        dependency_t dependency;
        if (!json_scalar(value, "id", id) || !safe_identifier(id) ||
            !json_scalar(value, "version", dependency.version) ||
            dependency.version.empty() || dependency.version.size() > 128 ||
            !json_scalar(value, "usage", dependency.usage) ||
            (dependency.usage != "production" && dependency.usage != "build_only" &&
             dependency.usage != "evidence_only" && dependency.usage != "non_use") ||
            !json_scalar(value, "license", dependency.license) ||
            dependency.license.empty() || dependency.license.size() > 256 ||
            !json_string_array(value["artifact_ids"], dependency.artifact_ids) ||
            !json_string_array(value["notice_artifact_ids"], dependency.notice_ids) ||
            !json_string_array(value["dependencies"], dependency.dependencies))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid,
                           request.manifest_path));
        const auto valid_dependency_identifiers = [](const std::vector<std::string>& values) {
            return std::all_of(values.begin(), values.end(), [](const std::string& value) {
                return safe_identifier(value);
            });
        };
        if (!valid_dependency_identifiers(dependency.artifact_ids) ||
            !valid_dependency_identifiers(dependency.notice_ids) ||
            !valid_dependency_identifiers(dependency.dependencies))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid,
                           request.manifest_path));
        if (!dependencies.emplace(id, dependency).second)
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::duplicate_entry, {}, id));
        const auto lower_id = lowercase(id);
        if ((lower_id == "lmdb" || lower_id == "unicorn") &&
            (dependency.usage != "non_use" || !dependency.artifact_ids.empty()))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::forbidden_link_detected, {}, id));
        if (lower_id == "remill" &&
            (dependency.usage != "evidence_only" || !dependency.artifact_ids.empty()))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::forbidden_link_detected, {}, id));
        if (dependency.usage == "production" && dependency.notice_ids.empty())
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::notice_missing, {}, id));
        if (dependency.usage != "production" && !dependency.artifact_ids.empty())
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::package_policy_violation, {}, id));
        for (const auto& artifact_id : dependency.artifact_ids) {
            if (artifacts.find(artifact_id) == artifacts.end())
                return build_worker_result_t<package_verification_result_t>::failure(
                    make_error(build_worker_error_code_t::dependency_graph_invalid, {}, artifact_id));
        }
        for (const auto& notice_id : dependency.notice_ids) {
            const auto found = artifacts.find(notice_id);
            if (found == artifacts.end() ||
                (found->second.kind != "notice" && found->second.kind != "license"))
                return build_worker_result_t<package_verification_result_t>::failure(
                    make_error(build_worker_error_code_t::notice_missing, {}, notice_id));
        }
    }
    struct expected_dependency_t final {
        std::string_view id;
        std::string_view version;
        std::string_view usage;
        std::string_view license;
    };
    constexpr std::array expected_dependencies{
        expected_dependency_t{"zydis", "4.1.1", "production", "MIT"},
        expected_dependency_t{"zycore", "bundled-4.1.1", "production", "MIT"},
        expected_dependency_t{"capstone", "5.0.9", "production", "BSD-style"},
        expected_dependency_t{"taskflow", "local-pinned", "production", "MIT"},
        expected_dependency_t{"ghidra-worker", "local-pinned", "production", "Apache-2.0"},
        expected_dependency_t{"triton", "local-pinned", "production", "Apache-2.0"},
        expected_dependency_t{"z3", "4.13.4", "production", "MIT"},
        expected_dependency_t{"sqlite", "3.53.3", "production", "Public-Domain"},
        expected_dependency_t{"imgui", "local-pinned", "production", "MIT"},
        expected_dependency_t{"zlib", "1.3.2", "production", "zlib"},
        expected_dependency_t{"zstd", "1.5.7", "production", "BSD-3-Clause"},
        expected_dependency_t{"liblzma", "5.8.3", "production", "0BSD"},
        expected_dependency_t{"minizip-ng", "4.2.2", "production", "zlib"},
        expected_dependency_t{"pcre2", "10.47", "production", "BSD-3-Clause-WITH-PCRE2-exception"},
        expected_dependency_t{"nlohmann-json", "3.12.0", "production", "MIT"},
        expected_dependency_t{"json-schema-validator", "2.4.0", "production", "MIT"},
        expected_dependency_t{"llvm-demangle", "22.1.8", "production", "Apache-2.0-WITH-LLVM-exception"},
        expected_dependency_t{"dotnet-runtime", "10.0.9", "production", "Microsoft-.NET-Library-and-third-party"},
        expected_dependency_t{"dotnet-sdk", "10.0.301", "build_only", "Microsoft-.NET-Library"},
        expected_dependency_t{"icsharpcode-decompiler", "10.1.0.8386", "production", "MIT"},
        expected_dependency_t{"system-collections-immutable", "9.0.0", "production", "MIT"},
        expected_dependency_t{"system-reflection-metadata", "9.0.0", "production", "MIT"},
        expected_dependency_t{"analysis-python-worker", "protocol-v1", "production", "AiDA-Proprietary"},
        expected_dependency_t{"camoufox", "135.0.1-beta.24", "production", "MPL-2.0-and-third-party"},
        expected_dependency_t{"camoufox-reverse-mcp", "local-pinned", "production", "MIT-and-runtime-graph"},
        expected_dependency_t{"pyinstaller", "6.21.0", "build_only", "GPL-2.0-or-later-with-bootloader-exception"},
        expected_dependency_t{"lief", "0.17.6", "evidence_only", "Apache-2.0"},
        expected_dependency_t{"remill", "6.0.1", "evidence_only", "Apache-2.0"},
        expected_dependency_t{"lmdb", "not-selected", "non_use", "not-shipped"},
        expected_dependency_t{"unicorn", "not-selected", "non_use", "not-shipped"},
    };
    for (const auto& expected : expected_dependencies) {
        auto control = poll_verification_control(package_root, "dependency_policy");
        if (!control)
            return build_worker_result_t<package_verification_result_t>::failure(
                control.error());
        const auto found = dependencies.find(std::string(expected.id));
        if (found == dependencies.end() || found->second.version != expected.version ||
            found->second.usage != expected.usage || found->second.license != expected.license)
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid, {},
                           std::string(expected.id)));
    }
    enum class visit_t : std::uint8_t { none, active, complete };
    std::unordered_map<std::string, visit_t> visits;
    std::function<bool(const std::string&)> visit = [&](const std::string& id) {
        auto& state = visits[id];
        if (state == visit_t::active)
            return false;
        if (state == visit_t::complete)
            return true;
        const auto found = dependencies.find(id);
        if (found == dependencies.end())
            return false;
        state = visit_t::active;
        for (const auto& child : found->second.dependencies) {
            if (!visit(child))
                return false;
        }
        state = visit_t::complete;
        return true;
    };
    for (const auto& dependency : dependencies) {
        auto control = poll_verification_control(package_root, "dependency_graph");
        if (!control)
            return build_worker_result_t<package_verification_result_t>::failure(
                control.error());
        if (!visit(dependency.first))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid, {},
                           dependency.first));
    }

    const auto& workers = manifest["workers"];
    if (!workers.is_array() || workers.size() != k_required_worker_count)
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::worker_inventory_mismatch,
                       request.manifest_path, {}, k_required_worker_count, workers.size()));
    struct expected_worker_t final {
        std::string_view executable;
        std::string_view protocol_name;
        std::string_view manifest_protocol_hash;
        std::string_view binary_protocol_hash;
        std::string_view provider_name;
        std::string_view provider_version;
        std::string_view worker_build_id;
        std::string_view worker_build_hash;
        std::string_view provider_binary_hash;
        std::uint32_t manifest_magic;
        std::uint32_t manifest_protocol;
        std::uint32_t binary_protocol;
        std::uint32_t manifest_schema;
        std::uint8_t provider;
        bool provider_binary_is_worker;
        std::uint64_t cpu_quota_ms;
        std::uint64_t memory_quota_bytes;
        std::uint64_t deadline_ms;
    };
    const std::map<std::string, expected_worker_t> expected_workers{
        {"native_decompiler", {"deps/AiDA_NativeDecompilerWorker.exe",
          "aida-native-decompiler", "a0026d656b22dac563f5118b2d18f132c2bc2a64efaa28e5d170da0b725edccc",
          "a0026d656b22dac563f5118b2d18f132c2bc2a64efaa28e5d170da0b725edccc",
          "aida-native-decompiler", "2", "aida-native-decompiler-worker-v3",
          "50c79d3e14004aecfea4b2dd358d236d160a7c1b468b96806df00ede6e765a47", {},
          0x464d574eU, 3, 3, 2, 1, true, 30000, 2147483648ULL, 60000}},
        {"managed_cli_decompiler", {"deps/AiDA_ManagedDecompilerWorker.exe",
          "aida-managed-cli-decompiler", "4fe173593d2e044466706c58b3573ec528930a1762a3177ac53e7b84c166cfa6",
          "a0026d656b22dac563f5118b2d18f132c2bc2a64efaa28e5d170da0b725edccc",
          "ICSharpCode.Decompiler", "10.1.0.8386", "aida-managed-decompiler-worker-v3",
          "4dd8c0d095629437387a4b631fd9ac3c3cb8e840f6b7af277ccc2ad49d4bc3b7",
          "bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345",
          0x464d574eU, 3, 3, 3, 2, false, 30000, 2147483648ULL, 60000}},
        {"analysis_python", {"deps/AiDA_AnalysisPythonWorker.exe",
          "aida-analysis-python", "0a8dd2e97f78ef594ea2b7b5399eb1a049972e0b2d9a9541378aca0c76879004",
          "0a8dd2e97f78ef594ea2b7b5399eb1a049972e0b2d9a9541378aca0c76879004",
           {}, {}, {}, {}, {}, 0x4d575041U, 1, 1, 1, 0, false,
           15000, 536870912ULL, 30000}},
    };
    const std::map<std::string, std::pair<std::string_view, std::uint64_t>> expected_acl{
        {"native_decompiler", {"native", 105}},
        {"managed_cli_decompiler", {"managed", 207}},
        {"analysis_python", {"analysis_python", 1}},
    };
    std::set<std::string> worker_ids;
    for (const auto& value : workers) {
        auto control = poll_verification_control(package_root, "worker_inventory");
        if (!control)
            return build_worker_result_t<package_verification_result_t>::failure(
                control.error());
        if (!json_has_exact_keys(value, {"id", "executable_artifact",
                                         "worker_manifest_artifact",
                                         "worker_manifest_digest_artifact",
                                         "acl_receipt_artifact",
                                         "protector_receipt_artifact",
                                         "signature_receipt_artifact", "protocol",
                                         "containment", "target_execution_forbidden",
                                         "dependency_ids"}))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::worker_inventory_mismatch,
                           request.manifest_path));
        std::string id;
        std::string executable_id;
        std::string manifest_id;
        std::string manifest_digest_id;
        std::string acl_id;
        std::string protector_id;
        std::string signature_id;
        if (!json_scalar(value, "id", id) || !worker_ids.emplace(id).second ||
            !json_scalar(value, "executable_artifact", executable_id) ||
            !json_scalar(value, "worker_manifest_artifact", manifest_id) ||
            !json_scalar(value, "worker_manifest_digest_artifact", manifest_digest_id) ||
            !json_scalar(value, "acl_receipt_artifact", acl_id) ||
            !json_scalar(value, "protector_receipt_artifact", protector_id) ||
            !json_scalar(value, "signature_receipt_artifact", signature_id))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::worker_inventory_mismatch,
                           request.manifest_path));
        const auto expected = expected_workers.find(id);
        const auto executable = artifacts.find(executable_id);
        const auto worker_manifest = artifacts.find(manifest_id);
        const auto manifest_digest = artifacts.find(manifest_digest_id);
        const auto acl = artifacts.find(acl_id);
        const auto protector = artifacts.find(protector_id);
        const auto signature = artifacts.find(signature_id);
        if (expected == expected_workers.end() || executable == artifacts.end() ||
            worker_manifest == artifacts.end() || manifest_digest == artifacts.end() ||
            acl == artifacts.end() || protector == artifacts.end() ||
            signature == artifacts.end() ||
            std::string_view(executable->second.relative_path) != expected->second.executable ||
            executable->second.kind != "worker_executable" ||
            worker_manifest->second.kind != "worker_manifest" ||
            manifest_digest->second.kind != "manifest_digest" ||
            acl->second.kind != "acl_receipt" ||
            protector->second.kind != "protector_receipt" ||
            signature->second.kind != "signature_receipt" ||
            executable->second.owner != id || worker_manifest->second.owner != id ||
            manifest_digest->second.owner != id || acl->second.owner != id ||
            protector->second.owner != id ||
            signature->second.owner != id)
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::worker_inventory_mismatch, {}, id));

        const auto& protocol = value["protocol"];
        std::string protocol_name;
        std::string hash_material_sha256;
        std::uint32_t protocol_version = 0;
        std::uint32_t manifest_schema_version = 0;
        if (!json_has_exact_keys(protocol, {"name", "version", "hash_material_sha256",
                                            "worker_manifest_schema_version"}) ||
            !json_scalar(protocol, "name", protocol_name) ||
            std::string_view(protocol_name) != expected->second.protocol_name ||
            !json_scalar(protocol, "version", protocol_version) ||
            protocol_version != expected->second.manifest_protocol ||
            !json_scalar(protocol, "hash_material_sha256", hash_material_sha256) ||
            !valid_sha256(hash_material_sha256) ||
            !fixed_time_equal(hash_material_sha256, expected->second.manifest_protocol_hash) ||
            !json_scalar(protocol, "worker_manifest_schema_version", manifest_schema_version) ||
            manifest_schema_version != expected->second.manifest_schema)
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::protocol_mismatch, {}, id,
                           expected->second.manifest_protocol, protocol_version));

        const auto& containment = value["containment"];
        std::uint64_t cpu_quota = 0;
        std::uint64_t memory_quota = 0;
        std::uint64_t deadline = 0;
        if (!json_has_exact_keys(containment, {"job_object", "kill_on_parent_close",
                                               "restricted_token", "network_denied",
                                               "child_process_denied", "unrelated_handles_denied",
                                               "process_mitigations", "acl_restricted_ipc",
                                               "authenticated_ipc", "monotonic_sequence",
                                               "cpu_quota_ms", "memory_quota_bytes",
                                               "deadline_ms", "cancellation_replaces_worker"}) ||
            !bool_true(containment, "job_object") ||
            !bool_true(containment, "kill_on_parent_close") ||
            !bool_true(containment, "restricted_token") ||
            !bool_true(containment, "network_denied") ||
            !bool_true(containment, "child_process_denied") ||
            !bool_true(containment, "unrelated_handles_denied") ||
            !bool_true(containment, "process_mitigations") ||
            !bool_true(containment, "acl_restricted_ipc") ||
            !bool_true(containment, "authenticated_ipc") ||
            !bool_true(containment, "monotonic_sequence") ||
            !bool_true(containment, "cancellation_replaces_worker") ||
            !json_scalar(containment, "cpu_quota_ms", cpu_quota) ||
            cpu_quota != expected->second.cpu_quota_ms ||
            !json_scalar(containment, "memory_quota_bytes", memory_quota) ||
            memory_quota != expected->second.memory_quota_bytes ||
            !json_scalar(containment, "deadline_ms", deadline) ||
            deadline != expected->second.deadline_ms ||
            !bool_true(value, "target_execution_forbidden"))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::containment_policy_mismatch, {}, id));

        std::vector<std::string> worker_dependencies;
        if (!json_string_array(value["dependency_ids"], worker_dependencies) ||
            worker_dependencies.empty())
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid, {}, id));
        const std::map<std::string, std::vector<std::string>> expected_worker_dependencies{
            {"native_decompiler", {"ghidra-worker"}},
            {"managed_cli_decompiler", {"dotnet-runtime", "icsharpcode-decompiler",
                                          "system-collections-immutable",
                                          "system-reflection-metadata"}},
            {"analysis_python", {"analysis-python-worker"}},
        };
        const auto expected_dependencies = expected_worker_dependencies.find(id);
        if (expected_dependencies == expected_worker_dependencies.end() ||
            worker_dependencies != expected_dependencies->second)
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid, {}, id));
        for (const auto& dependency_id : worker_dependencies) {
            const auto dependency = dependencies.find(dependency_id);
            if (dependency == dependencies.end() || dependency->second.usage != "production")
                return build_worker_result_t<package_verification_result_t>::failure(
                    make_error(build_worker_error_code_t::dependency_graph_invalid, {},
                               dependency_id));
        }
        win_handle_t executable_lock;
        executable_lock.handle = CreateFileW(
            executable->second.path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
                               FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (executable_lock.handle == INVALID_HANDLE_VALUE)
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::file_read_failed,
                           executable->second.path, "CreateFileW:worker-lock", 0,
                           GetLastError()));
        auto locked_executable = inspect_regular_file(
            executable->second.path, request.maximum_artifact_bytes, false);
        if (!locked_executable)
            return build_worker_result_t<package_verification_result_t>::failure(
                locked_executable.error());
        if (locked_executable.value().size != executable->second.size ||
            !fixed_time_equal(locked_executable.value().sha256,
                              executable->second.sha256))
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::file_changed,
                           executable->second.path));
        const std::string_view managed_runtime_hash =
            id == "managed_cli_decompiler" ? std::string_view(managed_runtime.value())
                                            : std::string_view{};
        auto binary_manifest = verify_worker_manifest_binary(
            worker_manifest->second, manifest_digest->second, executable->second,
            expected->second.manifest_magic, expected->second.manifest_schema,
            expected->second.provider, expected->second.binary_protocol,
            expected->second.binary_protocol_hash, expected->second.provider_name,
            expected->second.provider_version, expected->second.worker_build_id,
            expected->second.worker_build_hash, expected->second.provider_binary_hash,
            expected->second.provider_binary_is_worker, managed_runtime_hash,
            request.maximum_receipt_bytes);
        if (!binary_manifest)
            return build_worker_result_t<package_verification_result_t>::failure(
                binary_manifest.error());
        const auto acl_expectation = expected_acl.find(id);
        if (acl_expectation == expected_acl.end())
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::worker_inventory_mismatch, {}, id));
        auto acl_check = verify_worker_acl_receipt(
            acl->second, worker_manifest->second, acl_expectation->second.first,
            acl_expectation->second.second, request.maximum_receipt_bytes);
        if (!acl_check)
            return build_worker_result_t<package_verification_result_t>::failure(
                acl_check.error());
        ++acl_receipts;
        auto protector_check = verify_protector_receipt(
            protector->second, executable->second, request.expected_protector_tool_sha256,
            request.expected_protector_verifier_sha256,
            request.expected_signer_policy_sha256,
            request.expected_signing_provider_sha256, "strict-no-imports",
            request.protector_verifier, request.maximum_receipt_bytes);
        if (!protector_check)
            return build_worker_result_t<package_verification_result_t>::failure(
                protector_check.error());
        ++protector_receipts;
        auto signature_check = verify_signature_receipt(
            signature->second, executable->second,
            request.expected_signature_verifier_sha256,
            request.expected_signer_policy_sha256,
            request.expected_signing_provider_sha256,
            request.authorized_signer_thumbprints_sha256,
            request.signature_verifier, request.maximum_receipt_bytes);
        if (!signature_check)
            return build_worker_result_t<package_verification_result_t>::failure(
                signature_check.error());
        ++signature_receipts;
    }
    if (worker_ids.size() != expected_workers.size())
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::worker_inventory_mismatch,
                       request.manifest_path));

    const auto& sidecars = manifest["customer_sidecars"];
    if (!json_has_exact_keys(sidecars, {"only_supported_browser", "browser_artifact",
                                        "reverse_mcp_artifact", "developer_source_shipped",
                                        "loose_python_shipped", "stock_browser_fallback",
                                        "environment"}))
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::package_policy_violation,
                       request.manifest_path));
    std::string browser;
    std::string browser_artifact;
    std::string reverse_mcp_artifact;
    if (!json_scalar(sidecars, "only_supported_browser", browser) || browser != "camoufox" ||
        !json_scalar(sidecars, "browser_artifact", browser_artifact) ||
        !json_scalar(sidecars, "reverse_mcp_artifact", reverse_mcp_artifact) ||
        artifacts.find(browser_artifact) == artifacts.end() ||
        artifacts.find(reverse_mcp_artifact) == artifacts.end() ||
        artifacts.at(browser_artifact).kind != "browser" ||
        artifacts.at(reverse_mcp_artifact).kind != "reverse_mcp" ||
        artifacts.at(browser_artifact).relative_path !=
            "deps/camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe" ||
        artifacts.at(reverse_mcp_artifact).relative_path !=
            "deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe" ||
        !bool_false(sidecars, "developer_source_shipped") ||
        !bool_false(sidecars, "loose_python_shipped") ||
        !bool_false(sidecars, "stock_browser_fallback"))
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::package_policy_violation,
                       request.manifest_path));
    const auto& environment = sidecars["environment"];
    std::string browser_environment;
    std::string mcp_environment;
    std::string python_environment;
    if (!json_has_exact_keys(environment, {"AIDA_CAMOUFOX_EXECUTABLE",
                                            "AIDA_CAMOUFOX_MCP_EXECUTABLE",
                                            "AIDA_CAMOUFOX_PYTHON"}) ||
        !json_scalar(environment, "AIDA_CAMOUFOX_EXECUTABLE", browser_environment) ||
        browser_environment != "verified-browser" ||
        !json_scalar(environment, "AIDA_CAMOUFOX_MCP_EXECUTABLE", mcp_environment) ||
        mcp_environment != "verified-frozen-sidecar" ||
        !json_scalar(environment, "AIDA_CAMOUFOX_PYTHON", python_environment) ||
        python_environment != "unset-unless-verified-sidecar-runtime")
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::package_policy_violation,
                       request.manifest_path));

    package_verification_result_t result;
    result.manifest_sha256 = manifest_evidence.value().sha256;
    result.manifest_size_bytes = manifest_evidence.value().size;
    if (request.verification_checkpoint) {
        try {
            request.verification_checkpoint(
                package_verification_checkpoint_t::immutable_generation_precommit);
        } catch (const std::exception& exception) {
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::internal_error, package_root,
                           exception.what()));
        } catch (...) {
            return build_worker_result_t<package_verification_result_t>::failure(
                make_error(build_worker_error_code_t::internal_error, package_root,
                           "immutable_generation_checkpoint"));
        }
    }
    auto final_inventory = enumerate_package_tree(package_root, request);
    if (!final_inventory)
        return build_worker_result_t<package_verification_result_t>::failure(
            final_inventory.error());
    if (final_inventory.value().files != bounded_inventory.value().files ||
        final_inventory.value().bytes != bounded_inventory.value().bytes ||
        final_inventory.value().directories != bounded_inventory.value().directories ||
        final_inventory.value().entries != bounded_inventory.value().entries ||
        final_inventory.value().path_bytes != bounded_inventory.value().path_bytes ||
        final_inventory.value().stream_inventories !=
            bounded_inventory.value().stream_inventories)
        return build_worker_result_t<package_verification_result_t>::failure(
            make_error(build_worker_error_code_t::file_changed, package_root,
                       "immutable_generation_inventory"));
    auto immutable_check = revalidate_immutable_generation(immutable_generation);
    if (!immutable_check)
        return build_worker_result_t<package_verification_result_t>::failure(
            immutable_check.error());

    result.artifacts_verified = artifacts.size();
    result.workers_verified = worker_ids.size();
    result.dependencies_verified = dependencies.size();
    result.notices_verified = notice_count;
    result.resource_manifests_verified = 2;
    result.acl_receipts_verified = acl_receipts;
    result.protector_receipts_verified = protector_receipts;
    result.signature_receipts_verified = signature_receipts;
    result.artifact_bytes_verified = total_bytes;
    result.directories_verified = bounded_inventory.value().directories;
    result.entries_verified = bounded_inventory.value().entries;
    result.stream_inventories_verified = bounded_inventory.value().stream_inventories;
    result.exact_package_inventory = true;
    result.no_network_fetch = true;
    result.deny_link_policy = production_link_graph_verified;
    result.disk_backed = true;
    result.arc_license_gates_required = true;
    result.camoufox_only = true;
    package_verifications_.fetch_add(1, std::memory_order_release);
    return build_worker_result_t<package_verification_result_t>::success(std::move(result));
}

build_worker_result_t<source_authority_result_t>
build_worker_packaging_integration_t::verify_source_authority(
    const source_authority_request_t& request) const {
    if (request.repository_root.empty() || request.lock_path.empty() ||
        request.maximum_lock_bytes == 0 || request.maximum_source_bytes == 0 ||
        request.maximum_total_source_bytes == 0 ||
        request.maximum_inventory_entries == 0 ||
        request.maximum_lock_bytes > k_default_manifest_limit ||
        request.maximum_source_bytes > k_default_artifact_limit ||
        request.maximum_total_source_bytes > k_default_source_total_limit ||
        request.maximum_inventory_entries > 4096)
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::invalid_argument));
    if (!valid_sha256(request.expected_lock_sha256))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::invalid_argument, request.lock_path));
    auto root_result = canonical_directory(request.repository_root);
    if (!root_result)
        return build_worker_result_t<source_authority_result_t>::failure(root_result.error());
    auto lock_evidence = inspect_regular_file(request.lock_path, request.maximum_lock_bytes, true);
    if (!lock_evidence)
        return build_worker_result_t<source_authority_result_t>::failure(lock_evidence.error());
    if (!fixed_time_equal(lock_evidence.value().sha256,
                          request.expected_lock_sha256))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::hash_mismatch, request.lock_path,
                       lock_evidence.value().sha256));
    json lock;
    try {
        lock = json::parse(lock_evidence.value().content, nullptr, true, true);
    } catch (const std::exception& exception) {
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::malformed_json, request.lock_path,
                       exception.what()));
    }
    if (json_contains_remote_reference(lock))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::remote_reference_forbidden,
                       request.lock_path));
    std::string schema;
    std::uint32_t version = 0;
    if (!json_has_exact_keys(lock, {"schema", "schema_version", "no_network_fetch",
                                    "source_inventory", "dependencies",
                                    "production_link_denylist", "offline_managed_restore",
                                    "analysis_python_worker", "notice_artifacts",
                                    "dependency_decisions", "customer_sidecars"}) ||
        !json_scalar(lock, "schema", schema) ||
        std::string_view(schema) != k_worker_manifest_lock_schema ||
        !json_scalar(lock, "schema_version", version) ||
        version != k_worker_manifest_lock_schema_version ||
        !bool_true(lock, "no_network_fetch"))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path));

    const auto inventory_iterator = lock.find("source_inventory");
    if (inventory_iterator == lock.end() || !inventory_iterator->is_array() ||
        inventory_iterator->size() != 58 ||
        inventory_iterator->size() > request.maximum_inventory_entries)
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path));
    source_authority_result_t result;
    result.lock_sha256 = lock_evidence.value().sha256;
    std::unordered_set<std::string> paths;
    std::unordered_map<std::string, std::string> source_hashes;
    for (const auto& entry : *inventory_iterator) {
        if (!json_has_exact_keys(entry, {"path", "size_bytes", "sha256", "component",
                                         "usage", "license"}))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::source_authority_invalid,
                           request.lock_path));
        std::string relative;
        std::string digest;
        std::string component;
        std::string usage;
        std::string license;
        std::uint64_t expected_size = 0;
        if (!json_scalar(entry, "path", relative) || !safe_relative_path(relative) ||
            !paths.emplace(relative).second ||
            !json_scalar(entry, "size_bytes", expected_size) || expected_size == 0 ||
            !json_scalar(entry, "sha256", digest) || !valid_sha256(digest) ||
            !json_scalar(entry, "component", component) || component.empty() ||
            component.size() > 256 ||
            !json_scalar(entry, "usage", usage) ||
            (usage != "production" && usage != "build_only" &&
             usage != "evidence_only") ||
            !json_scalar(entry, "license", license) || license.empty() ||
            license.size() > 256 || !source_hashes.emplace(relative, digest).second)
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::source_authority_invalid,
                           request.lock_path));
        auto resolved = resolve_regular_under_root(root_result.value(), relative);
        if (!resolved)
            return build_worker_result_t<source_authority_result_t>::failure(resolved.error());
        auto evidence = inspect_regular_file(resolved.value(), request.maximum_source_bytes, false);
        if (!evidence)
            return build_worker_result_t<source_authority_result_t>::failure(evidence.error());
        if (evidence.value().size != expected_size)
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::size_mismatch, resolved.value(), {},
                           expected_size, evidence.value().size));
        if (!fixed_time_equal(evidence.value().sha256, digest))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::hash_mismatch, resolved.value(),
                           evidence.value().sha256));
        if (evidence.value().size >
            request.maximum_total_source_bytes - result.source_bytes_verified)
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::file_too_large,
                           request.lock_path));
        result.source_bytes_verified += evidence.value().size;
        ++result.source_files_verified;
        if (relative.find(".nupkg") != std::string::npos)
            ++result.managed_packages_verified;
        const auto lower_relative = lowercase(relative);
        if (lower_relative.find("license") != std::string::npos ||
            lower_relative.find("notice") != std::string::npos ||
            lower_relative.find("copying") != std::string::npos)
            ++result.notices_verified;
    }

    const auto dependencies_iterator = lock.find("dependencies");
    if (dependencies_iterator == lock.end() || !dependencies_iterator->is_array() ||
        dependencies_iterator->size() != 30)
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::dependency_graph_invalid,
                       request.lock_path));
    std::unordered_map<std::string, std::string> decisions;
    for (const auto& dependency : *dependencies_iterator) {
        if (!json_has_exact_keys(dependency, {"id", "version", "usage", "license",
                                              "components", "source_paths",
                                              "ships_to_customer"}))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid,
                           request.lock_path));
        std::string id;
        std::string version;
        std::string usage;
        std::string license;
        std::vector<std::string> dependency_components;
        std::vector<std::string> source_paths;
        if (!json_scalar(dependency, "id", id) || !safe_identifier(id) ||
            lowercase(id) != id ||
            !json_scalar(dependency, "version", version) || version.empty() ||
            version.size() > 128 ||
            !json_scalar(dependency, "usage", usage) ||
            (usage != "production" && usage != "build_only" &&
             usage != "evidence_only" && usage != "non_use") ||
            !json_scalar(dependency, "license", license) || license.empty() ||
            license.size() > 256 ||
            !json_string_array(dependency["components"], dependency_components, 128) ||
            !json_string_array(dependency["source_paths"], source_paths, 128) ||
            !decisions.emplace(lowercase(id), usage).second)
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid,
                           request.lock_path));
        const bool ships_to_customer = bool_true(dependency, "ships_to_customer");
        const bool does_not_ship = bool_false(dependency, "ships_to_customer");
        if ((!ships_to_customer && !does_not_ship) ||
            (usage == "production" && !ships_to_customer) ||
            (usage != "production" && !does_not_ship) ||
            (usage == "non_use" && (!dependency_components.empty() || !source_paths.empty())) ||
            (usage != "non_use" && (dependency_components.empty() || source_paths.empty())))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid,
                           request.lock_path, id));
        for (const auto& source_path : source_paths) {
            if (!safe_relative_path(source_path) || paths.find(source_path) == paths.end())
                return build_worker_result_t<source_authority_result_t>::failure(
                    make_error(build_worker_error_code_t::dependency_graph_invalid,
                               request.lock_path, source_path));
        }
    }
    const std::map<std::string, std::string> required_decisions{
        {"lmdb", "non_use"}, {"unicorn", "non_use"},
        {"remill", "evidence_only"}, {"lief", "evidence_only"},
        {"dotnet-runtime", "production"}
    };
    for (const auto& required : required_decisions) {
        const auto found = decisions.find(required.first);
        if (found == decisions.end() || found->second != required.second)
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::dependency_graph_invalid, {},
                           required.first));
    }
    const auto denylist_iterator = lock.find("production_link_denylist");
    std::vector<std::string> denylist;
    if (denylist_iterator == lock.end() || !json_string_array(*denylist_iterator, denylist, 16))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::dependency_graph_invalid,
                       request.lock_path));
    std::set<std::string> denyset(denylist.begin(), denylist.end());
    if (denyset != std::set<std::string>{"lmdb", "remill", "unicorn"})
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::dependency_graph_invalid,
                       request.lock_path));

    const auto managed_iterator = lock.find("offline_managed_restore");
    std::string managed_source;
    if (managed_iterator == lock.end() ||
        !json_has_exact_keys(*managed_iterator, {"locked_mode_required",
                                                 "network_sources_forbidden",
                                                 "local_source", "sdk", "packages"}) ||
        !bool_true(*managed_iterator, "locked_mode_required") ||
        !bool_true(*managed_iterator, "network_sources_forbidden") ||
        !json_scalar(*managed_iterator, "local_source", managed_source) ||
        managed_source != ".deps/nuget-offline")
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path));
    const auto sdk_iterator = managed_iterator->find("sdk");
    std::string sdk_path;
    std::string sdk_digest;
    if (sdk_iterator == managed_iterator->end() ||
        !json_has_exact_keys(*sdk_iterator, {"path", "sha256", "shipped"}) ||
        !json_scalar(*sdk_iterator, "path", sdk_path) ||
        sdk_path != ".deps/dotnet-sdk-10.0.301-win-x64/dotnet.exe" ||
        !json_scalar(*sdk_iterator, "sha256", sdk_digest) || !valid_sha256(sdk_digest) ||
        !bool_false(*sdk_iterator, "shipped") ||
        source_hashes.find(sdk_path) == source_hashes.end() ||
        !fixed_time_equal(source_hashes.at(sdk_path), sdk_digest))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path, "managed SDK authority"));
    const auto packages_iterator = managed_iterator->find("packages");
    if (packages_iterator == managed_iterator->end() || !packages_iterator->is_array() ||
        packages_iterator->size() != 3 || result.managed_packages_verified < 3)
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path));
    const std::map<std::string, std::pair<std::string_view, std::string_view>> managed_packages{
        {"ICSharpCode.Decompiler", {"10.1.0.8386",
          ".deps/nuget-offline/ICSharpCode.Decompiler.10.1.0.8386.nupkg"}},
        {"System.Collections.Immutable", {"9.0.0",
          ".deps/nuget-offline/System.Collections.Immutable.9.0.0.nupkg"}},
        {"System.Reflection.Metadata", {"9.0.0",
          ".deps/nuget-offline/System.Reflection.Metadata.9.0.0.nupkg"}}
    };
    std::unordered_set<std::string> managed_ids;
    for (const auto& managed_package : *packages_iterator) {
        std::string id;
        std::string package_version;
        std::string package_path;
        std::string package_digest;
        std::string package_license;
        if (!json_has_exact_keys(managed_package, {"id", "version", "path", "sha256",
                                                   "license"}) ||
            !json_scalar(managed_package, "id", id) || !managed_ids.emplace(id).second ||
            !json_scalar(managed_package, "version", package_version) ||
            !json_scalar(managed_package, "path", package_path) ||
            !json_scalar(managed_package, "sha256", package_digest) ||
            !valid_sha256(package_digest) ||
            !json_scalar(managed_package, "license", package_license) ||
            package_license != "MIT")
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::source_authority_invalid,
                           request.lock_path, "managed package authority"));
        const auto expected = managed_packages.find(id);
        const auto inventory_hash = source_hashes.find(package_path);
        if (expected == managed_packages.end() ||
            expected->second.first != std::string_view(package_version) ||
            expected->second.second != std::string_view(package_path) ||
            inventory_hash == source_hashes.end() ||
            !fixed_time_equal(inventory_hash->second, package_digest))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::source_authority_invalid,
                           request.lock_path, id));
    }

    const auto python_iterator = lock.find("analysis_python_worker");
    std::string python_id;
    if (python_iterator == lock.end() ||
        !json_has_exact_keys(*python_iterator, {"id", "network_fetch_forbidden",
                                                "pinned_freezer_required", "source",
                                                "build_script", "manifest", "protocol",
                                                "containment", "runtime_coupling",
                                                "prebuilt_artifact"}) ||
        !json_scalar(*python_iterator, "id", python_id) || python_id != "analysis_python" ||
        !bool_true(*python_iterator, "network_fetch_forbidden") ||
        !bool_true(*python_iterator, "pinned_freezer_required"))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path));
    const auto locked_path_matches = [&](std::string_view key,
                                         std::string_view expected_path) {
        const auto iterator = python_iterator->find(std::string(key));
        std::string relative;
        std::string digest;
        if (iterator == python_iterator->end() ||
            !json_has_exact_keys(*iterator, {"path", "sha256"}) ||
            !json_scalar(*iterator, "path", relative) ||
            std::string_view(relative) != expected_path ||
            !json_scalar(*iterator, "sha256", digest) || !valid_sha256(digest))
            return false;
        const auto inventory_digest = source_hashes.find(relative);
        return inventory_digest != source_hashes.end() &&
               fixed_time_equal(inventory_digest->second, digest);
    };
    if (!locked_path_matches("source",
                             "src/standalone/workers/analysis_python/analysis_python_worker.py") ||
        !locked_path_matches("build_script",
                             "src/standalone/workers/analysis_python/build_frozen_worker.ps1"))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path, "analysis Python source authority"));
    const auto manifest_iterator = python_iterator->find("manifest");
    std::string manifest_magic;
    std::string manifest_algorithm;
    std::string manifest_capability;
    std::uint32_t manifest_version = 0;
    if (manifest_iterator == python_iterator->end() ||
        !json_has_exact_keys(*manifest_iterator, {"magic", "schema_version",
                                                  "digest_algorithm", "capability"}) ||
        !json_scalar(*manifest_iterator, "magic", manifest_magic) ||
        manifest_magic != "APWM" ||
        !json_scalar(*manifest_iterator, "schema_version", manifest_version) ||
        manifest_version != 1 ||
        !json_scalar(*manifest_iterator, "digest_algorithm", manifest_algorithm) ||
        manifest_algorithm != "sha256" ||
        !json_scalar(*manifest_iterator, "capability", manifest_capability) ||
        manifest_capability != "execute-approved-file")
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path, "analysis Python manifest authority"));
    const auto protocol_iterator = python_iterator->find("protocol");
    std::uint32_t protocol_version = 0;
    std::string protocol_material;
    if (protocol_iterator == python_iterator->end() ||
        !json_has_exact_keys(*protocol_iterator, {"version", "hash_material"}) ||
        !json_scalar(*protocol_iterator, "version", protocol_version) ||
        protocol_version != 1 ||
        !json_scalar(*protocol_iterator, "hash_material", protocol_material) ||
        protocol_material !=
            "aida.analysis-python.worker.frame.v1|bootstrap.v1|hmac-sha256|strict-sequence|approved-workspace-api")
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::protocol_mismatch,
                       request.lock_path, "analysis Python protocol authority"));
    const auto containment_iterator = python_iterator->find("containment");
    std::uint64_t cpu_quota = 0;
    std::uint64_t memory_quota = 0;
    std::uint64_t deadline = 0;
    if (containment_iterator == python_iterator->end() ||
        !json_has_exact_keys(*containment_iterator,
            {"job_object", "kill_on_parent_close", "restricted_token", "network_denied",
             "child_process_denied", "unrelated_handles_denied", "process_mitigations",
             "acl_restricted_ipc", "authenticated_ipc", "monotonic_sequence",
             "cancellation_replaces_worker", "cpu_quota_ms", "memory_quota_bytes",
             "deadline_ms"}))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::containment_policy_mismatch,
                       request.lock_path));
    for (const auto key : {"job_object", "kill_on_parent_close", "restricted_token",
                           "network_denied", "child_process_denied",
                           "unrelated_handles_denied", "process_mitigations",
                           "acl_restricted_ipc", "authenticated_ipc", "monotonic_sequence",
                           "cancellation_replaces_worker"}) {
        if (!bool_true(*containment_iterator, key))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::containment_policy_mismatch,
                           request.lock_path, key));
    }
    if (!json_scalar(*containment_iterator, "cpu_quota_ms", cpu_quota) ||
        cpu_quota != 15000 ||
        !json_scalar(*containment_iterator, "memory_quota_bytes", memory_quota) ||
        memory_quota != 536870912 ||
        !json_scalar(*containment_iterator, "deadline_ms", deadline) || deadline != 30000)
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::containment_policy_mismatch,
                       request.lock_path));
    const auto coupling_iterator = python_iterator->find("runtime_coupling");
    if (coupling_iterator == python_iterator->end() ||
        !json_has_exact_keys(*coupling_iterator, {"camoufox_forbidden",
                                                  "browser_runtime_forbidden",
                                                  "target_execution_forbidden"}) ||
        !bool_true(*coupling_iterator, "camoufox_forbidden") ||
        !bool_true(*coupling_iterator, "browser_runtime_forbidden") ||
        !bool_true(*coupling_iterator, "target_execution_forbidden"))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::containment_policy_mismatch,
                       request.lock_path, "analysis Python runtime coupling"));
    const auto prebuilt_iterator = python_iterator->find("prebuilt_artifact");
    std::string prebuilt_relative;
    std::string prebuilt_directory;
    std::string package_relative;
    std::string manifest_relative;
    std::string manifest_digest_relative;
    std::string frozen_contents_relative;
    std::string build_receipt_relative;
    std::string protector_receipt_relative;
    std::string signature_receipt_relative;
    std::string identity_state;
    std::string expected_prebuilt_sha256;
    std::string expected_signer_sha256;
    std::string expected_protector_tool_sha256;
    std::string expected_protector_verifier_sha256;
    std::string expected_signature_verifier_sha256;
    std::uint64_t expected_prebuilt_size = 0;
    if (prebuilt_iterator == python_iterator->end() ||
        !json_has_exact_keys(*prebuilt_iterator,
            {"source_directory", "source_path", "package_relative_path",
             "manifest_relative_path", "manifest_digest_relative_path",
             "frozen_contents_path", "build_receipt_path", "protector_receipt_path",
             "signature_receipt_path", "identity_state", "expected_sha256",
             "expected_size_bytes", "expected_signer_thumbprint_sha256",
             "expected_protector_tool_sha256", "expected_protector_verifier_sha256",
             "expected_signature_verifier_sha256", "freezer", "protector_flags",
             "required_for_staging"}) ||
        !json_scalar(*prebuilt_iterator, "source_directory", prebuilt_directory) ||
        prebuilt_directory != ".deps/AiDA_AnalysisPythonWorker" ||
        !json_scalar(*prebuilt_iterator, "source_path", prebuilt_relative) ||
        prebuilt_relative != ".deps/AiDA_AnalysisPythonWorker/AiDA_AnalysisPythonWorker.exe" ||
        !json_scalar(*prebuilt_iterator, "package_relative_path", package_relative) ||
        package_relative != "deps/AiDA_AnalysisPythonWorker.exe" ||
        !json_scalar(*prebuilt_iterator, "manifest_relative_path", manifest_relative) ||
        manifest_relative != "deps/AiDA_AnalysisPythonWorker.manifest.bin" ||
        !json_scalar(*prebuilt_iterator, "manifest_digest_relative_path",
                     manifest_digest_relative) ||
        manifest_digest_relative != "deps/AiDA_AnalysisPythonWorker.manifest.sha256" ||
        !json_scalar(*prebuilt_iterator, "frozen_contents_path", frozen_contents_relative) ||
        frozen_contents_relative !=
            ".deps/AiDA_AnalysisPythonWorker/AiDA_AnalysisPythonWorker.frozen_contents.json" ||
        !json_scalar(*prebuilt_iterator, "build_receipt_path", build_receipt_relative) ||
        build_receipt_relative !=
            ".deps/AiDA_AnalysisPythonWorker/AiDA_AnalysisPythonWorker.build_receipt.json" ||
        !json_scalar(*prebuilt_iterator, "protector_receipt_path",
                     protector_receipt_relative) ||
        protector_receipt_relative !=
            ".deps/AiDA_AnalysisPythonWorker/AiDA_AnalysisPythonWorker.protector_receipt.json" ||
        !json_scalar(*prebuilt_iterator, "signature_receipt_path",
                     signature_receipt_relative) ||
        signature_receipt_relative !=
            ".deps/AiDA_AnalysisPythonWorker/AiDA_AnalysisPythonWorker.signature_receipt.json" ||
        !json_scalar(*prebuilt_iterator, "identity_state", identity_state) ||
        !json_scalar(*prebuilt_iterator, "expected_sha256", expected_prebuilt_sha256) ||
        !json_scalar(*prebuilt_iterator, "expected_size_bytes", expected_prebuilt_size) ||
        !json_scalar(*prebuilt_iterator, "expected_signer_thumbprint_sha256",
                     expected_signer_sha256) ||
        !json_scalar(*prebuilt_iterator, "expected_protector_tool_sha256",
                     expected_protector_tool_sha256) ||
        !json_scalar(*prebuilt_iterator, "expected_protector_verifier_sha256",
                     expected_protector_verifier_sha256) ||
        !json_scalar(*prebuilt_iterator, "expected_signature_verifier_sha256",
                     expected_signature_verifier_sha256) ||
        !bool_true(*prebuilt_iterator, "required_for_staging"))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path));
    const auto freezer_iterator = prebuilt_iterator->find("freezer");
    std::string freezer_name;
    std::string freezer_version;
    std::string freezer_lock_sha256;
    std::vector<std::string> protector_flags;
    if (freezer_iterator == prebuilt_iterator->end() ||
        !json_has_exact_keys(*freezer_iterator, {"name", "version",
                                                 "environment_lock_sha256"}) ||
        !json_scalar(*freezer_iterator, "name", freezer_name) || freezer_name.empty() ||
        !json_scalar(*freezer_iterator, "version", freezer_version) ||
        freezer_version.empty() ||
        !json_scalar(*freezer_iterator, "environment_lock_sha256", freezer_lock_sha256) ||
        !json_string_array((*prebuilt_iterator)["protector_flags"], protector_flags, 32) ||
        std::set<std::string>(protector_flags.begin(), protector_flags.end()) !=
            std::set<std::string>{"/Qspectre", "/guard:cf", "/guard:ehcont",
                                  "/guard:xfg", "/sdl"})
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path, "analysis Python prebuilt policy"));
    const auto prebuilt = root_result.value() / std::filesystem::u8path(prebuilt_relative);
    const DWORD prebuilt_attributes = GetFileAttributesW(prebuilt.c_str());
    if (prebuilt_attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD last_error = GetLastError();
        if ((last_error != ERROR_FILE_NOT_FOUND && last_error != ERROR_PATH_NOT_FOUND) ||
            identity_state != "external_fixture_required" ||
            !expected_prebuilt_sha256.empty() || expected_prebuilt_size != 0 ||
            !expected_signer_sha256.empty() || !expected_protector_tool_sha256.empty() ||
            !expected_protector_verifier_sha256.empty() ||
            !expected_signature_verifier_sha256.empty() ||
            freezer_name != "external-locked-freezer" ||
            freezer_version != "external-fixture-required" ||
            !freezer_lock_sha256.empty())
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::source_authority_invalid, prebuilt,
                           "analysis Python external artifact authority", 0, last_error));
        result.analysis_python_external_blocker_confirmed = true;
    } else if ((prebuilt_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::file_type_invalid, prebuilt));
    } else {
        if (identity_state != "locked" || !valid_sha256(expected_prebuilt_sha256) ||
            expected_prebuilt_size == 0 || !valid_sha256(expected_signer_sha256) ||
            !valid_sha256(expected_protector_tool_sha256) ||
            !valid_sha256(expected_protector_verifier_sha256) ||
            !valid_sha256(expected_signature_verifier_sha256) ||
            !valid_sha256(freezer_lock_sha256))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::source_authority_invalid, prebuilt,
                           "analysis Python prebuilt identity"));
        auto prebuilt_path = resolve_regular_under_root(root_result.value(), prebuilt_relative);
        if (!prebuilt_path)
            return build_worker_result_t<source_authority_result_t>::failure(prebuilt_path.error());
        win_handle_t prebuilt_lock;
        prebuilt_lock.handle = CreateFileW(
            prebuilt_path.value().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
                               FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (prebuilt_lock.handle == INVALID_HANDLE_VALUE)
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::file_read_failed,
                           prebuilt_path.value(), "CreateFileW:worker-lock", 0,
                           GetLastError()));
        auto prebuilt_evidence = inspect_regular_file(prebuilt_path.value(),
                                                       request.maximum_source_bytes, false);
        if (!prebuilt_evidence)
            return build_worker_result_t<source_authority_result_t>::failure(
                prebuilt_evidence.error());
        if (prebuilt_evidence.value().size != expected_prebuilt_size ||
            !fixed_time_equal(prebuilt_evidence.value().sha256, expected_prebuilt_sha256))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::hash_mismatch, prebuilt_path.value(),
                           prebuilt_evidence.value().sha256, expected_prebuilt_size,
                           prebuilt_evidence.value().size));
        if (prebuilt_evidence.value().size >
            request.maximum_total_source_bytes - result.source_bytes_verified)
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::file_too_large,
                           prebuilt_path.value()));
        result.source_bytes_verified += prebuilt_evidence.value().size;
        LONG trust_status = TRUST_E_FAIL;
        if (!offline_authenticode_valid(prebuilt_path.value(), trust_status))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::authenticode_verification_failed,
                           prebuilt_path.value(), "WinVerifyTrust", 0,
                           static_cast<std::uint32_t>(trust_status)));
        auto actual_signer = authenticode_signer_sha256(prebuilt_path.value());
        if (!actual_signer)
            return build_worker_result_t<source_authority_result_t>::failure(
                actual_signer.error());
        if (!fixed_time_equal(actual_signer.value(), expected_signer_sha256))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::source_authority_invalid,
                           prebuilt_path.value(), "analysis Python signer"));
    }

    const auto notices_iterator = lock.find("notice_artifacts");
    std::string ledger_source;
    std::string customer_ledger;
    if (notices_iterator == lock.end() ||
        !json_has_exact_keys(*notices_iterator,
            {"ledger_source_path", "customer_ledger_relative_path",
             "managed_package_notices", "build_only_notices", "evidence_only_notices"}) ||
        !json_scalar(*notices_iterator, "ledger_source_path", ledger_source) ||
        ledger_source != "licenses/c03/THIRD_PARTY_NOTICES.md" ||
        source_hashes.find(ledger_source) == source_hashes.end() ||
        !json_scalar(*notices_iterator, "customer_ledger_relative_path", customer_ledger) ||
        customer_ledger != "notices/THIRD_PARTY_NOTICES.md")
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::notice_missing, request.lock_path));
    const auto managed_notices_iterator = notices_iterator->find("managed_package_notices");
    if (managed_notices_iterator == notices_iterator->end() ||
        !managed_notices_iterator->is_array() || managed_notices_iterator->size() != 2)
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::notice_missing, request.lock_path));
    std::unordered_set<std::string> managed_notice_ids;
    for (const auto& notice : *managed_notices_iterator) {
        std::string id;
        std::string archive;
        std::string license_entry;
        std::string license_relative;
        std::string license_digest;
        std::string third_party_entry;
        std::string third_party_relative;
        std::string third_party_digest;
        if (!json_has_exact_keys(notice,
                {"id", "archive", "license_entry", "license_relative_path",
                 "license_sha256", "third_party_notices_entry",
                 "third_party_notices_relative_path", "third_party_notices_sha256"}) ||
            !json_scalar(notice, "id", id) || !managed_notice_ids.emplace(id).second ||
            managed_packages.find(id) == managed_packages.end() ||
            !json_scalar(notice, "archive", archive) ||
            archive != managed_packages.at(id).second ||
            !json_scalar(notice, "license_entry", license_entry) ||
            license_entry != "LICENSE.TXT" ||
            !json_scalar(notice, "license_relative_path", license_relative) ||
            !safe_relative_path(license_relative) ||
            !json_scalar(notice, "license_sha256", license_digest) ||
            !valid_sha256(license_digest) ||
            !json_scalar(notice, "third_party_notices_entry", third_party_entry) ||
            third_party_entry != "THIRD-PARTY-NOTICES.TXT" ||
            !json_scalar(notice, "third_party_notices_relative_path",
                         third_party_relative) ||
            !safe_relative_path(third_party_relative) ||
            !json_scalar(notice, "third_party_notices_sha256", third_party_digest) ||
            !valid_sha256(third_party_digest))
            return build_worker_result_t<source_authority_result_t>::failure(
                make_error(build_worker_error_code_t::notice_missing,
                           request.lock_path, id));
    }
    if (managed_notice_ids !=
        std::unordered_set<std::string>{"System.Collections.Immutable",
                                        "System.Reflection.Metadata"})
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::notice_missing,
                       request.lock_path, "managed notice authority"));
    const auto verify_source_notices = [&](std::string_view key,
                                           const std::set<std::string>& expected_ids) {
        const auto iterator = notices_iterator->find(std::string(key));
        if (iterator == notices_iterator->end() || !iterator->is_array() ||
            iterator->size() != expected_ids.size())
            return false;
        std::set<std::string> actual_ids;
        for (const auto& notice : *iterator) {
            std::string id;
            std::string source;
            std::string digest;
            if (!json_has_exact_keys(notice, {"id", "license_source", "license_sha256"}) ||
                !json_scalar(notice, "id", id) || !actual_ids.emplace(id).second ||
                !json_scalar(notice, "license_source", source) ||
                !json_scalar(notice, "license_sha256", digest) || !valid_sha256(digest))
                return false;
            const auto source_digest = source_hashes.find(source);
            if (source_digest == source_hashes.end() ||
                !fixed_time_equal(source_digest->second, digest))
                return false;
        }
        return actual_ids == expected_ids;
    };
    if (!verify_source_notices("build_only_notices", {"pyinstaller"}) ||
        !verify_source_notices("evidence_only_notices", {"lief", "remill"}))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::notice_missing, request.lock_path));

    const auto decisions_iterator = lock.find("dependency_decisions");
    if (decisions_iterator == lock.end() ||
        !json_has_exact_keys(*decisions_iterator,
            {"production", "build_only", "evidence_only", "non_use",
             "llvm_component_allowlist", "production_link_denylist"}))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::dependency_graph_invalid,
                       request.lock_path));
    const auto decision_set_matches = [&](std::string_view key,
                                           const std::set<std::string>& expected) {
        const auto iterator = decisions_iterator->find(std::string(key));
        std::vector<std::string> values;
        return iterator != decisions_iterator->end() &&
               json_string_array(*iterator, values, 128) &&
               std::set<std::string>(values.begin(), values.end()) == expected;
    };
    if (!decision_set_matches("production",
            {"analysis_python_worker", "capstone", "ghidra_worker", "imgui",
              "dotnet_runtime", "json_schema_validator", "liblzma_minimal", "llvm_demangle_support",
             "managed_worker_packages", "minizip_ng_read_only", "nlohmann_json",
             "pcre2_8bit_no_jit", "sqlite", "taskflow", "triton_thorough_only",
             "z3_thorough_only", "zycore", "zydis", "zlib", "zstd"}) ||
        !decision_set_matches("build_only", {"dotnet_sdk", "pyinstaller"}) ||
        !decision_set_matches("evidence_only", {"lief", "remill"}) ||
        !decision_set_matches("non_use", {"lmdb", "unicorn"}) ||
        !decision_set_matches("llvm_component_allowlist", {"Demangle", "Support"}) ||
        !decision_set_matches("production_link_denylist", {"lmdb", "remill", "unicorn"}))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::dependency_graph_invalid,
                       request.lock_path, "dependency decision authority"));

    const auto sidecars_iterator = lock.find("customer_sidecars");
    std::string distribution;
    if (sidecars_iterator == lock.end() ||
        !json_has_exact_keys(*sidecars_iterator,
            {"distribution", "raw_standalone_download_forbidden",
             "fileless_launch_forbidden", "camoufox"}) ||
        !json_scalar(*sidecars_iterator, "distribution", distribution) ||
        distribution != "protected-disk-backed" ||
        !bool_true(*sidecars_iterator, "raw_standalone_download_forbidden") ||
        !bool_true(*sidecars_iterator, "fileless_launch_forbidden"))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::package_policy_violation,
                       request.lock_path));
    const auto camoufox_iterator = sidecars_iterator->find("camoufox");
    std::string only_browser;
    std::string browser_source;
    std::string browser_relative;
    std::string browser_digest;
    std::string reverse_source;
    std::string reverse_relative;
    std::string reverse_digest;
    std::string build_lock;
    if (camoufox_iterator == sidecars_iterator->end() ||
        !json_has_exact_keys(*camoufox_iterator,
            {"only_supported_browser", "browser_source_path", "browser_relative_path",
             "browser_sha256", "reverse_mcp_source_path", "reverse_mcp_relative_path",
             "reverse_mcp_sha256", "offline_build_lock", "developer_source_shipped",
             "loose_python_shipped", "stock_browser_fallback", "environment"}) ||
        !json_scalar(*camoufox_iterator, "only_supported_browser", only_browser) ||
        only_browser != "camoufox" ||
        !json_scalar(*camoufox_iterator, "browser_source_path", browser_source) ||
        browser_source != "camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe" ||
        !json_scalar(*camoufox_iterator, "browser_relative_path", browser_relative) ||
        browser_relative != "deps/camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe" ||
        !json_scalar(*camoufox_iterator, "browser_sha256", browser_digest) ||
        !valid_sha256(browser_digest) ||
        !json_scalar(*camoufox_iterator, "reverse_mcp_source_path", reverse_source) ||
        reverse_source != ".deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe" ||
        !json_scalar(*camoufox_iterator, "reverse_mcp_relative_path", reverse_relative) ||
        reverse_relative != "deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe" ||
        !json_scalar(*camoufox_iterator, "reverse_mcp_sha256", reverse_digest) ||
        !valid_sha256(reverse_digest) ||
        !json_scalar(*camoufox_iterator, "offline_build_lock", build_lock) ||
        build_lock != "packaging/c03_camoufox_reverse_mcp_build.lock.json" ||
        !bool_false(*camoufox_iterator, "developer_source_shipped") ||
        !bool_false(*camoufox_iterator, "loose_python_shipped") ||
        !bool_false(*camoufox_iterator, "stock_browser_fallback"))
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::package_policy_violation,
                       request.lock_path, "Camoufox authority"));
    const auto browser_inventory = source_hashes.find(browser_source);
    const auto reverse_inventory = source_hashes.find(reverse_source);
    if (browser_inventory == source_hashes.end() ||
        !fixed_time_equal(browser_inventory->second, browser_digest) ||
        reverse_inventory == source_hashes.end() ||
        !fixed_time_equal(reverse_inventory->second, reverse_digest) ||
        source_hashes.find(build_lock) == source_hashes.end())
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::source_authority_invalid,
                       request.lock_path, "Camoufox source identity"));
    const auto environment_iterator = camoufox_iterator->find("environment");
    std::string camoufox_executable;
    std::string mcp_executable;
    std::string camoufox_python;
    if (environment_iterator == camoufox_iterator->end() ||
        !json_has_exact_keys(*environment_iterator,
            {"AIDA_CAMOUFOX_EXECUTABLE", "AIDA_CAMOUFOX_MCP_EXECUTABLE",
             "AIDA_CAMOUFOX_PYTHON"}) ||
        !json_scalar(*environment_iterator, "AIDA_CAMOUFOX_EXECUTABLE",
                     camoufox_executable) || camoufox_executable != "verified-browser" ||
        !json_scalar(*environment_iterator, "AIDA_CAMOUFOX_MCP_EXECUTABLE",
                     mcp_executable) || mcp_executable != "verified-frozen-sidecar" ||
        !json_scalar(*environment_iterator, "AIDA_CAMOUFOX_PYTHON", camoufox_python) ||
        camoufox_python != "unset-unless-verified-sidecar-runtime")
        return build_worker_result_t<source_authority_result_t>::failure(
            make_error(build_worker_error_code_t::package_policy_violation,
                       request.lock_path, "Camoufox environment authority"));

    result.dependencies_verified = dependencies_iterator->size();
    result.no_network_fetch = true;
    result.dependency_decisions_complete = true;
    result.managed_graph_locked = true;
    source_authority_verifications_.fetch_add(1, std::memory_order_release);
    return build_worker_result_t<source_authority_result_t>::success(std::move(result));
}

std::uint64_t build_worker_packaging_integration_t::deny_link_checks_completed() const noexcept {
    return deny_link_checks_.load(std::memory_order_acquire);
}

std::uint64_t build_worker_packaging_integration_t::package_verifications_completed() const noexcept {
    return package_verifications_.load(std::memory_order_acquire);
}

std::uint64_t build_worker_packaging_integration_t::source_authority_verifications_completed() const noexcept {
    return source_authority_verifications_.load(std::memory_order_acquire);
}

}
