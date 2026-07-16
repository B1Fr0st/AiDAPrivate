#include "core/analysis/build_worker_packaging_integration.hpp"
#include "tools/protector/verify_api.hpp"

#include <Windows.h>
#include <bcrypt.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cwchar>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

struct handle_closer_t final {
    void operator()(void* value) const noexcept {
        const auto handle = static_cast<HANDLE>(value);
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
            CloseHandle(handle);
    }
};

using unique_handle_t = std::unique_ptr<void, handle_closer_t>;
using json = nlohmann::json;

[[noreturn]] void fail(std::string message);

std::atomic_bool cancellation_requested{false};
std::chrono::steady_clock::time_point command_deadline =
    std::chrono::steady_clock::time_point::max();

BOOL WINAPI console_control_handler(DWORD control) {
    if (control == CTRL_C_EVENT || control == CTRL_BREAK_EVENT ||
        control == CTRL_CLOSE_EVENT || control == CTRL_LOGOFF_EVENT ||
        control == CTRL_SHUTDOWN_EVENT) {
        cancellation_requested.store(true, std::memory_order_release);
        return TRUE;
    }
    return FALSE;
}

struct console_handler_scope_t final {
    ~console_handler_scope_t() {
        SetConsoleCtrlHandler(console_control_handler, FALSE);
    }
};

void poll_command() {
    if (cancellation_requested.load(std::memory_order_acquire))
        fail("package verification cancelled");
    if (std::chrono::steady_clock::now() >= command_deadline)
        fail("package verification deadline exceeded");
}

struct locked_file_t final {
    std::filesystem::path path;
    unique_handle_t handle;
    BY_HANDLE_FILE_INFORMATION identity{};
    std::uint64_t size = 0;
    std::string sha256;
    std::string content;
    bool replacement_tolerant = false;
};

struct locked_directory_t final {
    std::filesystem::path path;
    std::vector<unique_handle_t> handles;
    BY_HANDLE_FILE_INFORMATION identity{};
};

[[noreturn]] void fail(std::string message) {
    throw std::runtime_error(std::move(message));
}

bool same_identity(const BY_HANDLE_FILE_INFORMATION& left,
                   const BY_HANDLE_FILE_INFORMATION& right) noexcept {
    return left.dwVolumeSerialNumber == right.dwVolumeSerialNumber &&
           left.nFileIndexHigh == right.nFileIndexHigh &&
           left.nFileIndexLow == right.nFileIndexLow &&
           left.nFileSizeHigh == right.nFileSizeHigh &&
           left.nFileSizeLow == right.nFileSizeLow &&
           left.nNumberOfLinks == 1 && right.nNumberOfLinks == 1 &&
           left.ftLastWriteTime.dwHighDateTime == right.ftLastWriteTime.dwHighDateTime &&
           left.ftLastWriteTime.dwLowDateTime == right.ftLastWriteTime.dwLowDateTime;
}

std::string identity_key(const BY_HANDLE_FILE_INFORMATION& identity) {
    std::ostringstream output;
    output << identity.dwVolumeSerialNumber << ':' << std::hex << std::setfill('0')
           << std::setw(8) << identity.nFileIndexHigh
           << std::setw(8) << identity.nFileIndexLow;
    return output.str();
}

std::string hex_lower(const std::uint8_t* bytes, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < size; ++index)
        output << std::setw(2) << static_cast<unsigned>(bytes[index]);
    return output.str();
}

locked_file_t lock_file(const std::filesystem::path& path, std::uint64_t maximum_bytes,
                         bool retain_content, bool replacement_tolerant = false) {
    poll_command();
    auto absolute = std::filesystem::absolute(path).lexically_normal();
    absolute.make_preferred();
    const DWORD sharing = FILE_SHARE_READ |
        (replacement_tolerant ? FILE_SHARE_DELETE : 0U);
    unique_handle_t handle(CreateFileW(absolute.c_str(), GENERIC_READ, sharing,
                                      nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
                                          FILE_FLAG_OPEN_REPARSE_POINT,
                                      nullptr));
    if (!handle || handle.get() == INVALID_HANDLE_VALUE)
        fail("unable to lock required file");
    BY_HANDLE_FILE_INFORMATION before{};
    if (!GetFileInformationByHandle(static_cast<HANDLE>(handle.get()), &before) ||
        (before.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        before.nNumberOfLinks != 1)
        fail("required file identity is invalid");
    std::array<wchar_t, 32768> final_path{};
    const auto final_size = GetFinalPathNameByHandleW(
        static_cast<HANDLE>(handle.get()), final_path.data(),
        static_cast<DWORD>(final_path.size()), 0);
    if (final_size == 0 || final_size >= final_path.size())
        fail("required file final path is invalid");
    std::wstring observed(final_path.data(), final_size);
    if (observed.rfind(L"\\\\?\\UNC\\", 0) == 0)
        fail("required file final path is invalid");
    if (observed.rfind(L"\\\\?\\", 0) == 0)
        observed.erase(0, 4);
    if (observed != absolute.native())
        fail("required file final path differs from its authority path");
    const auto size = (static_cast<std::uint64_t>(before.nFileSizeHigh) << 32U) |
                      before.nFileSizeLow;
    if (size == 0 || size > maximum_bytes)
        fail("required file exceeds its bounded size");

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        fail("unable to open SHA-256 provider");
    [[maybe_unused]] const auto algorithm_guard = std::unique_ptr<void, void (*)(void*)>(
        algorithm, [](void* value) {
            if (value != nullptr)
                BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(value), 0);
        });
    DWORD object_bytes = 0;
    DWORD result_bytes = 0;
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes),
                          &result_bytes, 0) < 0 ||
        result_bytes != static_cast<DWORD>(sizeof(object_bytes)) ||
        object_bytes == 0 || object_bytes > 1024U * 1024U)
        fail("invalid SHA-256 provider object length");
    std::vector<std::uint8_t> object(object_bytes);
    if (BCryptCreateHash(algorithm, &hash, object.data(), object_bytes, nullptr, 0, 0) < 0)
        fail("unable to create SHA-256 state");
    [[maybe_unused]] const auto hash_guard = std::unique_ptr<void, void (*)(void*)>(
        hash, [](void* value) {
            if (value != nullptr)
                BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(value));
        });

    std::vector<std::uint8_t> buffer(1024U * 1024U);
    std::string content;
    if (retain_content) {
        if (size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            fail("required content cannot be represented");
        content.reserve(static_cast<std::size_t>(size));
    }
    std::uint64_t received_total = 0;
    while (received_total < size) {
        poll_command();
        const auto remaining = size - received_total;
        const auto requested = static_cast<DWORD>(
            std::min<std::uint64_t>(remaining, buffer.size()));
        DWORD received = 0;
        if (!ReadFile(static_cast<HANDLE>(handle.get()), buffer.data(), requested,
                      &received, nullptr) || received == 0 || received > requested)
            fail("required file read failed");
        if (BCryptHashData(hash, buffer.data(), received, 0) < 0)
            fail("required file hashing failed");
        if (retain_content)
            content.append(reinterpret_cast<const char*>(buffer.data()), received);
        received_total += received;
    }
    std::array<std::uint8_t, 32> digest{};
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
        fail("required file hashing finalization failed");
    BY_HANDLE_FILE_INFORMATION after{};
    if (!GetFileInformationByHandle(static_cast<HANDLE>(handle.get()), &after) ||
        !same_identity(before, after))
        fail("required file changed during verification");
    return locked_file_t{absolute, std::move(handle), after, size,
                         hex_lower(digest.data(), digest.size()), std::move(content),
                         replacement_tolerant};
}

std::wstring final_path(HANDLE handle, std::string_view label) {
    std::array<wchar_t, 32768> buffer{};
    const auto size = GetFinalPathNameByHandleW(
        handle, buffer.data(), static_cast<DWORD>(buffer.size()), 0);
    if (size == 0 || size >= buffer.size())
        fail(std::string(label) + " final path is invalid");
    std::wstring value(buffer.data(), size);
    if (value.rfind(L"\\\\?\\UNC\\", 0) == 0)
        fail(std::string(label) + " cannot use UNC storage");
    if (value.rfind(L"\\\\?\\", 0) == 0)
        value.erase(0, 4);
    return value;
}

locked_directory_t lock_directory(const std::filesystem::path& path,
                                  std::string_view label) {
    poll_command();
    auto absolute = std::filesystem::absolute(path).lexically_normal();
    absolute.make_preferred();
    if (!absolute.is_absolute() || absolute.root_name().empty() ||
        absolute.root_directory().empty())
        fail(std::string(label) + " path is not absolute");
    locked_directory_t result;
    result.path = absolute;
    auto current = absolute.root_path();
    std::vector<std::filesystem::path> components{current};
    for (const auto& component : absolute.relative_path()) {
        if (component.empty() || component == L"." || component == L"..")
            fail(std::string(label) + " path component is invalid");
        current /= component;
        components.emplace_back(current);
    }
    for (const auto& component : components) {
        unique_handle_t handle(CreateFileW(
            component.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr));
        if (!handle || handle.get() == INVALID_HANDLE_VALUE)
            fail(std::string(label) + " path component cannot be locked");
        BY_HANDLE_FILE_INFORMATION information{};
        if (!GetFileInformationByHandle(static_cast<HANDLE>(handle.get()), &information) ||
            (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            fail(std::string(label) + " path component identity is invalid");
        auto expected = component.lexically_normal();
        expected.make_preferred();
        if (final_path(static_cast<HANDLE>(handle.get()), label) != expected.native())
            fail(std::string(label) + " path component is not canonical");
        result.identity = information;
        result.handles.emplace_back(std::move(handle));
    }
    if (result.handles.empty())
        fail(std::string(label) + " path has no identity chain");
    return result;
}

void revalidate(const locked_directory_t& directory) {
    poll_command();
    if (directory.handles.empty())
        fail("locked directory chain is empty");
    BY_HANDLE_FILE_INFORMATION current{};
    if (!GetFileInformationByHandle(
            static_cast<HANDLE>(directory.handles.back().get()), &current) ||
        current.dwVolumeSerialNumber != directory.identity.dwVolumeSerialNumber ||
        current.nFileIndexHigh != directory.identity.nFileIndexHigh ||
        current.nFileIndexLow != directory.identity.nFileIndexLow ||
        (current.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (current.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        final_path(static_cast<HANDLE>(directory.handles.back().get()),
                   "locked directory") != directory.path.native())
        fail("locked directory identity changed");
}

bool strict_descendant(const std::filesystem::path& candidate,
                       const std::filesystem::path& root) {
    auto candidate_value = candidate.lexically_normal();
    auto root_value = root.lexically_normal();
    candidate_value.make_preferred();
    root_value.make_preferred();
    const auto& candidate_text = candidate_value.native();
    auto root_text = root_value.native();
    if (!root_text.empty() && root_text.back() != L'\\')
        root_text.push_back(L'\\');
    return candidate_text.size() > root_text.size() &&
        _wcsnicmp(candidate_text.c_str(), root_text.c_str(), root_text.size()) == 0;
}

bool fixed_time_equal(std::string_view left, std::string_view right) noexcept {
    if (left.size() != right.size())
        return false;
    unsigned char difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index)
        difference |= static_cast<unsigned char>(left[index] ^ right[index]);
    return difference == 0;
}

void revalidate(const locked_file_t& file) {
    poll_command();
    BY_HANDLE_FILE_INFORMATION current{};
    if (!GetFileInformationByHandle(static_cast<HANDLE>(file.handle.get()), &current) ||
        !same_identity(file.identity, current))
        fail("locked verification authority changed");
    if (file.replacement_tolerant)
        return;
    const auto observed = lock_file(file.path, file.size, false);
    if (!same_identity(file.identity, observed.identity) ||
        !fixed_time_equal(file.sha256, observed.sha256))
        fail("locked verification authority bytes changed");
}

bool valid_digest(std::string_view value) noexcept {
    if (value.size() != 64)
        return false;
    for (const auto character : value) {
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f')))
            return false;
    }
    return true;
}

std::uint64_t bounded_decimal(const std::filesystem::path& value,
                              std::uint64_t minimum,
                              std::uint64_t maximum) {
    const auto text = value.generic_string();
    if (text.empty() || text.size() > 20)
        fail("bounded decimal argument is invalid");
    std::uint64_t result = 0;
    for (const auto character : text) {
        if (character < '0' || character > '9' ||
            result > (maximum - static_cast<std::uint64_t>(character - '0')) / 10)
            fail("bounded decimal argument is invalid");
        result = result * 10 + static_cast<std::uint64_t>(character - '0');
    }
    if (result < minimum || result > maximum)
        fail("bounded decimal argument is outside policy");
    return result;
}

void configure_deadline(const parsed_arguments_t& parsed) {
    const auto found = parsed.values.find(L"deadline-ms");
    if (found == parsed.values.end())
        fail("missing verifier deadline");
    const auto milliseconds = bounded_decimal(found->second, 1, 7200000);
    command_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(milliseconds);
    poll_command();
}

struct signer_policy_t final {
    locked_file_t authority;
    std::vector<std::string> authorized_signers;
    std::string signing_provider_sha256;
};

struct complete_generation_t final {
    locked_directory_t customer_stage_anchor;
    locked_directory_t evidence_root;
    locked_directory_t stage_owner_root;
    locked_directory_t pointer_parent;
    locked_directory_t package_directory;
    locked_directory_t evidence_directory;
    locked_file_t pointer;
    std::filesystem::path package_root;
    std::filesystem::path manifest_path;
    std::filesystem::path digest_path;
    std::string manifest_sha256;
    std::string package_directory_identity;
    std::string manifest_file_identity;
    std::string digest_file_identity;
    locked_file_t manifest;
    locked_file_t digest;
};

complete_generation_t load_complete_generation(
    const std::filesystem::path& path,
    const std::filesystem::path& customer_stage_anchor_path,
    const std::filesystem::path& evidence_root_path,
    const std::filesystem::path& stage_owner_root_path) {
    auto customer_stage_anchor = lock_directory(
        customer_stage_anchor_path, "customer stage anchor");
    auto evidence_root = lock_directory(evidence_root_path, "evidence root");
    auto stage_owner_root = lock_directory(stage_owner_root_path, "stage owner root");
    if (!strict_descendant(customer_stage_anchor.path, stage_owner_root.path) ||
        !strict_descendant(evidence_root.path, stage_owner_root.path) ||
        strict_descendant(customer_stage_anchor.path, evidence_root.path) ||
        strict_descendant(evidence_root.path, customer_stage_anchor.path) ||
        customer_stage_anchor.path == evidence_root.path)
        fail("complete generation detached root contract is invalid");
    auto pointer_path = std::filesystem::absolute(path).lexically_normal();
    pointer_path.make_preferred();
    if (!strict_descendant(pointer_path, evidence_root.path))
        fail("complete generation pointer is outside the configured evidence root");
    auto pointer_parent = lock_directory(pointer_path.parent_path(),
                                         "generation pointer parent");
    const auto publication_lock_path =
        pointer_parent.path / L".aida-c03-publication.lock";
    unique_handle_t publication_lock;
    for (;;) {
        poll_command();
        publication_lock.reset(CreateFileW(
            publication_lock_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr));
        if (publication_lock && publication_lock.get() != INVALID_HANDLE_VALUE)
            break;
        publication_lock.reset();
        const auto error = GetLastError();
        if (error != ERROR_SHARING_VIOLATION && error != ERROR_LOCK_VIOLATION)
            fail("complete generation publication lock is unavailable");
        Sleep(5);
    }
    BY_HANDLE_FILE_INFORMATION publication_lock_information{};
    if (!GetFileInformationByHandle(
            static_cast<HANDLE>(publication_lock.get()),
            &publication_lock_information) ||
        (publication_lock_information.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        publication_lock_information.nNumberOfLinks != 1)
        fail("complete generation publication lock identity is invalid");
    std::array<wchar_t, 32768> publication_lock_final{};
    const auto publication_lock_final_size = GetFinalPathNameByHandleW(
        static_cast<HANDLE>(publication_lock.get()), publication_lock_final.data(),
        static_cast<DWORD>(publication_lock_final.size()), 0);
    if (publication_lock_final_size == 0 ||
        publication_lock_final_size >= publication_lock_final.size())
        fail("complete generation publication lock path is invalid");
    std::wstring publication_lock_observed(
        publication_lock_final.data(), publication_lock_final_size);
    if (publication_lock_observed.rfind(L"\\\\?\\UNC\\", 0) == 0)
        fail("complete generation publication lock path is invalid");
    if (publication_lock_observed.rfind(L"\\\\?\\", 0) == 0)
        publication_lock_observed.erase(0, 4);
    if (publication_lock_observed != publication_lock_path.native())
        fail("complete generation publication lock path is invalid");
    auto pointer = lock_file(pointer_path, 65536, true, true);
    json value;
    try {
        value = json::parse(pointer.content, nullptr, true, true);
    } catch (...) {
        fail("complete generation pointer JSON is malformed");
    }
    const std::set<std::string> expected_keys{
        "schema", "schema_version", "generation_id", "package_root",
        "package_directory_identity", "manifest_path", "manifest_sha256",
        "manifest_file_identity", "digest_path", "digest_file_identity"};
    std::set<std::string> actual_keys;
    if (value.is_object()) {
        for (const auto& item : value.items())
            actual_keys.emplace(item.key());
    }
    if (!value.is_object() || actual_keys != expected_keys ||
        value.value("schema", "") != "aida.c03.complete-generation-pointer" ||
        value.value("schema_version", 0) != 1 ||
        !value.contains("generation_id") || !value["generation_id"].is_string() ||
        !value.contains("package_root") || !value["package_root"].is_string() ||
        !value.contains("manifest_path") || !value["manifest_path"].is_string() ||
        !value.contains("digest_path") || !value["digest_path"].is_string() ||
        !value.contains("manifest_sha256") || !value["manifest_sha256"].is_string() ||
        !value.contains("package_directory_identity") ||
        !value["package_directory_identity"].is_string() ||
        !value.contains("manifest_file_identity") ||
        !value["manifest_file_identity"].is_string() ||
        !value.contains("digest_file_identity") ||
        !value["digest_file_identity"].is_string())
        fail("complete generation pointer contract is invalid");
    const auto generation_id = value["generation_id"].get<std::string>();
    const auto manifest_sha256 = value["manifest_sha256"].get<std::string>();
    const auto valid_identity = [](const std::string& identity) {
        const auto separator = identity.find(':');
        return separator != std::string::npos && separator > 0 &&
               separator + 17 == identity.size() &&
               std::all_of(identity.begin(), identity.begin() + separator,
                           [](unsigned char character) { return std::isdigit(character) != 0; }) &&
               std::all_of(identity.begin() + separator + 1, identity.end(),
                           [](unsigned char character) {
                               return (character >= '0' && character <= '9') ||
                                      (character >= 'a' && character <= 'f');
                           });
    };
    if (generation_id.size() != 32 ||
        !std::all_of(generation_id.begin(), generation_id.end(),
                     [](unsigned char character) {
                         return (character >= '0' && character <= '9') ||
                                (character >= 'a' && character <= 'f');
                     }) ||
        !valid_digest(manifest_sha256) ||
        !valid_identity(value["package_directory_identity"].get<std::string>()) ||
        !valid_identity(value["manifest_file_identity"].get<std::string>()) ||
        !valid_identity(value["digest_file_identity"].get<std::string>()))
        fail("complete generation pointer identity is invalid");
    auto package_root = std::filesystem::u8path(
        value["package_root"].get<std::string>());
    auto manifest_path = std::filesystem::u8path(
        value["manifest_path"].get<std::string>());
    auto digest_path = std::filesystem::u8path(
        value["digest_path"].get<std::string>());
    package_root.make_preferred();
    manifest_path.make_preferred();
    digest_path.make_preferred();
    const auto generation_name = std::filesystem::u8path(
        ".aida-c03-generation-" + generation_id);
    const auto evidence_directory_path = manifest_path.parent_path();
    if (!package_root.is_absolute() || !manifest_path.is_absolute() ||
        !digest_path.is_absolute() ||
        package_root.filename() != generation_name ||
        evidence_directory_path.filename() != generation_name ||
        package_root.parent_path() != customer_stage_anchor.path ||
        evidence_directory_path.parent_path() != pointer_parent.path ||
        !strict_descendant(evidence_directory_path, evidence_root.path) ||
        !strict_descendant(package_root, stage_owner_root.path) ||
        !strict_descendant(evidence_directory_path, stage_owner_root.path) ||
        digest_path.parent_path() != evidence_directory_path ||
        manifest_path == digest_path ||
        manifest_path.filename().empty() || digest_path.filename().empty())
        fail("complete generation pointer paths are invalid");
    auto package_directory = lock_directory(package_root, "package generation");
    auto evidence_directory = lock_directory(evidence_directory_path,
                                             "evidence generation");
    if (identity_key(package_directory.identity) !=
            value["package_directory_identity"].get<std::string>())
        fail("complete generation package identity is invalid");
    auto manifest = lock_file(manifest_path, 16ULL * 1024ULL * 1024ULL, false);
    auto digest = lock_file(digest_path, 256, true);
    if (!fixed_time_equal(manifest.sha256, manifest_sha256) ||
        identity_key(manifest.identity) !=
            value["manifest_file_identity"].get<std::string>() ||
        identity_key(digest.identity) !=
            value["digest_file_identity"].get<std::string>() ||
        digest.content != manifest_sha256 + "\n")
        fail("complete generation evidence binding is invalid");
    return complete_generation_t{
        std::move(customer_stage_anchor), std::move(evidence_root),
        std::move(stage_owner_root), std::move(pointer_parent),
        std::move(package_directory), std::move(evidence_directory),
        std::move(pointer), package_root, manifest_path, digest_path, manifest_sha256,
        value["package_directory_identity"].get<std::string>(),
        value["manifest_file_identity"].get<std::string>(),
        value["digest_file_identity"].get<std::string>(),
        std::move(manifest), std::move(digest)};
}

void revalidate_complete_generation(const complete_generation_t& generation) {
    revalidate(generation.customer_stage_anchor);
    revalidate(generation.evidence_root);
    revalidate(generation.stage_owner_root);
    revalidate(generation.pointer_parent);
    revalidate(generation.package_directory);
    revalidate(generation.evidence_directory);
    revalidate(generation.pointer);
    revalidate(generation.manifest);
    revalidate(generation.digest);
    if (identity_key(generation.package_directory.identity) !=
            generation.package_directory_identity ||
        identity_key(generation.manifest.identity) !=
            generation.manifest_file_identity ||
        identity_key(generation.digest.identity) != generation.digest_file_identity)
        fail("complete generation identity binding changed");
}

signer_policy_t load_signer_policy(const std::filesystem::path& path) {
    auto authority = lock_file(path, 1024ULL * 1024ULL, true);
    json value;
    try {
        value = json::parse(authority.content, nullptr, true, true);
    } catch (...) {
        fail("signer policy JSON is malformed");
    }
    if (!value.is_object() || value.size() != 5 ||
        value.value("schema", "") != "aida.c03.authorized-signer-policy" ||
        value.value("schema_version", 0) != 1 ||
        !value.value("require_trusted_timestamp", false) ||
        !value.contains("authorized_signer_thumbprints_sha256") ||
        !value["authorized_signer_thumbprints_sha256"].is_array() ||
        !value.contains("signing_provider_sha256") ||
        !value["signing_provider_sha256"].is_string())
        fail("signer policy contract is invalid");
    std::vector<std::string> signers;
    for (const auto& item : value["authorized_signer_thumbprints_sha256"]) {
        poll_command();
        if (!item.is_string())
            fail("signer policy identity is invalid");
        signers.emplace_back(item.get<std::string>());
    }
    if (signers.empty() || signers.size() > 16 ||
        !std::all_of(signers.begin(), signers.end(), valid_digest))
        fail("signer policy identity set is invalid");
    std::sort(signers.begin(), signers.end());
    if (std::adjacent_find(signers.begin(), signers.end()) != signers.end())
        fail("signer policy identity set contains duplicates");
    const auto provider = value["signing_provider_sha256"].get<std::string>();
    if (!valid_digest(provider))
        fail("signing provider identity is invalid");
    return signer_policy_t{std::move(authority), std::move(signers), provider};
}

std::string json_escape(std::string_view value) {
    std::string output;
    output.reserve(value.size());
    for (const auto character : value) {
        switch (character) {
        case '\\': output += "\\\\"; break;
        case '"': output += "\\\""; break;
        case '\b': output += "\\b"; break;
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (static_cast<unsigned char>(character) < 0x20U) {
                std::ostringstream escaped;
                escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<unsigned>(static_cast<unsigned char>(character));
                output += escaped.str();
            } else {
                output += character;
            }
        }
    }
    return output;
}

struct parsed_arguments_t final {
    std::wstring mode;
    std::unordered_map<std::wstring, std::filesystem::path> values;
};

parsed_arguments_t parse_arguments(int argc, wchar_t** argv) {
    if (argc < 4 || (argc % 2) != 0 || argv[1][0] == L'\0')
        fail("invalid package verifier command line");
    parsed_arguments_t parsed;
    parsed.mode = argv[1];
    std::unordered_map<std::wstring, std::filesystem::path> values;
    for (int index = 2; index < argc; index += 2) {
        const std::wstring_view key(argv[index]);
        if (key.size() < 3 || key.substr(0, 2) != L"--" || argv[index + 1][0] == L'\0')
            fail("invalid verifier argument");
        const std::wstring key_value(key.substr(2));
        if (!values.emplace(key_value, std::filesystem::path(argv[index + 1])).second)
            fail("duplicate verifier argument");
    }
    parsed.values = std::move(values);
    return parsed;
}

void require_arguments(const parsed_arguments_t& parsed,
                       std::initializer_list<std::wstring_view> required) {
    if (parsed.values.size() != required.size())
        fail("package verifier argument cardinality is invalid");
    for (const auto required_value : required) {
        const std::wstring required_key(required_value);
        if (parsed.values.find(required_key) == parsed.values.end())
            fail("missing verifier argument");
    }
}

struct authenticode_metadata_t final {
    std::string signer_thumbprint_sha256;
    bool trusted_timestamp = false;
    std::uint64_t trusted_timestamp_filetime = 0;
};

struct wintrust_state_t final {
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    bool active = false;

    ~wintrust_state_t() {
        if (active) {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &policy, &data);
        }
    }
};

std::uint64_t filetime_value(const FILETIME& value) noexcept {
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32U) |
           static_cast<std::uint64_t>(value.dwLowDateTime);
}

authenticode_metadata_t verify_authenticode(const std::filesystem::path& path) {
    poll_command();
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path.c_str();
    wintrust_state_t state;
    state.data.cbStruct = sizeof(state.data);
    state.data.dwUIChoice = WTD_UI_NONE;
    state.data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    state.data.dwUnionChoice = WTD_CHOICE_FILE;
    state.data.pFile = &file_info;
    state.data.dwStateAction = WTD_STATEACTION_VERIFY;
    state.data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL |
                             WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
                             WTD_SAFER_FLAG;
    const auto trust_status = WinVerifyTrust(nullptr, &state.policy, &state.data);
    state.active = state.data.hWVTStateData != nullptr;
    if (trust_status != ERROR_SUCCESS)
        fail("offline Authenticode verification failed");
    poll_command();
    auto* provider = WTHelperProvDataFromStateData(state.data.hWVTStateData);
    auto* signer = provider == nullptr ? nullptr :
        WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
    if (provider == nullptr || signer == nullptr || signer->dwError != ERROR_SUCCESS ||
        signer->pChainContext == nullptr ||
        signer->pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR ||
        signer->csCertChain == 0)
        fail("Authenticode signer provider chain is invalid");
    auto* provider_certificate = WTHelperGetProvCertFromChain(signer, 0);
    if (provider_certificate == nullptr || provider_certificate->pCert == nullptr ||
        provider_certificate->dwError != ERROR_SUCCESS ||
        (provider_certificate->dwConfidence & CERT_CONFIDENCE_SIG) == 0)
        fail("Authenticode signer provider certificate is invalid");
    const auto certificate = provider_certificate->pCert;
    std::array<std::uint8_t, 32> certificate_digest{};
    DWORD certificate_digest_bytes = static_cast<DWORD>(certificate_digest.size());
    if (!CertGetCertificateContextProperty(certificate, CERT_SHA256_HASH_PROP_ID,
                                           certificate_digest.data(),
                                           &certificate_digest_bytes) ||
        certificate_digest_bytes != static_cast<DWORD>(certificate_digest.size()))
        fail("signed artifact certificate digest is unavailable");
    std::uint64_t trusted_timestamp = 0;
    if (signer->csCounterSigners == 0 || signer->csCounterSigners > 16)
        fail("trusted Authenticode timestamp provider chain is missing");
    for (DWORD index = 0; index < signer->csCounterSigners; ++index) {
        poll_command();
        auto* counter_signer = WTHelperGetProvSignerFromChain(provider, 0, TRUE, index);
        if (counter_signer == nullptr || counter_signer->dwError != ERROR_SUCCESS ||
            counter_signer->pChainContext == nullptr ||
            counter_signer->pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR ||
            counter_signer->csCertChain == 0)
            continue;
        auto* counter_certificate = WTHelperGetProvCertFromChain(counter_signer, 0);
        const auto timestamp_value = filetime_value(counter_signer->sftVerifyAsOf);
        if (counter_certificate == nullptr || counter_certificate->pCert == nullptr ||
            counter_certificate->dwError != ERROR_SUCCESS ||
            (counter_certificate->dwConfidence & CERT_CONFIDENCE_SIG) == 0 ||
            timestamp_value == 0 ||
            CertVerifyTimeValidity(&counter_signer->sftVerifyAsOf,
                                   counter_certificate->pCert->pCertInfo) != 0)
            continue;
        trusted_timestamp = timestamp_value;
        break;
    }
    if (trusted_timestamp == 0)
        fail("trusted Authenticode timestamp is missing");
    return authenticode_metadata_t{
        hex_lower(certificate_digest.data(), certificate_digest.size()), true,
        trusted_timestamp};
}

std::filesystem::path current_executable_path() {
    std::vector<wchar_t> buffer(32768);
    const auto length = GetModuleFileNameW(nullptr, buffer.data(),
                                           static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= static_cast<DWORD>(buffer.size()))
        fail("package verifier executable identity is unavailable");
    return std::filesystem::path(std::wstring(buffer.data(), length));
}

void write_all(HANDLE handle, const std::string& content) {
    std::size_t offset = 0;
    while (offset < content.size()) {
        poll_command();
        const auto request = static_cast<DWORD>(
            std::min<std::size_t>(content.size() - offset, 1024U * 1024U));
        DWORD written = 0;
        if (!WriteFile(handle, content.data() + offset, request, &written, nullptr) ||
            written == 0 || written > request)
            fail("receipt write failed");
        offset += written;
    }
}

void write_atomic(const std::filesystem::path& destination, const std::string& content) {
    const auto absolute = std::filesystem::absolute(destination).lexically_normal();
    const auto parent = absolute.parent_path();
    const auto attributes = GetFileAttributesW(parent.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        fail("receipt output directory is invalid");
    std::filesystem::path temporary;
    unique_handle_t stream;
    for (std::uint32_t attempt = 0; attempt < 32; ++attempt) {
        temporary = parent / (L"." + absolute.filename().wstring() + L"." +
                              std::to_wstring(GetCurrentProcessId()) + L"." +
                              std::to_wstring(GetTickCount64()) + L"." +
                              std::to_wstring(attempt) + L".tmp");
        stream.reset(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
                                 CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (stream && stream.get() != INVALID_HANDLE_VALUE)
            break;
        stream.reset();
    }
    if (!stream)
        fail("receipt candidate creation failed");
    try {
        write_all(static_cast<HANDLE>(stream.get()), content);
        if (!FlushFileBuffers(static_cast<HANDLE>(stream.get())))
            fail("receipt flush failed");
        stream.reset();
        if (GetFileAttributesW(absolute.c_str()) != INVALID_FILE_ATTRIBUTES) {
            if (!ReplaceFileW(absolute.c_str(), temporary.c_str(), nullptr,
                              0, nullptr, nullptr))
                fail("receipt replacement failed");
        } else if (!MoveFileExW(temporary.c_str(), absolute.c_str(),
                                MOVEFILE_WRITE_THROUGH)) {
            fail("receipt publication failed");
        }
    } catch (...) {
        stream.reset();
        DeleteFileW(temporary.c_str());
        throw;
    }
}

std::wstring quote_command_argument(const std::wstring& value) {
    std::wstring result(1, L'"');
    std::size_t backslashes = 0;
    for (const auto character : value) {
        if (character == L'\\') {
            ++backslashes;
            continue;
        }
        if (character == L'"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(L'"');
            backslashes = 0;
            continue;
        }
        result.append(backslashes, L'\\');
        backslashes = 0;
        result.push_back(character);
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

std::filesystem::path copy_locked_authority(const locked_file_t& source,
                                             std::wstring_view role,
                                             std::wstring_view extension) {
    auto destination = source.path.parent_path() /
        (L".aida-c03-" + std::wstring(role) + L"-" +
         std::wstring(source.sha256.begin(), source.sha256.end()) + L"-" +
         std::to_wstring(GetCurrentProcessId()) + L"-" +
         std::to_wstring(GetTickCount64()) + std::wstring(extension));
    unique_handle_t output(CreateFileW(destination.c_str(), GENERIC_WRITE, 0, nullptr,
                                       CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!output || output.get() == INVALID_HANDLE_VALUE)
        fail("immutable signing authority copy cannot be created");
    LARGE_INTEGER start{};
    if (!SetFilePointerEx(static_cast<HANDLE>(source.handle.get()), start,
                          nullptr, FILE_BEGIN))
        fail("signing authority copy source seek failed");
    std::vector<std::uint8_t> buffer(1024U * 1024U);
    std::uint64_t copied = 0;
    while (copied < source.size) {
        poll_command();
        const auto request = static_cast<DWORD>((std::min<std::uint64_t>)(
            buffer.size(), source.size - copied));
        DWORD received = 0;
        if (!ReadFile(static_cast<HANDLE>(source.handle.get()), buffer.data(), request,
                      &received, nullptr) || received == 0 || received > request)
            fail("signing authority copy source read failed");
        DWORD written = 0;
        if (!WriteFile(static_cast<HANDLE>(output.get()), buffer.data(), received,
                       &written, nullptr) || written != received)
            fail("signing authority copy write failed");
        copied += received;
    }
    if (!FlushFileBuffers(static_cast<HANDLE>(output.get())))
        fail("signing authority copy flush failed");
    output.reset();
    return destination;
}

int run_bound_signing_provider(const parsed_arguments_t& parsed) {
    require_arguments(parsed, {L"artifact", L"signer-policy",
                               L"expected-signer-policy-sha256", L"signing-provider",
                               L"expected-signing-provider-sha256", L"deadline-ms"});
    configure_deadline(parsed);
    const auto& arguments = parsed.values;
    auto policy = load_signer_policy(arguments.at(L"signer-policy"));
    auto provider = lock_file(arguments.at(L"signing-provider"),
                              1024ULL * 1024ULL * 1024ULL, false);
    const auto expected_policy =
        arguments.at(L"expected-signer-policy-sha256").generic_string();
    const auto expected_provider =
        arguments.at(L"expected-signing-provider-sha256").generic_string();
    if (!valid_digest(expected_policy) || !valid_digest(expected_provider) ||
        !fixed_time_equal(policy.authority.sha256, expected_policy) ||
        !fixed_time_equal(provider.sha256, expected_provider) ||
        !fixed_time_equal(policy.signing_provider_sha256, expected_provider))
        fail("signing authority point-of-use identity mismatch");
    auto artifact_path = std::filesystem::absolute(
        arguments.at(L"artifact")).lexically_normal();
    artifact_path.make_preferred();
    auto artifact_before = lock_file(artifact_path,
                                     8ULL * 1024ULL * 1024ULL * 1024ULL, false);
    revalidate(artifact_before);
    artifact_before.handle.reset();
    std::filesystem::path provider_copy;
    std::filesystem::path policy_copy;
    try {
        provider_copy = copy_locked_authority(provider, L"signing-provider", L".exe");
        policy_copy = copy_locked_authority(policy.authority, L"signer-policy", L".json");
        auto immutable_provider = lock_file(provider_copy,
                                            1024ULL * 1024ULL * 1024ULL, false);
        auto immutable_policy = lock_file(policy_copy, 1024ULL * 1024ULL, false);
        if (!fixed_time_equal(immutable_provider.sha256, expected_provider) ||
            !fixed_time_equal(immutable_policy.sha256, expected_policy))
            fail("immutable signing authority copy identity mismatch");
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            command_deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0)
            fail("signing provider deadline exceeded");
        std::wstring command = quote_command_argument(immutable_provider.path.native()) +
            L" sign-artifact --artifact " + quote_command_argument(artifact_path.native()) +
            L" --signer-policy " + quote_command_argument(immutable_policy.path.native()) +
            L" --deadline-ms " + std::to_wstring(remaining.count());
        std::vector<wchar_t> mutable_command(command.begin(), command.end());
        mutable_command.push_back(L'\0');
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        const auto provider_directory = immutable_provider.path.parent_path();
        if (!CreateProcessW(immutable_provider.path.c_str(), mutable_command.data(), nullptr,
                            nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                            provider_directory.c_str(), &startup, &process))
            fail("immutable signing provider execution failed");
        unique_handle_t process_handle(process.hProcess);
        unique_handle_t thread_handle(process.hThread);
        for (;;) {
            const auto wait = WaitForSingleObject(process.hProcess, 25);
            if (wait == WAIT_OBJECT_0)
                break;
            if (wait != WAIT_TIMEOUT) {
                TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
                fail("immutable signing provider wait failed");
            }
            try {
                poll_command();
            } catch (...) {
                TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
                WaitForSingleObject(process.hProcess, 5000);
                throw;
            }
        }
        DWORD exit_code = 0;
        if (!GetExitCodeProcess(process.hProcess, &exit_code) || exit_code != 0)
            fail("immutable signing provider returned failure");
        revalidate(provider);
        revalidate(policy.authority);
        revalidate(immutable_provider);
        revalidate(immutable_policy);
        immutable_provider.handle.reset();
        immutable_policy.handle.reset();
        if (!DeleteFileW(provider_copy.c_str()) || !DeleteFileW(policy_copy.c_str()))
            fail("immutable signing authority copy cleanup failed");
        std::cout << "{\"signed\":true,\"signing_provider_sha256\":\""
                  << provider.sha256 << "\"}\n";
        return 0;
    } catch (...) {
        if (!provider_copy.empty())
            DeleteFileW(provider_copy.c_str());
        if (!policy_copy.empty())
            DeleteFileW(policy_copy.c_str());
        throw;
    }
}

bool valid_relative_artifact(std::string_view value) noexcept {
    if (value.empty() || value.size() > 32768 || value.front() == '/' ||
        value.back() == '/' || value.find("..") != std::string_view::npos ||
        value.find('\\') != std::string_view::npos || value.find(':') != std::string_view::npos)
        return false;
    for (const auto character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte < 0x21U || byte > 0x7eU)
            return false;
    }
    return true;
}

struct pe_post_process_measurement_t final {
    std::uint32_t coff_symbol_table_pointer = 0;
    std::uint32_t coff_symbol_count = 0;
    std::uint64_t debug_directory_entries = 0;
    std::uint64_t codeview_records = 0;
    std::uint64_t unscrubbed_debug_paths = 0;
    std::uint64_t rich_signature_count = 0;
    std::uint64_t dans_signature_count = 0;
    bool pe_headers_complete = false;
    bool debug_directory_complete = false;
};

void read_locked_at(const locked_file_t& file, std::uint64_t offset,
                    void* destination, std::size_t size) {
    if (size == 0 || offset > file.size || size > file.size - offset ||
        size > static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()))
        fail("PE measurement range is invalid");
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(static_cast<HANDLE>(file.handle.get()), position,
                          nullptr, FILE_BEGIN))
        fail("PE measurement seek failed");
    DWORD received = 0;
    if (!ReadFile(static_cast<HANDLE>(file.handle.get()), destination,
                  static_cast<DWORD>(size), &received, nullptr) || received != size)
        fail("PE measurement read failed");
}

pe_post_process_measurement_t measure_pe_post_process(const locked_file_t& artifact) {
    IMAGE_DOS_HEADER dos{};
    read_locked_at(artifact, 0, &dos, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        static_cast<std::uint64_t>(dos.e_lfanew) > artifact.size -
            sizeof(DWORD) - sizeof(IMAGE_FILE_HEADER))
        fail("final artifact PE headers are invalid");
    const auto nt_offset = static_cast<std::uint64_t>(dos.e_lfanew);
    DWORD signature = 0;
    IMAGE_FILE_HEADER file_header{};
    read_locked_at(artifact, nt_offset, &signature, sizeof(signature));
    read_locked_at(artifact, nt_offset + sizeof(signature), &file_header,
                   sizeof(file_header));
    if (signature != IMAGE_NT_SIGNATURE || file_header.NumberOfSections == 0 ||
        file_header.NumberOfSections > 96 || file_header.SizeOfOptionalHeader == 0 ||
        file_header.SizeOfOptionalHeader > 4096)
        fail("final artifact COFF headers are invalid");
    const auto optional_offset = nt_offset + sizeof(signature) + sizeof(file_header);
    if (optional_offset > artifact.size || file_header.SizeOfOptionalHeader >
        artifact.size - optional_offset)
        fail("final artifact optional header is truncated");
    std::vector<std::uint8_t> optional(file_header.SizeOfOptionalHeader);
    read_locked_at(artifact, optional_offset, optional.data(), optional.size());
    WORD optional_magic = 0;
    std::memcpy(&optional_magic, optional.data(), sizeof(optional_magic));
    std::size_t directory_offset = 0;
    DWORD size_of_headers = 0;
    if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        optional.size() >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
        const auto* header = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optional.data());
        directory_offset = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        size_of_headers = header->SizeOfHeaders;
    } else if (optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
               optional.size() >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
        const auto* header = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optional.data());
        directory_offset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        size_of_headers = header->SizeOfHeaders;
    } else {
        fail("final artifact optional header magic is invalid");
    }
    if (directory_offset + (IMAGE_DIRECTORY_ENTRY_DEBUG + 1) * sizeof(IMAGE_DATA_DIRECTORY) >
        optional.size())
        fail("final artifact debug directory declaration is incomplete");
    IMAGE_DATA_DIRECTORY debug_directory{};
    std::memcpy(&debug_directory,
                optional.data() + directory_offset +
                    IMAGE_DIRECTORY_ENTRY_DEBUG * sizeof(IMAGE_DATA_DIRECTORY),
                sizeof(debug_directory));
    const auto sections_offset = optional_offset + file_header.SizeOfOptionalHeader;
    const auto sections_bytes = static_cast<std::uint64_t>(file_header.NumberOfSections) *
        sizeof(IMAGE_SECTION_HEADER);
    if (sections_offset > artifact.size || sections_bytes > artifact.size - sections_offset)
        fail("final artifact section table is truncated");
    std::vector<IMAGE_SECTION_HEADER> sections(file_header.NumberOfSections);
    read_locked_at(artifact, sections_offset, sections.data(),
                   static_cast<std::size_t>(sections_bytes));
    const auto rva_to_file = [&](std::uint32_t rva, std::uint32_t bytes)
        -> std::optional<std::uint64_t> {
        if (rva < size_of_headers && bytes <= size_of_headers - rva &&
            bytes <= artifact.size - rva)
            return rva;
        for (const auto& section : sections) {
            const auto span = (std::max)(section.Misc.VirtualSize,
                                         section.SizeOfRawData);
            if (rva < section.VirtualAddress || rva - section.VirtualAddress > span ||
                bytes > span - (rva - section.VirtualAddress))
                continue;
            const auto offset = static_cast<std::uint64_t>(section.PointerToRawData) +
                (rva - section.VirtualAddress);
            if (offset <= artifact.size && bytes <= artifact.size - offset)
                return offset;
        }
        return std::nullopt;
    };
    pe_post_process_measurement_t measurement;
    measurement.pe_headers_complete = true;
    measurement.coff_symbol_table_pointer = file_header.PointerToSymbolTable;
    measurement.coff_symbol_count = file_header.NumberOfSymbols;
    const auto header_scan_size = static_cast<std::size_t>((std::min<std::uint64_t>)(
        nt_offset, 1024ULL * 1024ULL));
    if (header_scan_size >= 4) {
        std::vector<std::uint8_t> header_bytes(header_scan_size);
        read_locked_at(artifact, 0, header_bytes.data(), header_bytes.size());
        for (std::size_t offset = 0; offset + 4 <= header_bytes.size(); ++offset) {
            if (std::memcmp(header_bytes.data() + offset, "Rich", 4) == 0)
                ++measurement.rich_signature_count;
            if (std::memcmp(header_bytes.data() + offset, "DanS", 4) == 0)
                ++measurement.dans_signature_count;
        }
    }
    if ((debug_directory.VirtualAddress == 0) != (debug_directory.Size == 0) ||
        debug_directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0 ||
        debug_directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY) > 4096)
        fail("final artifact debug directory is malformed");
    if (debug_directory.Size != 0) {
        const auto debug_offset = rva_to_file(debug_directory.VirtualAddress,
                                              debug_directory.Size);
        if (!debug_offset)
            fail("final artifact debug directory is unmapped");
        measurement.debug_directory_entries =
            debug_directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        std::vector<IMAGE_DEBUG_DIRECTORY> entries(
            static_cast<std::size_t>(measurement.debug_directory_entries));
        read_locked_at(artifact, *debug_offset, entries.data(), debug_directory.Size);
        for (const auto& entry : entries) {
            poll_command();
            if (entry.SizeOfData != 0 &&
                (entry.PointerToRawData > artifact.size ||
                 entry.SizeOfData > artifact.size - entry.PointerToRawData))
                fail("final artifact debug payload is out of bounds");
            if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW)
                continue;
            ++measurement.codeview_records;
            if (entry.SizeOfData < 16 || entry.SizeOfData > 1024U * 1024U)
                fail("final artifact CodeView payload is malformed");
            std::vector<std::uint8_t> payload(entry.SizeOfData);
            read_locked_at(artifact, entry.PointerToRawData, payload.data(), payload.size());
            std::size_t path_offset = 0;
            if (std::memcmp(payload.data(), "RSDS", 4) == 0 && payload.size() >= 25)
                path_offset = 24;
            else if (std::memcmp(payload.data(), "NB10", 4) == 0 && payload.size() >= 17)
                path_offset = 16;
            else
                fail("final artifact CodeView signature is invalid");
            const auto terminator = std::find(payload.begin() + path_offset,
                                              payload.end(), 0);
            if (terminator == payload.end())
                fail("final artifact CodeView path is unterminated");
            const std::string path_text(payload.begin() + path_offset, terminator);
            if (!path_text.empty() && path_text != "none")
                ++measurement.unscrubbed_debug_paths;
        }
    }
    measurement.debug_directory_complete = true;
    if (measurement.coff_symbol_table_pointer != 0 ||
        measurement.coff_symbol_count != 0 ||
        measurement.unscrubbed_debug_paths != 0 ||
        measurement.rich_signature_count != 0 ||
        measurement.dans_signature_count != 0)
        fail("final PE artifact failed measured scrub policy");
    return measurement;
}

int inspect_pe_post_process(const parsed_arguments_t& parsed) {
    require_arguments(parsed, {L"artifact", L"deadline-ms"});
    configure_deadline(parsed);
    auto artifact = lock_file(parsed.values.at(L"artifact"),
                              8ULL * 1024ULL * 1024ULL * 1024ULL, false);
    const auto measurement = measure_pe_post_process(artifact);
    revalidate(artifact);
    std::cout << "{\"schema\":\"aida.c03.pe-post-process-measurement\",\"schema_version\":1,"
                 "\"coff_symbol_table_pointer\":"
              << measurement.coff_symbol_table_pointer << ",\"coff_symbol_count\":"
              << measurement.coff_symbol_count << ",\"debug_directory_entries\":"
              << measurement.debug_directory_entries << ",\"codeview_records\":"
              << measurement.codeview_records << ",\"unscrubbed_debug_paths\":"
              << measurement.unscrubbed_debug_paths << ",\"rich_signature_count\":"
              << measurement.rich_signature_count << ",\"dans_signature_count\":"
              << measurement.dans_signature_count << ",\"pe_headers_complete\":"
              << (measurement.pe_headers_complete ? "true" : "false")
              << ",\"debug_directory_complete\":"
              << (measurement.debug_directory_complete ? "true" : "false") << "}\n";
    return 0;
}

int emit_receipts(const parsed_arguments_t& parsed) {
    require_arguments(parsed, {L"artifact", L"artifact-relative", L"protector-tool",
                               L"protector-verifier", L"protector-profile",
                               L"protector-receipt", L"signature-receipt",
                               L"signer-policy", L"expected-signer-policy-sha256",
                               L"signing-provider", L"expected-signing-provider-sha256",
                               L"deadline-ms"});
    configure_deadline(parsed);
    const auto& arguments = parsed.values;
    auto signer_policy = load_signer_policy(arguments.at(L"signer-policy"));
    auto signing_provider = lock_file(arguments.at(L"signing-provider"),
                                      1024ULL * 1024ULL * 1024ULL, false);
    const auto expected_signer_policy =
        arguments.at(L"expected-signer-policy-sha256").generic_string();
    const auto expected_signing_provider =
        arguments.at(L"expected-signing-provider-sha256").generic_string();
    if (!valid_digest(expected_signer_policy) ||
        !valid_digest(expected_signing_provider) ||
        !fixed_time_equal(signer_policy.authority.sha256, expected_signer_policy) ||
        !fixed_time_equal(signing_provider.sha256, expected_signing_provider) ||
        !fixed_time_equal(signing_provider.sha256,
                          signer_policy.signing_provider_sha256))
        fail("signing provider does not match signer policy");
    auto artifact = lock_file(arguments.at(L"artifact"),
                              8ULL * 1024ULL * 1024ULL * 1024ULL, false);
    auto protector = lock_file(arguments.at(L"protector-tool"),
                               1024ULL * 1024ULL * 1024ULL, false);
    auto protector_verifier = lock_file(arguments.at(L"protector-verifier"),
                                        1024ULL * 1024ULL * 1024ULL, false);
    auto signature_verifier = lock_file(current_executable_path(),
                                        1024ULL * 1024ULL * 1024ULL, false);
    const auto relative = arguments.at(L"artifact-relative").generic_string();
    if (!valid_relative_artifact(relative))
        fail("artifact-relative is invalid");
    verifier::verify_profile_t profile{};
    const auto profile_text = arguments.at(L"protector-profile").string();
    if (!verifier::parse_profile(profile_text, profile))
        fail("protector verification profile is invalid");
    const auto protection = verifier::verify_report(artifact.path.string(), profile);
    if (!protection.loaded || protection.total <= 0 || protection.passed != protection.total)
        fail("protected artifact failed the direct verifier");
    const auto post_process = measure_pe_post_process(artifact);
    const auto signature = verify_authenticode(artifact.path);
    if (!std::binary_search(signer_policy.authorized_signers.begin(),
                            signer_policy.authorized_signers.end(),
                            signature.signer_thumbprint_sha256))
        fail("artifact signer is not authorized by AiDA signer policy");
    revalidate(artifact);
    revalidate(protector);
    revalidate(protector_verifier);
    revalidate(signature_verifier);
    revalidate(signer_policy.authority);
    revalidate(signing_provider);

    const json protector_receipt{
        {"schema", "aida.protector.receipt"}, {"schema_version", 4},
        {"status", "passed"}, {"artifact_relative_path", relative},
        {"artifact_sha256", artifact.sha256}, {"artifact_size_bytes", artifact.size},
        {"tool_sha256", protector.sha256},
        {"verifier_sha256", protector_verifier.sha256},
        {"signer_policy_sha256", signer_policy.authority.sha256},
        {"signing_provider_sha256", signing_provider.sha256},
        {"profile", profile_text},
        {"post_process", {
            {"protection_checks_total", protection.total},
            {"protection_checks_passed", protection.passed},
            {"coff_symbol_table_pointer", post_process.coff_symbol_table_pointer},
            {"coff_symbol_count", post_process.coff_symbol_count},
            {"debug_directory_entries", post_process.debug_directory_entries},
            {"codeview_records", post_process.codeview_records},
            {"unscrubbed_debug_paths", post_process.unscrubbed_debug_paths},
            {"rich_signature_count", post_process.rich_signature_count},
            {"dans_signature_count", post_process.dans_signature_count},
            {"pe_headers_complete", post_process.pe_headers_complete},
            {"debug_directory_complete", post_process.debug_directory_complete}}},
        {"production_flags", {"/Qspectre", "/sdl", "/guard:cf", "/guard:ehcont", "/guard:xfg"}}
    };
    const json signature_receipt{
        {"schema", "aida.signature.receipt"}, {"schema_version", 4},
        {"status", "verified"}, {"artifact_relative_path", relative},
        {"artifact_sha256", artifact.sha256}, {"artifact_size_bytes", artifact.size},
        {"verification_mode", "wintrust_offline"},
        {"signer_thumbprint_sha256", signature.signer_thumbprint_sha256},
        {"verifier_sha256", signature_verifier.sha256},
        {"signer_policy_sha256", signer_policy.authority.sha256},
        {"signing_provider_sha256", signing_provider.sha256},
        {"chain_status", "trusted"},
        {"timestamp_status", signature.trusted_timestamp ? "trusted" : "untrusted"},
        {"timestamp_validation", "wintrust_provider_counter_signer"},
        {"timestamp_filetime", signature.trusted_timestamp_filetime}
    };
    write_atomic(arguments.at(L"protector-receipt"), protector_receipt.dump() + "\n");
    write_atomic(arguments.at(L"signature-receipt"), signature_receipt.dump() + "\n");
    revalidate(artifact);
    revalidate(protector);
    revalidate(protector_verifier);
    revalidate(signature_verifier);
    revalidate(signer_policy.authority);
    revalidate(signing_provider);
    std::cout << "{\"receipts_emitted\":true,\"artifact_sha256\":\""
              << artifact.sha256 << "\"}\n";
    return 0;
}

int inspect_generation(const parsed_arguments_t& parsed) {
    require_arguments(parsed, {L"generation-pointer", L"customer-stage-anchor",
                               L"evidence-root", L"stage-owner-root", L"deadline-ms"});
    configure_deadline(parsed);
    auto generation = load_complete_generation(
        parsed.values.at(L"generation-pointer"),
        parsed.values.at(L"customer-stage-anchor"),
        parsed.values.at(L"evidence-root"),
        parsed.values.at(L"stage-owner-root"));
    if (!fixed_time_equal(generation.manifest.sha256, generation.manifest_sha256) ||
        identity_key(generation.manifest.identity) != generation.manifest_file_identity ||
        identity_key(generation.digest.identity) != generation.digest_file_identity ||
        generation.digest.content != generation.manifest_sha256 + "\n")
        fail("complete generation manifest binding is invalid");
    revalidate_complete_generation(generation);
    std::cout << "{\"generation_verified\":true,\"manifest_sha256\":\""
              << generation.manifest_sha256 << "\"}\n";
    return 0;
}

int verify_package(const parsed_arguments_t& parsed) {
    require_arguments(parsed, {L"generation-pointer", L"authority-lock", L"protector-tool",
                                L"protector-verifier", L"signature-verifier",
                                L"signer-policy", L"expected-signer-policy-sha256",
                                L"signing-provider", L"expected-signing-provider-sha256",
                                L"customer-stage-anchor", L"evidence-root",
                                L"stage-owner-root", L"deadline-ms"});
    configure_deadline(parsed);
    const auto& arguments = parsed.values;
    auto generation = load_complete_generation(
        arguments.at(L"generation-pointer"),
        arguments.at(L"customer-stage-anchor"),
        arguments.at(L"evidence-root"),
        arguments.at(L"stage-owner-root"));
    auto signer_policy = load_signer_policy(arguments.at(L"signer-policy"));
    auto signing_provider = lock_file(arguments.at(L"signing-provider"),
                                      1024ULL * 1024ULL * 1024ULL, false);
    const auto expected_signer_policy =
        arguments.at(L"expected-signer-policy-sha256").generic_string();
    const auto expected_signing_provider =
        arguments.at(L"expected-signing-provider-sha256").generic_string();
    if (!valid_digest(expected_signer_policy) ||
        !valid_digest(expected_signing_provider) ||
        !fixed_time_equal(signer_policy.authority.sha256, expected_signer_policy) ||
        !fixed_time_equal(signing_provider.sha256, expected_signing_provider) ||
        !fixed_time_equal(signing_provider.sha256,
                          signer_policy.signing_provider_sha256))
        fail("signing provider does not match signer policy");
    auto& manifest_digest = generation.digest;
    auto& manifest_file = generation.manifest;
    if (manifest_digest.content.size() != 65 || manifest_digest.content.back() != '\n' ||
        !valid_digest(std::string_view(manifest_digest.content).substr(0, 64)) ||
        !fixed_time_equal(std::string_view(manifest_digest.content).substr(0, 64),
                          generation.manifest_sha256) ||
        !fixed_time_equal(manifest_file.sha256, generation.manifest_sha256) ||
        identity_key(manifest_file.identity) != generation.manifest_file_identity ||
        identity_key(manifest_digest.identity) != generation.digest_file_identity)
        fail("distribution manifest digest is malformed");
    const auto expected_manifest = manifest_digest.content.substr(0, 64);
    auto authority = lock_file(arguments.at(L"authority-lock"), 16ULL * 1024ULL * 1024ULL, false);
    auto protector = lock_file(arguments.at(L"protector-tool"), 1024ULL * 1024ULL * 1024ULL, false);
    auto protector_verifier = lock_file(arguments.at(L"protector-verifier"),
                                        1024ULL * 1024ULL * 1024ULL, false);
    auto signature_verifier = lock_file(arguments.at(L"signature-verifier"),
                                        1024ULL * 1024ULL * 1024ULL, false);
    const auto revalidate_all = [&] {
        revalidate_complete_generation(generation);
        revalidate(authority);
        revalidate(protector);
        revalidate(protector_verifier);
        revalidate(signature_verifier);
        revalidate(signer_policy.authority);
        revalidate(signing_provider);
    };

    aida::analysis::c03::package_verification_request_t request;
    request.package_root = generation.package_root;
    request.manifest_path = generation.manifest_path;
    request.expected_manifest_sha256 = expected_manifest;
    request.expected_source_authority_sha256 = authority.sha256;
    request.expected_protector_tool_sha256 = protector.sha256;
    request.expected_protector_verifier_sha256 = protector_verifier.sha256;
    request.expected_signature_verifier_sha256 = signature_verifier.sha256;
    request.expected_signer_policy_sha256 = signer_policy.authority.sha256;
    request.expected_signing_provider_sha256 = signing_provider.sha256;
    request.authorized_signer_thumbprints_sha256 = signer_policy.authorized_signers;
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        command_deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0)
        fail("package verification deadline exceeded");
    request.deadline = remaining;
    request.cancellation_requested = [] {
        return cancellation_requested.load(std::memory_order_acquire);
    };
    request.protector_verifier = [](const std::filesystem::path& path,
                                    std::string_view profile_text) {
        verifier::verify_profile_t profile{};
        if (!verifier::parse_profile(std::string(profile_text), profile))
            return false;
        const auto report = verifier::verify_report(path.string(), profile);
        if (!report.loaded || report.total <= 0 || report.passed != report.total)
            return false;
        try {
            auto artifact = lock_file(path, 8ULL * 1024ULL * 1024ULL * 1024ULL, false);
            measure_pe_post_process(artifact);
            revalidate(artifact);
            return true;
        } catch (...) {
            return false;
        }
    };
    request.signature_verifier = [](const std::filesystem::path& path)
        -> std::optional<aida::analysis::c03::package_signature_identity_t> {
        const auto identity = verify_authenticode(path);
        return aida::analysis::c03::package_signature_identity_t{
            identity.signer_thumbprint_sha256, identity.trusted_timestamp,
            identity.trusted_timestamp_filetime};
    };
    request.verification_checkpoint = [&](aida::analysis::c03::package_verification_checkpoint_t) {
        revalidate_all();
    };
    aida::analysis::c03::build_worker_packaging_integration_t verifier;
    const auto result = verifier.verify_distribution_package(request);
    revalidate_all();
    if (!result) {
        const auto& error = result.error();
        std::cerr << "{\"verified\":false,\"code\":\""
                  << json_escape(error.stable_code) << "\",\"detail\":\""
                  << json_escape(error.detail) << "\",\"path\":\""
                  << json_escape(error.path.generic_string()) << "\"}\n";
        return 2;
    }
    const auto& verified = result.value();
    std::cout << "{\"verified\":true,\"manifest_sha256\":\""
              << verified.manifest_sha256 << "\",\"artifacts_verified\":"
              << verified.artifacts_verified << ",\"workers_verified\":"
              << verified.workers_verified << ",\"dependencies_verified\":"
              << verified.dependencies_verified << "}\n";
    return 0;
}

}

int wmain(int argc, wchar_t** argv) {
    try {
        if (!SetConsoleCtrlHandler(console_control_handler, TRUE))
            fail("package verifier cancellation handler is unavailable");
        [[maybe_unused]] const console_handler_scope_t control_guard;
        const auto arguments = parse_arguments(argc, argv);
        if (arguments.mode == L"verify-package")
            return verify_package(arguments);
        if (arguments.mode == L"inspect-generation")
            return inspect_generation(arguments);
        if (arguments.mode == L"emit-receipts")
            return emit_receipts(arguments);
        if (arguments.mode == L"inspect-pe-post-process")
            return inspect_pe_post_process(arguments);
        if (arguments.mode == L"run-signing-provider")
            return run_bound_signing_provider(arguments);
        fail("unknown package verifier mode");
    } catch (const std::exception& exception) {
        std::cerr << "{\"verified\":false,\"code\":\"C03_PACKAGE_VERIFIER_FAILURE\",\"detail\":\""
                  << json_escape(exception.what()) << "\"}\n";
        return 1;
    }
}
