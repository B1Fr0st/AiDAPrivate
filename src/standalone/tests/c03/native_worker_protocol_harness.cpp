#include "native_worker_protocol_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/native_worker_host.hpp"
#include "../../workers/native_decompiler/native_worker_runtime.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <userenv.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#pragma comment(lib, "userenv.lib")

namespace aida::analysis::c03_test {
namespace {

using namespace native_worker;

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

struct file_identity_t final {
    DWORD volume_serial = 0;
    DWORD file_index_high = 0;
    DWORD file_index_low = 0;

    bool operator==(const file_identity_t& other) const noexcept
    {
        return volume_serial == other.volume_serial &&
            file_index_high == other.file_index_high &&
            file_index_low == other.file_index_low;
    }
};

[[noreturn]] void fail_path(std::string_view message, DWORD error)
{
    throw std::runtime_error(std::string(message) + " (win32=" + std::to_string(error) + ")");
}

bool invalid_path_component(std::wstring_view value) noexcept
{
    if (value.empty() || value == L"." || value == L".." ||
        value.back() == L'.' || value.back() == L' ')
        return true;
    constexpr std::wstring_view invalid = L"<>:\"/\\|?*";
    return value.find_first_of(invalid) != std::wstring_view::npos ||
        std::any_of(value.begin(), value.end(), [](wchar_t character) {
            return character < 0x20 || character == 0x7f;
        });
}

bool equal_path_text(std::wstring_view left, std::wstring_view right) noexcept
{
    if (left.size() != right.size() || left.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        return false;
    if (left.empty())
        return true;
    return CompareStringOrdinal(left.data(), static_cast<int>(left.size()),
        right.data(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}

std::filesystem::path normalized_local_path(const std::filesystem::path& input, std::string_view failure)
{
    if (input.empty())
        throw std::runtime_error(std::string(failure));
    std::error_code error;
    auto path = std::filesystem::absolute(input, error);
    if (error || path.empty())
        throw std::runtime_error(std::string(failure));
    path = path.lexically_normal();
    path.make_preferred();
    std::wstring native = path.native();
    while (native.size() > 3 && native.back() == L'\\')
        native.pop_back();
    if (native.size() < 3 ||
        !((native[0] >= L'A' && native[0] <= L'Z') ||
          (native[0] >= L'a' && native[0] <= L'z')) ||
        native[1] != L':' || native[2] != L'\\' ||
        native.size() >= 32767 || native.find(L'\0') != std::wstring::npos)
        throw std::runtime_error(std::string(failure));
    path = std::filesystem::path(native);
    for (const auto& component : path.relative_path()) {
        if (invalid_path_component(component.native()))
            throw std::runtime_error(std::string(failure));
    }
    std::array<wchar_t, 32768> resolved{};
    const DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(resolved.size()),
        resolved.data(), nullptr);
    if (length == 0 || length >= resolved.size())
        fail_path(failure, GetLastError());
    auto full = std::filesystem::path(std::wstring(resolved.data(), length)).lexically_normal();
    full.make_preferred();
    std::wstring canonical = full.native();
    while (canonical.size() > 3 && canonical.back() == L'\\')
        canonical.pop_back();
    if (!equal_path_text(canonical, native))
        throw std::runtime_error(std::string(failure));
    return std::filesystem::path(std::move(canonical));
}

std::filesystem::path pinned_ghidra_specs_root()
{
#ifdef GHIDRA_SPECS_DIR
#define AIDA_C03_NATIVE_WORKER_STRINGIFY_IMPL(value) #value
#define AIDA_C03_NATIVE_WORKER_STRINGIFY(value) AIDA_C03_NATIVE_WORKER_STRINGIFY_IMPL(value)
    const auto encoded = std::string(AIDA_C03_NATIVE_WORKER_STRINGIFY(GHIDRA_SPECS_DIR));
#undef AIDA_C03_NATIVE_WORKER_STRINGIFY
#undef AIDA_C03_NATIVE_WORKER_STRINGIFY_IMPL
    return normalized_local_path(std::filesystem::u8path(encoded),
        "pinned Ghidra specifications path is invalid");
#else
    throw std::runtime_error("pinned Ghidra specifications path is unavailable");
#endif
}

bool final_handle_path(HANDLE handle, std::wstring& output) noexcept
{
    try {
        const DWORD required = GetFinalPathNameByHandleW(handle, nullptr, 0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (required == 0)
            return false;
        std::wstring value(required, L'\0');
        const DWORD written = GetFinalPathNameByHandleW(handle, value.data(), required,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (written == 0 || written >= required)
            return false;
        value.resize(written);
        if (value.rfind(L"\\\\?\\UNC\\", 0) == 0)
            return false;
        if (value.rfind(L"\\\\?\\", 0) == 0)
            value.erase(0, 4);
        std::replace(value.begin(), value.end(), L'/', L'\\');
        while (value.size() > 3 && value.back() == L'\\')
            value.pop_back();
        output = std::move(value);
        return true;
    } catch (...) {
        return false;
    }
}

bool inspect_path_handle(HANDLE handle, const std::filesystem::path& expected,
                         bool require_directory, file_identity_t& identity) noexcept
{
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    BY_HANDLE_FILE_INFORMATION information{};
    std::wstring final_path;
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        attributes.ReparseTag != 0 ||
        ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != require_directory ||
        !GetFileInformationByHandle(handle, &information) ||
        !final_handle_path(handle, final_path))
        return false;
    const auto& expected_text = expected.native();
    std::size_t expected_size = expected_text.size();
    while (expected_size > 3 && expected_text[expected_size - 1] == L'\\')
        --expected_size;
    if (!equal_path_text(final_path,
            std::wstring_view(expected_text.data(), expected_size)))
        return false;
    identity.volume_serial = information.dwVolumeSerialNumber;
    identity.file_index_high = information.nFileIndexHigh;
    identity.file_index_low = information.nFileIndexLow;
    return true;
}

std::vector<handle_t> verified_directory_chain(const std::filesystem::path& directory,
                                               bool materialize)
{
    std::vector<std::filesystem::path> components;
    for (const auto& component : directory.relative_path())
        components.push_back(component);
    const std::size_t component_count = components.size() + 1;
    std::vector<handle_t> handles;
    std::vector<std::filesystem::path> created;
    handles.reserve(component_count);
    created.reserve(component_count);
    try {
        std::filesystem::path current = directory.root_path();
        for (std::size_t index = 0; index < component_count; ++index) {
            if (index != 0)
                current /= components[index - 1];
            HANDLE raw = CreateFileW(current.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (raw == INVALID_HANDLE_VALUE) {
                const DWORD open_error = GetLastError();
                if (!materialize || index == 0 ||
                    (open_error != ERROR_FILE_NOT_FOUND && open_error != ERROR_PATH_NOT_FOUND))
                    fail_path("native worker directory path could not be opened", open_error);
                auto created_path = current;
                if (!CreateDirectoryW(current.c_str(), nullptr)) {
                    const DWORD create_error = GetLastError();
                    if (create_error != ERROR_ALREADY_EXISTS)
                        fail_path("native worker scratch root could not be materialized", create_error);
                } else {
                    created.push_back(std::move(created_path));
                }
                raw = CreateFileW(current.c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                if (raw == INVALID_HANDLE_VALUE)
                    fail_path("native worker materialized directory could not be opened", GetLastError());
            }
            handle_t handle(raw);
            file_identity_t identity;
            if (!inspect_path_handle(handle.get(), current, true, identity))
                throw std::runtime_error("native worker directory path is not a canonical non-reparse directory");
            handles.push_back(std::move(handle));
        }
        return handles;
    } catch (...) {
        handles.clear();
        bool rollback_ok = true;
        for (auto iterator = created.rbegin(); iterator != created.rend(); ++iterator) {
            const DWORD attributes = GetFileAttributesW(iterator->c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES) {
                const DWORD error = GetLastError();
                if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
                    rollback_ok = false;
                continue;
            }
            if ((attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
                    FILE_ATTRIBUTE_DIRECTORY ||
                !RemoveDirectoryW(iterator->c_str()))
                rollback_ok = false;
        }
        if (!rollback_ok)
            throw std::runtime_error("native worker scratch materialization rollback failed");
        throw;
    }
}

handle_t verified_regular_file(const std::filesystem::path& path, DWORD access, DWORD sharing,
                               DWORD flags, file_identity_t& identity)
{
    handle_t file(CreateFileW(path.c_str(), access | FILE_READ_ATTRIBUTES, sharing, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | flags, nullptr));
    if (!file)
        fail_path("native worker file could not be opened", GetLastError());
    if (!inspect_path_handle(file.get(), path, false, identity))
        throw std::runtime_error("native worker file is not a canonical regular non-reparse file");
    return file;
}

bool mark_for_deletion(HANDLE handle) noexcept
{
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    return SetFileInformationByHandle(handle, FileDispositionInfo,
        &disposition, sizeof(disposition)) != FALSE;
}

class pipe_pair_t final {
public:
    pipe_pair_t()
    {
        HANDLE read = nullptr;
        HANDLE write = nullptr;
        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength = sizeof(attributes);
        if (!CreatePipe(&read, &write, &attributes, 0))
            throw std::runtime_error("pipe creation failed");
        read_.reset(read);
        write_.reset(write);
    }

    HANDLE read() const noexcept { return read_.get(); }
    HANDLE write() const noexcept { return write_.get(); }

private:
    handle_t read_;
    handle_t write_;
};

class session_guard_t final {
public:
    explicit session_guard_t(wire::session_material_t& session) noexcept : session_(session) {}
    ~session_guard_t()
    {
        SecureZeroMemory(session_.key.data(), session_.key.size());
        SecureZeroMemory(session_.nonce.data(), session_.nonce.size());
    }

private:
    wire::session_material_t& session_;
};

class fixture_workspace_t final {
public:
    fixture_workspace_t(const std::filesystem::path& scratch_root, const std::filesystem::path& fake_worker)
    {
        owned_files_.reserve(128);
        owned_directories_.reserve(3);
        scratch_ = normalized_local_path(scratch_root, "native worker scratch root path is invalid");
        if (scratch_.relative_path().empty())
            throw std::runtime_error("native worker scratch root cannot be a volume root");
        scratch_chain_ = verified_directory_chain(scratch_, true);
        const auto source = normalized_local_path(fake_worker, "fake native worker path is invalid");
        if (source.parent_path().empty())
            throw std::runtime_error("fake native worker parent path is invalid");
        auto source_chain = verified_directory_chain(source.parent_path(), false);
        if (source_chain.empty())
            throw std::runtime_error("fake native worker parent path is unavailable");
        file_identity_t source_identity;
        auto source_file = verified_regular_file(source, GENERIC_READ, FILE_SHARE_READ,
            FILE_FLAG_SEQUENTIAL_SCAN, source_identity);
        const auto specs_source = pinned_ghidra_specs_root();
        auto specs_source_chain = verified_directory_chain(specs_source, false);
        if (specs_source_chain.empty())
            throw std::runtime_error("pinned Ghidra specifications directory is unavailable");
        try {
            create_workspace();
            stage_worker(source_file.get());
            stage_ghidra_specs(specs_source);
        } catch (...) {
            if (!cleanup())
                throw std::runtime_error("native worker workspace construction cleanup failed");
            throw;
        }
    }

    ~fixture_workspace_t()
    {
        cleanup();
    }

    fixture_workspace_t(const fixture_workspace_t&) = delete;
    fixture_workspace_t& operator=(const fixture_workspace_t&) = delete;

    const std::filesystem::path& root() const noexcept { return root_; }
    const std::filesystem::path& worker_path() const noexcept { return worker_path_; }

    std::filesystem::path write_owned_file(const std::filesystem::path& leaf, std::string_view bytes)
    {
        if (bytes.empty())
            throw std::runtime_error("native worker owned file bytes are empty");
        return write_owned_file_at(root_, leaf, bytes.data(), bytes.size());
    }

    bool cleanup() noexcept
    {
        if (root_.empty())
            return true;
        bool deletion_ok = true;
        for (auto iterator = owned_files_.rbegin(); iterator != owned_files_.rend(); ++iterator) {
            if (iterator->removed)
                continue;
            iterator->lock.reset();
            handle_t file(CreateFileW(iterator->path.c_str(), DELETE | FILE_READ_ATTRIBUTES, 0,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (!file) {
                const DWORD error = GetLastError();
                if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
                    iterator->removed = true;
                    cleanup_integrity_ = false;
                } else {
                    deletion_ok = false;
                }
                continue;
            }
            file_identity_t identity;
            if (!inspect_path_handle(file.get(), iterator->path, false, identity) ||
                !(identity == iterator->identity) || !mark_for_deletion(file.get())) {
                deletion_ok = false;
                continue;
            }
            file.reset();
            const DWORD attributes = GetFileAttributesW(iterator->path.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES) {
                deletion_ok = false;
                continue;
            }
            const DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                deletion_ok = false;
                continue;
            }
            iterator->removed = true;
        }
        if (!deletion_ok)
            return false;
        for (auto iterator = owned_directories_.rbegin();
             iterator != owned_directories_.rend(); ++iterator) {
            if (iterator->removed)
                continue;
            iterator->lock.reset();
            handle_t directory(CreateFileW(iterator->path.c_str(),
                DELETE | FILE_READ_ATTRIBUTES, 0, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (!directory) {
                const DWORD error = GetLastError();
                if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
                    iterator->removed = true;
                    cleanup_integrity_ = false;
                } else {
                    deletion_ok = false;
                }
                continue;
            }
            file_identity_t identity;
            if (!inspect_path_handle(directory.get(), iterator->path, true, identity) ||
                !(identity == iterator->identity) || !mark_for_deletion(directory.get())) {
                deletion_ok = false;
                continue;
            }
            directory.reset();
            const DWORD attributes = GetFileAttributesW(iterator->path.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES) {
                deletion_ok = false;
                continue;
            }
            const DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                deletion_ok = false;
                continue;
            }
            iterator->removed = true;
        }
        if (!deletion_ok)
            return false;
        workspace_handle_.reset();
        handle_t directory(CreateFileW(root_.c_str(), DELETE | FILE_READ_ATTRIBUTES, 0, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!directory) {
            const DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
                cleanup_integrity_ = false;
                clear_workspace_state();
            }
            return false;
        }
        file_identity_t identity;
        if (!inspect_path_handle(directory.get(), root_, true, identity) ||
            !(identity == workspace_identity_) || !mark_for_deletion(directory.get()))
            return false;
        directory.reset();
        const DWORD attributes = GetFileAttributesW(root_.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES)
            return false;
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
            return false;
        const bool intact = cleanup_integrity_;
        clear_workspace_state();
        return intact;
    }

private:
    struct owned_file_t final {
        std::filesystem::path path;
        file_identity_t identity;
        handle_t lock;
        bool removed = false;
    };

    struct owned_directory_t final {
        std::filesystem::path path;
        file_identity_t identity;
        handle_t lock;
        bool removed = false;
    };

    static std::wstring random_workspace_leaf()
    {
        std::array<std::uint8_t, 16> random{};
        const NTSTATUS status = BCryptGenRandom(nullptr, random.data(),
            static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status))
            throw std::runtime_error("native worker workspace entropy generation failed");
        constexpr std::wstring_view digits = L"0123456789abcdef";
        std::wstring leaf = L"aida-c03-native-worker-" + std::to_wstring(GetCurrentProcessId()) + L"-";
        leaf.reserve(leaf.size() + random.size() * 2);
        for (const auto byte : random) {
            leaf.push_back(digits[(byte >> 4) & 0x0f]);
            leaf.push_back(digits[byte & 0x0f]);
        }
        SecureZeroMemory(random.data(), random.size());
        return leaf;
    }

    static bool remove_fresh_directory(const std::filesystem::path& path) noexcept
    {
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            const DWORD error = GetLastError();
            return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
        }
        return (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ==
            FILE_ATTRIBUTE_DIRECTORY && RemoveDirectoryW(path.c_str()) != FALSE;
    }

    void create_workspace()
    {
        for (std::uint32_t attempt = 0; attempt < 64; ++attempt) {
            root_ = scratch_ / random_workspace_leaf();
            if (!CreateDirectoryW(root_.c_str(), nullptr)) {
                const DWORD error = GetLastError();
                root_.clear();
                if (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS)
                    continue;
                fail_path("native worker scratch workspace could not be created", error);
            }
            handle_t directory(CreateFileW(root_.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            file_identity_t identity;
            if (!directory || !inspect_path_handle(directory.get(), root_, true, identity)) {
                directory.reset();
                const bool removed = remove_fresh_directory(root_);
                root_.clear();
                if (!removed)
                    throw std::runtime_error("native worker scratch workspace validation rollback failed");
                throw std::runtime_error("native worker scratch workspace validation failed");
            }
            workspace_identity_ = identity;
            workspace_handle_ = std::move(directory);
            return;
        }
        throw std::runtime_error("native worker scratch workspace name could not be reserved");
    }

    const owned_directory_t* find_owned_directory(const std::filesystem::path& path) const noexcept
    {
        const auto iterator = std::find_if(owned_directories_.begin(), owned_directories_.end(),
            [&](const owned_directory_t& current) {
                return equal_path_text(current.path.native(), path.native());
            });
        return iterator == owned_directories_.end() ? nullptr : &*iterator;
    }

    void verify_owned_parent(const std::filesystem::path& path) const
    {
        file_identity_t identity;
        if (equal_path_text(path.native(), root_.native())) {
            if (!workspace_handle_ ||
                !inspect_path_handle(workspace_handle_.get(), root_, true, identity) ||
                !(identity == workspace_identity_))
                throw std::runtime_error("native worker workspace directory identity changed");
            return;
        }
        const auto* owned = find_owned_directory(path);
        if (!owned || !owned->lock ||
            !inspect_path_handle(owned->lock.get(), path, true, identity) ||
            !(identity == owned->identity))
            throw std::runtime_error("native worker owned directory identity changed");
    }

    std::filesystem::path create_owned_directory(const std::filesystem::path& parent,
                                                 const std::filesystem::path& leaf)
    {
        if (leaf.empty() || leaf.has_root_path() || leaf.filename() != leaf ||
            leaf.native().size() > 255 || invalid_path_component(leaf.native()))
            throw std::runtime_error("native worker owned directory name is invalid");
        verify_owned_parent(parent);
        const auto destination = parent / leaf;
        if (destination.native().size() >= 32767 ||
            std::any_of(owned_directories_.begin(), owned_directories_.end(),
                [&](const owned_directory_t& current) {
                    return equal_path_text(current.path.native(), destination.native());
                }))
            throw std::runtime_error("native worker owned directory path is invalid");
        if (!CreateDirectoryW(destination.c_str(), nullptr))
            fail_path("native worker owned directory could not be created", GetLastError());
        handle_t directory(CreateFileW(destination.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        file_identity_t identity;
        if (!directory || !inspect_path_handle(directory.get(), destination, true, identity)) {
            directory.reset();
            if (!remove_fresh_directory(destination))
                throw std::runtime_error("native worker invalid owned directory cleanup failed");
            throw std::runtime_error("native worker owned directory validation failed");
        }
        owned_directory_t record;
        record.path = destination;
        record.identity = identity;
        record.lock = std::move(directory);
        try {
            owned_directories_.push_back(std::move(record));
        } catch (...) {
            record.lock.reset();
            if (!remove_fresh_directory(destination))
                throw std::runtime_error("native worker owned directory registration cleanup failed");
            throw;
        }
        return destination;
    }

    handle_t create_owned_file(const std::filesystem::path& parent,
                               const std::filesystem::path& leaf,
                               std::filesystem::path& destination,
                               file_identity_t& identity)
    {
        if (leaf.empty() || leaf.has_root_path() || leaf.filename() != leaf ||
            leaf.native().size() > 255 || invalid_path_component(leaf.native()))
            throw std::runtime_error("native worker owned file name is invalid");
        verify_owned_parent(parent);
        destination = parent / leaf;
        if (destination.native().size() >= 32767)
            throw std::runtime_error("native worker owned file path is invalid");
        if (std::any_of(owned_files_.begin(), owned_files_.end(), [&](const owned_file_t& current) {
                return equal_path_text(current.path.native(), destination.native());
            }))
            throw std::runtime_error("native worker owned file name is duplicated");
        owned_file_t record;
        record.path = destination;
        handle_t file(CreateFileW(destination.c_str(), GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
            0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!file)
            fail_path("native worker owned file could not be created", GetLastError());
        if (!inspect_path_handle(file.get(), destination, false, identity)) {
            const bool removed = mark_for_deletion(file.get());
            file.reset();
            if (!removed)
                throw std::runtime_error("native worker invalid owned file cleanup failed");
            throw std::runtime_error("native worker owned file validation failed");
        }
        record.identity = identity;
        try {
            owned_files_.push_back(std::move(record));
        } catch (...) {
            const bool removed = mark_for_deletion(file.get());
            file.reset();
            if (!removed)
                throw std::runtime_error("native worker owned file registration cleanup failed");
            throw;
        }
        return file;
    }

    std::filesystem::path write_owned_file_at(const std::filesystem::path& parent,
                                              const std::filesystem::path& leaf,
                                              const void* bytes, std::size_t size)
    {
        if (!bytes || size == 0)
            throw std::runtime_error("native worker owned file bytes are empty");
        std::filesystem::path destination;
        file_identity_t identity;
        auto file = create_owned_file(parent, leaf, destination, identity);
        DWORD error = ERROR_SUCCESS;
        if (!wire::write_all(file.get(), bytes, size, error) ||
            FlushFileBuffers(file.get()) == FALSE)
            throw std::runtime_error("native worker owned file could not be committed");
        file.reset();
        lock_owned_file(destination, identity);
        return destination;
    }

    void lock_owned_file(const std::filesystem::path& path, const file_identity_t& expected)
    {
        const auto iterator = std::find_if(owned_files_.begin(), owned_files_.end(),
            [&](const owned_file_t& current) {
                return equal_path_text(current.path.native(), path.native());
            });
        if (iterator == owned_files_.end())
            throw std::runtime_error("native worker owned file registration is missing");
        file_identity_t identity;
        auto lock = verified_regular_file(path, GENERIC_READ, FILE_SHARE_READ,
            FILE_FLAG_SEQUENTIAL_SCAN, identity);
        if (!(identity == expected))
            throw std::runtime_error("native worker owned file identity changed");
        iterator->lock = std::move(lock);
    }

    void stage_worker(HANDLE source)
    {
        LARGE_INTEGER source_size{};
        if (!GetFileSizeEx(source, &source_size) || source_size.QuadPart <= 0 ||
            static_cast<std::uint64_t>(source_size.QuadPart) > 2ULL * 1024ULL * 1024ULL * 1024ULL)
            throw std::runtime_error("fake native worker size violates the harness contract");
        file_identity_t staged_identity;
        auto staged = create_owned_file(root_, L"AiDA_FakeNativeDecompilerWorker.exe",
            worker_path_, staged_identity);
        std::array<std::uint8_t, 64 * 1024> buffer{};
        std::uint64_t remaining = static_cast<std::uint64_t>(source_size.QuadPart);
        while (remaining != 0) {
            const DWORD requested = static_cast<DWORD>((std::min<std::uint64_t>)(remaining, buffer.size()));
            DWORD read = 0;
            if (!ReadFile(source, buffer.data(), requested, &read, nullptr) || read != requested)
                throw std::runtime_error("fake native worker could not be read for staging");
            DWORD written = 0;
            while (written != read) {
                DWORD current = 0;
                if (!WriteFile(staged.get(), buffer.data() + written, read - written, &current, nullptr) ||
                    current == 0)
                    throw std::runtime_error("fake native worker could not be staged");
                written += current;
            }
            remaining -= read;
        }
        LARGE_INTEGER staged_size{};
        if (FlushFileBuffers(staged.get()) == FALSE ||
            !GetFileSizeEx(staged.get(), &staged_size) || staged_size.QuadPart != source_size.QuadPart)
            throw std::runtime_error("fake native worker staging could not be committed");
        staged.reset();
        lock_owned_file(worker_path_, staged_identity);
    }

    void stage_ghidra_specs(const std::filesystem::path& source_root)
    {
        constexpr std::size_t required_file_count = 51;
        constexpr std::uint64_t maximum_file_bytes = 8ULL * 1024ULL * 1024ULL;
        constexpr std::uint64_t maximum_inventory_bytes = 64ULL * 1024ULL * 1024ULL;
        const auto direct_mirror = create_owned_directory(root_, L"ghidra_specs");
        const auto deps_root = create_owned_directory(root_, L"deps");
        const auto deps_mirror = create_owned_directory(deps_root, L"ghidra_specs");
        std::error_code error;
        std::vector<std::filesystem::path> sources;
        sources.reserve(required_file_count);
        for (std::filesystem::directory_iterator iterator(source_root,
                 std::filesystem::directory_options::none, error), end;
             !error && iterator != end; iterator.increment(error)) {
            const auto path = iterator->path();
            const DWORD attributes = GetFileAttributesW(path.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
                throw std::runtime_error("pinned Ghidra specification inventory contains a non-regular entry");
            const auto name = path.filename();
            if (name.empty() || name.has_root_path() || name.filename() != name ||
                name.native().size() > 255 || invalid_path_component(name.native()))
                throw std::runtime_error("pinned Ghidra specification name is invalid");
            const auto extension = name.extension().wstring();
            if (extension != L".sla" && extension != L".pspec" &&
                extension != L".cspec" && extension != L".ldefs")
                throw std::runtime_error("pinned Ghidra specification extension is invalid");
            sources.push_back(path);
            if (sources.size() > required_file_count)
                throw std::runtime_error("pinned Ghidra specification inventory is oversized");
        }
        if (error || sources.size() != required_file_count)
            throw std::runtime_error("pinned Ghidra specification inventory count is invalid");
        std::sort(sources.begin(), sources.end(), [](const auto& left, const auto& right) {
            const auto left_name = left.filename().wstring();
            const auto right_name = right.filename().wstring();
            const int insensitive = _wcsicmp(left_name.c_str(), right_name.c_str());
            return insensitive == 0 ? left_name < right_name : insensitive < 0;
        });
        for (std::size_t index = 1; index < sources.size(); ++index) {
            if (_wcsicmp(sources[index - 1].filename().c_str(),
                    sources[index].filename().c_str()) == 0)
                throw std::runtime_error("pinned Ghidra specification inventory has duplicate names");
        }
        std::uint64_t inventory_bytes = 0;
        for (const auto& source_path : sources) {
            file_identity_t source_identity;
            auto source = verified_regular_file(source_path, GENERIC_READ, FILE_SHARE_READ,
                FILE_FLAG_SEQUENTIAL_SCAN, source_identity);
            LARGE_INTEGER source_size{};
            if (!GetFileSizeEx(source.get(), &source_size) || source_size.QuadPart <= 0 ||
                static_cast<std::uint64_t>(source_size.QuadPart) > maximum_file_bytes)
                throw std::runtime_error("pinned Ghidra specification size is invalid");
            const auto size = static_cast<std::uint64_t>(source_size.QuadPart);
            if (inventory_bytes > maximum_inventory_bytes - size)
                throw std::runtime_error("pinned Ghidra specification inventory exceeds its byte budget");
            inventory_bytes += size;
            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
            std::size_t consumed = 0;
            while (consumed != bytes.size()) {
                const DWORD requested = static_cast<DWORD>((std::min<std::size_t>)(
                    bytes.size() - consumed, 64U * 1024U));
                DWORD read = 0;
                if (!ReadFile(source.get(), bytes.data() + consumed, requested, &read, nullptr) ||
                    read != requested)
                    throw std::runtime_error("pinned Ghidra specification could not be read");
                consumed += read;
            }
            LARGE_INTEGER confirmed_size{};
            if (!GetFileSizeEx(source.get(), &confirmed_size) ||
                confirmed_size.QuadPart != source_size.QuadPart)
                throw std::runtime_error("pinned Ghidra specification changed while staging");
            const auto name = source_path.filename();
            write_owned_file_at(direct_mirror, name, bytes.data(), bytes.size());
            write_owned_file_at(deps_mirror, name, bytes.data(), bytes.size());
        }
    }

    void clear_workspace_state() noexcept
    {
        workspace_handle_.reset();
        scratch_chain_.clear();
        owned_files_.clear();
        owned_directories_.clear();
        worker_path_.clear();
        root_.clear();
        scratch_.clear();
        workspace_identity_ = {};
    }

    std::filesystem::path scratch_;
    std::filesystem::path root_;
    std::filesystem::path worker_path_;
    std::vector<handle_t> scratch_chain_;
    handle_t workspace_handle_;
    file_identity_t workspace_identity_;
    std::vector<owned_file_t> owned_files_;
    std::vector<owned_directory_t> owned_directories_;
    bool cleanup_integrity_ = true;
};

void require(bool condition, std::string_view message)
{
    assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

sha256_digest_t digest(std::string_view value)
{
    sha256_digest_t result;
    require(wire::sha256(value.data(), value.size(), result), "SHA-256 calculation failed");
    return result;
}

sha256_digest_t locked_digest(std::string_view value)
{
    const auto parsed = sha256_digest_t::from_hex(std::string(value));
    require(parsed.has_value(), "locked SHA-256 value is malformed");
    return *parsed;
}

sha256_digest_t file_digest(const std::filesystem::path& path)
{
    handle_t file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    require(static_cast<bool>(file), "worker file could not be opened for hashing");
    LARGE_INTEGER size{};
    require(GetFileSizeEx(file.get(), &size) != FALSE && size.QuadPart > 0 &&
        static_cast<std::uint64_t>(size.QuadPart) <= 2ULL * 1024ULL * 1024ULL * 1024ULL,
        "worker file size violates the harness contract");
    std::vector<std::uint8_t> bytes;
    try {
        bytes.resize(static_cast<std::size_t>(size.QuadPart));
    } catch (...) {
        throw std::runtime_error("worker hash buffer allocation failed");
    }
    DWORD error = ERROR_SUCCESS;
    require(wire::read_all(file.get(), bytes.data(), bytes.size(), error), "worker file could not be read for hashing");
    sha256_digest_t result;
    require(wire::sha256(bytes.data(), bytes.size(), result), "worker file hash calculation failed");
    return result;
}

native_worker_manifest_t manifest_fixture(const sha256_digest_t& worker_hash, std::string fixture)
{
    native_worker_manifest_t result;
    result.worker_relative_path = "AiDA_FakeNativeDecompilerWorker.exe";
    result.worker_binary_hash = worker_hash;
    result.provider.provider = decompiler_provider_id_t::ghidra_native;
    result.provider.provider_name = runtime::k_provider_name;
    result.provider.provider_version = runtime::k_provider_version;
    result.provider.provider_binary_hash = result.worker_binary_hash;
    result.provider.worker_build_id = runtime::k_worker_build_id;
    result.provider.worker_build_hash = stable_serialization_hash(runtime::k_worker_build_hash_material);
    result.worker_protocol_hash = native_worker_protocol_hash();
    if (!fixture.empty())
        result.startup_arguments.push_back("--fixture=" + std::move(fixture));
    return result;
}

native_worker_manifest_t manifest_fixture()
{
    return manifest_fixture(digest("worker-binary"), "replay");
}

native_worker_manifest_t managed_manifest_fixture()
{
    native_worker_manifest_t result;
    result.schema_version = k_managed_worker_manifest_schema_version;
    result.worker_relative_path = std::string(k_managed_worker_binary_artifact_relative_path);
    result.worker_binary_hash = digest("managed-worker-binary");
    result.provider.provider = decompiler_provider_id_t::ilspy_cli;
    result.provider.provider_name = "ICSharpCode.Decompiler";
    result.provider.provider_version = "10.1.0.8386";
    result.provider.provider_binary_hash = locked_digest(
        "bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345");
    result.provider.worker_build_id = "aida-managed-decompiler-worker-v3";
    result.provider.worker_build_hash = locked_digest(
        "4dd8c0d095629437387a4b631fd9ac3c3cb8e840f6b7af277ccc2ad49d4bc3b7");
    result.worker_protocol_hash = native_worker_protocol_hash();
    result.managed_runtime_manifest_hash = digest("managed-runtime-manifest");
    return result;
}

decompiler_worker_message_t heartbeat(const wire::session_material_t& session, std::uint64_t sequence)
{
    decompiler_worker_heartbeat_t value;
    value.envelope.kind = decompiler_worker_message_kind_t::heartbeat;
    value.envelope.session_nonce_hash = session.nonce_hash;
    value.envelope.sequence = sequence;
    value.active_job_id = 1;
    return value;
}

std::array<std::uint8_t, wire::k_frame_header_bytes> rejected_header(
    const wire::session_material_t& session, std::uint64_t sequence, std::uint32_t payload_size,
    bool malformed, bool nonce_mismatch)
{
    std::array<std::uint8_t, wire::k_frame_header_bytes> header{};
    wire::write_u32(header.data(), malformed ? wire::k_frame_magic ^ 0x80000000U : wire::k_frame_magic);
    wire::write_u16(header.data() + 4, wire::k_frame_version);
    wire::write_u16(header.data() + 6, static_cast<std::uint16_t>(wire::frame_kind_t::decompiler_contract));
    wire::write_u64(header.data() + 8, sequence);
    wire::write_u32(header.data() + 16, payload_size);
    std::memcpy(header.data() + 20, session.nonce_hash.bytes.data(), session.nonce_hash.bytes.size());
    if (nonce_mismatch)
        header[20] ^= 0x80U;
    return header;
}

void frame_round_trip_and_replay()
{
    pipe_pair_t pipe;
    wire::session_material_t session;
    session_guard_t session_guard(session);
    require(wire::make_session(session), "session creation failed");
    const auto message = heartbeat(session, 1);
    const auto payload = serialize_decompiler_worker_message(message);
    DWORD error = ERROR_SUCCESS;
    require(wire::send_frame(pipe.write(), session, wire::frame_kind_t::decompiler_contract, 1,
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), 1024 * 1024, error), "frame send failed");
    wire::frame_reader_t reader;
    wire::frame_t frame;
    require(reader.poll(pipe.read(), session, 1, 1024 * 1024, frame, error) == wire::read_state_t::complete,
        "valid frame was not accepted");
    require(frame.sequence == 1 && frame.payload.size() == payload.size(), "valid frame changed during receipt");
    require(wire::send_frame(pipe.write(), session, wire::frame_kind_t::decompiler_contract, 1,
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), 1024 * 1024, error), "replay frame send failed");
    require(reader.poll(pipe.read(), session, 2, 1024 * 1024, frame, error) == wire::read_state_t::failure &&
        reader.failure() == wire::frame_failure_t::replay, "replayed sequence did not produce a replay failure");
}

void rejected_header_diagnostics()
{
    wire::session_material_t session;
    session_guard_t session_guard(session);
    require(wire::make_session(session), "header diagnostic session creation failed");
    const auto verify = [&](const auto& header, wire::frame_failure_t expected, std::size_t maximum, std::string_view message) {
        pipe_pair_t pipe;
        DWORD error = ERROR_SUCCESS;
        require(wire::write_all(pipe.write(), header.data(), header.size(), error), "rejected header write failed");
        wire::frame_reader_t reader;
        wire::frame_t frame;
        require(reader.poll(pipe.read(), session, 1, maximum, frame, error) == wire::read_state_t::failure &&
            reader.failure() == expected, message);
    };
    verify(rejected_header(session, 1, 0, true, false), wire::frame_failure_t::malformed_header,
        1024 * 1024, "malformed header did not produce a distinct failure");
    verify(rejected_header(session, 1, 0, false, true), wire::frame_failure_t::nonce_mismatch,
        1024 * 1024, "nonce mismatch did not produce a distinct failure");
    verify(rejected_header(session, 1, 2U * 1024U * 1024U, false, false), wire::frame_failure_t::oversize,
        1024 * 1024, "oversize frame did not produce a distinct failure");
    auto authentication = rejected_header(session, 1, 0, false, false);
    std::array<std::uint8_t, wire::k_digest_bytes> tag{};
    require(wire::hmac_sha256(session.key.data(), session.key.size(), authentication.data(),
        wire::k_frame_header_without_tag_bytes, tag), "authentication fixture tag calculation failed");
    std::memcpy(authentication.data() + wire::k_frame_header_without_tag_bytes, tag.data(), tag.size());
    authentication.back() ^= 0x80U;
    SecureZeroMemory(tag.data(), tag.size());
    verify(authentication, wire::frame_failure_t::authentication_failed,
        1024 * 1024, "invalid frame tag did not produce an authentication failure");
}

void truncation_contract()
{
    pipe_pair_t pipe;
    wire::session_material_t session;
    session_guard_t session_guard(session);
    require(wire::make_session(session), "truncation session creation failed");
    std::array<std::uint8_t, 9> fragment{};
    wire::write_u32(fragment.data(), wire::k_frame_magic);
    DWORD error = ERROR_SUCCESS;
    require(wire::write_all(pipe.write(), fragment.data(), fragment.size(), error), "truncated frame write failed");
    wire::frame_reader_t reader;
    wire::frame_t frame;
    require(reader.poll(pipe.read(), session, 1, 1024 * 1024, frame, error) == wire::read_state_t::incomplete &&
        reader.has_partial_frame(), "truncated frame was not retained as an incomplete frame");
}

void manifest_and_snapshot_contracts()
{
    require(k_decompiler_worker_protocol_version == 3 &&
        native_worker_protocol_hash() == stable_serialization_hash(wire::k_protocol_hash_material) &&
        std::string_view(wire::k_protocol_hash_material).find(
            "bounded-native-printc-evidence|control-frame-8m|result-frame-80m|provider-artifacts-48m|printc-8m") !=
            std::string_view::npos,
        "native worker protocol identity does not bind the PrintC evidence extension");
    require(k_native_worker_binary_artifact_relative_path == "deps/AiDA_NativeDecompilerWorker.exe" &&
        k_native_worker_manifest_artifact_relative_path == "deps/AiDA_NativeDecompilerWorker.manifest.bin" &&
        k_native_worker_manifest_digest_relative_path == "deps/AiDA_NativeDecompilerWorker.manifest.sha256" &&
        k_managed_worker_binary_artifact_relative_path == "deps/AiDA_ManagedDecompilerWorker.exe" &&
        k_managed_worker_manifest_artifact_relative_path == "deps/AiDA_ManagedDecompilerWorker.manifest.bin" &&
        k_managed_worker_manifest_digest_relative_path == "deps/AiDA_ManagedDecompilerWorker.manifest.sha256" &&
        k_managed_runtime_manifest_artifact_relative_path == "deps/AiDA_ManagedRuntime.manifest.json" &&
        k_managed_runtime_manifest_digest_relative_path == "deps/AiDA_ManagedRuntime.manifest.sha256" &&
        k_managed_dotnet_root_relative_path == "deps/dotnet",
        "worker production artifact paths drifted from the packaging contract");
    const auto manifest = manifest_fixture();
    const std::string serialized = serialize_native_worker_manifest(manifest);
    require(!serialized.empty(), "manifest did not serialize");
    require(wire::read_u32(reinterpret_cast<const std::uint8_t*>(serialized.data())) == k_native_worker_manifest_magic,
        "manifest magic does not match the packaging contract");
    const auto decoded = deserialize_native_worker_manifest(serialized);
    require(decoded.valid() && decoded.value.has_value(), "manifest did not deserialize");
    require(decoded.value->worker_binary_hash == manifest.worker_binary_hash &&
        decoded.value->worker_protocol_hash == native_worker_protocol_hash(), "manifest identity changed during round trip");
    sha256_digest_t before;
    sha256_digest_t after;
    require(wire::sha256(serialized.data(), serialized.size(), before), "manifest hash failed");
    std::string tampered = serialized;
    tampered.back() ^= 0x01;
    require(wire::sha256(tampered.data(), tampered.size(), after) && before != after,
        "manifest hash mismatch fixture is ineffective");
    tampered.pop_back();
    require(!deserialize_native_worker_manifest(tampered).valid(), "truncated manifest was accepted");
    const auto managed_manifest = managed_manifest_fixture();
    const auto managed_serialized = serialize_native_worker_manifest(managed_manifest);
    require(!managed_serialized.empty(), "managed manifest v3 did not serialize");
    const auto managed_decoded = deserialize_native_worker_manifest(managed_serialized);
    require(managed_decoded.valid() && managed_decoded.value &&
        managed_decoded.value->schema_version == k_managed_worker_manifest_schema_version &&
        managed_decoded.value->provider.provider == decompiler_provider_id_t::ilspy_cli &&
        managed_decoded.value->managed_runtime_manifest_hash ==
            managed_manifest.managed_runtime_manifest_hash &&
        managed_serialized.size() >= managed_manifest.managed_runtime_manifest_hash.bytes.size() &&
        std::equal(managed_manifest.managed_runtime_manifest_hash.bytes.begin(),
            managed_manifest.managed_runtime_manifest_hash.bytes.end(),
            reinterpret_cast<const std::uint8_t*>(managed_serialized.data()) +
                managed_serialized.size() -
                managed_manifest.managed_runtime_manifest_hash.bytes.size()),
        "managed manifest v3 runtime identity did not round trip as the final digest field");
    auto truncated_managed = managed_serialized;
    truncated_managed.pop_back();
    require(!deserialize_native_worker_manifest(truncated_managed).valid(),
        "managed manifest v3 accepted a truncated runtime identity");
    auto snapshot = make_native_worker_snapshot({0x48, 0x31, 0xc0, 0xc3});
    require(snapshot.has_value() && snapshot->valid(), "read-only snapshot factory failed");
    sha256_digest_t verified;
    require(wire::sha256(snapshot->bytes->data(), snapshot->bytes->size(), verified) && verified == snapshot->hash,
        "snapshot hash is not bound to immutable bytes");
}

address_t fixture_address(std::uint64_t value)
{
    address_t result;
    result.space = address_space_id_t::relative_virtual;
    result.value = value;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_entity_key_t fixture_entity(const sha256_digest_t& snapshot_hash)
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = 1;
    identity.entry = fixture_address(0x1000);
    identity.end = fixture_address(0x1004);
    identity.function_bytes_hash = snapshot_hash;
    identity.canonical_symbol = "c03::native_worker_fixture";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::native_function;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.identity = std::move(identity);
    return result;
}

decompiler_language_identity_t fixture_language()
{
    decompiler_language_identity_t result;
    result.language_id = "x86:LE:64:default";
    result.language_version = "1";
    result.compiler_spec_id = "windows";
    result.language_spec_hash = digest("c03-native-worker-language");
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_profile_budget_t fixture_profile()
{
    decompiler_profile_budget_t result;
    result.profile = decompiler_profile_id_t::balanced;
    result.max_wall_clock_ms = 5000;
    result.max_cpu_ms = 4000;
    result.max_memory_bytes = 256ULL << 20;
    result.max_provider_ir_nodes = 100000;
    result.max_hir_nodes = 100000;
    result.max_ast_nodes = 100000;
    return result;
}

decompiler_pipeline_cache_key_t fixture_cache_key(const decompiler_entity_key_t& entity,
                                                   const decompiler_provider_identity_t& provider,
                                                   const sha256_digest_t& snapshot_hash,
                                                   const decompiler_profile_budget_t& profile)
{
    decompiler_pipeline_cache_key_t result;
    result.stage = decompiler_cache_stage_t::rendered_document;
    result.workspace_id = "c03-native-worker-host";
    result.workspace_generation = 1;
    result.analysis_revision = 1;
    result.entity = entity;
    result.provider = provider;
    result.worker_protocol_hash = native_worker_protocol_hash();
    result.language = fixture_language();
    result.loader_layout_hash = digest("c03-native-worker-layout");
    result.function_bytes_hash = snapshot_hash;
    result.chunk_fingerprints.push_back({fixture_address(0x1000), fixture_address(0x1004), snapshot_hash});
    result.metadata_revision = 1;
    result.type_graph_revision = 1;
    result.overlay_revision = 1;
    result.profile = profile;
    result.renderer.style_id = "aida.c03.native-worker";
    result.renderer.indentation_spaces = 4;
    result.dependencies.push_back({"native-worker", runtime::k_provider_version, provider.provider_binary_hash});
    return result;
}

enum class fixture_execution_t : std::uint8_t {
    normal,
    cancellation,
    deadline
};

native_worker_execution_result_t execute_fixture(fixture_workspace_t& workspace,
                                                  const sha256_digest_t& worker_hash,
                                                  std::string fixture, std::uint64_t job_id,
                                                  fixture_execution_t execution = fixture_execution_t::normal)
{
    const native_worker_manifest_t manifest = manifest_fixture(worker_hash, fixture);
    const std::string manifest_bytes = serialize_native_worker_manifest(manifest);
    require(!manifest_bytes.empty(), "host fixture manifest did not serialize");
    sha256_digest_t manifest_hash;
    require(wire::sha256(manifest_bytes.data(), manifest_bytes.size(), manifest_hash),
        "host fixture manifest hash failed");
    const auto manifest_path = workspace.write_owned_file(
        L"native-worker-" + std::wstring(fixture.begin(), fixture.end()) + L".manifest.bin",
        manifest_bytes);
    native_worker_launch_contract_t contract;
    contract.approved_root = workspace.root();
    contract.manifest_path = manifest_path;
    contract.expected_manifest_hash = manifest_hash;
    native_worker_host_limits_t limits;
    limits.max_frame_bytes = 1024U * 1024U;
    limits.max_snapshot_bytes = 1024U * 1024U;
    limits.startup_timeout = std::chrono::seconds(10);
    limits.cancellation_grace = std::chrono::seconds(2);
    limits.poll_interval = std::chrono::milliseconds(2);
    native_worker_host_t host(std::move(contract), limits);
    native_worker_execution_request_t request;
    request.job_id = job_id;
    request.profile = fixture_profile();
    const auto snapshot = make_native_worker_snapshot({0x48, 0x31, 0xc0, 0xc3});
    require(snapshot.has_value(), "host fixture snapshot creation failed");
    request.snapshot = *snapshot;
    const auto entity = fixture_entity(request.snapshot.hash);
    request.cache_key = fixture_cache_key(entity, manifest.provider, request.snapshot.hash, request.profile);
    require(validate_decompiler_profile(request.profile).valid() &&
        validate_decompiler_pipeline_cache_key(request.cache_key).valid(), "host fixture request contract is invalid");
    if (execution == fixture_execution_t::cancellation)
        request.cancellation_requested = [] { return true; };
    if (execution == fixture_execution_t::deadline)
        request.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    auto result = host.execute(request);
    require(host.worker_generation() == 1 && result.worker_generation == 1,
        "host fixture did not allocate exactly one worker generation");
    const std::string profile_name_utf8 = std::string("AiDA.NativeWorker.") + manifest_hash.to_hex().substr(0, 32);
    const std::wstring profile_name(profile_name_utf8.begin(), profile_name_utf8.end());
    DeleteAppContainerProfile(profile_name.c_str());
    return result;
}

bool has_diagnostic(const native_worker_execution_result_t& result, native_worker_diagnostic_code_t code)
{
    return std::any_of(result.diagnostics.begin(), result.diagnostics.end(),
        [code](const native_worker_diagnostic_t& current) { return current.code == code; });
}

bool has_worker_key(const native_worker_execution_result_t& result, std::string_view key)
{
    return std::any_of(result.worker_diagnostics.begin(), result.worker_diagnostics.end(),
        [key](const decompiler_diagnostic_t& current) { return current.localization_key == key; });
}

void require_replaced_failure(const native_worker_execution_result_t& result,
                              native_worker_diagnostic_code_t code, std::string_view fixture)
{
    std::string diagnostic_failure = std::string(fixture) + " did not emit its required host diagnostic";
    for (const auto& diagnostic : result.diagnostics) {
        diagnostic_failure.append("; code=");
        diagnostic_failure.append(std::to_string(static_cast<std::uint16_t>(diagnostic.code)));
        diagnostic_failure.append(" phase=");
        diagnostic_failure.append(diagnostic.phase);
        diagnostic_failure.append(" win32=");
        diagnostic_failure.append(std::to_string(diagnostic.win32_error));
        diagnostic_failure.append(" detail=");
        diagnostic_failure.append(diagnostic.detail);
    }
    require(has_diagnostic(result, code), std::move(diagnostic_failure));
    require(result.worker_process_id != 0 && result.worker_terminated && result.worker_replaced &&
        has_diagnostic(result, native_worker_diagnostic_code_t::worker_replaced),
        std::string(fixture) + " did not terminate and invalidate the worker generation");
}

void host_protocol_fixtures(fixture_workspace_t& workspace, const sha256_digest_t& worker_hash)
{
    std::uint64_t job_id = 1;
    require_replaced_failure(execute_fixture(workspace, worker_hash, "replay", job_id++),
        native_worker_diagnostic_code_t::protocol_replay, "replay fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "truncation", job_id++),
        native_worker_diagnostic_code_t::protocol_truncated, "truncation fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "oversize", job_id++),
        native_worker_diagnostic_code_t::protocol_oversize, "oversize fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "malformed_header", job_id++),
        native_worker_diagnostic_code_t::protocol_malformed, "malformed-header fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "nonce_mismatch", job_id++),
        native_worker_diagnostic_code_t::protocol_nonce_mismatch, "nonce-mismatch fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "hash_mismatch", job_id++),
        native_worker_diagnostic_code_t::worker_identity_mismatch, "hash-mismatch fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "crash", job_id++),
        native_worker_diagnostic_code_t::worker_crashed, "crash fixture");
    const auto hang = execute_fixture(workspace, worker_hash, "hang", job_id++, fixture_execution_t::deadline);
    require(hang.status == native_worker_execution_status_t::deadline_exceeded,
        "hang fixture did not end with deadline status");
    require_replaced_failure(hang, native_worker_diagnostic_code_t::deadline_exceeded, "hang fixture");
    const auto cancelled = execute_fixture(workspace, worker_hash, "cancel", job_id++, fixture_execution_t::cancellation);
    require(cancelled.status == native_worker_execution_status_t::cancelled &&
        has_worker_key(cancelled, "native_worker.fixture.cancelled"),
        "cancel fixture did not preserve the worker cancellation response");
    require_replaced_failure(cancelled, native_worker_diagnostic_code_t::cancelled, "cancel fixture");
    const auto replacement = execute_fixture(workspace, worker_hash, "replacement", job_id++);
    require(replacement.status == native_worker_execution_status_t::failed &&
        has_worker_key(replacement, "native_worker.fixture.replacement"),
        "replacement fixture did not preserve its typed retryable failure");
    require_replaced_failure(replacement, native_worker_diagnostic_code_t::worker_failed, "replacement fixture");
}

void host_containment_fixtures(fixture_workspace_t& workspace, const sha256_digest_t& worker_hash)
{
    const auto network = execute_fixture(workspace, worker_hash, "no_network", 100);
    require(network.status == native_worker_execution_status_t::failed && network.worker_terminated &&
        !network.worker_replaced && has_worker_key(network, "native_worker.fixture.network_denied") &&
        !has_worker_key(network, "native_worker.fixture.network_violation"),
        "network fixture did not prove fail-closed AppContainer network isolation");
    const auto child = execute_fixture(workspace, worker_hash, "child", 101);
    require(child.status == native_worker_execution_status_t::failed && child.worker_terminated &&
        !child.worker_replaced && has_worker_key(child, "native_worker.fixture.child_denied") &&
        !has_worker_key(child, "native_worker.fixture.child_violation"),
        "child fixture did not prove child-process restriction");
    const auto handles = execute_fixture(workspace, worker_hash, "handles", 102);
    require(handles.status == native_worker_execution_status_t::failed && handles.worker_terminated &&
        !handles.worker_replaced && has_worker_key(handles, "native_worker.fixture.handle_capability_denied") &&
        !has_worker_key(handles, "native_worker.fixture.handle_capability_violation"),
        "handle fixture did not prove the inherited-handle and protected-DACL boundary");
}

void fixture_inventory()
{
    constexpr std::array<std::string_view, 13> fixtures{
        "replay", "truncation", "oversize", "malformed_header", "nonce_mismatch", "hash_mismatch", "crash",
        "hang", "cancel", "replacement", "no_network", "child", "handles"
    };
    require(fixtures.size() == 13, "fixture inventory is incomplete");
    for (const auto fixture : fixtures)
        require(!fixture.empty(), "fixture identifier is empty");
}

void result_frame_contracts()
{
    require(runtime::classify_document_payload_size(1) ==
        runtime::document_send_status_t::sent,
        "result-frame classifier rejected a bounded payload");
    require(runtime::classify_document_payload_size(
        k_decompiler_worker_result_frame_max_bytes) ==
        runtime::document_send_status_t::sent,
        "result-frame classifier rejected the exact frame boundary");
    require(runtime::classify_document_payload_size(
        k_decompiler_worker_result_frame_max_bytes + 1U) ==
        runtime::document_send_status_t::resource_limit,
        "result-frame classifier accepted a one-byte-over payload");
    runtime::startup_t unavailable_channel;
    require(!runtime::send_failure(unavailable_channel, 1,
        decompiler_diagnostic_code_t::resource_limit,
        "decompiler.isolated_worker.result_frame_limit"),
        "resource-limit fallback unexpectedly succeeded without an authenticated channel");
}

}

bool run_native_worker_protocol_harness(std::string& failure)
{
    try {
        require(!native_worker_protocol_hash().empty(), "protocol hash is empty");
        manifest_and_snapshot_contracts();
        frame_round_trip_and_replay();
        rejected_header_diagnostics();
        truncation_contract();
        result_frame_contracts();
        fixture_inventory();
        failure.clear();
        return true;
    } catch (const std::exception& error) {
        assertion_telemetry::record_exception(error.what());
        failure = error.what();
        return false;
    } catch (...) {
        assertion_telemetry::record_exception(
            "native worker protocol harness failed with a non-standard exception");
        failure = "native worker protocol harness failed with a non-standard exception";
        return false;
    }
}

bool run_native_worker_host_harness(const native_worker_host_harness_paths_t& paths, std::string& failure)
{
    try {
        require(!paths.fake_worker_path.empty() && !paths.scratch_root.empty(),
            "native worker host harness paths are incomplete");
        fixture_workspace_t workspace(paths.scratch_root, paths.fake_worker_path);
        try {
            const auto worker_hash = file_digest(workspace.worker_path());
            require(!worker_hash.empty(), "staged fake native worker hash is empty");
            host_protocol_fixtures(workspace, worker_hash);
            host_containment_fixtures(workspace, worker_hash);
        } catch (...) {
            if (!workspace.cleanup())
                throw std::runtime_error("native worker scratch workspace failure cleanup failed");
            throw;
        }
        require(workspace.cleanup(), "native worker scratch workspace cleanup failed");
        failure.clear();
        return true;
    } catch (const std::exception& error) {
        assertion_telemetry::record_exception(error.what());
        failure = error.what();
        return false;
    } catch (...) {
        assertion_telemetry::record_exception(
            "native worker host harness failed with a non-standard exception");
        failure = "native worker host harness failed with a non-standard exception";
        return false;
    }
}

}

int main(int argc, char** argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--protocol-only") {
        std::string failure;
        if (!aida::analysis::c03_test::run_native_worker_protocol_harness(failure)) {
            std::cerr << failure << '\n';
            return 1;
        }
        return 0;
    }
    if (argc != 3) {
        aida::analysis::c03_test::assertion_telemetry::record_assertion(false,
            "native worker protocol harness arguments are invalid", __FILE__, __LINE__);
        std::cerr << "usage: native_worker_protocol_harness --protocol-only | <fake-worker> <scratch-root>\n";
        return 2;
    }
    std::string failure;
    if (!aida::analysis::c03_test::run_native_worker_protocol_harness(failure)) {
        std::cerr << failure << '\n';
        return 1;
    }
    aida::analysis::c03_test::native_worker_host_harness_paths_t paths;
    paths.fake_worker_path = std::filesystem::u8path(argv[1]);
    paths.scratch_root = std::filesystem::u8path(argv[2]);
    if (!aida::analysis::c03_test::run_native_worker_host_harness(paths, failure)) {
        std::cerr << failure << '\n';
        return 1;
    }
    return 0;
}
