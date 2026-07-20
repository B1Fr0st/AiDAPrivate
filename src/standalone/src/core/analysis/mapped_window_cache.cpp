#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "mapped_window_cache.hpp"

#include "workspace/checked_range.hpp"
#include "workspace/workspace_identity.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kMinimumWindowBytes = 64ULL * 1024ULL;
constexpr std::uint64_t kMaximumWindowBytes = 64ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaximumCacheBytes = 1024ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaximumGlobalMappedBytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;

struct handle_closer_t {
    void operator()(void* value) const noexcept {
        if (value && value != INVALID_HANDLE_VALUE)
            CloseHandle(static_cast<HANDLE>(value));
    }
};

using unique_handle_t = std::unique_ptr<void, handle_closer_t>;

struct mapping_file_state_t {
    unique_handle_t file;
    unique_handle_t mapping;
    byte_provider_identity_t identity;
};

std::atomic<std::uint64_t>& global_mapped_window_bytes() noexcept {
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::atomic<std::uint64_t>& global_reserved_window_bytes() noexcept {
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::atomic<std::uint64_t>& global_admitted_window_bytes() noexcept {
    static std::atomic<std::uint64_t> value{0};
    return value;
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

workspace_result_t<std::wstring> utf8_to_wide(const std::string& text) {
    if (text.empty() || text.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        return workspace_result_t<std::wstring>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "source path length is invalid", "mapped_window_open"));
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                             static_cast<int>(text.size()), nullptr, 0);
    if (required <= 0) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "source path is not valid UTF-8", "mapped_window_open");
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), result.data(), required) != required) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                                          "source path conversion failed", "mapped_window_open");
        error.win32_status = GetLastError();
        return workspace_result_t<std::wstring>::failure(std::move(error));
    }
    return workspace_result_t<std::wstring>::success(std::move(result));
}

workspace_result_t<byte_provider_identity_t> query_identity(HANDLE file,
                                                            const std::string& source,
                                                            const char* phase) {
    FILE_STANDARD_INFO standard{};
    if (!GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard))) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to query source size", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<byte_provider_identity_t>::failure(std::move(error));
    }
    if (standard.Directory || standard.EndOfFile.QuadPart < 0)
        return workspace_result_t<byte_provider_identity_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "source is not a regular file", phase));
    FILE_BASIC_INFO basic{};
    if (!GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic))) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to query source timestamps", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<byte_provider_identity_t>::failure(std::move(error));
    }
    FILE_ID_INFO id_info{};
    if (!GetFileInformationByHandleEx(file, FileIdInfo, &id_info, sizeof(id_info))) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to query source file identity", phase);
        error.win32_status = GetLastError();
        return workspace_result_t<byte_provider_identity_t>::failure(std::move(error));
    }
    byte_provider_identity_t identity;
    identity.normalized_source = source;
    identity.size = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    identity.volume_serial = id_info.VolumeSerialNumber;
    std::memcpy(identity.file_id.data(), id_info.FileId.Identifier, identity.file_id.size());
    identity.last_write_time_100ns = static_cast<std::uint64_t>(basic.LastWriteTime.QuadPart);
    return workspace_result_t<byte_provider_identity_t>::success(std::move(identity));
}

workspace_result_t<byte_provider_identity_t> query_current_path_identity(
    const std::string& source, const char* phase) {
    auto wide_result = utf8_to_wide(source);
    if (!wide_result)
        return workspace_result_t<byte_provider_identity_t>::failure(wide_result.error());
    HANDLE raw_file = CreateFileW(wide_result.value().c_str(), FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (raw_file == INVALID_HANDLE_VALUE) {
        auto error = make_workspace_error(workspace_error_code_t::file_changed,
                                          "source path is no longer available", phase);
        error.win32_status = GetLastError();
        error.details.emplace_back("source", source);
        return workspace_result_t<byte_provider_identity_t>::failure(std::move(error));
    }
    unique_handle_t file(raw_file);
    auto identity = query_identity(raw_file, source, phase);
    if (!identity)
        return identity;
    return identity;
}

bool same_identity(const byte_provider_identity_t& lhs,
                   const byte_provider_identity_t& rhs) noexcept {
    return lhs.normalized_source == rhs.normalized_source && lhs.size == rhs.size &&
           lhs.volume_serial == rhs.volume_serial && lhs.file_id == rhs.file_id &&
           lhs.last_write_time_100ns == rhs.last_write_time_100ns;
}

bool is_power_of_two(std::uint32_t value) noexcept {
    return value != 0 && (value & (value - 1U)) == 0;
}

bool reserve_global_bytes(std::uint64_t bytes, std::uint64_t limit) noexcept {
    auto& admitted = global_admitted_window_bytes();
    auto& reserved = global_reserved_window_bytes();
    std::uint64_t admitted_now = admitted.load(std::memory_order_acquire);
    for (;;) {
        if (admitted_now > limit || bytes > limit - admitted_now)
            return false;
        if (admitted.compare_exchange_weak(admitted_now, admitted_now + bytes,
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire)) {
            reserved.fetch_add(bytes, std::memory_order_acq_rel);
            return true;
        }
    }
}

void release_global_reservation(std::uint64_t bytes) noexcept {
    global_reserved_window_bytes().fetch_sub(bytes, std::memory_order_acq_rel);
    global_admitted_window_bytes().fetch_sub(bytes, std::memory_order_acq_rel);
}

void commit_global_reservation(std::uint64_t bytes) noexcept {
    global_reserved_window_bytes().fetch_sub(bytes, std::memory_order_acq_rel);
}

struct mapped_window_t {
    std::shared_ptr<const mapping_file_state_t> file;
    void* base = nullptr;
    std::uint64_t start = 0;
    std::uint64_t mapped_size = 0;
    std::uint64_t last_access = 0;
    bool globally_accounted = false;

    ~mapped_window_t() {
        if (base)
            UnmapViewOfFile(base);
        if (globally_accounted) {
            global_mapped_window_bytes().fetch_sub(mapped_size, std::memory_order_acq_rel);
            global_admitted_window_bytes().fetch_sub(mapped_size, std::memory_order_acq_rel);
        }
    }
};

struct window_shard_t {
    std::mutex mutex;
    std::unordered_map<std::uint64_t, std::shared_ptr<mapped_window_t>> windows;
};

}

struct mapped_window_cache_t::state_t {
    std::shared_ptr<mapping_file_state_t> file;
    mapped_window_cache_options_t options;
    std::vector<std::unique_ptr<window_shard_t>> shards;
    mutable std::mutex admission_mutex;
    std::uint64_t reserved_window_bytes = 0;
    std::atomic<std::uint64_t> cached_window_bytes{0};
    std::atomic<std::uint64_t> access_sequence{1};
    std::atomic<std::uint64_t> mapped_windows{0};
    std::atomic<std::uint64_t> cache_hits{0};
    std::atomic<std::uint64_t> cache_misses{0};
    std::atomic<std::uint64_t> evictions{0};

    std::size_t shard_index(std::uint64_t window_start) const noexcept {
        const std::uint64_t ordinal = window_start / options.window_bytes;
        return static_cast<std::size_t>(ordinal & (options.shard_count - 1U));
    }

    workspace_result_t<void> revalidate() const {
        auto current = query_current_path_identity(file->identity.normalized_source,
                                                   "mapped_window_revalidate");
        if (!current)
            return workspace_result_t<void>::failure(current.error());
        if (!same_identity(file->identity, current.value())) {
            auto error = make_workspace_error(workspace_error_code_t::file_changed,
                                              "mapped source identity changed",
                                              "mapped_window_revalidate");
            error.details.emplace_back("source", file->identity.normalized_source);
            return workspace_result_t<void>::failure(std::move(error));
        }
        return workspace_result_t<void>::success();
    }

    std::shared_ptr<mapped_window_t> find_window(std::uint64_t window_start) {
        auto& shard = *shards[shard_index(window_start)];
        std::lock_guard<std::mutex> lock(shard.mutex);
        const auto iterator = shard.windows.find(window_start);
        if (iterator == shard.windows.end())
            return {};
        iterator->second->last_access = access_sequence.fetch_add(1, std::memory_order_relaxed);
        cache_hits.fetch_add(1, std::memory_order_relaxed);
        return iterator->second;
    }

    bool evict_one() {
        std::size_t selected_shard = shards.size();
        std::uint64_t selected_start = 0;
        std::uint64_t oldest_access = (std::numeric_limits<std::uint64_t>::max)();
        for (std::size_t index = 0; index < shards.size(); ++index) {
            auto& shard = *shards[index];
            std::lock_guard<std::mutex> lock(shard.mutex);
            for (const auto& item : shard.windows) {
                if (item.second.use_count() != 1 || item.second->last_access >= oldest_access)
                    continue;
                selected_shard = index;
                selected_start = item.first;
                oldest_access = item.second->last_access;
            }
        }
        if (selected_shard == shards.size())
            return false;
        std::shared_ptr<mapped_window_t> retired;
        {
            auto& shard = *shards[selected_shard];
            std::lock_guard<std::mutex> lock(shard.mutex);
            const auto iterator = shard.windows.find(selected_start);
            if (iterator == shard.windows.end() || iterator->second.use_count() != 1)
                return false;
            retired = std::move(iterator->second);
            shard.windows.erase(iterator);
        }
        cached_window_bytes.fetch_sub(retired->mapped_size, std::memory_order_acq_rel);
        evictions.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    workspace_result_t<void> reserve_window_bytes(std::uint64_t bytes) {
        std::unique_lock<std::mutex> admission(admission_mutex);
        for (;;) {
            const std::uint64_t cached = cached_window_bytes.load(std::memory_order_acquire);
            if (cached <= options.max_cached_window_bytes &&
                reserved_window_bytes <= options.max_cached_window_bytes - cached &&
                bytes <= options.max_cached_window_bytes - cached - reserved_window_bytes)
                break;
            if (!evict_one()) {
                auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                                  "all mapped windows are pinned",
                                                  "mapped_window_reserve");
                error.size = bytes;
                error.details.emplace_back("cached_window_bytes", std::to_string(cached));
                error.details.emplace_back("max_cached_window_bytes",
                                           std::to_string(options.max_cached_window_bytes));
                return workspace_result_t<void>::failure(std::move(error));
            }
        }
        if (!reserve_global_bytes(bytes, options.max_global_mapped_window_bytes)) {
            auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                              "global mapped-window capacity is exhausted",
                                              "mapped_window_reserve");
            error.size = bytes;
            error.details.emplace_back("global_mapped_window_bytes",
                std::to_string(global_mapped_window_bytes().load(std::memory_order_acquire)));
            error.details.emplace_back("global_reserved_window_bytes",
                std::to_string(global_reserved_window_bytes().load(std::memory_order_acquire)));
            error.details.emplace_back("global_admitted_window_bytes",
                std::to_string(global_admitted_window_bytes().load(std::memory_order_acquire)));
            error.details.emplace_back("max_global_mapped_window_bytes",
                                       std::to_string(options.max_global_mapped_window_bytes));
            return workspace_result_t<void>::failure(std::move(error));
        }
        reserved_window_bytes += bytes;
        return workspace_result_t<void>::success();
    }

    void release_window_reservation(std::uint64_t bytes) noexcept {
        std::lock_guard<std::mutex> admission(admission_mutex);
        reserved_window_bytes -= bytes;
        release_global_reservation(bytes);
    }

    workspace_result_t<std::shared_ptr<mapped_window_t>> commit_window(
        std::uint64_t window_start, std::uint64_t bytes,
        std::shared_ptr<mapped_window_t> candidate) {
        std::lock_guard<std::mutex> admission(admission_mutex);
        auto& shard = *shards[shard_index(window_start)];
        std::lock_guard<std::mutex> shard_lock(shard.mutex);
        const auto existing = shard.windows.find(window_start);
        if (existing != shard.windows.end()) {
            existing->second->last_access = access_sequence.fetch_add(1, std::memory_order_relaxed);
            cache_hits.fetch_add(1, std::memory_order_relaxed);
            reserved_window_bytes -= bytes;
            release_global_reservation(bytes);
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::success(existing->second);
        }
        try {
            candidate->last_access = access_sequence.fetch_add(1, std::memory_order_relaxed);
            auto inserted = shard.windows.emplace(window_start, candidate);
            if (!inserted.second) {
                reserved_window_bytes -= bytes;
                release_global_reservation(bytes);
                return workspace_result_t<std::shared_ptr<mapped_window_t>>::success(inserted.first->second);
            }
        } catch (const std::bad_alloc&) {
            reserved_window_bytes -= bytes;
            release_global_reservation(bytes);
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                                     "mapped-window cache allocation failed", "mapped_window_commit"));
        }
        candidate->globally_accounted = true;
        global_mapped_window_bytes().fetch_add(bytes, std::memory_order_acq_rel);
        cached_window_bytes.fetch_add(bytes, std::memory_order_acq_rel);
        mapped_windows.fetch_add(1, std::memory_order_relaxed);
        reserved_window_bytes -= bytes;
        commit_global_reservation(bytes);
        return workspace_result_t<std::shared_ptr<mapped_window_t>>::success(std::move(candidate));
    }

    workspace_result_t<std::shared_ptr<mapped_window_t>> acquire_window(
        std::uint64_t window_start, std::uint64_t mapped_size,
        const cancellation_token_t& cancel) {
        if (auto existing = find_window(window_start))
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::success(std::move(existing));
        cache_misses.fetch_add(1, std::memory_order_relaxed);
        if (!file->identity.immutable_snapshot) {
            auto valid_before = revalidate();
            if (!valid_before)
                return workspace_result_t<std::shared_ptr<mapped_window_t>>::failure(valid_before.error());
        }
        if (cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::failure(
                stop_error(cancel, "mapped_window_lease"));
        auto reservation = reserve_window_bytes(mapped_size);
        if (!reservation)
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::failure(reservation.error());
        bool reservation_held = true;
        const auto release_reservation = [&]() {
            if (reservation_held) {
                release_window_reservation(mapped_size);
                reservation_held = false;
            }
        };
        if (cancel.stop_requested()) {
            release_reservation();
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::failure(
                stop_error(cancel, "mapped_window_lease"));
        }
        const DWORD high = static_cast<DWORD>(window_start >> 32U);
        const DWORD low = static_cast<DWORD>(window_start & 0xffffffffULL);
        void* mapped = MapViewOfFile(static_cast<HANDLE>(file->mapping.get()), FILE_MAP_READ,
                                     high, low, static_cast<SIZE_T>(mapped_size));
        if (!mapped) {
            auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                              "failed to map source window", "mapped_window_lease");
            error.offset = window_start;
            error.size = mapped_size;
            error.win32_status = GetLastError();
            release_reservation();
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::failure(std::move(error));
        }
        std::shared_ptr<mapped_window_t> candidate;
        try {
            candidate = std::make_shared<mapped_window_t>();
            candidate->file = file;
            candidate->base = mapped;
            candidate->start = window_start;
            candidate->mapped_size = mapped_size;
        } catch (const std::bad_alloc&) {
            UnmapViewOfFile(mapped);
            release_reservation();
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                                     "mapped-window allocation failed", "mapped_window_lease"));
        }
        if (cancel.stop_requested()) {
            release_reservation();
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::failure(
                stop_error(cancel, "mapped_window_lease"));
        }
        if (!file->identity.immutable_snapshot) {
            auto valid_after = revalidate();
            if (!valid_after) {
                release_reservation();
                return workspace_result_t<std::shared_ptr<mapped_window_t>>::failure(valid_after.error());
            }
        }
        auto committed = commit_window(window_start, mapped_size, std::move(candidate));
        reservation_held = false;
        return committed;
    }

    mapped_window_cache_statistics_t statistics() const noexcept {
        mapped_window_cache_statistics_t result;
        result.source_bytes = file->identity.size;
        {
            std::lock_guard<std::mutex> admission(admission_mutex);
            result.cached_window_bytes = cached_window_bytes.load(std::memory_order_acquire);
            result.reserved_window_bytes = reserved_window_bytes;
        }
        result.global_mapped_window_bytes =
            global_mapped_window_bytes().load(std::memory_order_acquire);
        result.global_reserved_window_bytes =
            global_reserved_window_bytes().load(std::memory_order_acquire);
        result.global_admitted_window_bytes =
            global_admitted_window_bytes().load(std::memory_order_acquire);
        result.mapped_windows = mapped_windows.load(std::memory_order_relaxed);
        result.cache_hits = cache_hits.load(std::memory_order_relaxed);
        result.cache_misses = cache_misses.load(std::memory_order_relaxed);
        result.evictions = evictions.load(std::memory_order_relaxed);
        for (const auto& shard_ptr : shards) {
            std::lock_guard<std::mutex> lock(shard_ptr->mutex);
            for (const auto& item : shard_ptr->windows)
                if (item.second.use_count() > 1)
                    ++result.pinned_windows;
        }
        return result;
    }

    workspace_result_t<void> trim() {
        std::unique_lock<std::mutex> admission(admission_mutex);
        while (evict_one()) {
        }
        return workspace_result_t<void>::success();
    }
};

workspace_result_t<std::shared_ptr<mapped_window_cache_t>> mapped_window_cache_t::open(
    const std::string& utf8_path, mapped_window_cache_options_t options) {
    if (!is_power_of_two(options.shard_count) || options.shard_count > 64 ||
        options.window_bytes < kMinimumWindowBytes || options.window_bytes > kMaximumWindowBytes ||
        options.max_lease_bytes == 0 || options.max_lease_bytes > options.window_bytes ||
        options.max_cached_window_bytes < options.window_bytes ||
        options.max_cached_window_bytes > kMaximumCacheBytes ||
        options.max_global_mapped_window_bytes < options.max_cached_window_bytes ||
        options.max_global_mapped_window_bytes > kMaximumGlobalMappedBytes ||
        options.window_bytes > static_cast<std::uint64_t>((std::numeric_limits<SIZE_T>::max)())) {
        return workspace_result_t<std::shared_ptr<mapped_window_cache_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "mapped-window cache options are invalid", "mapped_window_open"));
    }
    auto normalized = normalize_utf8_path(utf8_path, true);
    if (!normalized)
        return workspace_result_t<std::shared_ptr<mapped_window_cache_t>>::failure(normalized.error());
    auto wide = utf8_to_wide(normalized.value());
    if (!wide)
        return workspace_result_t<std::shared_ptr<mapped_window_cache_t>>::failure(wide.error());
    const DWORD share_mode = options.immutable_source
        ? FILE_SHARE_READ
        : FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    HANDLE raw_file = CreateFileW(wide.value().c_str(), GENERIC_READ,
                                  share_mode, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
    if (raw_file == INVALID_HANDLE_VALUE) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "failed to open mapped-window source", "mapped_window_open");
        error.win32_status = GetLastError();
        return workspace_result_t<std::shared_ptr<mapped_window_cache_t>>::failure(std::move(error));
    }
    unique_handle_t file(raw_file);
    auto identity = query_identity(raw_file, normalized.value(), "mapped_window_open");
    if (!identity)
        return workspace_result_t<std::shared_ptr<mapped_window_cache_t>>::failure(identity.error());
    identity.value().immutable_snapshot = options.immutable_source;
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    if (system_info.dwAllocationGranularity == 0 ||
        options.window_bytes % system_info.dwAllocationGranularity != 0) {
        return workspace_result_t<std::shared_ptr<mapped_window_cache_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "mapped-window size is not allocation-granularity aligned",
                                 "mapped_window_open"));
    }
    unique_handle_t mapping;
    if (identity.value().size != 0) {
        HANDLE raw_mapping = CreateFileMappingW(raw_file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!raw_mapping) {
            auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                              "failed to create mapped-window file mapping",
                                              "mapped_window_open");
            error.win32_status = GetLastError();
            return workspace_result_t<std::shared_ptr<mapped_window_cache_t>>::failure(std::move(error));
        }
        mapping.reset(raw_mapping);
    }
    try {
        auto file_state = std::make_shared<mapping_file_state_t>();
        file_state->file = std::move(file);
        file_state->mapping = std::move(mapping);
        file_state->identity = identity.take_value();
        auto state = std::make_shared<state_t>();
        state->file = std::move(file_state);
        state->options = options;
        state->shards.reserve(options.shard_count);
        for (std::uint32_t index = 0; index < options.shard_count; ++index)
            state->shards.push_back(std::make_unique<window_shard_t>());
        return workspace_result_t<std::shared_ptr<mapped_window_cache_t>>::success(
            std::shared_ptr<mapped_window_cache_t>(new mapped_window_cache_t(std::move(state))));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<mapped_window_cache_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "mapped-window cache allocation failed", "mapped_window_open"));
    }
}

mapped_window_cache_t::mapped_window_cache_t(std::shared_ptr<state_t> state)
    : state_(std::move(state)) {}

mapped_window_cache_t::~mapped_window_cache_t() = default;

const byte_provider_identity_t& mapped_window_cache_t::identity() const noexcept {
    return state_->file->identity;
}

std::uint64_t mapped_window_cache_t::size() const noexcept {
    return state_->file->identity.size;
}

std::uint64_t mapped_window_cache_t::maximum_contiguous_lease(std::uint64_t offset) const noexcept {
    const std::uint64_t source_size = size();
    if (offset >= source_size)
        return 0;
    const std::uint64_t offset_in_window = offset % state_->options.window_bytes;
    return (std::min)((std::min)(source_size - offset,
                                 state_->options.window_bytes - offset_in_window),
                      state_->options.max_lease_bytes);
}

workspace_result_t<void> mapped_window_cache_t::revalidate() const {
    return state_->revalidate();
}

workspace_result_t<byte_view_t> mapped_window_cache_t::lease(
    std::uint64_t offset, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    if (cancel.stop_requested())
        return workspace_result_t<byte_view_t>::failure(stop_error(cancel, "mapped_window_lease"));
    auto range = validate_span(offset, size_value, size(), "mapped_window_lease");
    if (!range)
        return workspace_result_t<byte_view_t>::failure(range.error());
    if (size_value > state_->options.max_lease_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "mapped-window lease exceeds its configured limit",
                                          "mapped_window_lease");
        error.offset = offset;
        error.size = size_value;
        error.details.emplace_back("max_lease_bytes", std::to_string(state_->options.max_lease_bytes));
        return workspace_result_t<byte_view_t>::failure(std::move(error));
    }
    if (!state_->file->identity.immutable_snapshot) {
        auto valid_before = revalidate();
        if (!valid_before)
            return workspace_result_t<byte_view_t>::failure(valid_before.error());
    }
    if (size_value == 0)
        return workspace_result_t<byte_view_t>::success(
            byte_view_t(std::static_pointer_cast<const void>(state_->file), nullptr, 0));
    const std::uint64_t window_start = offset - (offset % state_->options.window_bytes);
    const std::uint64_t delta = offset - window_start;
    if (delta > state_->options.window_bytes ||
        size_value > state_->options.window_bytes - delta) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "mapped-window lease crosses a cache-window boundary",
                                          "mapped_window_lease");
        error.offset = offset;
        error.size = size_value;
        error.details.emplace_back("window_bytes", std::to_string(state_->options.window_bytes));
        return workspace_result_t<byte_view_t>::failure(std::move(error));
    }
    const std::uint64_t window_size = (std::min)(state_->options.window_bytes, size() - window_start);
    auto window = state_->acquire_window(window_start, window_size, cancel);
    if (!window)
        return workspace_result_t<byte_view_t>::failure(window.error());
    if (!state_->file->identity.immutable_snapshot) {
        auto valid_after = revalidate();
        if (!valid_after)
            return workspace_result_t<byte_view_t>::failure(valid_after.error());
    }
    auto owner = window.take_value();
    const auto* bytes = static_cast<const std::uint8_t*>(owner->base) +
                        static_cast<std::size_t>(delta);
    return workspace_result_t<byte_view_t>::success(
        byte_view_t(std::static_pointer_cast<const void>(std::move(owner)), bytes,
                    static_cast<std::size_t>(size_value)));
}

workspace_result_t<void> mapped_window_cache_t::trim() {
    return state_->trim();
}

mapped_window_cache_statistics_t mapped_window_cache_t::statistics() const noexcept {
    return state_->statistics();
}

}
