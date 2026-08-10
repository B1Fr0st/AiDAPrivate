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
#include "working_set_governor.hpp"
#include "../../helpers/diag_log.hpp"
#include "../infra/fast_containers.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kMinimumWindowBytes = 64ULL * 1024ULL;
constexpr std::uint64_t kMaximumWindowBytes = 64ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaximumCacheBytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaximumGlobalMappedBytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kAutoCacheFloorBytes = 256ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kAutoWindowLargeSourceBytes = 256ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kAutoWindowMediumSourceBytes = 64ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kAutoWindowLargeBytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kAutoWindowMediumBytes = 8ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kAutoWindowSmallBytes = 4ULL * 1024ULL * 1024ULL;

std::atomic<std::uint64_t>& adaptive_per_file_ceiling_bytes() noexcept {
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::atomic<std::uint64_t>& adaptive_global_ceiling_bytes() noexcept {
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::atomic<bool>& adaptive_ceiling_claimed() noexcept {
    static std::atomic<bool> value{false};
    return value;
}

std::atomic<bool>& adaptive_ceiling_installed() noexcept {
    static std::atomic<bool> value{false};
    return value;
}

std::wstring create_file_api_path(const std::wstring& normalized) {
    if (normalized.size() < static_cast<std::size_t>(MAX_PATH) ||
        normalized.rfind(L"\\\\?\\", 0) == 0)
        return normalized;
    if (normalized.size() >= 2 && normalized[0] == L'\\' && normalized[1] == L'\\')
        return L"\\\\?\\UNC\\" + normalized.substr(2);
    return L"\\\\?\\" + normalized;
}

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

std::atomic<analysis_metrics_t*>& relay_sink() noexcept {
    static std::atomic<analysis_metrics_t*> sink{nullptr};
    return sink;
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
    const std::wstring api_path = create_file_api_path(wide_result.value());
    HANDLE raw_file = CreateFileW(api_path.c_str(), FILE_READ_ATTRIBUTES,
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
    aida::infra::fast_u64_map<std::shared_ptr<mapped_window_t>> windows;
};

}

namespace provider_metrics_relay {

void attach_analysis_metrics(analysis_metrics_t* metrics) noexcept {
    relay_sink().store(metrics, std::memory_order_release);
}

void detach_analysis_metrics(const analysis_metrics_t* metrics) noexcept {
    analysis_metrics_t* expected = const_cast<analysis_metrics_t*>(metrics);
    relay_sink().compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel,
                                         std::memory_order_acquire);
}

void record_mapped_window_bytes(std::uint64_t bytes) noexcept {
    if (auto* sink = relay_sink().load(std::memory_order_acquire))
        sink->set_max(analysis_metric_t::mapped_window_bytes_peak, bytes);
}

void record_global_mapped_window_bytes(std::uint64_t bytes) noexcept {
    if (auto* sink = relay_sink().load(std::memory_order_acquire))
        sink->set_max(analysis_metric_t::mapped_window_bytes_global_peak, bytes);
}

void record_spill_high_water(std::uint64_t bytes) noexcept {
    if (auto* sink = relay_sink().load(std::memory_order_acquire))
        sink->set_max(analysis_metric_t::spill_bytes_peak, bytes);
}

void record_spill_write(std::uint64_t bytes) noexcept {
    if (auto* sink = relay_sink().load(std::memory_order_acquire))
        sink->add(analysis_metric_t::spill_bytes_written, bytes);
}

void record_spill_read(std::uint64_t bytes) noexcept {
    if (auto* sink = relay_sink().load(std::memory_order_acquire))
        sink->add(analysis_metric_t::spill_bytes_read, bytes);
}

void record_budget_rejection() noexcept {
    if (auto* sink = relay_sink().load(std::memory_order_acquire))
        sink->add(analysis_metric_t::budget_rejections, 1);
}

void record_memory_pressure_event() noexcept {
    if (auto* sink = relay_sink().load(std::memory_order_acquire))
        sink->add(analysis_metric_t::memory_pressure_events, 1);
}

}

struct mapped_window_cache_t::state_t {
    std::shared_ptr<mapping_file_state_t> file;
    mapped_window_cache_options_t options;
    std::vector<std::unique_ptr<window_shard_t>> shards;
    std::atomic<std::uint64_t> reserved_window_bytes{0};
    std::atomic<std::uint64_t> cached_window_bytes{0};
    std::atomic<std::uint64_t> access_sequence{1};
    std::atomic<std::uint64_t> mapped_windows{0};
    std::atomic<std::uint64_t> cache_hits{0};
    std::atomic<std::uint64_t> cache_misses{0};
    std::atomic<std::uint64_t> evictions{0};
    std::atomic<std::uint64_t> lease_count{0};
    std::atomic<std::uint64_t> lease_wait_ns{0};
    std::atomic<std::uint64_t> shard_lock_contention{0};
    std::atomic<std::uint64_t> admission_steals{0};
    std::atomic<std::uint64_t> duplicate_map_races{0};
    std::atomic<std::uint64_t> map_calls{0};
    std::atomic<std::uint64_t> prefetch_warm_issued{0};
    mutable std::mutex pin_mutex;
    mutable aida::infra::fast_u64_map<std::vector<std::shared_ptr<mapped_window_t>>>
        pins;
    mutable std::atomic<std::uint64_t> next_pin_token{1};

    void warm_next_window(std::uint64_t next_start) noexcept {
        if (!options.prefetch_next_window || next_start >= file->identity.size ||
            file->identity.size == 0)
            return;
        const std::uint64_t next_size =
            (std::min)(options.window_bytes, file->identity.size - next_start);
        if (next_size == 0)
            return;
        try {
            auto warmed = acquire_window(next_start, next_size, {});
            if (warmed)
                prefetch_warm_issued.fetch_add(1, std::memory_order_relaxed);
        } catch (...) {
        }
    }

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

    std::unique_lock<std::mutex> contention_lock(window_shard_t& shard) {
        std::unique_lock<std::mutex> lock(shard.mutex, std::try_to_lock);
        if (!lock.owns_lock()) {
            shard_lock_contention.fetch_add(1, std::memory_order_relaxed);
            lock.lock();
        }
        return lock;
    }

    bool evict_one_approx(std::size_t hint_shard) {
        for (;;) {
            std::size_t selected_shard = shards.size();
            std::uint64_t oldest_access = (std::numeric_limits<std::uint64_t>::max)();
            const auto scan_shard = [&](std::size_t index) {
                auto& shard = *shards[index];
                auto lock = contention_lock(shard);
                for (const auto& item : shard.windows) {
                    if (item.second.use_count() != 1 || item.second->last_access >= oldest_access)
                        continue;
                    selected_shard = index;
                    oldest_access = item.second->last_access;
                }
            };
            scan_shard(hint_shard);
            if (selected_shard == shards.size()) {
                for (std::size_t offset = 1; offset < shards.size(); ++offset)
                    scan_shard((hint_shard + offset) % shards.size());
            }
            if (selected_shard == shards.size())
                return false;
            auto& shard = *shards[selected_shard];
            std::shared_ptr<mapped_window_t> retired;
            bool erased = false;
            {
                auto lock = contention_lock(shard);
                std::uint64_t best_access = (std::numeric_limits<std::uint64_t>::max)();
                auto best = shard.windows.end();
                for (auto iterator = shard.windows.begin(); iterator != shard.windows.end();
                     ++iterator) {
                    if (iterator->second.use_count() != 1 ||
                        iterator->second->last_access >= best_access)
                        continue;
                    best = iterator;
                    best_access = iterator->second->last_access;
                }
                if (best != shard.windows.end()) {
                    retired = std::move(best->second);
                    shard.windows.erase(best);
                    erased = true;
                }
            }
            if (!erased)
                continue;
            if (selected_shard != hint_shard)
                admission_steals.fetch_add(1, std::memory_order_relaxed);
            cached_window_bytes.fetch_sub(retired->mapped_size, std::memory_order_acq_rel);
            evictions.fetch_add(1, std::memory_order_relaxed);
            provider_metrics_relay::record_memory_pressure_event();
            return true;
        }
    }

    workspace_result_t<void> reserve_window_bytes(std::uint64_t bytes, std::size_t hint_shard) {
        for (;;) {
            std::uint64_t cached = cached_window_bytes.load(std::memory_order_acquire);
            std::uint64_t reserved = reserved_window_bytes.load(std::memory_order_acquire);
            if (cached <= options.max_cached_window_bytes &&
                reserved <= options.max_cached_window_bytes - cached &&
                bytes <= options.max_cached_window_bytes - cached - reserved) {
                if (reserved_window_bytes.compare_exchange_weak(
                        reserved, reserved + bytes, std::memory_order_acq_rel,
                        std::memory_order_acquire)) {
                    const std::uint64_t cached_now =
                        cached_window_bytes.load(std::memory_order_acquire);
                    if (cached_now <= options.max_cached_window_bytes &&
                        reserved + bytes <= options.max_cached_window_bytes - cached_now)
                        break;
                    reserved_window_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
                } else {
                    continue;
                }
            }
            if (!evict_one_approx(hint_shard)) {
                auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                                  "all mapped windows are pinned",
                                                  "mapped_window_reserve");
                error.size = bytes;
                error.details.emplace_back("cached_window_bytes", std::to_string(cached));
                error.details.emplace_back("max_cached_window_bytes",
                                           std::to_string(options.max_cached_window_bytes));
                provider_metrics_relay::record_budget_rejection();
                return workspace_result_t<void>::failure(std::move(error));
            }
        }
        if (!reserve_global_bytes(bytes, options.max_global_mapped_window_bytes)) {
            reserved_window_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
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
            provider_metrics_relay::record_budget_rejection();
            return workspace_result_t<void>::failure(std::move(error));
        }
        provider_metrics_relay::record_global_mapped_window_bytes(
            global_admitted_window_bytes().load(std::memory_order_acquire));
        return workspace_result_t<void>::success();
    }

    void release_window_reservation(std::uint64_t bytes) noexcept {
        reserved_window_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
        release_global_reservation(bytes);
    }

    workspace_result_t<std::shared_ptr<mapped_window_t>> commit_window(
        std::uint64_t window_start, std::uint64_t bytes,
        std::shared_ptr<mapped_window_t> candidate) {
        auto& shard = *shards[shard_index(window_start)];
        std::lock_guard<std::mutex> shard_lock(shard.mutex);
        const auto existing = shard.windows.find(window_start);
        if (existing != shard.windows.end()) {
            existing->second->last_access = access_sequence.fetch_add(1, std::memory_order_relaxed);
            cache_hits.fetch_add(1, std::memory_order_relaxed);
            duplicate_map_races.fetch_add(1, std::memory_order_relaxed);
            reserved_window_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
            release_global_reservation(bytes);
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::success(existing->second);
        }
        try {
            candidate->last_access = access_sequence.fetch_add(1, std::memory_order_relaxed);
            auto inserted = shard.windows.emplace(window_start, candidate);
            if (!inserted.second) {
                duplicate_map_races.fetch_add(1, std::memory_order_relaxed);
                reserved_window_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
                release_global_reservation(bytes);
                return workspace_result_t<std::shared_ptr<mapped_window_t>>::success(inserted.first->second);
            }
        } catch (const std::bad_alloc&) {
            reserved_window_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
            release_global_reservation(bytes);
            return workspace_result_t<std::shared_ptr<mapped_window_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                                     "mapped-window cache allocation failed", "mapped_window_commit"));
        }
        candidate->globally_accounted = true;
        global_mapped_window_bytes().fetch_add(bytes, std::memory_order_acq_rel);
        cached_window_bytes.fetch_add(bytes, std::memory_order_acq_rel);
        mapped_windows.fetch_add(1, std::memory_order_relaxed);
        reserved_window_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
        commit_global_reservation(bytes);
        provider_metrics_relay::record_mapped_window_bytes(
            cached_window_bytes.load(std::memory_order_acquire));
        provider_metrics_relay::record_global_mapped_window_bytes(
            global_mapped_window_bytes().load(std::memory_order_acquire));
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
        auto reservation = reserve_window_bytes(mapped_size, shard_index(window_start));
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
        map_calls.fetch_add(1, std::memory_order_relaxed);
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
        if (committed) {
            auto& governor = working_set_governor_t::instance();
            governor.note(working_set_metrics::subsystem_t::mapped_windows,
                global_mapped_window_bytes().load(std::memory_order_acquire));
            if (governor.refresh() == governor_zone_t::red)
                (void)trim();
        }
        return committed;
    }

    mapped_window_cache_statistics_t statistics() const noexcept {
        mapped_window_cache_statistics_t result;
        result.source_bytes = file->identity.size;
        result.cached_window_bytes = cached_window_bytes.load(std::memory_order_acquire);
        result.reserved_window_bytes = reserved_window_bytes.load(std::memory_order_acquire);
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
        result.capacity_bytes = options.max_cached_window_bytes;
        result.lease_count = lease_count.load(std::memory_order_relaxed);
        result.lease_wait_ns = lease_wait_ns.load(std::memory_order_relaxed);
        result.shard_lock_contention = shard_lock_contention.load(std::memory_order_relaxed);
        result.admission_steals = admission_steals.load(std::memory_order_relaxed);
        result.duplicate_map_races = duplicate_map_races.load(std::memory_order_relaxed);
        result.map_calls = map_calls.load(std::memory_order_relaxed);
        result.prefetch_warm_issued = prefetch_warm_issued.load(std::memory_order_relaxed);
        for (const auto& shard_ptr : shards) {
            std::lock_guard<std::mutex> lock(shard_ptr->mutex);
            for (const auto& item : shard_ptr->windows)
                if (item.second.use_count() > 1)
                    ++result.pinned_windows;
        }
        return result;
    }

    workspace_result_t<void> trim() {
        for (std::size_t index = 0; index < shards.size(); ++index) {
            for (;;) {
                std::shared_ptr<mapped_window_t> retired;
                {
                    auto& shard = *shards[index];
                    std::lock_guard<std::mutex> lock(shard.mutex);
                    const auto iterator = std::find_if(
                        shard.windows.begin(), shard.windows.end(),
                        [](const std::pair<const std::uint64_t, std::shared_ptr<mapped_window_t>>&
                               item) { return item.second.use_count() == 1; });
                    if (iterator == shard.windows.end())
                        break;
                    retired = std::move(iterator->second);
                    shard.windows.erase(iterator);
                }
                cached_window_bytes.fetch_sub(retired->mapped_size, std::memory_order_acq_rel);
                evictions.fetch_add(1, std::memory_order_relaxed);
            }
        }
        return workspace_result_t<void>::success();
    }
};

void mapped_window_cache_t::set_adaptive_window_ceiling(std::uint64_t per_file_bytes,
                                                        std::uint64_t global_bytes) {
    if (per_file_bytes == 0 || global_bytes == 0) {
        ::diag::log_tagged_fmt("mapped_window_cache",
            "adaptive_window_ceiling rejected per_file=%llu global=%llu reason=zero",
            static_cast<unsigned long long>(per_file_bytes),
            static_cast<unsigned long long>(global_bytes));
        return;
    }
    per_file_bytes = (std::max)(per_file_bytes, kMaximumWindowBytes);
    per_file_bytes = (std::min)(per_file_bytes, kMaximumCacheBytes);
    global_bytes = (std::min)(global_bytes, kMaximumGlobalMappedBytes);
    if (global_bytes < per_file_bytes) {
        ::diag::log_tagged_fmt("mapped_window_cache",
            "adaptive_window_ceiling rejected per_file=%llu global=%llu reason=global_below_per_file",
            static_cast<unsigned long long>(per_file_bytes),
            static_cast<unsigned long long>(global_bytes));
        return;
    }
    bool expected = false;
    if (!adaptive_ceiling_claimed().compare_exchange_strong(
            expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
        ::diag::log_tagged_fmt("mapped_window_cache",
            "adaptive_window_ceiling already installed active_per_file=%llu active_global=%llu ignored_per_file=%llu ignored_global=%llu",
            static_cast<unsigned long long>(
                adaptive_per_file_ceiling_bytes().load(std::memory_order_acquire)),
            static_cast<unsigned long long>(
                adaptive_global_ceiling_bytes().load(std::memory_order_acquire)),
            static_cast<unsigned long long>(per_file_bytes),
            static_cast<unsigned long long>(global_bytes));
        return;
    }
    adaptive_per_file_ceiling_bytes().store(per_file_bytes, std::memory_order_release);
    adaptive_global_ceiling_bytes().store(global_bytes, std::memory_order_release);
    adaptive_ceiling_installed().store(true, std::memory_order_release);
    ::diag::log_tagged_fmt("mapped_window_cache",
        "adaptive_window_ceiling installed per_file=%llu global=%llu",
        static_cast<unsigned long long>(per_file_bytes),
        static_cast<unsigned long long>(global_bytes));
}

workspace_result_t<std::shared_ptr<mapped_window_cache_t>> mapped_window_cache_t::open(
    const std::string& utf8_path, mapped_window_cache_options_t options) {
    if (!is_power_of_two(options.shard_count) || options.shard_count > 64 ||
        options.max_lease_bytes == 0 ||
        options.max_span_windows == 0 ||
        options.max_span_windows > byte_span_storage_t::kMaxSegments ||
        options.max_global_mapped_window_bytes == 0 ||
        options.max_global_mapped_window_bytes > kMaximumGlobalMappedBytes ||
        (options.window_bytes != 0 &&
         (options.window_bytes < kMinimumWindowBytes ||
          options.window_bytes > kMaximumWindowBytes)) ||
        (options.max_cached_window_bytes != 0 &&
         options.max_cached_window_bytes > kMaximumCacheBytes)) {
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
    const std::wstring api_path = create_file_api_path(wide.value());
    HANDLE raw_file = CreateFileW(api_path.c_str(), GENERIC_READ,
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
    if (options.window_bytes == 0) {
        const std::uint64_t source_bytes = identity.value().size;
        options.window_bytes = source_bytes >= kAutoWindowLargeSourceBytes
            ? kAutoWindowLargeBytes
            : source_bytes >= kAutoWindowMediumSourceBytes
                ? kAutoWindowMediumBytes
                : kAutoWindowSmallBytes;
        options.window_bytes = (std::min)(
            (std::max)(options.window_bytes, kMinimumWindowBytes), kMaximumWindowBytes);
    }
    if (options.max_lease_bytes > options.window_bytes)
        options.max_lease_bytes = options.window_bytes;
    if (options.max_cached_window_bytes == 0) {
        const std::uint64_t source_bytes = identity.value().size;
        const std::uint64_t windows = source_bytes / options.window_bytes +
            (source_bytes % options.window_bytes != 0 ? 1ULL : 0ULL);
        const std::uint64_t bounded = (std::min)(windows,
            kMaximumCacheBytes / options.window_bytes);
        options.max_cached_window_bytes = (std::min)(
            (std::max)(bounded * options.window_bytes, kAutoCacheFloorBytes),
            kMaximumCacheBytes);
    }
    if (adaptive_ceiling_installed().load(std::memory_order_acquire)) {
        options.max_cached_window_bytes = (std::min)(
            options.max_cached_window_bytes,
            adaptive_per_file_ceiling_bytes().load(std::memory_order_acquire));
        options.max_global_mapped_window_bytes = (std::min)(
            options.max_global_mapped_window_bytes,
            adaptive_global_ceiling_bytes().load(std::memory_order_acquire));
    }
    if (options.window_bytes > static_cast<std::uint64_t>((std::numeric_limits<SIZE_T>::max)()) ||
        options.max_cached_window_bytes < options.window_bytes ||
        options.max_global_mapped_window_bytes < options.max_cached_window_bytes) {
        return workspace_result_t<std::shared_ptr<mapped_window_cache_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "mapped-window cache options are invalid", "mapped_window_open"));
    }
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

bool mapped_window_cache_t::content_pin_active() const noexcept {
    return state_->file->identity.immutable_snapshot;
}

std::optional<mapped_window_cache_statistics_t>
mapped_window_cache_t::window_cache_statistics() const noexcept {
    return state_->statistics();
}

workspace_result_t<byte_view_t> mapped_window_cache_t::lease(
    std::uint64_t offset, std::uint64_t size_value,
    const cancellation_token_t& cancel) const {
    struct lease_timing_guard_t {
        state_t& state;
        std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
        ~lease_timing_guard_t() {
            const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - started).count();
            state.lease_count.fetch_add(1, std::memory_order_relaxed);
            state.lease_wait_ns.fetch_add(static_cast<std::uint64_t>(elapsed),
                                          std::memory_order_relaxed);
        }
    } timing{*state_};
    if (cancel.stop_requested())
        return workspace_result_t<byte_view_t>::failure(stop_error(cancel, "mapped_window_lease"));
    auto range = validate_span(offset, size_value, size(), "mapped_window_lease");
    if (!range)
        return workspace_result_t<byte_view_t>::failure(range.error());
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
    if (delta > state_->options.window_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "mapped-window lease crosses a cache-window boundary",
                                          "mapped_window_lease");
        error.offset = offset;
        error.size = size_value;
        error.details.emplace_back("window_bytes", std::to_string(state_->options.window_bytes));
        return workspace_result_t<byte_view_t>::failure(std::move(error));
    }
    if (size_value > state_->options.window_bytes - delta) {
        const std::uint64_t window_count =
            (delta + size_value + state_->options.window_bytes - 1ULL) /
            state_->options.window_bytes;
        if (window_count > state_->options.max_span_windows ||
            window_count > byte_span_storage_t::kMaxSegments) {
            auto error = make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "mapped-window lease crosses a cache-window boundary",
                "mapped_window_lease");
            error.offset = offset;
            error.size = size_value;
            error.details.emplace_back("window_bytes",
                                       std::to_string(state_->options.window_bytes));
            error.details.emplace_back("span_windows", std::to_string(window_count));
            error.details.emplace_back("max_span_windows",
                                       std::to_string(state_->options.max_span_windows));
            return workspace_result_t<byte_view_t>::failure(std::move(error));
        }
        std::shared_ptr<byte_span_storage_t> storage;
        try {
            storage = std::make_shared<byte_span_storage_t>();
        } catch (const std::bad_alloc&) {
            return workspace_result_t<byte_view_t>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                                     "mapped-window span allocation failed",
                                     "mapped_window_lease"));
        }
        std::size_t produced = 0;
        std::uint64_t cursor = offset;
        for (std::uint32_t span_index = 0; span_index < window_count; ++span_index) {
            if (cancel.stop_requested())
                return workspace_result_t<byte_view_t>::failure(
                    stop_error(cancel, "mapped_window_lease"));
            const std::uint64_t span_window_start =
                window_start + span_index * state_->options.window_bytes;
            const std::uint64_t span_window_size = (std::min)(
                state_->options.window_bytes, size() - span_window_start);
            auto window = state_->acquire_window(span_window_start, span_window_size, cancel);
            if (!window)
                return workspace_result_t<byte_view_t>::failure(window.error());
            const std::uint64_t inner =
                cursor > span_window_start ? cursor - span_window_start : 0;
            if (inner >= span_window_size)
                break;
            const std::uint64_t available = span_window_size - inner;
            const std::size_t amount = static_cast<std::size_t>((std::min)(
                available, size_value - static_cast<std::uint64_t>(produced)));
            storage->owners[span_index] =
                std::static_pointer_cast<const void>(window.value());
            storage->bases[span_index] =
                static_cast<const std::uint8_t*>(window.value()->base) +
                static_cast<std::size_t>(inner);
            storage->sizes[span_index] = amount;
            produced += amount;
            cursor += amount;
        }
        if (produced != size_value) {
            auto error = make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "mapped-window span lease could not cover its requested range",
                "mapped_window_lease");
            error.offset = offset;
            error.size = size_value;
            return workspace_result_t<byte_view_t>::failure(std::move(error));
        }
        storage->segment_count = static_cast<std::uint32_t>(window_count);
        storage->total_bytes = static_cast<std::size_t>(size_value);
        if (!state_->file->identity.immutable_snapshot) {
            auto valid_after = revalidate();
            if (!valid_after)
                return workspace_result_t<byte_view_t>::failure(valid_after.error());
        }
        state_->warm_next_window(
            window_start + window_count * state_->options.window_bytes);
        return workspace_result_t<byte_view_t>::success(
            byte_view_t(std::static_pointer_cast<const byte_span_storage_t>(
                std::move(storage))));
    }
    if (size_value > state_->options.max_lease_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                          "mapped-window lease exceeds its configured limit",
                                          "mapped_window_lease");
        error.offset = offset;
        error.size = size_value;
        error.details.emplace_back("max_lease_bytes", std::to_string(state_->options.max_lease_bytes));
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
    state_->warm_next_window(window_start + state_->options.window_bytes);
    const auto* bytes = static_cast<const std::uint8_t*>(owner->base) +
                        static_cast<std::size_t>(delta);
    return workspace_result_t<byte_view_t>::success(
        byte_view_t(std::static_pointer_cast<const void>(std::move(owner)), bytes,
                    static_cast<std::size_t>(size_value)));
}

workspace_result_t<std::uint64_t> mapped_window_cache_t::pin_range(
    std::uint64_t file_offset, std::uint64_t size_value, std::uint32_t max_windows,
    const cancellation_token_t& cancel) const {
    if (max_windows == 0 || size_value == 0) {
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "mapped-window pin range is empty", "mapped_window_pin"));
    }
    auto range = validate_span(file_offset, size_value, size(), "mapped_window_pin");
    if (!range)
        return workspace_result_t<std::uint64_t>::failure(range.error());
    const std::uint64_t first_window =
        file_offset - (file_offset % state_->options.window_bytes);
    const std::uint64_t delta = file_offset - first_window;
    const std::uint64_t window_count =
        (delta + size_value + state_->options.window_bytes - 1ULL) /
        state_->options.window_bytes;
    const std::uint32_t pinned_count = static_cast<std::uint32_t>(
        (std::min)(window_count, static_cast<std::uint64_t>(max_windows)));
    std::vector<std::shared_ptr<mapped_window_t>> held;
    held.reserve(pinned_count);
    for (std::uint32_t index = 0; index < pinned_count; ++index) {
        if (cancel.stop_requested())
            return workspace_result_t<std::uint64_t>::failure(
                stop_error(cancel, "mapped_window_pin"));
        const std::uint64_t window_start =
            first_window + index * state_->options.window_bytes;
        if (window_start >= size())
            break;
        const std::uint64_t window_size =
            (std::min)(state_->options.window_bytes, size() - window_start);
        auto window = state_->acquire_window(window_start, window_size, cancel);
        if (!window)
            return workspace_result_t<std::uint64_t>::failure(window.error());
        held.push_back(window.take_value());
    }
    if (held.empty()) {
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::out_of_range,
                                 "mapped-window pin range covers no windows",
                                 "mapped_window_pin"));
    }
    std::uint64_t token = 0;
    for (;;) {
        token = state_->next_pin_token.fetch_add(1, std::memory_order_acq_rel);
        if (token != 0)
            break;
    }
    try {
        std::lock_guard<std::mutex> lock(state_->pin_mutex);
        state_->pins.emplace(token, std::move(held));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::uint64_t>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "mapped-window pin allocation failed", "mapped_window_pin"));
    }
    ::diag::log_tagged_fmt("mapped_window_cache",
        "pin_range token=%llu source='%s' offset=%llu size=%llu windows=%zu pinned_total=%zu",
        static_cast<unsigned long long>(token),
        state_->file->identity.normalized_source.c_str(),
        static_cast<unsigned long long>(file_offset),
        static_cast<unsigned long long>(size_value),
        pinned_count <= static_cast<std::uint32_t>(window_count)
            ? static_cast<std::size_t>(pinned_count)
            : static_cast<std::size_t>(window_count),
        [&] {
            std::lock_guard<std::mutex> lock(state_->pin_mutex);
            return state_->pins.size();
        }());
    return workspace_result_t<std::uint64_t>::success(token);
}

void mapped_window_cache_t::unpin_range(std::uint64_t token) const noexcept {
    if (token == 0)
        return;
    std::size_t remaining = 0;
    {
        std::lock_guard<std::mutex> lock(state_->pin_mutex);
        state_->pins.erase(token);
        remaining = state_->pins.size();
    }
    ::diag::log_tagged_fmt("mapped_window_cache",
        "unpin_range token=%llu source='%s' pinned_total=%zu",
        static_cast<unsigned long long>(token),
        state_->file->identity.normalized_source.c_str(), remaining);
}

workspace_result_t<void> mapped_window_cache_t::trim() {
    return state_->trim();
}

mapped_window_cache_statistics_t mapped_window_cache_t::statistics() const noexcept {
    return state_->statistics();
}

struct delete_on_close_spill_file_t::state_t {
    unique_handle_t file;
    std::uint64_t written_bytes = 0;
    mutable std::mutex io_mutex;
};

delete_on_close_spill_file_t::delete_on_close_spill_file_t(
    std::shared_ptr<state_t> state)
    : state_(std::move(state)) {}

delete_on_close_spill_file_t::~delete_on_close_spill_file_t() = default;

workspace_result_t<std::unique_ptr<delete_on_close_spill_file_t>>
delete_on_close_spill_file_t::create() {
    wchar_t temp_directory[MAX_PATH + 1];
    const auto directory_length =
        GetTempPathW(static_cast<DWORD>(MAX_PATH), temp_directory);
    if (directory_length == 0 || directory_length > MAX_PATH) {
        return workspace_result_t<std::unique_ptr<delete_on_close_spill_file_t>>::failure(
            make_workspace_error(workspace_error_code_t::persistence_failure,
                                 "unable to locate the temporary directory",
                                 "spill_file"));
    }
    wchar_t temp_path[MAX_PATH + 1];
    if (GetTempFileNameW(temp_directory, L"afs", 0, temp_path) == 0) {
        return workspace_result_t<std::unique_ptr<delete_on_close_spill_file_t>>::failure(
            make_workspace_error(workspace_error_code_t::persistence_failure,
                                 "unable to allocate a spill file name",
                                 "spill_file"));
    }
    const std::wstring api_path = create_file_api_path(temp_path);
    HANDLE raw_file = CreateFileW(api_path.c_str(), GENERIC_READ | GENERIC_WRITE,
        0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (raw_file == INVALID_HANDLE_VALUE) {
        return workspace_result_t<std::unique_ptr<delete_on_close_spill_file_t>>::failure(
            make_workspace_error(workspace_error_code_t::persistence_failure,
                                 "unable to create the delete-on-close spill file",
                                 "spill_file"));
    }
    auto state = std::make_shared<state_t>();
    state->file.reset(raw_file);
    state->written_bytes = 0;
    ::diag::log_tagged_fmt("mapped_window_cache", "spill_file_created");
    return workspace_result_t<std::unique_ptr<delete_on_close_spill_file_t>>::success(
        std::unique_ptr<delete_on_close_spill_file_t>(
            new delete_on_close_spill_file_t(std::move(state))));
}

workspace_result_t<void> delete_on_close_spill_file_t::write_at(
    std::uint64_t offset, const std::uint8_t* data, std::size_t size) {
    if (!state_ || !state_->file.get() || (!data && size != 0)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "spill file write received an invalid range",
                                 "spill_file"));
    }
    std::size_t written_total = 0;
    while (written_total < size) {
        const auto chunk = static_cast<DWORD>((std::min)(
            size - written_total, static_cast<std::size_t>(1ULL << 30)));
        OVERLAPPED overlapped{};
        overlapped.Offset = static_cast<DWORD>(offset & 0xFFFFFFFFULL);
        overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32U);
        DWORD written = 0;
        if (!WriteFile(state_->file.get(), data + written_total, chunk, &written,
                       &overlapped) || written != chunk) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::persistence_failure,
                                     "spill file write failed", "spill_file"));
        }
        written_total += written;
        offset += written;
    }
    std::lock_guard<std::mutex> lock(state_->io_mutex);
    const auto end = offset;
    if (end > state_->written_bytes)
        state_->written_bytes = end;
    provider_metrics_relay::record_spill_write(size);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> delete_on_close_spill_file_t::read_at(
    std::uint64_t offset, std::uint8_t* data, std::size_t size) const {
    if (!state_ || !state_->file.get() || (!data && size != 0)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "spill file read received an invalid range",
                                 "spill_file"));
    }
    if (offset > state_->written_bytes || size > state_->written_bytes - offset) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "spill file read exceeds the written range",
                                 "spill_file"));
    }
    std::size_t read_total = 0;
    while (read_total < size) {
        const auto chunk = static_cast<DWORD>((std::min)(
            size - read_total, static_cast<std::size_t>(1ULL << 30)));
        OVERLAPPED overlapped{};
        overlapped.Offset = static_cast<DWORD>(offset & 0xFFFFFFFFULL);
        overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32U);
        DWORD read_count = 0;
        if (!ReadFile(state_->file.get(), data + read_total, chunk, &read_count,
                      &overlapped) || read_count != chunk) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::persistence_failure,
                                     "spill file read failed", "spill_file"));
        }
        read_total += read_count;
        offset += read_count;
    }
    provider_metrics_relay::record_spill_read(size);
    return workspace_result_t<void>::success();
}

std::uint64_t delete_on_close_spill_file_t::written_bytes() const noexcept {
    return state_ ? state_->written_bytes : 0;
}

}
