#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "../workspace/workspace_types.hpp"
#include "../../../helpers/diag_log.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>

namespace aida::analysis {

class generation_snapshot_store_t final {
public:
    struct entry_t {
        std::uint64_t generation = 0;
        sha256_digest_t snapshot_hash;
        std::shared_ptr<const std::vector<std::uint8_t>> bytes;
        void* mapping_handle = nullptr;
        std::uint64_t mapping_size = 0;
        std::uint64_t publish_tick = 0;
        mutable std::atomic<std::uint32_t> pins{0};

        entry_t() = default;
        entry_t(const entry_t&) = delete;
        entry_t& operator=(const entry_t&) = delete;
        ~entry_t()
        {
            if (mapping_handle)
                CloseHandle(static_cast<HANDLE>(mapping_handle));
        }
    };

    static generation_snapshot_store_t& instance() noexcept
    {
        static generation_snapshot_store_t store;
        return store;
    }

    std::shared_ptr<const entry_t> publish(
        std::uint64_t generation,
        const sha256_digest_t& snapshot_hash,
        const std::shared_ptr<const std::vector<std::uint8_t>>& bytes)
    {
        auto entry = create_entry(generation, snapshot_hash, bytes);
        if (!entry)
            return nullptr;
        std::lock_guard lock(mutex_);
        entry->publish_tick = ++next_tick_;
        for (std::size_t index = 0; index < entries_.size(); ++index) {
            const auto& existing = entries_[index];
            if (existing && existing->snapshot_hash.constant_time_equal(snapshot_hash) &&
                existing->pins.load(std::memory_order_acquire) == 0) {
                diag::log_tagged_fmt("dec_batch",
                    "generation_snapshot_replaced generation=%llu bytes=%llu",
                    static_cast<unsigned long long>(generation),
                    static_cast<unsigned long long>(bytes->size()));
                entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(index));
                break;
            }
        }
        entries_.push_back(entry);
        evict_unpinned_locked();
        diag::log_tagged_fmt("dec_batch",
            "generation_snapshot_published generation=%llu bytes=%llu entries=%zu shared=1",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long long>(bytes->size()),
            entries_.size());
        return entry;
    }

    std::shared_ptr<const entry_t> publish_pinned(
        std::uint64_t generation,
        const sha256_digest_t& snapshot_hash,
        const std::shared_ptr<const std::vector<std::uint8_t>>& bytes)
    {
        auto entry = create_entry(generation, snapshot_hash, bytes);
        if (!entry)
            return nullptr;
        std::lock_guard lock(mutex_);
        for (const auto& existing : entries_) {
            if (existing && existing->snapshot_hash.constant_time_equal(snapshot_hash)) {
                const std::uint32_t pins = existing->pins.fetch_add(1, std::memory_order_acq_rel) + 1;
                diag::log_tagged_fmt("dec_batch",
                    "generation_snapshot_pinned generation=%llu bytes=%llu pins=%u shared=1",
                    static_cast<unsigned long long>(existing->generation),
                    static_cast<unsigned long long>(existing->mapping_size), pins);
                return existing;
            }
        }
        entry->pins.store(1, std::memory_order_release);
        entry->publish_tick = ++next_tick_;
        entries_.push_back(entry);
        evict_unpinned_locked();
        if (entries_.size() > k_max_entries) {
            for (auto iterator = entries_.begin(); iterator != entries_.end(); ++iterator) {
                if (iterator->get() == entry.get()) {
                    entries_.erase(iterator);
                    break;
                }
            }
            const std::uint64_t mapping_size = entry->mapping_size;
            diag::log_tagged_fmt("dec_batch",
                "generation_snapshot_pinned_rejected generation=%llu bytes=%llu",
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long long>(mapping_size));
            return nullptr;
        }
        diag::log_tagged_fmt("dec_batch",
            "generation_snapshot_published generation=%llu bytes=%llu entries=%zu shared=1 pinned=1",
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long long>(bytes->size()),
            entries_.size());
        return entry;
    }

    void unpin(const std::shared_ptr<const entry_t>& entry) noexcept
    {
        if (!entry)
            return;
        try {
            std::lock_guard lock(mutex_);
            std::uint32_t pins = entry->pins.load(std::memory_order_acquire);
            if (pins != 0)
                pins = entry->pins.fetch_sub(1, std::memory_order_acq_rel) - 1;
            diag::log_tagged_fmt("dec_batch",
                "generation_snapshot_unpinned generation=%llu bytes=%llu pins=%u",
                static_cast<unsigned long long>(entry->generation),
                static_cast<unsigned long long>(entry->mapping_size), pins);
        } catch (...) {
        }
    }

    std::shared_ptr<const entry_t> find(
        std::uint64_t generation,
        const sha256_digest_t& snapshot_hash) const
    {
        if (snapshot_hash.empty())
            return nullptr;
        std::lock_guard lock(mutex_);
        for (const auto& entry : entries_) {
            if (entry && entry->generation == generation &&
                entry->snapshot_hash.constant_time_equal(snapshot_hash))
                return entry;
        }
        for (const auto& entry : entries_) {
            if (entry && entry->snapshot_hash.constant_time_equal(snapshot_hash))
                return entry;
        }
        return nullptr;
    }

private:
    static constexpr std::size_t k_max_entries = 4;
    static constexpr std::size_t k_max_unpinned_entries = 2;
    static constexpr std::uint64_t k_max_entry_bytes = 1ULL << 30;

    generation_snapshot_store_t() = default;
    ~generation_snapshot_store_t() = default;
    generation_snapshot_store_t(const generation_snapshot_store_t&) = delete;
    generation_snapshot_store_t& operator=(const generation_snapshot_store_t&) = delete;

    std::shared_ptr<entry_t> create_entry(
        std::uint64_t generation,
        const sha256_digest_t& snapshot_hash,
        const std::shared_ptr<const std::vector<std::uint8_t>>& bytes)
    {
        if (!bytes || bytes->empty() || snapshot_hash.empty() ||
            bytes->size() > k_max_entry_bytes)
            return nullptr;
        auto entry = std::make_shared<entry_t>();
        entry->generation = generation;
        entry->snapshot_hash = snapshot_hash;
        entry->bytes = bytes;
        entry->mapping_size = bytes->size();
        HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
            static_cast<DWORD>(bytes->size() >> 32U),
            static_cast<DWORD>(bytes->size() & 0xFFFFFFFFU), nullptr);
        if (!mapping) {
            diag::log_tagged_fmt("dec_batch",
                "generation_snapshot_mapping_failed gle=%lu bytes=%llu",
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(bytes->size()));
            return nullptr;
        }
        void* view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, bytes->size());
        if (!view) {
            const DWORD error = GetLastError();
            CloseHandle(mapping);
            diag::log_tagged_fmt("dec_batch",
                "generation_snapshot_mapview_failed gle=%lu bytes=%llu",
                static_cast<unsigned long>(error),
                static_cast<unsigned long long>(bytes->size()));
            return nullptr;
        }
        std::memcpy(view, bytes->data(), bytes->size());
        if (!UnmapViewOfFile(view)) {
            const DWORD error = GetLastError();
            CloseHandle(mapping);
            diag::log_tagged_fmt("dec_batch",
                "generation_snapshot_unmap_failed gle=%lu", static_cast<unsigned long>(error));
            return nullptr;
        }
        entry->mapping_handle = static_cast<void*>(mapping);
        return entry;
    }

    void evict_unpinned_locked()
    {
        std::size_t unpinned = 0;
        for (const auto& entry : entries_)
            if (entry && entry->pins.load(std::memory_order_acquire) == 0)
                ++unpinned;
        while (unpinned > k_max_unpinned_entries && !entries_.empty()) {
            const auto& front = entries_.front();
            if (front && front->pins.load(std::memory_order_acquire) != 0) {
                auto iterator = entries_.begin();
                for (; iterator != entries_.end(); ++iterator)
                    if (*iterator && (*iterator)->pins.load(std::memory_order_acquire) == 0)
                        break;
                if (iterator == entries_.end())
                    break;
                diag::log_tagged_fmt("dec_batch",
                    "generation_snapshot_evicted generation=%llu bytes=%llu reason=lru",
                    static_cast<unsigned long long>((*iterator)->generation),
                    static_cast<unsigned long long>((*iterator)->mapping_size));
                entries_.erase(iterator);
                --unpinned;
                continue;
            }
            diag::log_tagged_fmt("dec_batch",
                "generation_snapshot_evicted generation=%llu bytes=%llu reason=lru",
                static_cast<unsigned long long>(front ? front->generation : 0),
                static_cast<unsigned long long>(front ? front->mapping_size : 0));
            entries_.pop_front();
            --unpinned;
        }
    }

    mutable std::mutex mutex_;
    std::deque<std::shared_ptr<entry_t>> entries_;
    std::uint64_t next_tick_ = 0;
};

}
