#include "fact_page_cache.hpp"

#include "analysis_budget.hpp"
#include "mapped_window_cache.hpp"
#include "../../helpers/diag_log.hpp"
#include "../infra/fast_containers.hpp"

#include <algorithm>
#include <atomic>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kMinimumCacheBytes = 1ULL << 30;
constexpr std::uint64_t kMaximumCacheBytes = 4ULL << 30;
constexpr std::uint64_t kPageEntryOverheadBytes = 256;

std::uint64_t adaptive_default_ceiling() noexcept {
    const auto envelope = host_memory_envelope();
    const std::uint64_t fraction = envelope.usable_bytes / 12ULL;
    return (std::min)((std::max)(fraction, kMinimumCacheBytes), kMaximumCacheBytes);
}

struct fact_page_key_hash_t {
    std::size_t operator()(const fact_page_key_t& key) const noexcept {
        std::uint64_t value = 0;
        for (std::size_t index = 0; index < 8; ++index)
            value |= static_cast<std::uint64_t>(key.binary_id.bytes[index]) << (index * 8);
        value ^= key.generation * 0x9E3779B97F4A7C15ULL;
        value ^= (key.analysis_revision + 0x9E3779B97F4A7C15ULL + (value << 6U) +
                  (value >> 2U));
        value ^= (key.overlay_revision + 0x9E3779B97F4A7C15ULL + (value << 6U) +
                  (value >> 2U));
        value ^= (static_cast<std::uint64_t>(key.domain) << 32U) ^ key.page_index;
        value ^= value >> 33U;
        value *= 0xFF51AFD7ED558CCDULL;
        value ^= value >> 33U;
        return static_cast<std::size_t>(value);
    }
};

struct fact_page_entry_t {
    std::shared_ptr<const fact_page_t> page;
    std::uint64_t bytes = 0;
    std::uint64_t last_access = 0;
};

struct fact_page_shard_t {
    std::mutex mutex;
    aida::infra::fast_flat_map<fact_page_key_t, fact_page_entry_t, fact_page_key_hash_t> entries;
};

bool ranges_overlap(std::uint64_t entry_min, std::uint64_t entry_max,
                    std::uint64_t range_offset, std::uint64_t range_size) noexcept {
    if (range_size == 0)
        return false;
    const std::uint64_t range_end = range_offset + (range_size - 1ULL) < range_offset
        ? (std::numeric_limits<std::uint64_t>::max)()
        : range_offset + (range_size - 1ULL);
    return entry_min <= range_end && range_offset <= entry_max;
}

}

struct fact_page_coherence_hub_t::state_t {
    mutable std::mutex mutex;
    std::vector<std::pair<std::uint64_t, fact_page_coherence_subscriber_t>> subscribers;
    std::atomic<std::uint64_t> next_token{1};
};

fact_page_coherence_hub_t::fact_page_coherence_hub_t()
    : state_(std::make_shared<state_t>()) {}

fact_page_coherence_hub_t& fact_page_coherence_hub_t::instance() noexcept {
    static fact_page_coherence_hub_t hub;
    return hub;
}

std::uint64_t fact_page_coherence_hub_t::subscribe(
    fact_page_coherence_subscriber_t subscriber) {
    if (!subscriber)
        return 0;
    std::uint64_t token = 0;
    for (;;) {
        token = state_->next_token.fetch_add(1, std::memory_order_acq_rel);
        if (token != 0)
            break;
    }
    try {
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->subscribers.emplace_back(token, std::move(subscriber));
    } catch (const std::bad_alloc&) {
        return 0;
    }
    return token;
}

void fact_page_coherence_hub_t::unsubscribe(std::uint64_t token) noexcept {
    if (!state_ || token == 0)
        return;
    std::lock_guard<std::mutex> lock(state_->mutex);
    auto& subscribers = state_->subscribers;
    subscribers.erase(
        std::remove_if(subscribers.begin(), subscribers.end(),
                       [token](const auto& entry) { return entry.first == token; }),
        subscribers.end());
}

void fact_page_coherence_hub_t::publish(
    const fact_page_coherence_notification_t& notification) const noexcept {
    if (!state_)
        return;
    std::vector<fact_page_coherence_subscriber_t> subscribers;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        subscribers.reserve(state_->subscribers.size());
        for (const auto& entry : state_->subscribers)
            subscribers.push_back(entry.second);
    }
    for (const auto& subscriber : subscribers) {
        try {
            subscriber(notification);
        } catch (...) {
            ::diag::log_tagged_fmt("fact_page_cache",
                "coherence subscriber raised during publish source_generation=%llu target_generation=%llu",
                static_cast<unsigned long long>(notification.source_generation),
                static_cast<unsigned long long>(notification.target_generation));
        }
    }
}

struct fact_page_cache_t::state_t {
    std::vector<std::unique_ptr<fact_page_shard_t>> shards;
    std::atomic<std::uint64_t> access_sequence{1};
    std::atomic<std::uint64_t> ceiling_bytes{0};
    std::atomic<std::uint64_t> resident_bytes{0};
    std::atomic<std::uint64_t> hits{0};
    std::atomic<std::uint64_t> misses{0};
    std::atomic<std::uint64_t> admissions{0};
    std::atomic<std::uint64_t> admission_rejections{0};
    std::atomic<std::uint64_t> evictions{0};
    std::atomic<std::uint64_t> bypass_decodes{0};
    std::uint64_t drop_calls{0};
    std::uint64_t dropped_pages{0};
    std::uint64_t dropped_bytes{0};
    std::uint64_t trims{0};
    std::mutex drop_mutex;

    std::size_t shard_index(const fact_page_key_t& key) const noexcept {
        const std::size_t mask = shards.empty() ? 0 : shards.size() - 1;
        return static_cast<std::size_t>(
            (key.binary_id.bytes[8] ^ key.generation ^
             (key.domain * 0x9E37U) ^ key.page_index) & mask);
    }

    bool evict_one_approx(std::size_t hint_shard) {
        std::size_t selected = shards.size();
        std::uint64_t oldest = (std::numeric_limits<std::uint64_t>::max)();
        const auto scan = [&](std::size_t index) {
            auto& shard = *shards[index];
            std::lock_guard<std::mutex> lock(shard.mutex);
            for (const auto& item : shard.entries) {
                if (item.second.page.use_count() != 1 ||
                    item.second.last_access >= oldest)
                    continue;
                selected = index;
                oldest = item.second.last_access;
            }
        };
        scan(hint_shard);
        if (selected == shards.size()) {
            for (std::size_t offset = 1; offset < shards.size(); ++offset)
                scan((hint_shard + offset) % shards.size());
        }
        if (selected == shards.size())
            return false;
        auto& shard = *shards[selected];
        std::shared_ptr<const fact_page_t> retired;
        std::uint64_t retired_bytes = 0;
        {
            std::lock_guard<std::mutex> lock(shard.mutex);
            std::uint64_t best_access = (std::numeric_limits<std::uint64_t>::max)();
            auto best = shard.entries.end();
            for (auto iterator = shard.entries.begin(); iterator != shard.entries.end();
                 ++iterator) {
                if (iterator->second.page.use_count() != 1 ||
                    iterator->second.last_access >= best_access)
                    continue;
                best = iterator;
                best_access = iterator->second.last_access;
            }
            if (best == shard.entries.end())
                return false;
            retired_bytes = best->second.bytes;
            retired = std::move(best->second.page);
            shard.entries.erase(best);
        }
        resident_bytes.fetch_sub(retired_bytes, std::memory_order_acq_rel);
        evictions.fetch_add(1, std::memory_order_relaxed);
        provider_metrics_relay::record_memory_pressure_event();
        return true;
    }
};

fact_page_cache_t::fact_page_cache_t() : state_(std::make_shared<state_t>()) {
    state_->ceiling_bytes.store(adaptive_default_ceiling(), std::memory_order_release);
    state_->shards.reserve(64);
    for (std::uint32_t index = 0; index < 64; ++index)
        state_->shards.push_back(std::make_unique<fact_page_shard_t>());
}

fact_page_cache_t& fact_page_cache_t::instance() noexcept {
    static fact_page_cache_t cache;
    return cache;
}

void fact_page_cache_t::configure(const fact_page_cache_options_t& options) {
    if (options.max_resident_bytes != 0) {
        const std::uint64_t bounded = (std::min)(
            (std::max)(options.max_resident_bytes, kMinimumCacheBytes),
            kMaximumCacheBytes);
        set_ceiling(bounded);
    }
    ::diag::log_tagged_fmt("fact_page_cache",
        "configured ceiling=%llu",
        static_cast<unsigned long long>(ceiling()));
}

std::shared_ptr<const fact_page_t> fact_page_cache_t::lookup(
    const fact_page_key_t& key) noexcept {
    auto& shard = *state_->shards[state_->shard_index(key)];
    std::lock_guard<std::mutex> lock(shard.mutex);
    const auto iterator = shard.entries.find(key);
    if (iterator == shard.entries.end()) {
        state_->misses.fetch_add(1, std::memory_order_relaxed);
        return {};
    }
    iterator->second.last_access =
        state_->access_sequence.fetch_add(1, std::memory_order_relaxed);
    state_->hits.fetch_add(1, std::memory_order_relaxed);
    return iterator->second.page;
}

bool fact_page_cache_t::insert(const fact_page_key_t& key,
                               std::shared_ptr<const fact_page_t> page) noexcept {
    if (!page || page->payload.empty())
        return false;
    std::uint64_t bytes = page->decoded_bytes;
    if (bytes == 0)
        bytes = static_cast<std::uint64_t>(page->payload.size()) + kPageEntryOverheadBytes;
    const std::uint64_t ceiling = state_->ceiling_bytes.load(std::memory_order_acquire);
    if (bytes > ceiling) {
        state_->admission_rejections.fetch_add(1, std::memory_order_relaxed);
        provider_metrics_relay::record_budget_rejection();
        return false;
    }
    const std::size_t hint = state_->shard_index(key);
    auto& shard = *state_->shards[hint];
    for (;;) {
        {
            std::lock_guard<std::mutex> lock(shard.mutex);
            const auto existing = shard.entries.find(key);
            const std::uint64_t resident =
                state_->resident_bytes.load(std::memory_order_acquire);
            if (existing != shard.entries.end()) {
                const std::uint64_t previous_bytes = existing->second.bytes;
                if (resident - previous_bytes + bytes <= ceiling) {
                    existing->second.page = std::move(page);
                    existing->second.bytes = bytes;
                    existing->second.last_access =
                        state_->access_sequence.fetch_add(1, std::memory_order_relaxed);
                    if (previous_bytes >= bytes)
                        state_->resident_bytes.fetch_sub(
                            previous_bytes - bytes, std::memory_order_acq_rel);
                    else
                        state_->resident_bytes.fetch_add(
                            bytes - previous_bytes, std::memory_order_acq_rel);
                    return true;
                }
            } else if (resident <= ceiling && bytes <= ceiling - resident) {
                try {
                    fact_page_entry_t entry;
                    entry.bytes = bytes;
                    entry.last_access =
                        state_->access_sequence.fetch_add(1, std::memory_order_relaxed);
                    entry.page = std::move(page);
                    shard.entries.emplace(key, std::move(entry));
                } catch (const std::bad_alloc&) {
                    state_->admission_rejections.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
                state_->resident_bytes.fetch_add(bytes, std::memory_order_acq_rel);
                state_->admissions.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
        }
        if (!evict_one_approx(hint)) {
            state_->admission_rejections.fetch_add(1, std::memory_order_relaxed);
            provider_metrics_relay::record_budget_rejection();
            return false;
        }
    }
}

std::uint64_t fact_page_cache_t::drop_ranges(
    const binary_id_t& binary_id, std::uint64_t generation,
    const std::vector<fact_page_range_t>& ranges) noexcept {
    std::lock_guard<std::mutex> drop_lock(state_->drop_mutex);
    std::uint64_t dropped = 0;
    std::uint64_t dropped_byte_total = 0;
    if (ranges.empty()) {
        state_->drop_calls += 1;
        return 0;
    }
    for (auto& shard_ptr : state_->shards) {
        std::vector<std::uint64_t> evicted_bytes;
        {
            std::lock_guard<std::mutex> lock(shard_ptr->mutex);
            for (auto iterator = shard_ptr->entries.begin();
                 iterator != shard_ptr->entries.end();) {
                const auto& key = iterator->first;
                const auto& entry = iterator->second;
                if (key.binary_id != binary_id || key.generation != generation) {
                    ++iterator;
                    continue;
                }
                bool overlaps = false;
                for (const auto& range : ranges) {
                    if (ranges_overlap(entry.page->address_value_min,
                                       entry.page->address_value_max,
                                       range.offset, range.size)) {
                        overlaps = true;
                        break;
                    }
                }
                if (!overlaps) {
                    ++iterator;
                    continue;
                }
                evicted_bytes.push_back(entry.bytes);
                iterator = shard_ptr->entries.erase(iterator);
                ++dropped;
            }
        }
        for (const auto bytes : evicted_bytes)
            dropped_byte_total += bytes;
    }
    if (dropped_byte_total != 0)
        state_->resident_bytes.fetch_sub(dropped_byte_total, std::memory_order_acq_rel);
    state_->drop_calls += 1;
    state_->dropped_pages += dropped;
    state_->dropped_bytes += dropped_byte_total;
    ::diag::log_tagged_fmt("fact_page_cache",
        "drop_ranges generation=%llu ranges=%zu dropped_pages=%llu dropped_bytes=%llu resident_bytes=%llu",
        static_cast<unsigned long long>(generation), ranges.size(),
        static_cast<unsigned long long>(dropped),
        static_cast<unsigned long long>(dropped_byte_total),
        static_cast<unsigned long long>(
            state_->resident_bytes.load(std::memory_order_acquire)));
    return dropped;
}

void fact_page_cache_t::set_ceiling(std::uint64_t bytes) noexcept {
    const std::uint64_t bounded =
        (std::min)((std::max)(bytes, kMinimumCacheBytes), kMaximumCacheBytes);
    state_->ceiling_bytes.store(bounded, std::memory_order_release);
    std::size_t guard = 0;
    while (state_->resident_bytes.load(std::memory_order_acquire) > bounded &&
           guard < state_->shards.size() * 4U) {
        if (!evict_one_approx(guard % state_->shards.size()))
            break;
        ++guard;
    }
    ::diag::log_tagged_fmt("fact_page_cache",
        "set_ceiling bytes=%llu bounded=%llu resident_bytes=%llu",
        static_cast<unsigned long long>(bytes),
        static_cast<unsigned long long>(bounded),
        static_cast<unsigned long long>(
            state_->resident_bytes.load(std::memory_order_acquire)));
}

std::uint64_t fact_page_cache_t::ceiling() const noexcept {
    return state_->ceiling_bytes.load(std::memory_order_acquire);
}

void fact_page_cache_t::record_bypass() noexcept {
    state_->bypass_decodes.fetch_add(1, std::memory_order_relaxed);
}

void fact_page_cache_t::trim() noexcept {
    std::uint64_t removed = 0;
    std::uint64_t removed_bytes = 0;
    for (auto& shard_ptr : state_->shards) {
        std::uint64_t shard_bytes = 0;
        std::uint64_t shard_count = 0;
        {
            std::lock_guard<std::mutex> lock(shard_ptr->mutex);
            for (auto iterator = shard_ptr->entries.begin();
                 iterator != shard_ptr->entries.end();) {
                if (iterator->second.page.use_count() != 1) {
                    ++iterator;
                    continue;
                }
                shard_bytes += iterator->second.bytes;
                ++shard_count;
                iterator = shard_ptr->entries.erase(iterator);
            }
        }
        removed += shard_count;
        removed_bytes += shard_bytes;
    }
    if (removed_bytes != 0)
        state_->resident_bytes.fetch_sub(removed_bytes, std::memory_order_acq_rel);
    state_->trims += 1;
    ::diag::log_tagged_fmt("fact_page_cache",
        "trim removed_pages=%llu removed_bytes=%llu resident_bytes=%llu",
        static_cast<unsigned long long>(removed),
        static_cast<unsigned long long>(removed_bytes),
        static_cast<unsigned long long>(
            state_->resident_bytes.load(std::memory_order_acquire)));
}

fact_page_cache_statistics_t fact_page_cache_t::statistics() const noexcept {
    fact_page_cache_statistics_t result;
    result.capacity_bytes = state_->ceiling_bytes.load(std::memory_order_acquire);
    result.resident_bytes = state_->resident_bytes.load(std::memory_order_acquire);
    result.hits = state_->hits.load(std::memory_order_relaxed);
    result.misses = state_->misses.load(std::memory_order_relaxed);
    result.admissions = state_->admissions.load(std::memory_order_relaxed);
    result.admission_rejections =
        state_->admission_rejections.load(std::memory_order_relaxed);
    result.evictions = state_->evictions.load(std::memory_order_relaxed);
    result.bypass_decodes = state_->bypass_decodes.load(std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lock(state_->drop_mutex);
        result.drop_calls = state_->drop_calls;
        result.dropped_pages = state_->dropped_pages;
        result.dropped_bytes = state_->dropped_bytes;
        result.trims = state_->trims;
    }
    for (const auto& shard_ptr : state_->shards) {
        std::lock_guard<std::mutex> lock(shard_ptr->mutex);
        result.entries += shard_ptr->entries.size();
    }
    return result;
}

}
