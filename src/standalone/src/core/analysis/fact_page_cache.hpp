#pragma once

#include "workspace/workspace_types.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace aida::analysis {

struct fact_page_range_t final {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
};

struct fact_page_key_t final {
    binary_id_t binary_id;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint32_t domain = 0;
    std::uint32_t page_index = 0;

    friend bool operator==(const fact_page_key_t& lhs,
                           const fact_page_key_t& rhs) noexcept {
        return lhs.binary_id == rhs.binary_id && lhs.generation == rhs.generation &&
               lhs.analysis_revision == rhs.analysis_revision &&
               lhs.overlay_revision == rhs.overlay_revision &&
               lhs.domain == rhs.domain && lhs.page_index == rhs.page_index;
    }
    friend bool operator!=(const fact_page_key_t& lhs,
                           const fact_page_key_t& rhs) noexcept {
        return !(lhs == rhs);
    }
};

struct fact_page_t final {
    std::vector<std::uint8_t> payload;
    std::uint64_t address_value_min = 0;
    std::uint64_t address_value_max = 0;
    std::uint32_t ordinal_begin = 0;
    std::uint32_t record_count = 0;
    std::uint64_t decoded_bytes = 0;
};

struct fact_page_cache_options_t final {
    std::uint64_t max_resident_bytes = 0;
};

struct fact_page_cache_statistics_t final {
    std::uint64_t capacity_bytes = 0;
    std::uint64_t resident_bytes = 0;
    std::uint64_t entries = 0;
    std::uint64_t hits = 0;
    std::uint64_t misses = 0;
    std::uint64_t admissions = 0;
    std::uint64_t admission_rejections = 0;
    std::uint64_t evictions = 0;
    std::uint64_t drop_calls = 0;
    std::uint64_t dropped_pages = 0;
    std::uint64_t dropped_bytes = 0;
    std::uint64_t trims = 0;
    std::uint64_t bypass_decodes = 0;
};

struct fact_page_coherence_notification_t final {
    binary_id_t binary_id;
    std::uint64_t source_generation = 0;
    std::uint64_t target_generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t source_overlay_revision = 0;
    std::uint64_t target_overlay_revision = 0;
    std::vector<fact_page_range_t> affected_ranges;
    bool rebuild_all = false;
};

using fact_page_coherence_subscriber_t =
    std::function<void(const fact_page_coherence_notification_t&)>;

class fact_page_coherence_hub_t final {
public:
    static fact_page_coherence_hub_t& instance() noexcept;

    std::uint64_t subscribe(fact_page_coherence_subscriber_t subscriber);
    void unsubscribe(std::uint64_t token) noexcept;
    void publish(const fact_page_coherence_notification_t& notification) const noexcept;

private:
    fact_page_coherence_hub_t();
    struct state_t;
    std::shared_ptr<state_t> state_;
};

class fact_page_cache_t final {
public:
    static fact_page_cache_t& instance() noexcept;

    fact_page_cache_t(const fact_page_cache_t&) = delete;
    fact_page_cache_t& operator=(const fact_page_cache_t&) = delete;

    void configure(const fact_page_cache_options_t& options);
    std::shared_ptr<const fact_page_t> lookup(const fact_page_key_t& key) noexcept;
    bool insert(const fact_page_key_t& key,
                std::shared_ptr<const fact_page_t> page) noexcept;
    std::uint64_t drop_ranges(
        const binary_id_t& binary_id, std::uint64_t generation,
        const std::vector<fact_page_range_t>& ranges) noexcept;
    void set_ceiling(std::uint64_t bytes) noexcept;
    std::uint64_t ceiling() const noexcept;
    void trim() noexcept;
    void record_bypass() noexcept;
    fact_page_cache_statistics_t statistics() const noexcept;

private:
    fact_page_cache_t();
    struct state_t;
    std::shared_ptr<state_t> state_;
};

}
