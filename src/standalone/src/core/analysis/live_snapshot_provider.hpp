#pragma once

#include "live_request_budget.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <list>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida::analysis::c03 {

enum class live_snapshot_error_code_t : std::uint8_t {
    none = 0,
    invalid_request,
    invalid_adapter,
    cancelled,
    deadline_exceeded,
    pid_reused,
    process_identity_changed,
    module_unloaded,
    module_remapped,
    range_invalid,
    result_byte_limit_exceeded,
    adapter_byte_limit_exceeded,
    page_limit_exceeded,
    cache_limit_exceeded,
    partial_read,
    adapter_failure,
    arithmetic_overflow,
    allocation_failed
};

struct live_snapshot_error_t final {
    live_snapshot_error_code_t code = live_snapshot_error_code_t::none;
    std::string_view stable_code;
    std::string_view phase;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;
};

std::string_view live_snapshot_error_code_name(live_snapshot_error_code_t code) noexcept;
live_snapshot_error_t make_live_snapshot_error(live_snapshot_error_code_t code,
                                                std::string_view phase = {},
                                                std::uint64_t expected = 0,
                                                std::uint64_t actual = 0) noexcept;

template <typename value_t>
class live_snapshot_result_t final {
public:
    static live_snapshot_result_t success(value_t value)
    {
        return live_snapshot_result_t(std::move(value));
    }

    static live_snapshot_result_t failure(live_snapshot_error_t error) noexcept
    {
        return live_snapshot_result_t(error);
    }

    bool has_value() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return has_value(); }
    const value_t& value() const & { return value_.value(); }
    value_t& value() & { return value_.value(); }
    value_t take_value() && { return std::move(value_).value(); }
    const live_snapshot_error_t& error() const noexcept { return error_; }

private:
    explicit live_snapshot_result_t(value_t value) : value_(std::move(value)) {}
    explicit live_snapshot_result_t(live_snapshot_error_t error) noexcept : error_(error) {}

    std::optional<value_t> value_;
    live_snapshot_error_t error_{};
};

template <>
class live_snapshot_result_t<void> final {
public:
    static constexpr live_snapshot_result_t success() noexcept
    {
        return live_snapshot_result_t();
    }

    static constexpr live_snapshot_result_t failure(live_snapshot_error_t error) noexcept
    {
        return live_snapshot_result_t(error);
    }

    constexpr bool has_value() const noexcept
    {
        return error_.code == live_snapshot_error_code_t::none;
    }

    constexpr explicit operator bool() const noexcept { return has_value(); }
    constexpr const live_snapshot_error_t& error() const noexcept { return error_; }

private:
    constexpr live_snapshot_result_t() noexcept = default;
    constexpr explicit live_snapshot_result_t(live_snapshot_error_t error) noexcept : error_(error) {}

    live_snapshot_error_t error_{};
};

using live_snapshot_fingerprint_t = std::array<std::uint8_t, 32>;

struct live_process_identity_t final {
    std::uint32_t pid = 0;
    std::uint64_t creation_identity = 0;

    constexpr bool valid() const noexcept
    {
        return pid != 0 && creation_identity != 0;
    }

    constexpr bool operator==(const live_process_identity_t& other) const noexcept
    {
        return pid == other.pid && creation_identity == other.creation_identity;
    }

    constexpr bool operator!=(const live_process_identity_t& other) const noexcept
    {
        return !(*this == other);
    }
};

struct live_module_identity_t final {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint64_t mapping_identity = 0;
    live_snapshot_fingerprint_t fingerprint{};

    constexpr bool valid() const noexcept
    {
        if (base == 0 || size == 0 || mapping_identity == 0 ||
            size > (std::numeric_limits<std::uint64_t>::max)() - base)
            return false;
        for (const auto byte : fingerprint) {
            if (byte != 0)
                return true;
        }
        return false;
    }

    constexpr bool operator==(const live_module_identity_t& other) const noexcept
    {
        return base == other.base && size == other.size &&
            mapping_identity == other.mapping_identity && fingerprint == other.fingerprint;
    }

    constexpr bool operator!=(const live_module_identity_t& other) const noexcept
    {
        return !(*this == other);
    }
};

class live_snapshot_cancellation_t final {
public:
    live_snapshot_cancellation_t() = default;
    bool stop_requested() const noexcept;

private:
    friend class live_snapshot_cancellation_source_t;
    explicit live_snapshot_cancellation_t(std::shared_ptr<const std::atomic_bool> state) noexcept;

    std::shared_ptr<const std::atomic_bool> state_;
};

class live_snapshot_cancellation_source_t final {
public:
    live_snapshot_cancellation_source_t();

    live_snapshot_cancellation_t token() const noexcept;
    void request_stop() noexcept;

private:
    std::shared_ptr<std::atomic_bool> state_;
};

struct live_snapshot_operation_context_t final {
    live_snapshot_cancellation_t cancellation;
    live_request_budget_t::time_point_t deadline{};
    live_request_budget_t::time_point_t wall_deadline{};
};

struct live_snapshot_adapter_page_t final {
    std::uint64_t address = 0;
    std::vector<std::uint8_t> bytes;
};

class live_snapshot_adapter_t {
public:
    virtual ~live_snapshot_adapter_t() = default;

    virtual live_snapshot_result_t<live_process_identity_t>
        query_process(std::uint32_t pid, const live_snapshot_operation_context_t& context) const = 0;
    virtual live_snapshot_result_t<live_module_identity_t>
        query_module(const live_process_identity_t& process, std::uint64_t module_base,
                     const live_snapshot_operation_context_t& context) const = 0;
    virtual live_snapshot_result_t<live_snapshot_adapter_page_t>
        read_page(const live_process_identity_t& process, const live_module_identity_t& module,
                  std::uint64_t address, std::uint64_t size,
                  const live_snapshot_operation_context_t& context) const = 0;

private:
    friend class live_snapshot_provider_t;
    mutable std::atomic_bool call_active_{false};
};

class live_snapshot_clock_t {
public:
    virtual ~live_snapshot_clock_t() = default;

    virtual live_request_budget_t::time_point_t now() const noexcept = 0;
};

struct live_snapshot_request_t final {
    live_process_identity_t process;
    live_module_identity_t module;
    std::uint64_t window_base = 0;
    std::uint64_t window_size = 0;
    live_request_budget_limits_t limits;

    constexpr bool valid() const noexcept
    {
        if (!process.valid() || !module.valid() || window_base == 0 || window_size == 0 ||
            window_size > (std::numeric_limits<std::uint64_t>::max)() - window_base ||
            !limits.valid())
            return false;
        const auto module_end = module.base + module.size;
        const auto window_end = window_base + window_size;
        return window_base >= module.base && window_end <= module_end;
    }
};

struct live_snapshot_read_t final {
    std::uint64_t address = 0;
    std::vector<std::uint8_t> bytes;
};

struct live_snapshot_cache_stats_t final {
    std::uint32_t cached_pages = 0;
    std::uint64_t cached_bytes = 0;
    std::uint64_t cache_hits = 0;
    std::uint64_t cache_misses = 0;
    std::uint64_t cache_evictions = 0;
};

class live_snapshot_provider_t final {
public:
    static live_snapshot_result_t<std::shared_ptr<live_snapshot_provider_t>>
        open(std::shared_ptr<const live_snapshot_adapter_t> adapter, live_snapshot_request_t request,
             std::shared_ptr<const live_snapshot_clock_t> clock = {},
             const live_snapshot_cancellation_t& cancellation = {});

    live_snapshot_provider_t(const live_snapshot_provider_t&) = delete;
    live_snapshot_provider_t& operator=(const live_snapshot_provider_t&) = delete;

    const live_snapshot_request_t& request() const noexcept { return request_; }
    live_snapshot_cache_stats_t cache_stats() const;
    live_snapshot_result_t<void>
        validate_current_identity(const live_snapshot_cancellation_t& cancellation = {}) const;
    live_snapshot_result_t<live_snapshot_read_t>
        read(std::uint64_t address, std::uint64_t size,
             const live_snapshot_cancellation_t& cancellation = {});

private:
    struct cache_entry_t final {
        std::vector<std::uint8_t> bytes;
        std::list<std::uint64_t>::iterator lru_position;
    };

    live_snapshot_provider_t(std::shared_ptr<const live_snapshot_adapter_t> adapter,
                             live_snapshot_request_t request,
                             std::shared_ptr<const live_snapshot_clock_t> clock);

    live_snapshot_result_t<void> validate_identity(live_request_budget_t& budget,
                                                    const live_snapshot_operation_context_t& context) const;
    live_snapshot_result_t<live_process_identity_t>
        query_process_bounded(live_request_budget_t& budget,
                              const live_snapshot_operation_context_t& context) const;
    live_snapshot_result_t<live_module_identity_t>
        query_module_bounded(const live_process_identity_t& process,
                             live_request_budget_t& budget,
                             const live_snapshot_operation_context_t& context) const;
    live_snapshot_result_t<live_snapshot_adapter_page_t>
        read_page_bounded(std::uint64_t address, std::uint64_t size,
                          live_request_budget_t& budget,
                          const live_snapshot_operation_context_t& context) const;
    live_snapshot_result_t<void> cache_page(std::uint64_t address,
                                            std::vector<std::uint8_t> bytes);
    void touch_cache_entry(std::unordered_map<std::uint64_t, cache_entry_t>::iterator entry) noexcept;
    void clear_cache() noexcept;
    void evict_oldest_cache_entry() noexcept;

    std::shared_ptr<const live_snapshot_adapter_t> adapter_;
    live_snapshot_request_t request_{};
    std::shared_ptr<const live_snapshot_clock_t> clock_;
    mutable std::timed_mutex operation_mutex_;
    mutable std::timed_mutex cache_mutex_;
    std::unordered_map<std::uint64_t, cache_entry_t> cache_;
    std::list<std::uint64_t> cache_lru_;
    std::uint64_t cached_bytes_ = 0;
    std::uint64_t cache_hits_ = 0;
    std::uint64_t cache_misses_ = 0;
    std::uint64_t cache_evictions_ = 0;
};

}
