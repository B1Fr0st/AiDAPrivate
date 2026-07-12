#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

namespace aida::analysis::c03 {

enum class live_request_budget_error_code_t : std::uint8_t {
    none = 0,
    invalid_limits,
    cancelled,
    deadline_exceeded,
    result_byte_limit_exceeded,
    adapter_byte_limit_exceeded,
    page_limit_exceeded,
    page_size_limit_exceeded,
    arithmetic_overflow
};

struct live_request_budget_error_t final {
    live_request_budget_error_code_t code = live_request_budget_error_code_t::none;
    std::string_view stable_code;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;
};

std::string_view live_request_budget_error_code_name(live_request_budget_error_code_t code) noexcept;
live_request_budget_error_t make_live_request_budget_error(
    live_request_budget_error_code_t code, std::uint64_t expected = 0,
    std::uint64_t actual = 0) noexcept;

template <typename value_t>
class live_request_budget_result_t final {
public:
    static live_request_budget_result_t success(value_t value)
    {
        return live_request_budget_result_t(std::move(value));
    }

    static live_request_budget_result_t failure(live_request_budget_error_t error) noexcept
    {
        return live_request_budget_result_t(error);
    }

    bool has_value() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return has_value(); }
    const value_t& value() const & { return value_.value(); }
    value_t& value() & { return value_.value(); }
    value_t take_value() && { return std::move(value_).value(); }
    const live_request_budget_error_t& error() const noexcept { return error_; }

private:
    explicit live_request_budget_result_t(value_t value) : value_(std::move(value)) {}
    explicit live_request_budget_result_t(live_request_budget_error_t error) noexcept : error_(error) {}

    std::optional<value_t> value_;
    live_request_budget_error_t error_{};
};

template <>
class live_request_budget_result_t<void> final {
public:
    static constexpr live_request_budget_result_t success() noexcept
    {
        return live_request_budget_result_t();
    }

    static constexpr live_request_budget_result_t failure(live_request_budget_error_t error) noexcept
    {
        return live_request_budget_result_t(error);
    }

    constexpr bool has_value() const noexcept
    {
        return error_.code == live_request_budget_error_code_t::none;
    }

    constexpr explicit operator bool() const noexcept { return has_value(); }
    constexpr const live_request_budget_error_t& error() const noexcept { return error_; }

private:
    constexpr live_request_budget_result_t() noexcept = default;
    constexpr explicit live_request_budget_result_t(live_request_budget_error_t error) noexcept
        : error_(error) {}

    live_request_budget_error_t error_{};
};

struct live_request_budget_limits_t final {
    std::uint64_t maximum_result_bytes = 0;
    std::uint64_t maximum_adapter_bytes = 0;
    std::uint32_t maximum_pages_per_request = 0;
    std::uint32_t maximum_page_bytes = 0;
    std::uint32_t maximum_cached_pages = 0;
    std::uint64_t maximum_cached_bytes = 0;
    std::chrono::milliseconds maximum_elapsed{0};

    constexpr bool valid() const noexcept
    {
        return maximum_result_bytes != 0 && maximum_adapter_bytes != 0 &&
            maximum_pages_per_request != 0 && maximum_page_bytes != 0 &&
            maximum_cached_pages != 0 && maximum_cached_bytes != 0 &&
            maximum_elapsed.count() > 0 && maximum_page_bytes <= maximum_adapter_bytes &&
            maximum_page_bytes <= maximum_cached_bytes;
    }
};

class live_request_budget_t final {
public:
    using clock_t = std::chrono::steady_clock;
    using time_point_t = clock_t::time_point;

    static live_request_budget_result_t<live_request_budget_t>
        create(live_request_budget_limits_t limits, time_point_t started) noexcept;

    const live_request_budget_limits_t& limits() const noexcept { return limits_; }
    time_point_t started() const noexcept { return started_; }
    time_point_t deadline() const noexcept;
    std::uint64_t result_bytes() const noexcept { return result_bytes_; }
    std::uint64_t adapter_bytes() const noexcept { return adapter_bytes_; }
    std::uint32_t page_count() const noexcept { return page_count_; }

    live_request_budget_result_t<void> checkpoint(bool cancelled, time_point_t now) const noexcept;
    live_request_budget_result_t<void> reserve_result_bytes(
        std::uint64_t bytes, bool cancelled, time_point_t now) noexcept;
    live_request_budget_result_t<void> reserve_adapter_bytes(
        std::uint64_t bytes, bool cancelled, time_point_t now) noexcept;
    live_request_budget_result_t<void> reserve_pages(
        std::uint32_t pages, bool cancelled, time_point_t now) noexcept;

private:
    live_request_budget_t(live_request_budget_limits_t limits, time_point_t started) noexcept;

    live_request_budget_result_t<void> reserve(std::uint64_t amount, std::uint64_t maximum,
                                                std::uint64_t& used,
                                                live_request_budget_error_code_t limit_error,
                                                bool cancelled, time_point_t now) noexcept;

    live_request_budget_limits_t limits_{};
    time_point_t started_{};
    std::uint64_t result_bytes_ = 0;
    std::uint64_t adapter_bytes_ = 0;
    std::uint32_t page_count_ = 0;
};

}
