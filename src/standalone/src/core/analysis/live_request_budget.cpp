#include "live_request_budget.hpp"

#include <limits>

namespace aida::analysis::c03 {
namespace {

bool can_add(std::uint64_t left, std::uint64_t right) noexcept
{
    return right <= (std::numeric_limits<std::uint64_t>::max)() - left;
}

}

std::string_view live_request_budget_error_code_name(live_request_budget_error_code_t code) noexcept
{
    switch (code) {
    case live_request_budget_error_code_t::none:
        return "none";
    case live_request_budget_error_code_t::invalid_limits:
        return "invalid_limits";
    case live_request_budget_error_code_t::cancelled:
        return "cancelled";
    case live_request_budget_error_code_t::deadline_exceeded:
        return "deadline_exceeded";
    case live_request_budget_error_code_t::result_byte_limit_exceeded:
        return "result_byte_limit_exceeded";
    case live_request_budget_error_code_t::adapter_byte_limit_exceeded:
        return "adapter_byte_limit_exceeded";
    case live_request_budget_error_code_t::page_limit_exceeded:
        return "page_limit_exceeded";
    case live_request_budget_error_code_t::page_size_limit_exceeded:
        return "page_size_limit_exceeded";
    case live_request_budget_error_code_t::arithmetic_overflow:
        return "arithmetic_overflow";
    }
    return "unknown";
}

live_request_budget_error_t make_live_request_budget_error(
    live_request_budget_error_code_t code, std::uint64_t expected, std::uint64_t actual) noexcept
{
    return {code, live_request_budget_error_code_name(code), expected, actual};
}

live_request_budget_result_t<live_request_budget_t>
live_request_budget_t::create(live_request_budget_limits_t limits, time_point_t started) noexcept
{
    if (!limits.valid()) {
        return live_request_budget_result_t<live_request_budget_t>::failure(
            make_live_request_budget_error(live_request_budget_error_code_t::invalid_limits));
    }
    return live_request_budget_result_t<live_request_budget_t>::success(
        live_request_budget_t(limits, started));
}

live_request_budget_t::live_request_budget_t(
    live_request_budget_limits_t limits, time_point_t started) noexcept
    : limits_(limits), started_(started)
{
}

live_request_budget_t::time_point_t live_request_budget_t::deadline() const noexcept
{
    const auto maximum = std::chrono::duration_cast<clock_t::duration>(limits_.maximum_elapsed);
    const auto remaining = time_point_t::max() - started_;
    if (maximum >= remaining)
        return time_point_t::max();
    return started_ + maximum;
}

live_request_budget_result_t<void>
live_request_budget_t::checkpoint(bool cancelled, time_point_t now) const noexcept
{
    if (cancelled) {
        return live_request_budget_result_t<void>::failure(
            make_live_request_budget_error(live_request_budget_error_code_t::cancelled));
    }
    if (now < started_ || now > deadline()) {
        return live_request_budget_result_t<void>::failure(
            make_live_request_budget_error(live_request_budget_error_code_t::deadline_exceeded));
    }
    return live_request_budget_result_t<void>::success();
}

live_request_budget_result_t<void> live_request_budget_t::reserve(
    std::uint64_t amount, std::uint64_t maximum, std::uint64_t& used,
    live_request_budget_error_code_t limit_error, bool cancelled, time_point_t now) noexcept
{
    const auto checked = checkpoint(cancelled, now);
    if (!checked)
        return checked;
    if (!can_add(used, amount)) {
        return live_request_budget_result_t<void>::failure(
            make_live_request_budget_error(live_request_budget_error_code_t::arithmetic_overflow,
                                           used, amount));
    }
    const auto updated = used + amount;
    if (updated > maximum) {
        return live_request_budget_result_t<void>::failure(
            make_live_request_budget_error(limit_error, maximum, updated));
    }
    used = updated;
    return live_request_budget_result_t<void>::success();
}

live_request_budget_result_t<void> live_request_budget_t::reserve_result_bytes(
    std::uint64_t bytes, bool cancelled, time_point_t now) noexcept
{
    return reserve(bytes, limits_.maximum_result_bytes, result_bytes_,
                   live_request_budget_error_code_t::result_byte_limit_exceeded,
                   cancelled, now);
}

live_request_budget_result_t<void> live_request_budget_t::reserve_adapter_bytes(
    std::uint64_t bytes, bool cancelled, time_point_t now) noexcept
{
    if (bytes > limits_.maximum_page_bytes) {
        return live_request_budget_result_t<void>::failure(
            make_live_request_budget_error(
                live_request_budget_error_code_t::page_size_limit_exceeded,
                limits_.maximum_page_bytes, bytes));
    }
    return reserve(bytes, limits_.maximum_adapter_bytes, adapter_bytes_,
                   live_request_budget_error_code_t::adapter_byte_limit_exceeded,
                   cancelled, now);
}

live_request_budget_result_t<void> live_request_budget_t::reserve_pages(
    std::uint32_t pages, bool cancelled, time_point_t now) noexcept
{
    const auto checked = checkpoint(cancelled, now);
    if (!checked)
        return checked;
    if (pages > limits_.maximum_pages_per_request - page_count_) {
        const auto actual = static_cast<std::uint64_t>(page_count_) + pages;
        return live_request_budget_result_t<void>::failure(
            make_live_request_budget_error(live_request_budget_error_code_t::page_limit_exceeded,
                                           limits_.maximum_pages_per_request, actual));
    }
    page_count_ += pages;
    return live_request_budget_result_t<void>::success();
}

}
