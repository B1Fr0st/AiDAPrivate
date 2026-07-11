#pragma once

#include "workspace_types.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>

namespace aida::analysis {

inline bool checked_add_u64(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out) noexcept {
    if (rhs > std::numeric_limits<std::uint64_t>::max() - lhs)
        return false;
    out = lhs + rhs;
    return true;
}

inline bool checked_sub_u64(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out) noexcept {
    if (rhs > lhs)
        return false;
    out = lhs - rhs;
    return true;
}

inline bool checked_mul_u64(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out) noexcept {
    if (lhs != 0 && rhs > std::numeric_limits<std::uint64_t>::max() / lhs)
        return false;
    out = lhs * rhs;
    return true;
}

inline bool u64_to_size(std::uint64_t value, std::size_t& out) noexcept {
    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
        return false;
    out = static_cast<std::size_t>(value);
    return true;
}

struct checked_span_t {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;

    workspace_result_t<std::uint64_t> end() const {
        std::uint64_t result = 0;
        if (!checked_add_u64(offset, size, result)) {
            auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                              "range end exceeds 64-bit address space", "range");
            error.offset = offset;
            error.size = size;
            return workspace_result_t<std::uint64_t>::failure(std::move(error));
        }
        return workspace_result_t<std::uint64_t>::success(result);
    }

    bool contains(std::uint64_t value) const noexcept {
        std::uint64_t finish = 0;
        return checked_add_u64(offset, size, finish) && value >= offset && value < finish;
    }

    bool contains(const checked_span_t& other) const noexcept {
        std::uint64_t finish = 0;
        std::uint64_t other_finish = 0;
        return checked_add_u64(offset, size, finish) &&
               checked_add_u64(other.offset, other.size, other_finish) &&
               other.offset >= offset && other_finish <= finish;
    }

    bool overlaps(const checked_span_t& other) const noexcept {
        std::uint64_t finish = 0;
        std::uint64_t other_finish = 0;
        if (!checked_add_u64(offset, size, finish) ||
            !checked_add_u64(other.offset, other.size, other_finish))
            return false;
        return offset < other_finish && other.offset < finish;
    }
};

inline workspace_result_t<checked_span_t> validate_span(std::uint64_t offset, std::uint64_t size,
                                                        std::uint64_t bound,
                                                        const char* phase = "range") {
    std::uint64_t finish = 0;
    if (!checked_add_u64(offset, size, finish)) {
        auto error = make_workspace_error(workspace_error_code_t::range_overflow,
                                          "range end exceeds 64-bit address space", phase);
        error.offset = offset;
        error.size = size;
        return workspace_result_t<checked_span_t>::failure(std::move(error));
    }
    if (finish > bound) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "range exceeds provider bounds", phase);
        error.offset = offset;
        error.size = size;
        error.details.emplace_back("bound", std::to_string(bound));
        return workspace_result_t<checked_span_t>::failure(std::move(error));
    }
    return workspace_result_t<checked_span_t>::success({offset, size});
}

}
