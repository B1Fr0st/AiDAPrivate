#pragma once

#include "../infra/fast_containers.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis {

enum class packed_store_error_code_t : std::uint16_t {
    none = 0,
    invalid_shard = 1,
    builder_finalized = 2,
    invalid_source_id = 3,
    duplicate_source_id = 4,
    invalid_entity_domain = 5,
    invalid_entity_reference = 6,
    invalid_string_id = 7,
    string_too_large = 8,
    duplicate_final_mirror = 9,
    duplicate_packed_id = 10,
    dangling_reference = 11,
    invalid_row = 12,
    invalid_string_pool = 13,
    integrity_mismatch = 14,
    arithmetic_overflow = 15
};

struct packed_store_error_t final {
    packed_store_error_code_t code = packed_store_error_code_t::none;
    std::string_view phase;
    std::uint16_t shard = 0;
    std::uint64_t subject = 0;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;

    constexpr bool operator==(const packed_store_error_t& other) const noexcept {
        return code == other.code && phase == other.phase && shard == other.shard &&
            subject == other.subject && expected == other.expected && actual == other.actual;
    }

    constexpr bool operator!=(const packed_store_error_t& other) const noexcept {
        return !(*this == other);
    }
};

template <typename value_t>
class packed_store_result_t final {
public:
    static packed_store_result_t success(value_t value) {
        return packed_store_result_t(std::move(value));
    }

    static packed_store_result_t failure(packed_store_error_t error) noexcept {
        return packed_store_result_t(error);
    }

    bool has_value() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return has_value(); }

    const value_t& value() const & { return value_.value(); }
    value_t& value() & { return value_.value(); }
    value_t take_value() && { return std::move(value_).value(); }
    const packed_store_error_t& error() const noexcept { return error_; }

private:
    explicit packed_store_result_t(value_t value) : value_(std::move(value)) {}
    explicit packed_store_result_t(packed_store_error_t error) noexcept : error_(error) {}

    std::optional<value_t> value_;
    packed_store_error_t error_{};
};

template <>
class packed_store_result_t<void> final {
public:
    static packed_store_result_t success() noexcept { return packed_store_result_t(true, {}); }

    static packed_store_result_t failure(packed_store_error_t error) noexcept {
        return packed_store_result_t(false, error);
    }

    bool has_value() const noexcept { return success_; }
    explicit operator bool() const noexcept { return has_value(); }
    const packed_store_error_t& error() const noexcept { return error_; }

private:
    packed_store_result_t(bool success, packed_store_error_t error) noexcept
        : success_(success), error_(error) {}

    bool success_ = false;
    packed_store_error_t error_{};
};

class packed_string_id_t final {
public:
    constexpr packed_string_id_t() noexcept = default;

    static constexpr packed_string_id_t from_value(std::uint32_t value) noexcept {
        return packed_string_id_t(value);
    }

    constexpr std::uint32_t value() const noexcept { return value_; }
    constexpr bool valid() const noexcept { return value_ != 0; }

    constexpr bool operator==(const packed_string_id_t& other) const noexcept {
        return value_ == other.value_;
    }

    constexpr bool operator!=(const packed_string_id_t& other) const noexcept {
        return !(*this == other);
    }

    constexpr bool operator<(const packed_string_id_t& other) const noexcept {
        return value_ < other.value_;
    }

private:
    explicit constexpr packed_string_id_t(std::uint32_t value) noexcept : value_(value) {}

    std::uint32_t value_ = 0;

    friend class packed_string_pool_t;
    friend class packed_string_pool_builder_t;
};

struct packed_string_pool_size_t final {
    std::uint64_t string_count = 0;
    std::uint64_t payload_bytes = 0;
    std::uint64_t reserved_bytes = 0;
};

class packed_string_pool_t final {
public:
    packed_string_pool_t() = default;

    static packed_store_result_t<packed_string_pool_t>
        build_deterministic(std::vector<std::string> values);

    std::uint32_t size() const noexcept;
    std::optional<std::string_view> lookup(packed_string_id_t id) const noexcept;
    packed_store_result_t<void> validate() const noexcept;
    packed_string_pool_size_t size_accounting() const noexcept;

private:
    static packed_store_result_t<packed_string_pool_t>
        build_preserving_order(const std::vector<std::string>& values);

    std::vector<std::uint32_t> offsets_;
    std::vector<std::uint32_t> lengths_;
    std::vector<char> bytes_;

    friend class packed_string_pool_builder_t;
    friend class packed_analysis_store_t;
};

class packed_string_pool_builder_t final {
public:
    packed_store_result_t<packed_string_id_t> intern(std::string_view value);
    packed_store_result_t<packed_string_pool_t> freeze() const;
    void reserve(std::size_t string_estimate);
    std::uint32_t size() const noexcept;

private:
    std::vector<std::string> values_;
    aida::infra::fast_flat_map<std::string, packed_string_id_t> index_;
};

static_assert(sizeof(packed_string_id_t) == sizeof(std::uint32_t),
              "packed string identifiers must remain 32-bit");

}
