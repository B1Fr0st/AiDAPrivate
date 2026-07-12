#pragma once

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace aida::standalone::mcp::compat {

enum class target_resolution_error_code_t : std::uint8_t {
    none = 0,
    invalid_target_record,
    invalid_selector,
    target_selection_required,
    target_not_found,
    target_ambiguous,
    target_generation_stale,
    target_pid_reused,
    target_retired
};

struct target_resolution_error_t final {
    target_resolution_error_code_t code = target_resolution_error_code_t::none;
    std::string_view stable_code;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;

    constexpr explicit operator bool() const noexcept {
        return code != target_resolution_error_code_t::none;
    }
};

struct target_selector_t final {
    std::optional<std::uint32_t> pid;
    std::optional<std::string> bin_name;
};

struct target_record_t final {
    std::uint64_t target_id = 0;
    std::uint32_t pid = 0;
    std::uint64_t process_creation_identity = 0;
    std::string bin_name;
    std::uint64_t generation = 0;
    std::uint64_t attach_generation = 0;
    bool live = false;
    std::uint64_t live_capture_base = 0;
    std::uint64_t live_capture_size = 0;
    bool live_snapshot_permitted = false;
    std::uint64_t live_snapshot_maximum_bytes = 0;
    std::uint64_t revision = 0;
};

struct target_resolution_options_t final {
    bool allow_unique_substring = true;
    bool require_selector_when_multiple = true;
};

class target_resolution_t final {
public:
    target_resolution_t() = default;

    bool valid() const noexcept;
    const target_record_t& target() const noexcept;
    std::uint64_t resolver_revision() const noexcept;

private:
    friend class target_resolver_t;

    target_resolution_t(target_record_t target, std::uint64_t resolver_revision) noexcept;

    target_record_t target_;
    std::uint64_t resolver_revision_ = 0;
};

class target_resolution_result_t final {
public:
    static target_resolution_result_t success(target_resolution_t value) noexcept;
    static target_resolution_result_t failure(target_resolution_error_t error) noexcept;

    bool has_value() const noexcept;
    explicit operator bool() const noexcept;
    const target_resolution_t& value() const noexcept;
    target_resolution_t take_value() && noexcept;
    const target_resolution_error_t& error() const noexcept;

private:
    explicit target_resolution_result_t(target_resolution_t value) noexcept;
    explicit target_resolution_result_t(target_resolution_error_t error) noexcept;

    std::optional<target_resolution_t> value_;
    target_resolution_error_t error_{};
};

class target_execution_pin_t final {
public:
    target_execution_pin_t() = default;
    target_execution_pin_t(const target_execution_pin_t&) = delete;
    target_execution_pin_t& operator=(const target_execution_pin_t&) = delete;
    target_execution_pin_t(target_execution_pin_t&&) noexcept = default;
    target_execution_pin_t& operator=(target_execution_pin_t&&) noexcept = default;

    bool owns_pin() const noexcept;
    const target_resolution_t& resolution() const noexcept;
    const target_record_t& target() const noexcept;

private:
    friend class target_resolver_t;

    target_execution_pin_t(std::shared_lock<std::shared_mutex> lock,
                           target_resolution_t resolution) noexcept;

    std::shared_lock<std::shared_mutex> lock_;
    target_resolution_t resolution_;
};

struct target_execution_pin_result_t final {
    target_execution_pin_t pin;
    target_resolution_error_t error{};

    bool has_value() const noexcept;
    explicit operator bool() const noexcept;
};

struct target_resolver_status_t final {
    target_resolution_error_t error{};

    bool succeeded() const noexcept;
    explicit operator bool() const noexcept;
};

class target_resolver_t final {
public:
    target_resolver_t() = default;
    target_resolver_t(const target_resolver_t&) = delete;
    target_resolver_t& operator=(const target_resolver_t&) = delete;

    target_resolver_status_t publish(target_record_t record);
    target_resolver_status_t retire(std::uint64_t target_id);
    target_resolution_result_t resolve(
        const target_selector_t& selector,
        std::optional<std::uint64_t> expected_generation = {},
        target_resolution_options_t options = {}) const;
    target_resolver_status_t validate_current(
        const target_resolution_t& resolution,
        std::optional<std::uint64_t> expected_generation = {}) const;
    target_execution_pin_result_t pin_current(
        const target_resolution_t& resolution,
        std::optional<std::uint64_t> expected_generation = {}) const;
    std::vector<target_record_t> snapshot() const;

private:
    struct retired_target_t final {
        target_resolution_error_t error;
    };

    static target_resolution_error_t make_error(target_resolution_error_code_t code,
                                                std::uint64_t expected = 0,
                                                std::uint64_t actual = 0) noexcept;
    static bool valid_record(const target_record_t& record) noexcept;
    static bool valid_selector(const target_selector_t& selector) noexcept;
    static std::string canonical_bin_name(std::string_view value);
    static bool record_matches_pid(const target_record_t& record,
                                   const target_selector_t& selector) noexcept;
    static bool record_matches_exact_name(const target_record_t& record,
                                          std::string_view canonical_name) noexcept;
    static bool record_matches_substring(const target_record_t& record,
                                         std::string_view canonical_name) noexcept;

    mutable std::shared_mutex mutex_;
    mutable std::shared_mutex execution_mutex_;
    std::unordered_map<std::uint64_t, target_record_t> active_;
    std::unordered_map<std::uint64_t, retired_target_t> retired_;
    std::uint64_t next_revision_ = 1;
};

}
