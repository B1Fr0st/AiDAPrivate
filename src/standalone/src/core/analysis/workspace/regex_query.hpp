#pragma once

#include "workspace_types.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace aida::analysis {

struct regex_query_limits_t {
    std::uint32_t max_pattern_bytes = 64U * 1024U;
    std::uint32_t max_subject_bytes = 16U * 1024U * 1024U;
    std::uint32_t max_compiled_bytes = 4U * 1024U * 1024U;
    std::uint32_t max_capture_count = 256;
    std::uint32_t max_parenthesis_depth = 256;
    std::uint32_t max_variable_lookbehind = 255;
    std::uint32_t match_limit = 250000;
    std::uint32_t depth_limit = 1000;
    std::uint32_t heap_limit_kib = 64U * 1024U;
    std::uint64_t max_elapsed_ns = 50ULL * 1000ULL * 1000ULL;
};

struct regex_compile_options_t {
    bool case_sensitive = true;
    bool multiline = false;
    bool dot_all = false;
    bool extended = false;
    bool literal = false;
};

struct regex_match_result_t {
    bool matched = false;
    std::size_t start = 0;
    std::size_t length = 0;
    std::uint64_t engine_steps = 0;
};

class regex_query_t;

class regex_match_session_t final {
public:
    regex_match_session_t(regex_match_session_t&&) noexcept;
    regex_match_session_t& operator=(regex_match_session_t&&) noexcept;
    ~regex_match_session_t();

    regex_match_session_t(const regex_match_session_t&) = delete;
    regex_match_session_t& operator=(const regex_match_session_t&) = delete;

    workspace_result_t<regex_match_result_t> match(std::string_view subject);
    std::uint64_t subjects_examined() const noexcept;
    std::uint64_t engine_steps() const noexcept;

private:
    struct impl_t;
    explicit regex_match_session_t(std::unique_ptr<impl_t> impl) noexcept;
    std::unique_ptr<impl_t> impl_;

    friend class regex_query_t;
};

class regex_query_t final : public std::enable_shared_from_this<regex_query_t> {
public:
    static workspace_result_t<void> validate_limits(const regex_query_limits_t& limits);
    static workspace_result_t<std::shared_ptr<const regex_query_t>> compile(
        std::string_view pattern, const regex_compile_options_t& options = {},
        const regex_query_limits_t& limits = {});

    ~regex_query_t();
    regex_query_t(const regex_query_t&) = delete;
    regex_query_t& operator=(const regex_query_t&) = delete;

    std::string_view pattern() const noexcept;
    const regex_compile_options_t& options() const noexcept;
    const regex_query_limits_t& limits() const noexcept;
    std::uint32_t capture_count() const noexcept;
    std::uint64_t compiled_bytes() const noexcept;
    workspace_result_t<regex_match_session_t> create_session(
        const cancellation_token_t& cancel,
        std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt) const;
    workspace_result_t<regex_match_result_t> match(
        std::string_view subject, const cancellation_token_t& cancel = {},
        std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt) const;

private:
    struct impl_t;
    explicit regex_query_t(std::unique_ptr<impl_t> impl) noexcept;
    std::unique_ptr<impl_t> impl_;
};

}
