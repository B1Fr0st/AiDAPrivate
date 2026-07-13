#pragma once

#include "regex_query.hpp"
#include "search_index.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace aida::analysis {

class provider_snapshot_t;

enum class search_query_kind_t : std::uint8_t {
    literal = 0,
    regex,
    bytes,
    instruction,
    entity,
    address,
    invalid = 0xffU
};

struct literal_search_query_t {
    std::string text;
    bool case_sensitive = false;
};

struct regex_search_query_t {
    std::string pattern;
    regex_compile_options_t options;
};

struct byte_search_query_t {
    std::vector<std::uint8_t> pattern;
    std::vector<std::uint8_t> mask;
    std::uint64_t begin_offset = 0;
    std::optional<std::uint64_t> end_offset;
};

struct instruction_search_query_t {
    search_instruction_filter_t filter;
};

struct entity_search_query_t {
    search_entity_filter_t filter;
};

struct address_search_query_t {
    address_t begin;
    address_t end;
};

using search_query_t = std::variant<literal_search_query_t, regex_search_query_t,
    byte_search_query_t, instruction_search_query_t, entity_search_query_t,
    address_search_query_t>;

struct query_cursor_t {
    search_generation_identity_t generation;
    std::uint64_t query_fingerprint = 0;
    std::uint64_t position = 0;
    std::uint64_t matches_consumed = 0;
    std::uint64_t integrity_tag = 0;
};

struct query_page_request_t {
    std::uint32_t limit = 100;
    std::optional<query_cursor_t> cursor;
};

struct query_page_t {
    std::vector<search_hit_t> hits;
    std::uint64_t total = 0;
    bool total_is_exact = true;
    bool truncated = false;
    std::optional<query_cursor_t> next;
};

enum class query_outcome_t : std::uint8_t {
    success = 0,
    invalid,
    cancelled,
    deadline,
    limited,
    failed
};

struct query_telemetry_t {
    search_query_kind_t kind = search_query_kind_t::literal;
    query_outcome_t outcome = query_outcome_t::success;
    std::uint64_t generation = 0;
    std::uint64_t query_fingerprint = 0;
    std::uint64_t elapsed_ns = 0;
    std::uint64_t candidates_examined = 0;
    std::uint64_t matches = 0;
    std::uint64_t returned = 0;
    std::uint64_t bytes_scanned = 0;
    std::uint64_t regex_engine_steps = 0;
    std::uint64_t cancellation_checks = 0;
    std::uint64_t invalid_utf_subjects = 0;
    bool total_is_exact = true;
};

using query_telemetry_hook_t = std::function<void(const query_telemetry_t&)>;

struct query_index_limits_t {
    std::uint32_t max_page_size = 4096;
    std::uint32_t max_query_bytes = 1U * 1024U * 1024U;
    std::uint32_t max_byte_pattern_bytes = 64U * 1024U;
    std::uint64_t max_bytes_scanned_per_page = 1024ULL * 1024ULL * 1024ULL;
    std::uint32_t byte_scan_window_bytes = 4U * 1024U * 1024U;
    std::uint64_t max_regex_candidates = 16ULL * 1024ULL * 1024ULL;
    std::uint32_t cancellation_check_interval = 4096;
    std::uint64_t max_query_elapsed_ns = 2ULL * 1000ULL * 1000ULL * 1000ULL;
    regex_query_limits_t regex;
};

class query_index_t final {
public:
    static workspace_result_t<std::shared_ptr<const query_index_t>> build(
        std::shared_ptr<const search_index_t> index,
        std::shared_ptr<const provider_snapshot_t> provider = {},
        const query_index_limits_t& limits = {},
        query_telemetry_hook_t telemetry = {});
    static workspace_result_t<std::shared_ptr<const query_index_t>> build(
        search_generation_handle_t generation,
        std::shared_ptr<const provider_snapshot_t> provider = {},
        const query_index_limits_t& limits = {},
        query_telemetry_hook_t telemetry = {});

    ~query_index_t();
    query_index_t(const query_index_t&) = delete;
    query_index_t& operator=(const query_index_t&) = delete;

    const search_generation_identity_t& identity() const noexcept;
    const search_generation_handle_t& generation_handle() const noexcept;
    const query_index_limits_t& limits() const noexcept;
    bool has_byte_provider() const noexcept;
    workspace_result_t<query_page_t> query(const search_query_t& query,
        const query_page_request_t& page = {},
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<void> validate_cursor(
        const search_query_t& query,
        const query_cursor_t& cursor) const;
    workspace_result_t<query_page_t> query_literal(
        const literal_search_query_t& query,
        const query_page_request_t& page = {},
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<query_page_t> query_regex(
        const regex_search_query_t& query,
        const query_page_request_t& page = {},
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<query_page_t> query_bytes(
        const byte_search_query_t& query,
        const query_page_request_t& page = {},
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<query_page_t> query_instruction(
        const instruction_search_query_t& query,
        const query_page_request_t& page = {},
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<query_page_t> query_entity(
        const entity_search_query_t& query,
        const query_page_request_t& page = {},
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<query_page_t> query_address(
        const address_search_query_t& query,
        const query_page_request_t& page = {},
        const cancellation_token_t& cancel = {}) const;

private:
    struct impl_t;
    explicit query_index_t(std::unique_ptr<impl_t> impl) noexcept;
    std::unique_ptr<impl_t> impl_;
};

}
