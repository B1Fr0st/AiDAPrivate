#pragma once

#include "../workbench_contracts.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace aida::workbench::navigator {

inline constexpr std::uint32_t k_navigator_contract_schema_version = 1;
inline constexpr std::uint32_t k_navigator_max_page_size = 4096;
inline constexpr std::size_t k_navigator_max_filter_bytes = 4096;

struct navigator_row_id_t final {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

constexpr bool operator==(navigator_row_id_t lhs, navigator_row_id_t rhs) noexcept
{
    return lhs.value == rhs.value;
}

constexpr bool operator!=(navigator_row_id_t lhs, navigator_row_id_t rhs) noexcept
{
    return !(lhs == rhs);
}

constexpr bool operator<(navigator_row_id_t lhs, navigator_row_id_t rhs) noexcept
{
    return lhs.value < rhs.value;
}

enum class navigator_domain_t : std::uint8_t {
    invalid = 0,
    binaries = 1,
    sections = 2,
    functions = 3,
    imports = 4,
    exports = 5,
    strings = 6,
    symbols = 7,
    types = 8,
    diagnostics = 9,
    bookmarks = 10,
    progress = 11
};

enum class navigator_severity_t : std::uint8_t {
    none = 0,
    information = 1,
    warning = 2,
    error = 3,
    fatal = 4
};

enum class navigator_sort_key_t : std::uint8_t {
    label = 0,
    secondary = 1,
    detail = 2,
    address = 3,
    metric = 4,
    severity = 5,
    identifier = 6
};

enum class navigator_query_status_t : std::uint8_t {
    idle = 0,
    filtering = 1,
    sorting = 2,
    ready = 3,
    cancelled = 4,
    stale = 5,
    failed = 6
};

enum class navigator_error_code_t : std::uint16_t {
    none = 0,
    invalid_argument = 1,
    invalid_domain = 2,
    invalid_page = 3,
    adapter_rejected = 4,
    stale_snapshot = 5,
    cancelled = 6,
    query_not_started = 7,
    query_not_ready = 8,
    query_failed = 9,
    resource_exhausted = 10,
    navigation_rejected = 11,
    sequence_exhausted = 12
};

struct navigator_error_t final {
    navigator_error_code_t code = navigator_error_code_t::none;
    navigator_domain_t domain = navigator_domain_t::invalid;
    std::uint64_t subject = 0;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;

    constexpr bool ok() const noexcept { return code == navigator_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

struct navigator_item_view_t final {
    navigator_domain_t domain = navigator_domain_t::invalid;
    navigator_row_id_t id;
    navigator_row_id_t parent;
    std::string_view label;
    std::string_view secondary;
    std::string_view detail;
    bool has_address = false;
    std::uint64_t address = 0;
    std::uint64_t metric = 0;
    navigator_severity_t severity = navigator_severity_t::none;
    bool selectable = true;
    bool expandable = false;
};

struct navigator_page_request_t final {
    std::uint64_t offset = 0;
    std::uint32_t limit = 0;
};

struct navigator_tree_request_t final {
    navigator_domain_t domain = navigator_domain_t::invalid;
    navigator_row_id_t parent;
    navigator_page_request_t page;
};

struct navigator_tree_page_t final {
    std::uint64_t snapshot_generation = 0;
    std::uint64_t total_rows = 0;
    std::uint64_t offset = 0;
    std::uint64_t next_offset = 0;
    std::vector<navigator_item_view_t> rows;
};

struct navigator_filter_t final {
    std::string text;
    bool case_sensitive = false;
};

struct navigator_sort_t final {
    navigator_sort_key_t key = navigator_sort_key_t::label;
    bool descending = false;
};

struct navigator_query_t final {
    navigator_domain_t domain = navigator_domain_t::invalid;
    navigator_filter_t filter;
    navigator_sort_t sort;
};

struct navigator_query_progress_t final {
    navigator_query_status_t status = navigator_query_status_t::idle;
    std::uint64_t snapshot_generation = 0;
    std::uint64_t source_rows = 0;
    std::uint64_t inspected_rows = 0;
    std::uint64_t matched_rows = 0;
    std::uint64_t sort_operations = 0;
};

struct navigator_query_page_t final {
    std::uint64_t snapshot_generation = 0;
    std::uint64_t total_rows = 0;
    std::uint64_t offset = 0;
    std::uint64_t next_offset = 0;
    std::vector<navigator_item_view_t> rows;
};

class navigator_cancellation_t {
public:
    virtual ~navigator_cancellation_t() = default;
    virtual bool cancelled() const noexcept = 0;
};

class navigator_packed_store_adapter_t {
public:
    virtual ~navigator_packed_store_adapter_t() = default;

    virtual std::uint64_t current_generation() const noexcept = 0;
    virtual bool generation_current(std::uint64_t generation) const noexcept = 0;
    virtual std::uint64_t record_count(navigator_domain_t domain,
                                       std::uint64_t generation) const noexcept = 0;
    virtual bool record_at(navigator_domain_t domain, std::uint64_t generation,
                           std::uint64_t ordinal, navigator_item_view_t& output) const noexcept = 0;
    virtual std::uint64_t tree_child_count(navigator_domain_t domain,
                                           std::uint64_t generation,
                                           navigator_row_id_t parent) const noexcept = 0;
    virtual bool tree_child_at(navigator_domain_t domain, std::uint64_t generation,
                               navigator_row_id_t parent, std::uint64_t ordinal,
                               navigator_item_view_t& output) const noexcept = 0;
    virtual bool navigation_document(navigator_domain_t domain, std::uint64_t generation,
                                     navigator_row_id_t id, std::uint64_t address,
                                     document_identity_t& output) const = 0;
};

class navigator_tree_model_t final {
public:
    explicit navigator_tree_model_t(const navigator_packed_store_adapter_t& adapter) noexcept;

    navigator_error_t page(const navigator_tree_request_t& request,
                           const navigator_cancellation_t* cancellation,
                           navigator_tree_page_t& output) const;

private:
    const navigator_packed_store_adapter_t* adapter_ = nullptr;
};

class navigator_query_model_t final {
public:
    explicit navigator_query_model_t(const navigator_packed_store_adapter_t& adapter) noexcept;

    navigator_error_t begin(const navigator_query_t& query);
    navigator_error_t advance(std::uint32_t work_budget,
                              const navigator_cancellation_t* cancellation);
    navigator_error_t page(const navigator_page_request_t& request,
                           navigator_query_page_t& output) const;
    void cancel() noexcept;

    navigator_query_status_t status() const noexcept;
    navigator_query_progress_t progress() const noexcept;
    std::size_t indexed_row_count() const noexcept;

private:
    struct row_reference_t final {
        std::uint64_t ordinal = 0;
        navigator_row_id_t id;
    };

    navigator_error_t fail(navigator_error_code_t code, std::uint64_t subject = 0,
                           std::uint64_t expected = 0, std::uint64_t actual = 0) noexcept;
    navigator_error_t stale() noexcept;
    navigator_error_t initialize_sorting();
    navigator_error_t advance_filtering(std::uint32_t& work_budget,
                                        const navigator_cancellation_t* cancellation);
    navigator_error_t advance_sorting(std::uint32_t& work_budget,
                                      const navigator_cancellation_t* cancellation);
    bool read_row(const row_reference_t& reference, navigator_item_view_t& output) const noexcept;
    bool read_row(std::uint64_t ordinal, navigator_item_view_t& output) const noexcept;
    bool matches_filter(const navigator_item_view_t& item) const noexcept;
    int compare_rows(const row_reference_t& lhs, const row_reference_t& rhs,
                     bool& adapter_ok) const noexcept;
    void start_merge() noexcept;
    const std::vector<row_reference_t>& sorted_rows() const noexcept;

    const navigator_packed_store_adapter_t* adapter_ = nullptr;
    navigator_query_t query_;
    navigator_query_progress_t progress_;
    std::vector<row_reference_t> rows_;
    std::vector<row_reference_t> scratch_;
    std::uint64_t filter_ordinal_ = 0;
    std::uint64_t sort_width_ = 0;
    std::uint64_t merge_left_ = 0;
    std::uint64_t merge_middle_ = 0;
    std::uint64_t merge_right_ = 0;
    std::uint64_t merge_left_cursor_ = 0;
    std::uint64_t merge_right_cursor_ = 0;
    std::uint64_t merge_output_cursor_ = 0;
    bool merge_source_is_rows_ = true;
};

class navigator_source_allocator_t {
public:
    virtual ~navigator_source_allocator_t() = default;
    virtual view_context_t allocate_copy(const view_context_t& source) const = 0;
};

class navigator_navigation_model_t final {
public:
    navigator_navigation_model_t(const navigator_packed_store_adapter_t& adapter,
                                 workspace_id_t workspace,
                                 navigation_event_id_t first_event_id = {1},
                                 std::uint64_t first_sequence = 1,
                                 bool request_focus = true,
                                 const navigator_source_allocator_t* source_allocator = nullptr) noexcept;

    navigator_error_t set_source(const view_context_t& source);
    void clear_source() noexcept;
    navigator_error_t make_address_event(const navigator_item_view_t& item,
                                         navigation_event_t& output);

private:
    navigator_error_t error(navigator_error_code_t code, navigator_domain_t domain,
                            std::uint64_t subject = 0) const noexcept;

    const navigator_packed_store_adapter_t* adapter_ = nullptr;
    const navigator_source_allocator_t* source_allocator_ = nullptr;
    workspace_id_t workspace_;
    view_context_t source_;
    navigation_event_id_t next_event_id_;
    std::uint64_t next_sequence_ = 0;
    bool has_source_ = false;
    bool request_focus_ = true;
    bool exhausted_ = false;
};

bool navigator_domain_valid(navigator_domain_t domain) noexcept;
std::string_view navigator_domain_name(navigator_domain_t domain) noexcept;

}
