#include "workbench_navigator.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>

namespace aida::workbench::navigator {
namespace {

navigator_error_t make_error(navigator_error_code_t code, navigator_domain_t domain,
                             std::uint64_t subject = 0, std::uint64_t expected = 0,
                             std::uint64_t actual = 0) noexcept
{
    return {code, domain, subject, expected, actual};
}

bool page_valid(const navigator_page_request_t& page) noexcept
{
    return page.limit != 0 && page.limit <= k_navigator_max_page_size;
}

bool sort_key_valid(navigator_sort_key_t key) noexcept
{
    return key <= navigator_sort_key_t::identifier;
}

bool cancellation_requested(const navigator_cancellation_t* cancellation) noexcept
{
    return cancellation != nullptr && cancellation->cancelled();
}

bool item_valid(const navigator_item_view_t& item, navigator_domain_t expected_domain) noexcept
{
    return item.domain == expected_domain && navigator_domain_valid(item.domain) && item.id.valid() &&
        item.severity <= navigator_severity_t::fatal && (!item.has_address ? item.address == 0 : true);
}

unsigned char ascii_lower(unsigned char value) noexcept
{
    return value >= static_cast<unsigned char>('A') && value <= static_cast<unsigned char>('Z')
        ? static_cast<unsigned char>(value + static_cast<unsigned char>('a' - 'A'))
        : value;
}

int compare_text(std::string_view lhs, std::string_view rhs, bool case_sensitive) noexcept
{
    const std::size_t common = (std::min)(lhs.size(), rhs.size());
    for (std::size_t index = 0; index < common; ++index) {
        const unsigned char left = case_sensitive ? static_cast<unsigned char>(lhs[index]) :
            ascii_lower(static_cast<unsigned char>(lhs[index]));
        const unsigned char right = case_sensitive ? static_cast<unsigned char>(rhs[index]) :
            ascii_lower(static_cast<unsigned char>(rhs[index]));
        if (left < right)
            return -1;
        if (left > right)
            return 1;
    }
    return lhs.size() < rhs.size() ? -1 : (lhs.size() > rhs.size() ? 1 : 0);
}

bool contains_text(std::string_view value, std::string_view needle, bool case_sensitive) noexcept
{
    if (needle.empty())
        return true;
    if (needle.size() > value.size())
        return false;
    const std::size_t last_start = value.size() - needle.size();
    for (std::size_t start = 0; start <= last_start; ++start) {
        bool matched = true;
        for (std::size_t offset = 0; offset < needle.size(); ++offset) {
            const unsigned char left = case_sensitive ? static_cast<unsigned char>(value[start + offset]) :
                ascii_lower(static_cast<unsigned char>(value[start + offset]));
            const unsigned char right = case_sensitive ? static_cast<unsigned char>(needle[offset]) :
                ascii_lower(static_cast<unsigned char>(needle[offset]));
            if (left != right) {
                matched = false;
                break;
            }
        }
        if (matched)
            return true;
    }
    return false;
}

int compare_u64(std::uint64_t lhs, std::uint64_t rhs) noexcept
{
    return lhs < rhs ? -1 : (lhs > rhs ? 1 : 0);
}

bool row_reference_count_representable(std::uint64_t count) noexcept
{
    return count <= static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)());
}

}

bool navigator_domain_valid(navigator_domain_t domain) noexcept
{
    return domain >= navigator_domain_t::binaries && domain <= navigator_domain_t::progress;
}

std::string_view navigator_domain_name(navigator_domain_t domain) noexcept
{
    switch (domain) {
        case navigator_domain_t::binaries: return "binaries";
        case navigator_domain_t::sections: return "sections";
        case navigator_domain_t::functions: return "functions";
        case navigator_domain_t::imports: return "imports";
        case navigator_domain_t::exports: return "exports";
        case navigator_domain_t::strings: return "strings";
        case navigator_domain_t::symbols: return "symbols";
        case navigator_domain_t::types: return "types";
        case navigator_domain_t::diagnostics: return "diagnostics";
        case navigator_domain_t::bookmarks: return "bookmarks";
        case navigator_domain_t::progress: return "progress";
        case navigator_domain_t::invalid: return "invalid";
    }
    return "invalid";
}

navigator_tree_model_t::navigator_tree_model_t(const navigator_packed_store_adapter_t& adapter) noexcept
    : adapter_(&adapter)
{
}

navigator_error_t navigator_tree_model_t::page(const navigator_tree_request_t& request,
                                                const navigator_cancellation_t* cancellation,
                                                navigator_tree_page_t& output) const
{
    output = {};
    if (!navigator_domain_valid(request.domain))
        return make_error(navigator_error_code_t::invalid_domain, request.domain);
    if (!page_valid(request.page))
        return make_error(navigator_error_code_t::invalid_page, request.domain, request.page.offset,
                          k_navigator_max_page_size, request.page.limit);
    if (cancellation_requested(cancellation))
        return make_error(navigator_error_code_t::cancelled, request.domain);

    const std::uint64_t generation = adapter_->current_generation();
    if (generation == 0 || !adapter_->generation_current(generation))
        return make_error(navigator_error_code_t::stale_snapshot, request.domain, generation);
    const std::uint64_t total = adapter_->tree_child_count(request.domain, generation, request.parent);
    if (request.page.offset > total)
        return make_error(navigator_error_code_t::invalid_page, request.domain, request.page.offset, total);

    const std::uint64_t available = total - request.page.offset;
    const std::uint64_t requested = (std::min)(available, static_cast<std::uint64_t>(request.page.limit));
    try {
        output.rows.reserve(static_cast<std::size_t>(requested));
    } catch (const std::bad_alloc&) {
        return make_error(navigator_error_code_t::resource_exhausted, request.domain, requested);
    }

    for (std::uint64_t offset = 0; offset < requested; ++offset) {
        if (cancellation_requested(cancellation)) {
            output = {};
            return make_error(navigator_error_code_t::cancelled, request.domain);
        }
        if (!adapter_->generation_current(generation)) {
            output = {};
            return make_error(navigator_error_code_t::stale_snapshot, request.domain, generation);
        }
        navigator_item_view_t item;
        if (!adapter_->tree_child_at(request.domain, generation, request.parent,
                                     request.page.offset + offset, item) ||
            !item_valid(item, request.domain) || item.parent != request.parent) {
            output = {};
            return make_error(navigator_error_code_t::adapter_rejected, request.domain,
                              request.page.offset + offset);
        }
        output.rows.push_back(item);
    }

    if (!adapter_->generation_current(generation)) {
        output = {};
        return make_error(navigator_error_code_t::stale_snapshot, request.domain, generation);
    }
    output.snapshot_generation = generation;
    output.total_rows = total;
    output.offset = request.page.offset;
    output.next_offset = request.page.offset + requested;
    return {};
}

navigator_query_model_t::navigator_query_model_t(const navigator_packed_store_adapter_t& adapter) noexcept
    : adapter_(&adapter)
{
}

navigator_error_t navigator_query_model_t::begin(const navigator_query_t& query)
{
    rows_.clear();
    scratch_.clear();
    query_ = {};
    query_.domain = query.domain;
    progress_ = {};
    filter_ordinal_ = 0;
    sort_width_ = 0;
    merge_left_ = 0;
    merge_middle_ = 0;
    merge_right_ = 0;
    merge_left_cursor_ = 0;
    merge_right_cursor_ = 0;
    merge_output_cursor_ = 0;
    merge_source_is_rows_ = true;

    if (!navigator_domain_valid(query.domain))
        return fail(navigator_error_code_t::invalid_domain);
    if (query.filter.text.size() > k_navigator_max_filter_bytes ||
        query.filter.text.find('\0') != std::string::npos || !sort_key_valid(query.sort.key)) {
        return fail(navigator_error_code_t::invalid_argument, query.filter.text.size());
    }
    const std::uint64_t generation = adapter_->current_generation();
    if (generation == 0 || !adapter_->generation_current(generation))
        return stale();
    const std::uint64_t source_rows = adapter_->record_count(query.domain, generation);
    if (!row_reference_count_representable(source_rows))
        return fail(navigator_error_code_t::resource_exhausted, source_rows);
    try {
        query_ = query;
    } catch (const std::bad_alloc&) {
        return fail(navigator_error_code_t::resource_exhausted, query.filter.text.size());
    }
    progress_.status = navigator_query_status_t::filtering;
    progress_.snapshot_generation = generation;
    progress_.source_rows = source_rows;
    return {};
}

navigator_error_t navigator_query_model_t::advance(std::uint32_t work_budget,
                                                    const navigator_cancellation_t* cancellation)
{
    if (progress_.status == navigator_query_status_t::idle)
        return make_error(navigator_error_code_t::query_not_started, query_.domain);
    if (progress_.status == navigator_query_status_t::ready)
        return {};
    if (progress_.status == navigator_query_status_t::cancelled)
        return make_error(navigator_error_code_t::cancelled, query_.domain);
    if (progress_.status == navigator_query_status_t::stale)
        return make_error(navigator_error_code_t::stale_snapshot, query_.domain,
                          progress_.snapshot_generation);
    if (progress_.status == navigator_query_status_t::failed)
        return make_error(navigator_error_code_t::query_failed, query_.domain);
    if (work_budget == 0)
        return make_error(navigator_error_code_t::invalid_argument, query_.domain);
    if (cancellation_requested(cancellation)) {
        cancel();
        return make_error(navigator_error_code_t::cancelled, query_.domain);
    }
    if (!adapter_->generation_current(progress_.snapshot_generation))
        return stale();

    if (progress_.status == navigator_query_status_t::filtering)
        return advance_filtering(work_budget, cancellation);
    return advance_sorting(work_budget, cancellation);
}

navigator_error_t navigator_query_model_t::page(const navigator_page_request_t& request,
                                                 navigator_query_page_t& output) const
{
    output = {};
    if (progress_.status == navigator_query_status_t::idle)
        return make_error(navigator_error_code_t::query_not_started, query_.domain);
    if (progress_.status == navigator_query_status_t::cancelled)
        return make_error(navigator_error_code_t::cancelled, query_.domain);
    if (progress_.status == navigator_query_status_t::stale)
        return make_error(navigator_error_code_t::stale_snapshot, query_.domain,
                          progress_.snapshot_generation);
    if (progress_.status == navigator_query_status_t::failed)
        return make_error(navigator_error_code_t::query_failed, query_.domain);
    if (progress_.status != navigator_query_status_t::ready)
        return make_error(navigator_error_code_t::query_not_ready, query_.domain);
    if (!page_valid(request))
        return make_error(navigator_error_code_t::invalid_page, query_.domain, request.offset,
                          k_navigator_max_page_size, request.limit);
    if (!adapter_->generation_current(progress_.snapshot_generation))
        return make_error(navigator_error_code_t::stale_snapshot, query_.domain,
                          progress_.snapshot_generation);

    const auto& sorted = sorted_rows();
    const std::uint64_t total = static_cast<std::uint64_t>(sorted.size());
    if (request.offset > total)
        return make_error(navigator_error_code_t::invalid_page, query_.domain, request.offset, total);
    const std::uint64_t available = total - request.offset;
    const std::uint64_t requested = (std::min)(available, static_cast<std::uint64_t>(request.limit));
    try {
        output.rows.reserve(static_cast<std::size_t>(requested));
    } catch (const std::bad_alloc&) {
        return make_error(navigator_error_code_t::resource_exhausted, query_.domain, requested);
    }

    for (std::uint64_t offset = 0; offset < requested; ++offset) {
        if (!adapter_->generation_current(progress_.snapshot_generation)) {
            output = {};
            return make_error(navigator_error_code_t::stale_snapshot, query_.domain,
                              progress_.snapshot_generation);
        }
        const auto& reference = sorted[static_cast<std::size_t>(request.offset + offset)];
        navigator_item_view_t item;
        if (!read_row(reference, item)) {
            output = {};
            return make_error(navigator_error_code_t::adapter_rejected, query_.domain,
                              reference.ordinal);
        }
        output.rows.push_back(item);
    }
    if (!adapter_->generation_current(progress_.snapshot_generation)) {
        output = {};
        return make_error(navigator_error_code_t::stale_snapshot, query_.domain,
                          progress_.snapshot_generation);
    }
    output.snapshot_generation = progress_.snapshot_generation;
    output.total_rows = total;
    output.offset = request.offset;
    output.next_offset = request.offset + requested;
    return {};
}

void navigator_query_model_t::cancel() noexcept
{
    rows_.clear();
    scratch_.clear();
    progress_.matched_rows = 0;
    progress_.status = navigator_query_status_t::cancelled;
}

navigator_query_status_t navigator_query_model_t::status() const noexcept
{
    return progress_.status;
}

navigator_query_progress_t navigator_query_model_t::progress() const noexcept
{
    return progress_;
}

std::size_t navigator_query_model_t::indexed_row_count() const noexcept
{
    return rows_.size();
}

navigator_error_t navigator_query_model_t::fail(navigator_error_code_t code, std::uint64_t subject,
                                                 std::uint64_t expected, std::uint64_t actual) noexcept
{
    rows_.clear();
    scratch_.clear();
    progress_.matched_rows = 0;
    progress_.status = navigator_query_status_t::failed;
    return make_error(code, query_.domain, subject, expected, actual);
}

navigator_error_t navigator_query_model_t::stale() noexcept
{
    rows_.clear();
    scratch_.clear();
    progress_.matched_rows = 0;
    progress_.status = navigator_query_status_t::stale;
    return make_error(navigator_error_code_t::stale_snapshot, query_.domain,
                      progress_.snapshot_generation);
}

navigator_error_t navigator_query_model_t::initialize_sorting()
{
    if (rows_.size() < 2) {
        progress_.status = navigator_query_status_t::ready;
        return {};
    }
    try {
        scratch_.resize(rows_.size());
    } catch (const std::bad_alloc&) {
        return fail(navigator_error_code_t::resource_exhausted, rows_.size());
    }
    sort_width_ = 1;
    merge_left_ = 0;
    merge_source_is_rows_ = true;
    start_merge();
    progress_.status = navigator_query_status_t::sorting;
    return {};
}

navigator_error_t navigator_query_model_t::advance_filtering(
    std::uint32_t& work_budget, const navigator_cancellation_t* cancellation)
{
    while (work_budget != 0 && filter_ordinal_ < progress_.source_rows) {
        if (cancellation_requested(cancellation)) {
            cancel();
            return make_error(navigator_error_code_t::cancelled, query_.domain);
        }
        if (!adapter_->generation_current(progress_.snapshot_generation))
            return stale();
        navigator_item_view_t item;
        if (!read_row(filter_ordinal_, item))
            return fail(navigator_error_code_t::adapter_rejected, filter_ordinal_);
        if (matches_filter(item)) {
            try {
                rows_.push_back({filter_ordinal_, item.id});
            } catch (const std::bad_alloc&) {
                return fail(navigator_error_code_t::resource_exhausted, filter_ordinal_);
            }
        }
        ++filter_ordinal_;
        ++progress_.inspected_rows;
        --work_budget;
    }
    progress_.matched_rows = static_cast<std::uint64_t>(rows_.size());
    if (filter_ordinal_ == progress_.source_rows)
        return initialize_sorting();
    return {};
}

navigator_error_t navigator_query_model_t::advance_sorting(
    std::uint32_t& work_budget, const navigator_cancellation_t* cancellation)
{
    const std::uint64_t count = static_cast<std::uint64_t>(rows_.size());
    while (work_budget != 0 && progress_.status == navigator_query_status_t::sorting) {
        if (cancellation_requested(cancellation)) {
            cancel();
            return make_error(navigator_error_code_t::cancelled, query_.domain);
        }
        if (!adapter_->generation_current(progress_.snapshot_generation))
            return stale();
        const auto& source = merge_source_is_rows_ ? rows_ : scratch_;
        auto& destination = merge_source_is_rows_ ? scratch_ : rows_;
        if (merge_output_cursor_ == merge_right_) {
            merge_left_ = merge_right_;
            if (merge_left_ == count) {
                if (sort_width_ >= count - sort_width_) {
                    if (merge_source_is_rows_)
                        rows_.swap(scratch_);
                    scratch_.clear();
                    progress_.status = navigator_query_status_t::ready;
                    return {};
                }
                merge_source_is_rows_ = !merge_source_is_rows_;
                sort_width_ *= 2U;
                merge_left_ = 0;
            }
            start_merge();
            continue;
        }
        bool choose_left = false;
        if (merge_left_cursor_ == merge_middle_) {
            choose_left = false;
        } else if (merge_right_cursor_ == merge_right_) {
            choose_left = true;
        } else {
            bool adapter_ok = true;
            choose_left = compare_rows(source[static_cast<std::size_t>(merge_left_cursor_)],
                                       source[static_cast<std::size_t>(merge_right_cursor_)],
                                       adapter_ok) <= 0;
            if (!adapter_ok)
                return fail(navigator_error_code_t::adapter_rejected, merge_left_cursor_);
        }
        destination[static_cast<std::size_t>(merge_output_cursor_)] = choose_left
            ? source[static_cast<std::size_t>(merge_left_cursor_++)]
            : source[static_cast<std::size_t>(merge_right_cursor_++)];
        ++merge_output_cursor_;
        ++progress_.sort_operations;
        --work_budget;
    }
    return {};
}

bool navigator_query_model_t::read_row(const row_reference_t& reference,
                                       navigator_item_view_t& output) const noexcept
{
    if (!read_row(reference.ordinal, output))
        return false;
    return output.id == reference.id;
}

bool navigator_query_model_t::read_row(std::uint64_t ordinal, navigator_item_view_t& output) const noexcept
{
    if (!adapter_->record_at(query_.domain, progress_.snapshot_generation, ordinal, output))
        return false;
    return item_valid(output, query_.domain);
}

bool navigator_query_model_t::matches_filter(const navigator_item_view_t& item) const noexcept
{
    return contains_text(item.label, query_.filter.text, query_.filter.case_sensitive) ||
        contains_text(item.secondary, query_.filter.text, query_.filter.case_sensitive) ||
        contains_text(item.detail, query_.filter.text, query_.filter.case_sensitive);
}

int navigator_query_model_t::compare_rows(const row_reference_t& lhs, const row_reference_t& rhs,
                                          bool& adapter_ok) const noexcept
{
    navigator_item_view_t left;
    navigator_item_view_t right;
    if (!read_row(lhs, left) || !read_row(rhs, right)) {
        adapter_ok = false;
        return 0;
    }
    int result = 0;
    switch (query_.sort.key) {
        case navigator_sort_key_t::label:
            result = compare_text(left.label, right.label, query_.filter.case_sensitive);
            break;
        case navigator_sort_key_t::secondary:
            result = compare_text(left.secondary, right.secondary, query_.filter.case_sensitive);
            break;
        case navigator_sort_key_t::detail:
            result = compare_text(left.detail, right.detail, query_.filter.case_sensitive);
            break;
        case navigator_sort_key_t::address:
            if (left.has_address != right.has_address)
                result = left.has_address ? -1 : 1;
            else if (left.has_address)
                result = compare_u64(left.address, right.address);
            break;
        case navigator_sort_key_t::metric:
            result = compare_u64(left.metric, right.metric);
            break;
        case navigator_sort_key_t::severity:
            result = compare_u64(static_cast<std::uint64_t>(left.severity),
                                 static_cast<std::uint64_t>(right.severity));
            break;
        case navigator_sort_key_t::identifier:
            result = compare_u64(left.id.value, right.id.value);
            break;
    }
    return query_.sort.descending ? -result : result;
}

void navigator_query_model_t::start_merge() noexcept
{
    const std::uint64_t count = static_cast<std::uint64_t>(rows_.size());
    const std::uint64_t first_span = (std::min)(sort_width_, count - merge_left_);
    merge_middle_ = merge_left_ + first_span;
    const std::uint64_t second_span = (std::min)(sort_width_, count - merge_middle_);
    merge_right_ = merge_middle_ + second_span;
    merge_left_cursor_ = merge_left_;
    merge_right_cursor_ = merge_middle_;
    merge_output_cursor_ = merge_left_;
}

const std::vector<navigator_query_model_t::row_reference_t>&
navigator_query_model_t::sorted_rows() const noexcept
{
    return rows_;
}

navigator_navigation_model_t::navigator_navigation_model_t(
    const navigator_packed_store_adapter_t& adapter, workspace_id_t workspace,
    navigation_event_id_t first_event_id, std::uint64_t first_sequence, bool request_focus) noexcept
    : adapter_(&adapter)
    , workspace_(workspace)
    , next_event_id_(first_event_id)
    , next_sequence_(first_sequence)
    , request_focus_(request_focus)
    , exhausted_(!workspace.valid() || !first_event_id.valid() || first_sequence == 0)
{
}

navigator_error_t navigator_navigation_model_t::set_source(const view_context_t& source)
{
    if (!workspace_.valid() || !source.workspace.valid() || source.workspace != workspace_ ||
        !validate_view_context(source)) {
        return error(navigator_error_code_t::invalid_argument, navigator_domain_t::invalid,
                     source.view.value);
    }
    try {
        view_context_t accepted_source(source);
        source_ = std::move(accepted_source);
    } catch (const std::bad_alloc&) {
        return error(navigator_error_code_t::resource_exhausted,
                     navigator_domain_t::invalid, source.view.value);
    }
    has_source_ = true;
    return {};
}

void navigator_navigation_model_t::clear_source() noexcept
{
    source_ = {};
    has_source_ = false;
}

navigator_error_t navigator_navigation_model_t::make_address_event(const navigator_item_view_t& item,
                                                                     navigation_event_t& output)
{
    output = {};
    if (!has_source_)
        return error(navigator_error_code_t::navigation_rejected, item.domain, item.id.value);
    if (exhausted_)
        return error(navigator_error_code_t::sequence_exhausted, item.domain, item.id.value);
    if (!item_valid(item, item.domain) || !item.has_address)
        return error(navigator_error_code_t::invalid_argument, item.domain, item.id.value);
    const std::uint64_t generation = adapter_->current_generation();
    if (generation == 0 || !adapter_->generation_current(generation))
        return error(navigator_error_code_t::stale_snapshot, item.domain, generation);
    document_identity_t document;
    try {
        if (!adapter_->navigation_document(item.domain, generation, item.id, item.address, document))
            return error(navigator_error_code_t::adapter_rejected, item.domain, item.id.value);
    } catch (const std::bad_alloc&) {
        return error(navigator_error_code_t::resource_exhausted, item.domain, item.id.value);
    }
    if (!adapter_->generation_current(generation))
        return error(navigator_error_code_t::stale_snapshot, item.domain, generation);

    navigation_event_t event;
    event.id = next_event_id_;
    event.workspace = workspace_;
    event.has_source = true;
    event.source = source_;
    event.target.document = std::move(document);
    event.target.selection = {selection_kind_t::address, true, item.address, 0, {}};
    event.target.cursor = {true, item.address};
    event.origin = navigation_origin_t::navigator;
    event.sequence = next_sequence_;
    event.request_focus = request_focus_;
    if (!validate_navigation_event(event))
        return error(navigator_error_code_t::navigation_rejected, item.domain, item.id.value);
    output = std::move(event);
    if (next_event_id_.value == (std::numeric_limits<std::uint64_t>::max)() ||
        next_sequence_ == (std::numeric_limits<std::uint64_t>::max)()) {
        exhausted_ = true;
    } else {
        ++next_event_id_.value;
        ++next_sequence_;
    }
    return {};
}

navigator_error_t navigator_navigation_model_t::error(navigator_error_code_t code,
                                                       navigator_domain_t domain,
                                                       std::uint64_t subject) const noexcept
{
    return make_error(code, domain, subject);
}

}
