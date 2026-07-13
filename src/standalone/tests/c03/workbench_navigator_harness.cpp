#include "workbench_navigator_harness.hpp"

#include "../../src/core/workbench/navigator/workbench_navigator.hpp"

#include <array>
#include <cstdint>
#include <exception>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::workbench::navigator::c03_test {
namespace {

using namespace aida::workbench;

constexpr std::array<navigator_domain_t, 11> k_domains{
    navigator_domain_t::binaries,
    navigator_domain_t::sections,
    navigator_domain_t::functions,
    navigator_domain_t::imports,
    navigator_domain_t::exports,
    navigator_domain_t::strings,
    navigator_domain_t::symbols,
    navigator_domain_t::types,
    navigator_domain_t::diagnostics,
    navigator_domain_t::bookmarks,
    navigator_domain_t::progress};

static_assert(k_navigator_contract_schema_version == 1,
              "navigator contract schema version changed");
static_assert(static_cast<std::uint8_t>(navigator_domain_t::progress) == 11,
              "navigator domain values changed");
static_assert(static_cast<std::uint16_t>(navigator_error_code_t::stale_snapshot) == 5,
              "navigator error values changed");

void require(bool condition, std::string_view message)
{
    if (!condition)
        throw std::runtime_error(std::string(message));
}

std::size_t domain_index(navigator_domain_t domain)
{
    const auto value = static_cast<std::size_t>(domain);
    if (value == 0 || value > k_domains.size())
        throw std::runtime_error("invalid fixture domain");
    return value - 1;
}

struct row_t final {
    navigator_domain_t domain = navigator_domain_t::invalid;
    navigator_row_id_t id;
    navigator_row_id_t parent;
    std::string label;
    std::string secondary;
    std::string detail;
    bool has_address = false;
    std::uint64_t address = 0;
    std::uint64_t metric = 0;
    navigator_severity_t severity = navigator_severity_t::none;
    bool selectable = true;
    bool expandable = false;
};

class failing_source_allocator_t final : public navigator_source_allocator_t {
public:
    view_context_t allocate_copy(const view_context_t&) const override
    {
        throw std::bad_alloc{};
    }
};

class fixture_store_t final : public navigator_packed_store_adapter_t {
public:
    std::uint64_t current_generation() const noexcept override
    {
        return generation_;
    }

    bool generation_current(std::uint64_t generation) const noexcept override
    {
        return generation == generation_;
    }

    std::uint64_t record_count(navigator_domain_t domain,
                               std::uint64_t generation) const noexcept override
    {
        if (!generation_current(generation) || !navigator_domain_valid(domain))
            return 0;
        return rows_[domain_index(domain)].size();
    }

    bool record_at(navigator_domain_t domain, std::uint64_t generation, std::uint64_t ordinal,
                   navigator_item_view_t& output) const noexcept override
    {
        ++record_reads_;
        if (!generation_current(generation) || !navigator_domain_valid(domain))
            return false;
        const auto& rows = rows_[domain_index(domain)];
        if (ordinal >= rows.size())
            return false;
        output = view(rows[static_cast<std::size_t>(ordinal)]);
        return true;
    }

    std::uint64_t tree_child_count(navigator_domain_t domain, std::uint64_t generation,
                                   navigator_row_id_t parent) const noexcept override
    {
        if (!generation_current(generation) || !navigator_domain_valid(domain))
            return 0;
        std::uint64_t total = 0;
        for (const auto& row : rows_[domain_index(domain)]) {
            if (row.parent == parent)
                ++total;
        }
        return total;
    }

    bool tree_child_at(navigator_domain_t domain, std::uint64_t generation,
                       navigator_row_id_t parent, std::uint64_t ordinal,
                       navigator_item_view_t& output) const noexcept override
    {
        ++tree_reads_;
        if (!generation_current(generation) || !navigator_domain_valid(domain))
            return false;
        std::uint64_t seen = 0;
        for (const auto& row : rows_[domain_index(domain)]) {
            if (row.parent != parent)
                continue;
            if (seen == ordinal) {
                output = view(row);
                return true;
            }
            ++seen;
        }
        return false;
    }

    bool navigation_document(navigator_domain_t domain, std::uint64_t generation,
                             navigator_row_id_t id, std::uint64_t address,
                             document_identity_t& output) const override
    {
        if (!generation_current(generation) || !navigator_domain_valid(domain))
            return false;
        for (const auto& row : rows_[domain_index(domain)]) {
            if (row.id != id || !row.has_address || row.address != address)
                continue;
            output.workspace = {7};
            output.kind = document_kind_t::disassembly;
            output.object_id = 0x1000U + static_cast<std::uint64_t>(domain);
            output.variant_id = id.value;
            output.provider_key = "fixture";
            output.has_address = true;
            output.address = address;
            return true;
        }
        return false;
    }

    void add(row_t row)
    {
        rows_[domain_index(row.domain)].push_back(std::move(row));
    }

    void advance_generation() noexcept
    {
        ++generation_;
    }

    std::uint64_t record_reads() const noexcept
    {
        return record_reads_;
    }

    std::uint64_t tree_reads() const noexcept
    {
        return tree_reads_;
    }

private:
    static navigator_item_view_t view(const row_t& row) noexcept
    {
        return {row.domain, row.id, row.parent, row.label, row.secondary, row.detail,
                row.has_address, row.address, row.metric, row.severity, row.selectable,
                row.expandable};
    }

    std::array<std::vector<row_t>, 11> rows_;
    std::uint64_t generation_ = 1;
    mutable std::uint64_t record_reads_ = 0;
    mutable std::uint64_t tree_reads_ = 0;
};

class cancellation_t final : public navigator_cancellation_t {
public:
    bool cancelled() const noexcept override
    {
        return cancelled_;
    }

    void cancel() noexcept
    {
        cancelled_ = true;
    }

private:
    bool cancelled_ = false;
};

row_t row(navigator_domain_t domain, std::uint64_t id, std::string label,
          std::uint64_t address = 0, navigator_row_id_t parent = {})
{
    row_t output;
    output.domain = domain;
    output.id = {id};
    output.parent = parent;
    output.label = std::move(label);
    output.secondary = navigator_domain_name(domain);
    output.detail = "fixture";
    output.has_address = true;
    output.address = address;
    output.metric = id * 10U;
    output.severity = navigator_severity_t::information;
    return output;
}

void advance_to_ready(navigator_query_model_t& model)
{
    while (model.status() == navigator_query_status_t::filtering ||
           model.status() == navigator_query_status_t::sorting) {
        const auto result = model.advance(1, nullptr);
        require(result.ok(), "query advance failed");
    }
    require(model.status() == navigator_query_status_t::ready, "query did not finish");
}

void verify_domains_and_tree_paging()
{
    fixture_store_t store;
    std::uint64_t id = 1;
    navigator_row_id_t functions_root;
    for (const auto domain : k_domains) {
        const navigator_row_id_t root_id{id++};
        store.add(row(domain, root_id.value, std::string(navigator_domain_name(domain)) + " root",
                      root_id.value * 0x10U));
        store.add(row(domain, id, std::string(navigator_domain_name(domain)) + " sibling",
                      id * 0x10U));
        ++id;
        if (domain == navigator_domain_t::functions) {
            functions_root = root_id;
            store.add(row(domain, id, "functions child", id * 0x10U, root_id));
            ++id;
        }
    }

    navigator_tree_model_t tree(store);
    for (const auto domain : k_domains) {
        navigator_tree_page_t first;
        const navigator_tree_request_t request{domain, {}, {0, 1}};
        require(tree.page(request, nullptr, first).ok(), "tree first page failed");
        require(first.total_rows == 2 && first.rows.size() == 1 && first.next_offset == 1,
                "tree first page was not bounded");
        require(first.rows.front().domain == domain && first.rows.front().label.data() != nullptr,
                "tree domain row lost its packed view");

        navigator_tree_page_t second;
        require(tree.page({domain, {}, {first.next_offset, 1}}, nullptr, second).ok(),
                "tree second page failed");
        require(second.rows.size() == 1 && second.next_offset == 2,
                "tree second page was not virtualized");
    }
    navigator_tree_page_t children;
    require(tree.page({navigator_domain_t::functions, functions_root, {0, 1}}, nullptr, children).ok() &&
                children.total_rows == 1 && children.rows.size() == 1 &&
                children.rows.front().parent == functions_root,
            "tree child page did not retain packed parent identity");
    require(store.tree_reads() == k_domains.size() * 2U + 1U,
            "tree paging read records outside requested pages");
}

void verify_query_filter_sort_and_page()
{
    fixture_store_t store;
    store.add(row(navigator_domain_t::functions, 1, "beta", 0x3000));
    store.add(row(navigator_domain_t::functions, 2, "Alpha", 0x1000));
    store.add(row(navigator_domain_t::functions, 3, "alpha", 0x2000));
    store.add(row(navigator_domain_t::functions, 4, "discard", 0x4000));

    navigator_query_model_t query(store);
    navigator_query_t request;
    request.domain = navigator_domain_t::functions;
    request.filter.text = "ALPHA";
    request.sort.key = navigator_sort_key_t::label;
    require(query.begin(request).ok(), "query begin failed");
    advance_to_ready(query);
    require(query.indexed_row_count() == 2, "query retained wrong compact index count");

    navigator_query_page_t first;
    require(query.page({0, 1}, first).ok(), "query first page failed");
    require(first.total_rows == 2 && first.rows.size() == 1 && first.rows.front().id.value == 2,
            "case-insensitive sort did not retain stable ordinal order");
    navigator_query_page_t second;
    require(query.page({1, 1}, second).ok(), "query second page failed");
    require(second.rows.size() == 1 && second.rows.front().id.value == 3,
            "query pagination did not resolve the second packed record");
    require(second.rows.front().label.data() != nullptr && store.record_reads() >= 4,
            "query did not retain packed row views");
}

void verify_cancellation_and_stale_snapshot()
{
    fixture_store_t store;
    for (std::uint64_t id = 1; id <= 8; ++id)
        store.add(row(navigator_domain_t::strings, id, "string" + std::to_string(id), id * 0x20U));

    navigator_query_model_t cancelled_query(store);
    navigator_query_t request;
    request.domain = navigator_domain_t::strings;
    require(cancelled_query.begin(request).ok(), "cancelled query begin failed");
    cancellation_t cancellation;
    cancellation.cancel();
    const auto cancelled = cancelled_query.advance(2, &cancellation);
    require(cancelled.code == navigator_error_code_t::cancelled &&
                cancelled_query.status() == navigator_query_status_t::cancelled &&
                cancelled_query.indexed_row_count() == 0,
            "cancelled query retained dataset state");

    navigator_query_model_t stale_query(store);
    require(stale_query.begin(request).ok(), "stale query begin failed");
    store.advance_generation();
    const auto stale = stale_query.advance(2, nullptr);
    require(stale.code == navigator_error_code_t::stale_snapshot &&
                stale_query.status() == navigator_query_status_t::stale,
            "stale packed generation was accepted");
}

void verify_address_navigation()
{
    fixture_store_t store;
    store.add(row(navigator_domain_t::symbols, 77, "entry", 0x401000));
    navigator_tree_model_t tree(store);
    navigator_tree_page_t page;
    require(tree.page({navigator_domain_t::symbols, {}, {0, 1}}, nullptr, page).ok() &&
                page.rows.size() == 1,
            "navigation fixture tree load failed");

    navigator_navigation_model_t navigation(store, {7}, {91}, 201, true);
    navigation_event_t missing_source_event;
    const navigator_error_t missing_source =
        navigation.make_address_event(page.rows.front(), missing_source_event);
    require(missing_source.code == navigator_error_code_t::navigation_rejected &&
                missing_source.domain == navigator_domain_t::symbols &&
                missing_source.subject == 77 && missing_source_event.id.value == 0 &&
                missing_source_event.sequence == 0,
            "address navigation accepted an event without a configured source");

    view_context_t source;
    source.workspace = {7};
    source.document = {8};
    source.view = {9};
    source.selection.kind = selection_kind_t::entity;
    source.selection.entity_key = "navigator-harness-source";
    source.synchronization_group = 0;
    source.synchronization_policy = view_synchronization_policy_t::independent;

    failing_source_allocator_t failing_source_allocator;
    navigator_navigation_model_t allocation_failure_navigation(
        store, {7}, {91}, 201, true, &failing_source_allocator);
    const navigator_error_t source_allocation_failure =
        allocation_failure_navigation.set_source(source);
    require(source_allocation_failure.code == navigator_error_code_t::resource_exhausted &&
                source_allocation_failure.domain == navigator_domain_t::invalid &&
                source_allocation_failure.subject == source.view.value,
            "source allocation failure violated the navigation error contract");
    navigation_event_t allocation_failure_event;
    const navigator_error_t allocation_failure_rejected =
        allocation_failure_navigation.make_address_event(page.rows.front(), allocation_failure_event);
    require(allocation_failure_rejected.code == navigator_error_code_t::navigation_rejected &&
                allocation_failure_rejected.domain == navigator_domain_t::symbols &&
                allocation_failure_rejected.subject == 77 && allocation_failure_event.id.value == 0 &&
                allocation_failure_event.sequence == 0,
            "source allocation failure retained a navigation source");

    require(navigation.set_source(source).ok(), "navigation source rejected");

    navigation_event_t event;
    require(navigation.make_address_event(page.rows.front(), event).ok(),
            "address navigation event failed");
    require(validate_navigation_event(event).ok() && event.id == navigation_event_id_t{91} &&
                event.sequence == 201 && event.origin == navigation_origin_t::navigator &&
                event.has_source && event.target.selection.kind == selection_kind_t::address &&
                event.target.selection.address == 0x401000 && event.target.cursor.has_position &&
                event.target.cursor.position == 0x401000 &&
                event.source.selection.kind == selection_kind_t::entity &&
                event.source.selection.entity_key == "navigator-harness-source",
            "address navigation event violated the workbench contract");

    navigation_event_t next;
    require(navigation.make_address_event(page.rows.front(), next).ok() &&
                next.id == navigation_event_id_t{92} && next.sequence == 202,
            "navigation event sequence was not monotonic");
}

void verify_invalid_requests()
{
    fixture_store_t store;
    navigator_tree_model_t tree(store);
    navigator_tree_page_t tree_page;
    require(tree.page({navigator_domain_t::invalid, {}, {0, 1}}, nullptr, tree_page).code ==
                navigator_error_code_t::invalid_domain,
            "invalid tree domain was accepted");

    navigator_query_model_t query(store);
    navigator_query_t invalid;
    invalid.domain = navigator_domain_t::functions;
    invalid.filter.text.assign(k_navigator_max_filter_bytes + 1U, 'x');
    const navigator_error_t oversized_filter = query.begin(invalid);
    require(oversized_filter.code == navigator_error_code_t::invalid_argument &&
                oversized_filter.domain == invalid.domain,
            "oversized filter error violated the query domain contract");
    invalid.filter.text.clear();
    invalid.sort.key = static_cast<navigator_sort_key_t>(255);
    const navigator_error_t invalid_sort = query.begin(invalid);
    require(invalid_sort.code == navigator_error_code_t::invalid_argument &&
                invalid_sort.domain == invalid.domain,
            "invalid sort error violated the query domain contract");

    navigator_query_t unsupported;
    unsupported.domain = static_cast<navigator_domain_t>(255);
    const navigator_error_t invalid_domain = query.begin(unsupported);
    require(invalid_domain.code == navigator_error_code_t::invalid_domain &&
                invalid_domain.domain == unsupported.domain,
            "invalid query domain was not preserved in the error contract");
}

std::string make_func_name(std::uint64_t index)
{
    std::string name = "func_";
    name += static_cast<char>('0' + (index / 10000) % 10);
    name += static_cast<char>('0' + (index / 1000) % 10);
    name += static_cast<char>('0' + (index / 100) % 10);
    name += static_cast<char>('0' + (index / 10) % 10);
    name += static_cast<char>('0' + index % 10);
    return name;
}

void verify_large_synthetic_model()
{
    constexpr std::uint64_t k_row_count = 10000;

    fixture_store_t store;
    for (std::uint64_t i = 0; i < k_row_count; ++i)
        store.add(row(navigator_domain_t::functions, i + 1, make_func_name(i),
                       0x1000 + i * 0x10));

    navigator_query_model_t chunked_query(store);
    navigator_query_t chunked_request;
    chunked_request.domain = navigator_domain_t::functions;
    require(chunked_query.begin(chunked_request).ok(), "large model chunked begin failed");
    std::uint64_t advance_count = 0;
    while (chunked_query.status() == navigator_query_status_t::filtering ||
           chunked_query.status() == navigator_query_status_t::sorting) {
        const auto result = chunked_query.advance(1, nullptr);
        require(result.ok(), "large model chunked advance failed");
        ++advance_count;
        require(advance_count <= k_row_count * 10,
                "large model chunked advance exceeded iteration budget");
    }
    require(chunked_query.status() == navigator_query_status_t::ready,
            "large model chunked query did not finish");
    require(chunked_query.indexed_row_count() == k_row_count,
            "large model chunked query did not index all rows");
    require(advance_count > 1, "large model chunked query did not require multiple advances");

    navigator_query_model_t addr_asc_query(store);
    navigator_query_t addr_asc_request;
    addr_asc_request.domain = navigator_domain_t::functions;
    addr_asc_request.sort.key = navigator_sort_key_t::address;
    addr_asc_request.sort.descending = false;
    require(addr_asc_query.begin(addr_asc_request).ok(), "large model address asc begin failed");
    advance_to_ready(addr_asc_query);
    require(addr_asc_query.indexed_row_count() == k_row_count,
            "large model address asc indexed wrong count");
    navigator_query_page_t addr_asc_first;
    require(addr_asc_query.page({0, 1}, addr_asc_first).ok(),
            "large model address asc first page failed");
    require(addr_asc_first.total_rows == k_row_count && addr_asc_first.rows.size() == 1,
            "large model address asc total was wrong");
    require(addr_asc_first.rows.front().address == 0x1000,
            "large model address asc first row not lowest address");
    navigator_query_page_t addr_asc_last;
    require(addr_asc_query.page({k_row_count - 1, 1}, addr_asc_last).ok(),
            "large model address asc last page failed");
    require(addr_asc_last.rows.size() == 1 &&
                addr_asc_last.rows.front().address == 0x1000 + (k_row_count - 1) * 0x10,
            "large model address asc last row not highest address");

    navigator_query_model_t addr_desc_query(store);
    navigator_query_t addr_desc_request;
    addr_desc_request.domain = navigator_domain_t::functions;
    addr_desc_request.sort.key = navigator_sort_key_t::address;
    addr_desc_request.sort.descending = true;
    require(addr_desc_query.begin(addr_desc_request).ok(), "large model address desc begin failed");
    advance_to_ready(addr_desc_query);
    require(addr_desc_query.indexed_row_count() == k_row_count,
            "large model address desc indexed wrong count");
    navigator_query_page_t addr_desc_first;
    require(addr_desc_query.page({0, 1}, addr_desc_first).ok(),
            "large model address desc first page failed");
    require(addr_desc_first.total_rows == k_row_count && addr_desc_first.rows.size() == 1,
            "large model address desc total was wrong");
    require(addr_desc_first.rows.front().address == 0x1000 + (k_row_count - 1) * 0x10,
            "large model address desc first row not highest address");
    navigator_query_page_t addr_desc_last;
    require(addr_desc_query.page({k_row_count - 1, 1}, addr_desc_last).ok(),
            "large model address desc last page failed");
    require(addr_desc_last.rows.size() == 1 && addr_desc_last.rows.front().address == 0x1000,
            "large model address desc last row not lowest address");

    navigator_query_model_t page_query(store);
    navigator_query_t page_request;
    page_request.domain = navigator_domain_t::functions;
    page_request.sort.key = navigator_sort_key_t::address;
    page_request.sort.descending = false;
    require(page_query.begin(page_request).ok(), "large model pagination begin failed");
    advance_to_ready(page_query);
    constexpr std::uint32_t k_page_size = 100;
    constexpr std::uint64_t k_page_count = k_row_count / k_page_size;
    for (std::uint64_t p = 0; p < k_page_count; ++p) {
        navigator_query_page_t page;
        require(page_query.page({p * k_page_size, k_page_size}, page).ok(),
                "large model pagination page failed");
        require(page.total_rows == k_row_count, "large model pagination total was wrong");
        require(page.rows.size() == k_page_size, "large model pagination page size was wrong");
        if (p == 0 || p == k_page_count / 2 || p == k_page_count - 1) {
            const std::uint64_t expected_first = 0x1000 + p * k_page_size * 0x10;
            const std::uint64_t expected_last =
                0x1000 + (p * k_page_size + k_page_size - 1) * 0x10;
            require(page.rows.front().address == expected_first,
                    "large model pagination page first address wrong");
            require(page.rows.back().address == expected_last,
                    "large model pagination page last address wrong");
        }
    }

    navigator_query_model_t cancel_query(store);
    navigator_query_t cancel_request;
    cancel_request.domain = navigator_domain_t::functions;
    require(cancel_query.begin(cancel_request).ok(), "large model cancellation begin failed");
    require(cancel_query.advance(1, nullptr).ok(), "large model cancellation first advance failed");
    require(cancel_query.advance(1, nullptr).ok(), "large model cancellation second advance failed");
    cancellation_t cancellation;
    cancellation.cancel();
    const auto cancelled = cancel_query.advance(1, &cancellation);
    require(cancelled.code == navigator_error_code_t::cancelled &&
                cancel_query.status() == navigator_query_status_t::cancelled,
            "large model cancellation did not produce clean cancellation");

    navigator_query_model_t bounded_query(store);
    navigator_query_t bounded_request;
    bounded_request.domain = navigator_domain_t::functions;
    bounded_request.sort.key = navigator_sort_key_t::address;
    bounded_request.sort.descending = false;
    require(bounded_query.begin(bounded_request).ok(), "large model read count begin failed");
    advance_to_ready(bounded_query);
    const std::uint64_t baseline_reads = store.record_reads();
    navigator_query_page_t bounded_page;
    require(bounded_query.page({0, k_page_size}, bounded_page).ok(),
            "large model read count page failed");
    const std::uint64_t page_reads = store.record_reads() - baseline_reads;
    require(page_reads <= k_page_size, "large model page read count exceeded page size");

    store.add(row(navigator_domain_t::functions, 10001, "func_00050", 0xAAAA));
    store.add(row(navigator_domain_t::functions, 10002, "func_00050", 0xBBBB));
    store.add(row(navigator_domain_t::functions, 10003, "func_00050", 0xCCCC));

    navigator_query_model_t stable_query(store);
    navigator_query_t stable_request;
    stable_request.domain = navigator_domain_t::functions;
    stable_request.sort.key = navigator_sort_key_t::label;
    stable_request.sort.descending = false;
    require(stable_query.begin(stable_request).ok(), "large model stable sort begin failed");
    advance_to_ready(stable_query);
    require(stable_query.indexed_row_count() == k_row_count + 3,
            "large model stable sort indexed wrong count");
    navigator_query_page_t stable_page;
    require(stable_query.page({50, 4}, stable_page).ok(),
            "large model stable sort page failed");
    require(stable_page.rows.size() == 4, "large model stable sort page size wrong");
    require(stable_page.rows[0].label == "func_00050" && stable_page.rows[0].id.value == 51,
            "large model stable sort first duplicate not original row");
    require(stable_page.rows[1].label == "func_00050" && stable_page.rows[1].id.value == 10001,
            "large model stable sort second duplicate not first extra");
    require(stable_page.rows[2].label == "func_00050" && stable_page.rows[2].id.value == 10002,
            "large model stable sort third duplicate not second extra");
    require(stable_page.rows[3].label == "func_00050" && stable_page.rows[3].id.value == 10003,
            "large model stable sort fourth duplicate not third extra");
}

void verify_additional_sort_keys()
{
    fixture_store_t store;

    auto r1 = row(navigator_domain_t::functions, 1, "alpha", 0x3000);
    r1.severity = navigator_severity_t::warning;
    store.add(r1);

    auto r2 = row(navigator_domain_t::functions, 2, "Alpha", 0x1000);
    r2.severity = navigator_severity_t::error;
    store.add(r2);

    auto r3 = row(navigator_domain_t::functions, 3, "ALPHA", 0x2000);
    r3.severity = navigator_severity_t::information;
    store.add(r3);

    auto r4 = row(navigator_domain_t::functions, 4, "beta", 0x4000);
    r4.severity = navigator_severity_t::fatal;
    store.add(r4);

    navigator_query_model_t addr_asc_query(store);
    navigator_query_t addr_asc_request;
    addr_asc_request.domain = navigator_domain_t::functions;
    addr_asc_request.sort.key = navigator_sort_key_t::address;
    addr_asc_request.sort.descending = false;
    require(addr_asc_query.begin(addr_asc_request).ok(), "additional sort address asc begin failed");
    advance_to_ready(addr_asc_query);
    require(addr_asc_query.indexed_row_count() == 4, "additional sort address asc indexed wrong count");
    navigator_query_page_t addr_asc_page;
    require(addr_asc_query.page({0, 4}, addr_asc_page).ok(), "additional sort address asc page failed");
    require(addr_asc_page.rows.size() == 4, "additional sort address asc page size wrong");
    require(addr_asc_page.rows[0].id.value == 2 && addr_asc_page.rows[0].address == 0x1000,
            "additional sort address asc first row wrong");
    require(addr_asc_page.rows[1].id.value == 3 && addr_asc_page.rows[1].address == 0x2000,
            "additional sort address asc second row wrong");
    require(addr_asc_page.rows[2].id.value == 1 && addr_asc_page.rows[2].address == 0x3000,
            "additional sort address asc third row wrong");
    require(addr_asc_page.rows[3].id.value == 4 && addr_asc_page.rows[3].address == 0x4000,
            "additional sort address asc fourth row wrong");

    navigator_query_model_t addr_desc_query(store);
    navigator_query_t addr_desc_request;
    addr_desc_request.domain = navigator_domain_t::functions;
    addr_desc_request.sort.key = navigator_sort_key_t::address;
    addr_desc_request.sort.descending = true;
    require(addr_desc_query.begin(addr_desc_request).ok(), "additional sort address desc begin failed");
    advance_to_ready(addr_desc_query);
    navigator_query_page_t addr_desc_page;
    require(addr_desc_query.page({0, 4}, addr_desc_page).ok(), "additional sort address desc page failed");
    require(addr_desc_page.rows.size() == 4, "additional sort address desc page size wrong");
    require(addr_desc_page.rows[0].id.value == 4 && addr_desc_page.rows[0].address == 0x4000,
            "additional sort address desc first row wrong");
    require(addr_desc_page.rows[1].id.value == 1 && addr_desc_page.rows[1].address == 0x3000,
            "additional sort address desc second row wrong");
    require(addr_desc_page.rows[2].id.value == 3 && addr_desc_page.rows[2].address == 0x2000,
            "additional sort address desc third row wrong");
    require(addr_desc_page.rows[3].id.value == 2 && addr_desc_page.rows[3].address == 0x1000,
            "additional sort address desc fourth row wrong");

    navigator_query_model_t sev_asc_query(store);
    navigator_query_t sev_asc_request;
    sev_asc_request.domain = navigator_domain_t::functions;
    sev_asc_request.sort.key = navigator_sort_key_t::severity;
    sev_asc_request.sort.descending = false;
    require(sev_asc_query.begin(sev_asc_request).ok(), "additional sort severity asc begin failed");
    advance_to_ready(sev_asc_query);
    navigator_query_page_t sev_asc_page;
    require(sev_asc_query.page({0, 4}, sev_asc_page).ok(), "additional sort severity asc page failed");
    require(sev_asc_page.rows.size() == 4, "additional sort severity asc page size wrong");
    require(sev_asc_page.rows[0].id.value == 3 &&
                sev_asc_page.rows[0].severity == navigator_severity_t::information,
            "additional sort severity asc first row wrong");
    require(sev_asc_page.rows[1].id.value == 1 &&
                sev_asc_page.rows[1].severity == navigator_severity_t::warning,
            "additional sort severity asc second row wrong");
    require(sev_asc_page.rows[2].id.value == 2 &&
                sev_asc_page.rows[2].severity == navigator_severity_t::error,
            "additional sort severity asc third row wrong");
    require(sev_asc_page.rows[3].id.value == 4 &&
                sev_asc_page.rows[3].severity == navigator_severity_t::fatal,
            "additional sort severity asc fourth row wrong");

    navigator_query_model_t sev_desc_query(store);
    navigator_query_t sev_desc_request;
    sev_desc_request.domain = navigator_domain_t::functions;
    sev_desc_request.sort.key = navigator_sort_key_t::severity;
    sev_desc_request.sort.descending = true;
    require(sev_desc_query.begin(sev_desc_request).ok(), "additional sort severity desc begin failed");
    advance_to_ready(sev_desc_query);
    navigator_query_page_t sev_desc_page;
    require(sev_desc_query.page({0, 4}, sev_desc_page).ok(), "additional sort severity desc page failed");
    require(sev_desc_page.rows.size() == 4, "additional sort severity desc page size wrong");
    require(sev_desc_page.rows[0].id.value == 4 &&
                sev_desc_page.rows[0].severity == navigator_severity_t::fatal,
            "additional sort severity desc first row wrong");
    require(sev_desc_page.rows[1].id.value == 2 &&
                sev_desc_page.rows[1].severity == navigator_severity_t::error,
            "additional sort severity desc second row wrong");
    require(sev_desc_page.rows[2].id.value == 1 &&
                sev_desc_page.rows[2].severity == navigator_severity_t::warning,
            "additional sort severity desc third row wrong");
    require(sev_desc_page.rows[3].id.value == 3 &&
                sev_desc_page.rows[3].severity == navigator_severity_t::information,
            "additional sort severity desc fourth row wrong");

    navigator_query_model_t ci_query(store);
    navigator_query_t ci_request;
    ci_request.domain = navigator_domain_t::functions;
    ci_request.filter.text = "alpha";
    ci_request.filter.case_sensitive = false;
    require(ci_query.begin(ci_request).ok(), "additional sort case-insensitive filter begin failed");
    advance_to_ready(ci_query);
    require(ci_query.indexed_row_count() == 3,
            "additional sort case-insensitive filter matched wrong count");

    navigator_query_model_t cs_query(store);
    navigator_query_t cs_request;
    cs_request.domain = navigator_domain_t::functions;
    cs_request.filter.text = "alpha";
    cs_request.filter.case_sensitive = true;
    require(cs_query.begin(cs_request).ok(), "additional sort case-sensitive filter begin failed");
    advance_to_ready(cs_query);
    require(cs_query.indexed_row_count() == 1,
            "additional sort case-sensitive filter matched wrong count");
}

}

bool run_workbench_navigator_harness(std::string& failure)
{
    try {
        verify_domains_and_tree_paging();
        verify_query_filter_sort_and_page();
        verify_cancellation_and_stale_snapshot();
        verify_address_navigation();
        verify_invalid_requests();
        verify_large_synthetic_model();
        verify_additional_sort_keys();
        failure.clear();
        return true;
    } catch (const std::exception& exception) {
        failure = exception.what();
        return false;
    }
}

}

int main()
{
    std::string failure;
    if (!aida::workbench::navigator::c03_test::run_workbench_navigator_harness(failure)) {
        std::cerr << "workbench_navigator_harness failed: " << failure << '\n';
        return 1;
    }
    std::cout << "workbench_navigator_harness source contract satisfied\n";
    return 0;
}
