#pragma once

#include "compact_ir.hpp"
#include "fact_residency.hpp"
#include "paged_fact_staging.hpp"
#include "record_span.hpp"
#include "workspace_database.hpp"
#include "workspace_types.hpp"

#include "../fact_page_cache.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

namespace aida::analysis {

class fact_page_pin_t final {
public:
    fact_page_pin_t() = default;
    fact_page_pin_t(const fact_page_pin_t&) = delete;
    fact_page_pin_t& operator=(const fact_page_pin_t&) = delete;
    fact_page_pin_t(fact_page_pin_t&&) noexcept = default;
    fact_page_pin_t& operator=(fact_page_pin_t&&) noexcept = default;

    void reset(std::shared_ptr<const fact_page_t> page) noexcept {
        page_ = std::move(page);
    }
    const fact_page_t* page() const noexcept { return page_.get(); }
    explicit operator bool() const noexcept { return static_cast<bool>(page_); }

    template <typename Record>
    const Record* place(Record&& record) noexcept {
        static_assert(sizeof(Record) <= k_scratch_bytes,
                      "paged view records must fit the pin scratch slot");
        static_assert(std::is_trivially_destructible<Record>::value,
                      "paged view records must be trivially destructible");
        auto* slot = new (scratch_.data()) Record(std::forward<Record>(record));
        return slot;
    }

private:
    static constexpr std::size_t k_scratch_bytes = 96;
    std::shared_ptr<const fact_page_t> page_;
    alignas(16) std::array<std::byte, k_scratch_bytes> scratch_{};
};

class paged_domain_source_t {
public:
    virtual ~paged_domain_source_t() = default;
    virtual std::uint64_t record_count(fact_domain_t domain) const noexcept = 0;
    virtual std::uint64_t page_count(fact_domain_t domain) const noexcept = 0;
    virtual std::uint64_t content_page_bytes() const noexcept = 0;
    virtual std::uint64_t total_content_bytes(fact_domain_t domain) const noexcept = 0;
    virtual workspace_result_t<paged_fact_page_meta_t> page_meta(
        fact_domain_t domain, std::uint64_t page_ordinal,
        const cancellation_token_t& cancel) const = 0;
    virtual workspace_result_t<std::vector<std::uint8_t>> fetch_page_content(
        fact_domain_t domain, std::uint64_t page_ordinal,
        const cancellation_token_t& cancel) const = 0;
};

std::shared_ptr<const paged_domain_source_t> make_staging_domain_source(
    std::shared_ptr<paged_fact_staging_t> staging, std::uint64_t content_page_bytes);

namespace detail {

workspace_result_t<std::uint64_t> paged_source_locate_page(
    const paged_domain_source_t* source, fact_domain_t domain,
    std::uint64_t ordinal, paged_fact_page_meta_t& meta,
    const cancellation_token_t& cancel);

workspace_result_t<std::shared_ptr<const fact_page_t>> paged_source_page(
    const paged_domain_source_t* source, fact_domain_t domain,
    std::uint64_t page_ordinal, const fact_page_key_t& key,
    const cancellation_token_t& cancel);

workspace_result_t<void> paged_source_record_bytes(
    const paged_domain_source_t* source, fact_domain_t domain,
    std::uint64_t ordinal, std::uint64_t record_stride,
    const fact_page_key_t& key_base, std::vector<std::uint8_t>& out,
    const cancellation_token_t& cancel);

}

template <typename Record>
class paged_table_t final {
public:
    paged_table_t() = default;

    static paged_table_t resident(record_span_t<const Record> rows) {
        paged_table_t table;
        table.resident_ = rows;
        table.count_ = rows.size();
        return table;
    }

    static paged_table_t resident_operands(
        const operand_fact_store_t* store,
        const snapshot_table_t<instruction_record_t>* instructions) {
        paged_table_t table;
        table.store_ = store;
        table.store_instructions_ = instructions;
        table.count_ = store != nullptr ? store->size() : 0;
        return table;
    }

    static paged_table_t paged(std::shared_ptr<const paged_domain_source_t> source,
                               fact_domain_t domain, std::uint64_t count,
                               fact_page_key_t key_base) {
        paged_table_t table;
        table.source_ = std::move(source);
        table.domain_ = domain;
        table.count_ = count;
        table.key_base_ = key_base;
        table.key_base_.domain = static_cast<std::uint32_t>(domain);
        return table;
    }

    std::uint64_t size() const noexcept { return count_; }
    bool empty() const noexcept { return count_ == 0; }
    bool resident() const noexcept { return source_ == nullptr; }
    record_span_t<const Record> resident_span() const noexcept { return resident_; }
    const paged_domain_source_t* source() const noexcept { return source_.get(); }

    workspace_result_t<const Record*> at(std::uint64_t ordinal, fact_page_pin_t& pin,
                                         const cancellation_token_t& cancel = {}) const {
        if (ordinal >= count_) {
            return workspace_result_t<const Record*>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "paged snapshot view ordinal is out of range", "paged_snapshot_view"));
        }
        if constexpr (std::is_same_v<Record, operand_fact_t>) {
            if (store_ != nullptr) {
                return workspace_result_t<const Record*>::success(
                    pin.place<Record>(operand_fact_materialize(
                        *store_, ordinal,
                        store_instructions_ != nullptr
                            ? *store_instructions_
                            : empty_instructions())));
            }
        }
        if (!resident_.empty()) {
            return workspace_result_t<const Record*>::success(&resident_[ordinal]);
        }
        if (source_ == nullptr) {
            return workspace_result_t<const Record*>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "paged snapshot view has no resident rows or page source",
                "paged_snapshot_view"));
        }
        if (cancel.stop_requested()) {
            return workspace_result_t<const Record*>::failure(
                paged_view_cancelled(cancel));
        }
        const auto stride = record_stride();
        std::vector<std::uint8_t> bytes;
        auto fetched = detail::paged_source_record_bytes(
            source_.get(), domain_, ordinal, stride, key_base_, bytes, cancel);
        if (!fetched)
            return workspace_result_t<const Record*>::failure(fetched.error());
        auto decoded = decode_record(bytes.data(), bytes.size());
        if (!decoded)
            return workspace_result_t<const Record*>::failure(decoded.error());
        return workspace_result_t<const Record*>::success(
            pin.place<Record>(decoded.take_value()));
    }

    template <typename F>
    workspace_result_t<void> for_each(std::uint64_t begin, std::uint64_t count, F&& fn,
                                      const cancellation_token_t& cancel = {}) const {
        if (begin > count_ || count > count_ - begin) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "paged snapshot view range is out of range", "paged_snapshot_view"));
        }
        fact_page_pin_t pin;
        for (std::uint64_t ordinal = begin; ordinal < begin + count; ++ordinal) {
            if ((ordinal & 0xFFFULL) == 0 && cancel.stop_requested()) {
                return workspace_result_t<void>::failure(paged_view_cancelled(cancel));
            }
            auto record = at(ordinal, pin, cancel);
            if (!record)
                return workspace_result_t<void>::failure(record.error());
            auto consumed = fn(*record.value());
            if (!consumed)
                return consumed;
        }
        return workspace_result_t<void>::success();
    }

private:
    static const snapshot_table_t<instruction_record_t>& empty_instructions() noexcept {
        static const snapshot_table_t<instruction_record_t> table;
        return table;
    }

    static workspace_error_t paged_view_cancelled(const cancellation_token_t& cancel) {
        if (cancel.deadline_exceeded()) {
            auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                "paged snapshot view deadline exceeded", "paged_snapshot_view");
            error.deadline = true;
            error.cancellation = true;
            return error;
        }
        auto error = make_workspace_error(workspace_error_code_t::cancelled,
            "paged snapshot view cancelled", "paged_snapshot_view");
        error.cancellation = true;
        return error;
    }

    constexpr std::uint64_t record_stride() const noexcept {
        if constexpr (std::is_same_v<Record, instruction_record_t>)
            return packed_instruction_stream_record_bytes;
        else if constexpr (std::is_same_v<Record, operand_fact_t>)
            return packed_operand_stream_record_bytes;
        else if constexpr (std::is_same_v<Record, target_fact_t>)
            return packed_target_stream_record_bytes;
        else if constexpr (std::is_same_v<Record, xref_record_t>)
            return packed_xref_stream_record_bytes;
        else
            return packed_edge_stream_record_min_bytes;
    }

    static workspace_result_t<Record> decode_record(const std::uint8_t* data,
                                                    std::size_t size) {
        if constexpr (std::is_same_v<Record, instruction_record_t>)
            return decode_packed_instruction_record(data, size);
        else if constexpr (std::is_same_v<Record, operand_fact_t>)
            return decode_packed_operand_record(data, size);
        else if constexpr (std::is_same_v<Record, target_fact_t>)
            return decode_packed_target_record(data, size);
        else if constexpr (std::is_same_v<Record, edge_record_t>)
            return decode_packed_edge_record(data, size);
        else if constexpr (std::is_same_v<Record, xref_record_t>)
            return decode_packed_xref_record(data, size);
        else
            return workspace_result_t<Record>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "paged snapshot view record type is unsupported",
                "paged_snapshot_view"));
    }

    record_span_t<const Record> resident_;
    const operand_fact_store_t* store_ = nullptr;
    const snapshot_table_t<instruction_record_t>* store_instructions_ = nullptr;
    std::shared_ptr<const paged_domain_source_t> source_;
    fact_domain_t domain_ = fact_domain_t::instructions;
    std::uint64_t count_ = 0;
    fact_page_key_t key_base_{};
};

paged_table_t<instruction_record_t> instructions_view(
    const analysis_snapshot_t& snapshot);
paged_table_t<operand_fact_t> operand_facts_view(
    const analysis_snapshot_t& snapshot);
paged_table_t<target_fact_t> target_facts_view(
    const analysis_snapshot_t& snapshot);
paged_table_t<edge_record_t> edges_view(
    const analysis_snapshot_t& snapshot);
paged_table_t<xref_record_t> xrefs_view(
    const analysis_snapshot_t& snapshot);

bool snapshot_domain_is_paged(const analysis_snapshot_t& snapshot,
                              fact_domain_t domain) noexcept;
std::shared_ptr<const paged_domain_source_t> snapshot_paged_source_handle(
    const analysis_snapshot_t& snapshot);

}
