#pragma once

#include "../fact_page_cache.hpp"
#include "packed_page_codec.hpp"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

namespace aida::analysis {

using snapshot_domain_page_source_t =
    std::function<workspace_result_t<std::shared_ptr<const fact_page_t>>(
        std::uint32_t page_index)>;

class snapshot_domain_view_t final {
public:
    snapshot_domain_view_t(std::uint32_t domain, std::uint32_t record_size,
                           std::vector<packed_page_index_entry_t> pages,
                           snapshot_domain_page_source_t source)
        : domain_(domain), record_size_(record_size), pages_(std::move(pages)),
          source_(std::move(source)) {
        pages_.erase(
            std::remove_if(pages_.begin(), pages_.end(),
                           [domain](const packed_page_index_entry_t& entry) {
                               return entry.domain != domain;
                           }),
            pages_.end());
        std::sort(pages_.begin(), pages_.end(),
                  [](const packed_page_index_entry_t& lhs,
                     const packed_page_index_entry_t& rhs) {
                      return lhs.ordinal_begin != rhs.ordinal_begin
                          ? lhs.ordinal_begin < rhs.ordinal_begin
                          : lhs.page_index < rhs.page_index;
                  });
        total_records_ = 0;
        for (const auto& page : pages_)
            total_records_ += page.count;
    }

    bool valid() const noexcept {
        return static_cast<bool>(source_) && !pages_.empty();
    }
    std::uint32_t domain() const noexcept { return domain_; }
    std::uint32_t record_size() const noexcept { return record_size_; }
    std::uint32_t page_count() const noexcept {
        return static_cast<std::uint32_t>(pages_.size());
    }
    std::uint64_t total_records() const noexcept { return total_records_; }

    const packed_page_index_entry_t* page_for_ordinal(
        std::uint32_t ordinal) const noexcept {
        if (pages_.empty())
            return nullptr;
        const auto next = std::upper_bound(
            pages_.begin(), pages_.end(), ordinal,
            [](std::uint32_t value, const packed_page_index_entry_t& entry) {
                return value < entry.ordinal_begin;
            });
        if (next == pages_.begin())
            return nullptr;
        const auto candidate = next - 1;
        if (candidate->count == 0)
            return ordinal == candidate->ordinal_begin ? &*candidate : nullptr;
        if (static_cast<std::uint64_t>(ordinal) - candidate->ordinal_begin >=
            candidate->count)
            return nullptr;
        return &*candidate;
    }

    workspace_result_t<std::shared_ptr<const fact_page_t>> page(
        std::uint32_t page_index) const {
        if (!source_) {
            return workspace_result_t<std::shared_ptr<const fact_page_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                                     "paged domain view has no page source",
                                     "snapshot_domain_view.page"));
        }
        const auto span = std::find_if(
            pages_.begin(), pages_.end(),
            [page_index](const packed_page_index_entry_t& entry) {
                return entry.page_index == page_index;
            });
        if (span == pages_.end()) {
            return workspace_result_t<std::shared_ptr<const fact_page_t>>::failure(
                make_workspace_error(workspace_error_code_t::out_of_range,
                                     "paged domain view page index is outside the domain",
                                     "snapshot_domain_view.page"));
        }
        auto loaded = source_(page_index);
        if (!loaded)
            return loaded;
        const auto& result = *loaded.value();
        if (result.ordinal_begin != span->ordinal_begin ||
            result.record_count != span->count ||
            result.address_value_min != span->address_value_min ||
            result.address_value_max != span->address_value_max ||
            (record_size_ != 0 &&
             result.payload.size() !=
                 static_cast<std::size_t>(span->count) * record_size_)) {
            return workspace_result_t<std::shared_ptr<const fact_page_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "paged domain page content diverged from its index",
                                     "snapshot_domain_view.page"));
        }
        return loaded;
    }

    workspace_result_t<std::vector<std::uint8_t>> materialize_domain(
        std::uint32_t ordinal_begin, std::uint32_t count) const {
        if (count == 0)
            return workspace_result_t<std::vector<std::uint8_t>>::success({});
        const auto* first = page_for_ordinal(ordinal_begin);
        if (!first) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                make_workspace_error(workspace_error_code_t::out_of_range,
                                     "materialize range begins outside the paged domain",
                                     "snapshot_domain_view.materialize"));
        }
        const std::uint64_t last_ordinal =
            static_cast<std::uint64_t>(ordinal_begin) + count - 1ULL;
        if (last_ordinal > (std::numeric_limits<std::uint32_t>::max)()) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "materialize range exceeds the ordinal space",
                                     "snapshot_domain_view.materialize"));
        }
        const auto* last = page_for_ordinal(static_cast<std::uint32_t>(last_ordinal));
        if (!last) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                make_workspace_error(workspace_error_code_t::out_of_range,
                                     "materialize range ends outside the paged domain",
                                     "snapshot_domain_view.materialize"));
        }
        if (record_size_ == 0 &&
            (ordinal_begin != first->ordinal_begin ||
             static_cast<std::uint32_t>(last_ordinal) + 1U !=
                 last->ordinal_begin + last->count)) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "variable-width domain materialize requires page-aligned ordinals",
                                     "snapshot_domain_view.materialize"));
        }
        std::vector<std::uint8_t> output;
        if (record_size_ != 0) {
            const std::uint64_t total_bytes =
                static_cast<std::uint64_t>(count) * record_size_;
            if (total_bytes >
                static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                                         "materialize range exceeds addressable memory",
                                         "snapshot_domain_view.materialize"));
            }
            output.reserve(static_cast<std::size_t>(total_bytes));
        }
        const auto* current = first;
        for (;;) {
            auto loaded = page(current->page_index);
            if (!loaded)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    loaded.error());
            const auto& content = *loaded.value();
            std::size_t begin_byte = 0;
            std::size_t end_byte = content.payload.size();
            if (record_size_ != 0) {
                if (content.ordinal_begin < ordinal_begin) {
                    begin_byte = static_cast<std::size_t>(
                        static_cast<std::uint64_t>(ordinal_begin -
                                                   content.ordinal_begin) *
                        record_size_);
                }
                if (static_cast<std::uint64_t>(content.ordinal_begin) +
                        content.record_count >
                    last_ordinal + 1ULL) {
                    end_byte = static_cast<std::size_t>(
                        (last_ordinal + 1ULL - content.ordinal_begin) * record_size_);
                }
                if (begin_byte > end_byte || end_byte > content.payload.size()) {
                    return workspace_result_t<std::vector<std::uint8_t>>::failure(
                        make_workspace_error(workspace_error_code_t::integrity_failure,
                                             "materialize window exceeds its page payload",
                                             "snapshot_domain_view.materialize"));
                }
            }
            output.insert(output.end(), content.payload.begin() + begin_byte,
                          content.payload.begin() + end_byte);
            if (current == last)
                break;
            const std::uint64_t next_ordinal =
                static_cast<std::uint64_t>(current->ordinal_begin) + current->count;
            if (next_ordinal > last_ordinal) {
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                                         "materialize range ordinal coverage is discontinuous",
                                         "snapshot_domain_view.materialize"));
            }
            current = page_for_ordinal(static_cast<std::uint32_t>(next_ordinal));
            if (!current) {
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                                         "materialize range crosses a missing page",
                                         "snapshot_domain_view.materialize"));
            }
        }
        return workspace_result_t<std::vector<std::uint8_t>>::success(std::move(output));
    }

    class cursor_t final {
    public:
        cursor_t() = default;

        bool valid() const noexcept { return view_ != nullptr && has_page_; }
        std::uint32_t ordinal() const noexcept { return ordinal_; }
        std::uint32_t page_index() const noexcept { return page_index_; }

        workspace_result_t<bool> seek(std::uint32_t ordinal) {
            if (!view_) {
                return workspace_result_t<bool>::failure(
                    make_workspace_error(workspace_error_code_t::invalid_argument,
                                         "paged domain cursor is detached",
                                         "snapshot_domain_view.cursor"));
            }
            const auto* span = view_->page_for_ordinal(ordinal);
            if (!span)
                return workspace_result_t<bool>::success(false);
            if (!has_page_ || page_index_ != span->page_index) {
                auto loaded = view_->page(span->page_index);
                if (!loaded)
                    return workspace_result_t<bool>::failure(loaded.error());
                page_ = loaded.take_value();
                page_index_ = span->page_index;
                has_page_ = true;
            }
            ordinal_ = ordinal;
            return workspace_result_t<bool>::success(true);
        }

        workspace_result_t<bool> next(std::uint32_t advance = 1) {
            if (!has_page_) {
                return workspace_result_t<bool>::failure(
                    make_workspace_error(workspace_error_code_t::invalid_argument,
                                         "paged domain cursor is not positioned",
                                         "snapshot_domain_view.cursor"));
            }
            const std::uint64_t next_ordinal =
                static_cast<std::uint64_t>(ordinal_) + advance;
            if (next_ordinal > (std::numeric_limits<std::uint32_t>::max)())
                return workspace_result_t<bool>::success(false);
            return seek(static_cast<std::uint32_t>(next_ordinal));
        }

        std::pair<const std::uint8_t*, std::size_t> current_chunk() const noexcept {
            if (!has_page_ || !page_ || view_->record_size() == 0)
                return {nullptr, 0};
            const std::uint64_t inner =
                static_cast<std::uint64_t>(ordinal_ - page_->ordinal_begin) *
                view_->record_size();
            if (inner >= page_->payload.size())
                return {nullptr, 0};
            return {page_->payload.data() + inner,
                    page_->payload.size() - static_cast<std::size_t>(inner)};
        }

        const std::shared_ptr<const fact_page_t>& current_page() const noexcept {
            return page_;
        }

    private:
        explicit cursor_t(const snapshot_domain_view_t* view) : view_(view) {}
        const snapshot_domain_view_t* view_ = nullptr;
        std::shared_ptr<const fact_page_t> page_;
        std::uint32_t page_index_ = 0;
        std::uint32_t ordinal_ = 0;
        bool has_page_ = false;

        friend class snapshot_domain_view_t;
    };

    cursor_t cursor() const noexcept { return cursor_t(this); }

private:
    std::uint32_t domain_ = 0;
    std::uint32_t record_size_ = 0;
    std::vector<packed_page_index_entry_t> pages_;
    snapshot_domain_page_source_t source_;
    std::uint64_t total_records_ = 0;
};

}
