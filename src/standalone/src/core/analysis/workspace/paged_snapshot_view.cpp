#include "paged_snapshot_view.hpp"

#include "checked_range.hpp"
#include "packed_page_codec.hpp"

#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <cstring>

namespace aida::analysis {

namespace {

workspace_error_t paged_view_integrity(const char* message) {
    return make_workspace_error(workspace_error_code_t::integrity_failure,
        message, "paged_snapshot_view");
}

workspace_error_t paged_view_cancelled_error(const cancellation_token_t& cancel) {
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

class staging_domain_source_t final : public paged_domain_source_t {
public:
    staging_domain_source_t(std::shared_ptr<paged_fact_staging_t> staging,
                            std::uint64_t content_page_bytes)
        : staging_(std::move(staging)), content_page_bytes_(content_page_bytes) {}

    std::uint64_t record_count(fact_domain_t domain) const noexcept override {
        return staging_ ? staging_->record_count(domain) : 0;
    }

    std::uint64_t page_count(fact_domain_t domain) const noexcept override {
        return staging_ ? staging_->page_count(domain) : 0;
    }

    std::uint64_t content_page_bytes() const noexcept override {
        return content_page_bytes_ != 0
            ? content_page_bytes_
            : (staging_ ? staging_->content_page_bytes() : 0);
    }

    std::uint64_t total_content_bytes(fact_domain_t domain) const noexcept override {
        if (!staging_)
            return 0;
        const auto total = staging_->total_bytes(domain);
        const auto pages = staging_->page_count(domain);
        const auto prefixes = pages * packed_record_page_prefix_size;
        return total >= prefixes ? total - prefixes : 0;
    }

    workspace_result_t<paged_fact_page_meta_t> page_meta(
        fact_domain_t domain, std::uint64_t page_ordinal,
        const cancellation_token_t& cancel) const override {
        if (!staging_) {
            return workspace_result_t<paged_fact_page_meta_t>::failure(
                paged_view_integrity("staging page source is unavailable"));
        }
        if (cancel.stop_requested()) {
            return workspace_result_t<paged_fact_page_meta_t>::failure(
                paged_view_cancelled_error(cancel));
        }
        if (page_ordinal >= staging_->page_count(domain)) {
            return workspace_result_t<paged_fact_page_meta_t>::failure(
                paged_view_integrity("staging page ordinal is out of range"));
        }
        paged_fact_page_meta_t meta;
        auto payload = staging_->page_payload(domain, page_ordinal, meta, cancel);
        if (!payload)
            return workspace_result_t<paged_fact_page_meta_t>::failure(payload.error());
        return workspace_result_t<paged_fact_page_meta_t>::success(meta);
    }

    workspace_result_t<std::vector<std::uint8_t>> fetch_page_content(
        fact_domain_t domain, std::uint64_t page_ordinal,
        const cancellation_token_t& cancel) const override {
        if (!staging_) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                paged_view_integrity("staging page source is unavailable"));
        }
        paged_fact_page_meta_t meta;
        auto payload = staging_->page_payload(domain, page_ordinal, meta, cancel);
        if (!payload)
            return payload;
        auto prefix = packed_record_page_prefix_t::decode(
            payload.value().data(), payload.value().size());
        if (!prefix || prefix->ordinal_begin != meta.ordinal_begin ||
            prefix->record_count != meta.record_count) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                paged_view_integrity("staging page prefix does not match its metadata"));
        }
        std::vector<std::uint8_t> content(
            payload.value().begin() + packed_record_page_prefix_size,
            payload.value().end());
        return workspace_result_t<std::vector<std::uint8_t>>::success(
            std::move(content));
    }

private:
    std::shared_ptr<paged_fact_staging_t> staging_;
    std::uint64_t content_page_bytes_ = 0;
};

}

std::shared_ptr<const paged_domain_source_t> make_staging_domain_source(
    std::shared_ptr<paged_fact_staging_t> staging, std::uint64_t content_page_bytes) {
    if (!staging)
        return {};
    const auto capacity = content_page_bytes != 0
        ? content_page_bytes
        : staging->content_page_bytes();
    if (capacity == 0)
        return {};
    return std::shared_ptr<const paged_domain_source_t>(
        new staging_domain_source_t(std::move(staging), capacity));
}

namespace detail {

workspace_result_t<std::uint64_t> paged_source_locate_page(
    const paged_domain_source_t* source, fact_domain_t domain,
    std::uint64_t ordinal, paged_fact_page_meta_t& meta,
    const cancellation_token_t& cancel) {
    if (source == nullptr) {
        return workspace_result_t<std::uint64_t>::failure(
            paged_view_integrity("paged snapshot view has no page source"));
    }
    const std::uint64_t pages = source->page_count(domain);
    if (pages == 0) {
        return workspace_result_t<std::uint64_t>::failure(
            paged_view_integrity("paged snapshot view source has no pages"));
    }
    std::uint64_t low = 0;
    std::uint64_t high = pages;
    while (low < high) {
        if (cancel.stop_requested()) {
            return workspace_result_t<std::uint64_t>::failure(
                paged_view_cancelled_error(cancel));
        }
        const std::uint64_t middle = low + (high - low) / 2ULL;
        auto candidate = source->page_meta(domain, middle, cancel);
        if (!candidate)
            return workspace_result_t<std::uint64_t>::failure(candidate.error());
        if (ordinal < candidate.value().ordinal_begin) {
            high = middle;
            continue;
        }
        if (ordinal >= candidate.value().ordinal_begin + candidate.value().record_count) {
            low = middle + 1ULL;
            continue;
        }
        meta = candidate.value();
        return workspace_result_t<std::uint64_t>::success(middle);
    }
    return workspace_result_t<std::uint64_t>::failure(
        paged_view_integrity("paged snapshot view ordinal is not covered by any page"));
}

workspace_result_t<std::shared_ptr<const fact_page_t>> paged_source_page(
    const paged_domain_source_t* source, fact_domain_t domain,
    std::uint64_t page_ordinal, const fact_page_key_t& key,
    const cancellation_token_t& cancel) {
    if (source == nullptr) {
        return workspace_result_t<std::shared_ptr<const fact_page_t>>::failure(
            paged_view_integrity("paged snapshot view has no page source"));
    }
    auto& cache = fact_page_cache_t::instance();
    const bool bypass = cache.ceiling() == 0;
    if (!bypass) {
        auto cached = cache.lookup(key);
        if (cached)
            return workspace_result_t<std::shared_ptr<const fact_page_t>>::success(
                std::move(cached));
    } else {
        cache.record_bypass();
    }
    auto meta = source->page_meta(domain, page_ordinal, cancel);
    if (!meta)
        return workspace_result_t<std::shared_ptr<const fact_page_t>>::failure(
            meta.error());
    auto content = source->fetch_page_content(domain, page_ordinal, cancel);
    if (!content)
        return workspace_result_t<std::shared_ptr<const fact_page_t>>::failure(
            content.error());
    auto page = std::make_shared<fact_page_t>();
    page->payload = content.take_value();
    page->address_value_min = meta.value().address_value_min;
    page->address_value_max = meta.value().address_value_max;
    page->ordinal_begin = static_cast<std::uint32_t>(meta.value().ordinal_begin);
    page->record_count = meta.value().record_count;
    page->decoded_bytes = page->payload.size();
    std::shared_ptr<const fact_page_t> shared = std::move(page);
    if (!bypass)
        cache.insert(key, shared);
    return workspace_result_t<std::shared_ptr<const fact_page_t>>::success(
        std::move(shared));
}

workspace_result_t<void> paged_source_record_bytes(
    const paged_domain_source_t* source, fact_domain_t domain,
    std::uint64_t ordinal, std::uint64_t record_stride,
    const fact_page_key_t& key_base, std::vector<std::uint8_t>& out,
    const cancellation_token_t& cancel) {
    if (source == nullptr) {
        return workspace_result_t<void>::failure(
            paged_view_integrity("paged snapshot view has no page source"));
    }
    if (record_stride == 0 || record_stride > packed_page_max_payload) {
        return workspace_result_t<void>::failure(
            paged_view_integrity("paged snapshot view record stride is invalid"));
    }
    if (domain == fact_domain_t::edges) {
        const auto total = source->total_content_bytes(domain);
        const auto records = source->record_count(domain);
        if (records == 0 || total <= packed_domain_stream_header_bytes ||
            (total - packed_domain_stream_header_bytes) % records != 0) {
            return workspace_result_t<void>::failure(paged_view_integrity(
                "paged snapshot view edge stream layout is irregular"));
        }
        const auto stride = (total - packed_domain_stream_header_bytes) / records;
        if (stride != packed_edge_stream_record_min_bytes &&
            stride != packed_edge_stream_record_max_bytes) {
            return workspace_result_t<void>::failure(paged_view_integrity(
                "paged snapshot view edge stream stride is unsupported"));
        }
        record_stride = stride;
    }
    paged_fact_page_meta_t meta;
    auto located = paged_source_locate_page(source, domain, ordinal, meta, cancel);
    if (!located)
        return workspace_result_t<void>::failure(located.error());
    const std::uint64_t page_ordinal = located.value();
    const std::uint64_t content_page_bytes = source->content_page_bytes();
    if (content_page_bytes == 0) {
        return workspace_result_t<void>::failure(
            paged_view_integrity("paged snapshot view page capacity is zero"));
    }
    std::uint64_t stream_offset = 0;
    if (!checked_mul_u64(ordinal, record_stride, stream_offset) ||
        !checked_add_u64(packed_domain_stream_header_bytes, stream_offset,
                         stream_offset)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "paged snapshot view record offset overflows", "paged_snapshot_view"));
    }
    const std::uint64_t page_stream_base = page_ordinal * content_page_bytes;
    if (stream_offset < page_stream_base) {
        return workspace_result_t<void>::failure(paged_view_integrity(
            "paged snapshot view record precedes its located page"));
    }
    const std::uint64_t local = stream_offset - page_stream_base;
    fact_page_key_t key = key_base;
    key.page_index = static_cast<std::uint32_t>(page_ordinal);
    auto page = paged_source_page(source, domain, page_ordinal, key, cancel);
    if (!page)
        return workspace_result_t<void>::failure(page.error());
    const auto& content = page.value()->payload;
    if (local > content.size()) {
        return workspace_result_t<void>::failure(paged_view_integrity(
            "paged snapshot view record offset exceeds its page"));
    }
    out.clear();
    const std::size_t available =
        static_cast<std::size_t>(content.size()) - static_cast<std::size_t>(local);
    if (available >= record_stride) {
        out.insert(out.end(), content.begin() + static_cast<std::ptrdiff_t>(local),
                   content.begin() + static_cast<std::ptrdiff_t>(local + record_stride));
        return workspace_result_t<void>::success();
    }
    out.insert(out.end(), content.begin() + static_cast<std::ptrdiff_t>(local),
               content.end());
    const std::size_t remaining =
        static_cast<std::size_t>(record_stride) - available;
    if (page_ordinal + 1ULL >= source->page_count(domain)) {
        return workspace_result_t<void>::failure(paged_view_integrity(
            "paged snapshot view record straddles the final page"));
    }
    fact_page_key_t next_key = key_base;
    next_key.page_index = static_cast<std::uint32_t>(page_ordinal + 1ULL);
    auto next_page = paged_source_page(source, domain, page_ordinal + 1ULL,
                                       next_key, cancel);
    if (!next_page)
        return workspace_result_t<void>::failure(next_page.error());
    const auto& next_content = next_page.value()->payload;
    if (next_content.size() < remaining) {
        return workspace_result_t<void>::failure(paged_view_integrity(
            "paged snapshot view record straddle exceeds the next page"));
    }
    out.insert(out.end(), next_content.begin(),
               next_content.begin() + static_cast<std::ptrdiff_t>(remaining));
    return workspace_result_t<void>::success();
}

}

bool snapshot_domain_is_paged(const analysis_snapshot_t& snapshot,
                              fact_domain_t domain) noexcept {
    const auto index = static_cast<std::size_t>(domain);
    if (index >= fact_domain_count)
        return false;
    if (snapshot.residency_plan.domains[index].mode == fact_residency_mode_t::paged)
        return true;
    const auto persisted = std::atomic_load_explicit(
        &snapshot.persisted_page_source.source, std::memory_order_acquire);
    return snapshot.paged_domain_counts[index] != 0 &&
        (snapshot.paged_staging != nullptr || persisted != nullptr);
}

std::shared_ptr<const paged_domain_source_t> snapshot_paged_source_handle(
    const analysis_snapshot_t& snapshot) {
    const auto persisted = std::atomic_load_explicit(
        &snapshot.persisted_page_source.source, std::memory_order_acquire);
    if (persisted)
        return persisted;
    if (snapshot.paged_staging)
        return make_staging_domain_source(snapshot.paged_staging, 0);
    return {};
}

namespace {

fact_page_key_t paged_view_key_base(const analysis_snapshot_t& snapshot) noexcept {
    fact_page_key_t key;
    key.binary_id = snapshot.binary_id;
    key.generation = snapshot.generation;
    key.analysis_revision = snapshot.analysis_revision;
    key.overlay_revision = snapshot.overlay_revision;
    return key;
}

template <typename Record>
paged_table_t<Record> paged_view_for_domain(
    const analysis_snapshot_t& snapshot, fact_domain_t domain,
    const snapshot_table_t<Record>& resident_rows) {
    if (snapshot_domain_is_paged(snapshot, domain)) {
        auto source = snapshot_paged_source_handle(snapshot);
        if (source) {
            const auto index = static_cast<std::size_t>(domain);
            const std::uint64_t count = snapshot.paged_domain_counts[index] != 0
                ? snapshot.paged_domain_counts[index]
                : source->record_count(domain);
            return paged_table_t<Record>::paged(
                std::move(source), domain, count, paged_view_key_base(snapshot));
        }
    }
    return paged_table_t<Record>::resident(
        record_span_t<const Record>(resident_rows.data(), resident_rows.size()));
}

}

paged_table_t<instruction_record_t> instructions_view(
    const analysis_snapshot_t& snapshot) {
    return paged_view_for_domain<instruction_record_t>(snapshot, fact_domain_t::instructions,
                                 snapshot.instructions);
}

paged_table_t<operand_fact_t> operand_facts_view(
    const analysis_snapshot_t& snapshot) {
    if (snapshot_domain_is_paged(snapshot, fact_domain_t::operand_facts)) {
        auto source = snapshot_paged_source_handle(snapshot);
        if (source) {
            const auto index =
                static_cast<std::size_t>(fact_domain_t::operand_facts);
            const std::uint64_t count = snapshot.paged_domain_counts[index] != 0
                ? snapshot.paged_domain_counts[index]
                : source->record_count(fact_domain_t::operand_facts);
            return paged_table_t<operand_fact_t>::paged(
                std::move(source), fact_domain_t::operand_facts, count,
                paged_view_key_base(snapshot));
        }
    }
    return paged_table_t<operand_fact_t>::resident_operands(
        &snapshot.operand_facts, &snapshot.instructions);
}

paged_table_t<target_fact_t> target_facts_view(
    const analysis_snapshot_t& snapshot) {
    return paged_view_for_domain<target_fact_t>(snapshot, fact_domain_t::target_facts,
                                 snapshot.target_facts);
}

paged_table_t<edge_record_t> edges_view(
    const analysis_snapshot_t& snapshot) {
    return paged_view_for_domain<edge_record_t>(snapshot, fact_domain_t::edges, snapshot.edges);
}

paged_table_t<xref_record_t> xrefs_view(
    const analysis_snapshot_t& snapshot) {
    return paged_view_for_domain<xref_record_t>(snapshot, fact_domain_t::xrefs, snapshot.xrefs);
}

}
