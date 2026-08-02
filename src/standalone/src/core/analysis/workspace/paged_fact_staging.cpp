#include "paged_fact_staging.hpp"

#include "checked_range.hpp"
#include "packed_page_codec.hpp"

#include "../mapped_window_cache.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>

namespace aida::analysis {

namespace {

constexpr std::uint64_t kSpillFrameHeaderBytes = 12;

workspace_error_t staging_cancelled(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "paged fact staging deadline exceeded", "paged_fact_staging");
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "paged fact staging cancelled", "paged_fact_staging");
    error.cancellation = true;
    return error;
}

workspace_error_t staging_integrity(const char* message) {
    return make_workspace_error(workspace_error_code_t::integrity_failure,
        message, "paged_fact_staging");
}

struct staged_page_entry_t {
    paged_fact_page_meta_t meta;
    std::vector<std::uint8_t> payload;
    std::uint64_t sequence = 0;
    bool spilled = false;
    std::uint64_t spill_offset = 0;
    std::uint64_t spill_length = 0;
    std::uint32_t spill_crc = 0;
};

struct domain_queue_t {
    std::vector<staged_page_entry_t> pages;
    std::uint64_t payload_bytes = 0;
    std::uint64_t records = 0;
    bool released = false;
};

} 

struct paged_fact_staging_t::state_t {
    std::array<domain_queue_t, fact_domain_count> domains{};
    std::uint64_t budget_bytes = 0;
    std::uint64_t page_content_bytes = 0;
    std::atomic<std::uint64_t> resident{0};
    std::atomic<std::uint64_t> spilled{0};
    std::unique_ptr<delete_on_close_spill_file_t> spill_file;
    std::uint64_t spill_cursor = 0;
    std::uint64_t next_sequence = 0;
    mutable std::mutex mutex;
};

paged_fact_staging_t::paged_fact_staging_t(std::shared_ptr<state_t> state)
    : state_(std::move(state)) {}

paged_fact_staging_t::~paged_fact_staging_t() {
    release_all();
}

workspace_result_t<std::shared_ptr<paged_fact_staging_t>>
paged_fact_staging_t::create(std::uint64_t resident_budget_bytes,
                             std::uint64_t content_page_bytes) {
    auto state = std::make_shared<state_t>();
    state->budget_bytes = resident_budget_bytes;
    state->page_content_bytes = content_page_bytes != 0
        ? content_page_bytes
        : (256ULL << 10) - packed_page_header_size - packed_record_page_prefix_size;
    return workspace_result_t<std::shared_ptr<paged_fact_staging_t>>::success(
        std::shared_ptr<paged_fact_staging_t>(new paged_fact_staging_t(std::move(state))));
}

std::uint64_t paged_fact_staging_t::content_page_bytes() const noexcept {
    return state_ ? state_->page_content_bytes : 0;
}

workspace_result_t<void> paged_fact_staging_t::stage_page(
    fact_domain_t domain, std::vector<std::uint8_t> page_bytes,
    const paged_fact_page_meta_t& meta, const cancellation_token_t& cancel) {
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(staging_cancelled(cancel));
    if (!state_ || page_bytes.empty()) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "paged fact staging received an empty page", "paged_fact_staging"));
    }
    const auto domain_index = static_cast<std::size_t>(domain);
    if (domain_index >= fact_domain_count) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "paged fact staging received an invalid domain", "paged_fact_staging"));
    }
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        auto& queue = state_->domains[domain_index];
        if (queue.released) {
            return workspace_result_t<void>::failure(staging_integrity(
                "paged fact staging accepted a page after domain release"));
        }
        staged_page_entry_t entry;
        entry.meta = meta;
        entry.sequence = ++state_->next_sequence;
        entry.payload = std::move(page_bytes);
        queue.payload_bytes += entry.payload.size();
        queue.records += meta.record_count;
        state_->resident.fetch_add(entry.payload.size(), std::memory_order_acq_rel);
        queue.pages.push_back(std::move(entry));
    }
    for (;;) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(staging_cancelled(cancel));
        std::size_t victim_domain = fact_domain_count;
        std::size_t victim_position = 0;
        std::uint64_t victim_sequence = ~0ULL;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if (state_->resident.load(std::memory_order_acquire) <= state_->budget_bytes)
                break;
            for (std::size_t index = 0; index < fact_domain_count; ++index) {
                auto& candidate = state_->domains[index];
                for (std::size_t position = 0; position < candidate.pages.size();
                     ++position) {
                    const auto& page = candidate.pages[position];
                    if (!page.spilled && page.sequence < victim_sequence) {
                        victim_sequence = page.sequence;
                        victim_domain = index;
                        victim_position = position;
                    }
                }
            }
            if (victim_domain == fact_domain_count)
                break;
        }
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            auto& queue = state_->domains[victim_domain];
            if (victim_position >= queue.pages.size())
                continue;
            auto& page = queue.pages[victim_position];
            if (page.spilled || page.payload.empty())
                continue;
            if (!state_->spill_file) {
                auto created = delete_on_close_spill_file_t::create();
                if (!created)
                    return workspace_result_t<void>::failure(created.error());
                state_->spill_file = created.take_value();
            }
            const std::uint32_t crc = crc32c(page.payload.data(), page.payload.size());
            const std::uint64_t frame_offset = state_->spill_cursor;
            std::array<std::uint8_t, kSpillFrameHeaderBytes> header{};
            const std::uint64_t length = page.payload.size();
            std::memcpy(header.data(), &length, sizeof(length));
            std::memcpy(header.data() + sizeof(length), &crc, sizeof(crc));
            auto written = state_->spill_file->write_at(
                state_->spill_cursor, header.data(), header.size());
            if (!written)
                return written;
            state_->spill_cursor += header.size();
            written = state_->spill_file->write_at(
                state_->spill_cursor, page.payload.data(), page.payload.size());
            if (!written)
                return written;
            state_->spill_cursor += length;
            page.payload.clear();
            page.payload.shrink_to_fit();
            page.spilled = true;
            page.spill_offset = frame_offset;
            page.spill_length = length;
            page.spill_crc = crc;
            state_->resident.fetch_sub(length, std::memory_order_acq_rel);
            state_->spilled.fetch_add(length, std::memory_order_acq_rel);
        }
        provider_metrics_relay::record_spill_high_water(
            state_->spilled.load(std::memory_order_acquire));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::vector<std::uint8_t>> paged_fact_staging_t::page_payload(
    fact_domain_t domain, std::uint64_t page_ordinal, paged_fact_page_meta_t& meta,
    const cancellation_token_t& cancel) const {
    if (cancel.stop_requested())
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            staging_cancelled(cancel));
    if (!state_) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            staging_integrity("paged fact staging is not initialized"));
    }
    const auto domain_index = static_cast<std::size_t>(domain);
    staged_page_entry_t entry;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        const auto& queue = state_->domains[domain_index];
        if (page_ordinal < queue.pages.size()) {
            entry = queue.pages[static_cast<std::size_t>(page_ordinal)];
            found = true;
        }
    }
    if (!found) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            staging_integrity("paged fact staging page ordinal is out of range"));
    }
    meta = entry.meta;
    if (!entry.spilled)
        return workspace_result_t<std::vector<std::uint8_t>>::success(
            std::move(entry.payload));
    if (!state_->spill_file) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            staging_integrity("paged fact staging spill file is unavailable"));
    }
    std::array<std::uint8_t, kSpillFrameHeaderBytes> header{};
    auto read = state_->spill_file->read_at(
        entry.spill_offset, header.data(), header.size());
    if (!read)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(read.error());
    std::uint64_t length = 0;
    std::uint32_t crc = 0;
    std::memcpy(&length, header.data(), sizeof(length));
    std::memcpy(&crc, header.data() + sizeof(length), sizeof(crc));
    if (length != entry.spill_length || crc != entry.spill_crc ||
        length == 0 || length > (1ULL << 21)) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            staging_integrity("paged fact staging spill frame is corrupt"));
    }
    std::vector<std::uint8_t> payload(static_cast<std::size_t>(length));
    read = state_->spill_file->read_at(
        entry.spill_offset + header.size(), payload.data(), payload.size());
    if (!read)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(read.error());
    if (crc32c(payload.data(), payload.size()) != crc) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            staging_integrity("paged fact staging spill page CRC mismatch"));
    }
    return workspace_result_t<std::vector<std::uint8_t>>::success(std::move(payload));
}

workspace_result_t<void> paged_fact_staging_t::visit(
    fact_domain_t domain, std::uint64_t ordinal_begin, std::uint64_t ordinal_end,
    const paged_staging_page_visitor_t& fn, const cancellation_token_t& cancel) const {
    if (!state_) {
        return workspace_result_t<void>::failure(
            staging_integrity("paged fact staging is not initialized"));
    }
    const std::uint64_t pages = page_count(domain);
    for (std::uint64_t page_ordinal = 0; page_ordinal < pages; ++page_ordinal) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(staging_cancelled(cancel));
        paged_fact_page_meta_t meta;
        auto payload = page_payload(domain, page_ordinal, meta, cancel);
        if (!payload)
            return workspace_result_t<void>::failure(payload.error());
        const std::uint64_t page_end = meta.ordinal_begin + meta.record_count;
        if (page_end <= ordinal_begin || meta.ordinal_begin >= ordinal_end)
            continue;
        auto visited = fn(meta, payload.value());
        if (!visited)
            return visited;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> paged_fact_staging_t::for_each_page(
    fact_domain_t domain, const paged_staging_page_visitor_t& fn,
    const cancellation_token_t& cancel) const {
    return visit(domain, 0, ~0ULL, fn, cancel);
}

std::uint64_t paged_fact_staging_t::total_bytes(fact_domain_t domain) const noexcept {
    if (!state_)
        return 0;
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->domains[static_cast<std::size_t>(domain)].payload_bytes;
}

std::uint64_t paged_fact_staging_t::page_count(fact_domain_t domain) const noexcept {
    if (!state_)
        return 0;
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->domains[static_cast<std::size_t>(domain)].pages.size();
}

std::uint64_t paged_fact_staging_t::record_count(fact_domain_t domain) const noexcept {
    if (!state_)
        return 0;
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->domains[static_cast<std::size_t>(domain)].records;
}

std::uint64_t paged_fact_staging_t::resident_bytes() const noexcept {
    return state_ ? state_->resident.load(std::memory_order_acquire) : 0;
}

std::uint64_t paged_fact_staging_t::spilled_bytes() const noexcept {
    return state_ ? state_->spilled.load(std::memory_order_acquire) : 0;
}

bool paged_fact_staging_t::spilled() const noexcept {
    return spilled_bytes() != 0;
}

workspace_result_t<void> paged_fact_staging_t::validate_contiguous(
    fact_domain_t domain) const {
    if (!state_) {
        return workspace_result_t<void>::failure(
            staging_integrity("paged fact staging is not initialized"));
    }
    std::lock_guard<std::mutex> lock(state_->mutex);
    const auto& queue = state_->domains[static_cast<std::size_t>(domain)];
    std::uint64_t expected = 0;
    for (const auto& page : queue.pages) {
        if (page.meta.ordinal_begin != expected) {
            return workspace_result_t<void>::failure(staging_integrity(
                "paged fact staging page ordinals are not contiguous"));
        }
        expected += page.meta.record_count;
    }
    return workspace_result_t<void>::success();
}

void paged_fact_staging_t::release(fact_domain_t domain) noexcept {
    if (!state_)
        return;
    std::lock_guard<std::mutex> lock(state_->mutex);
    auto& queue = state_->domains[static_cast<std::size_t>(domain)];
    std::uint64_t resident_drop = 0;
    for (const auto& page : queue.pages)
        if (!page.spilled)
            resident_drop += page.payload.size();
    state_->resident.fetch_sub(resident_drop, std::memory_order_acq_rel);
    queue.pages.clear();
    queue.pages.shrink_to_fit();
    queue.payload_bytes = 0;
    queue.records = 0;
    queue.released = true;
}

void paged_fact_staging_t::release_all() noexcept {
    if (!state_)
        return;
    for (std::size_t index = 0; index < fact_domain_count; ++index)
        release(static_cast<fact_domain_t>(index));
}

std::uint64_t paged_fact_staging_resident_bytes(
    const paged_fact_staging_t* staging) noexcept {
    return staging != nullptr ? staging->resident_bytes() : 0;
}

}
