#pragma once

#include "fact_residency.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace aida::analysis {

struct paged_fact_page_meta_t final {
    std::uint64_t ordinal_begin = 0;
    std::uint32_t record_count = 0;
    std::uint64_t address_value_min = 0;
    std::uint64_t address_value_max = 0;
};

using paged_staging_page_visitor_t = std::function<workspace_result_t<void>(
    const paged_fact_page_meta_t& meta, const std::vector<std::uint8_t>& payload)>;

class paged_fact_staging_t final {
public:
    static workspace_result_t<std::shared_ptr<paged_fact_staging_t>> create(
        std::uint64_t resident_budget_bytes,
        std::uint64_t content_page_bytes = 0);

    ~paged_fact_staging_t();
    paged_fact_staging_t(const paged_fact_staging_t&) = delete;
    paged_fact_staging_t& operator=(const paged_fact_staging_t&) = delete;

    std::uint64_t content_page_bytes() const noexcept;

    workspace_result_t<void> stage_page(fact_domain_t domain,
                                        std::vector<std::uint8_t> page_bytes,
                                        const paged_fact_page_meta_t& meta,
                                        const cancellation_token_t& cancel = {});
    workspace_result_t<void> visit(fact_domain_t domain,
                                   std::uint64_t ordinal_begin,
                                   std::uint64_t ordinal_end,
                                   const paged_staging_page_visitor_t& fn,
                                   const cancellation_token_t& cancel = {}) const;
    workspace_result_t<void> for_each_page(
        fact_domain_t domain, const paged_staging_page_visitor_t& fn,
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::vector<std::uint8_t>> page_payload(
        fact_domain_t domain, std::uint64_t page_ordinal,
        paged_fact_page_meta_t& meta,
        const cancellation_token_t& cancel = {}) const;
    std::uint64_t total_bytes(fact_domain_t domain) const noexcept;
    std::uint64_t page_count(fact_domain_t domain) const noexcept;
    std::uint64_t record_count(fact_domain_t domain) const noexcept;
    std::uint64_t resident_bytes() const noexcept;
    std::uint64_t spilled_bytes() const noexcept;
    bool spilled() const noexcept;
    workspace_result_t<void> validate_contiguous(fact_domain_t domain) const;
    void release(fact_domain_t domain) noexcept;
    void release_all() noexcept;

private:
    struct state_t;
    explicit paged_fact_staging_t(std::shared_ptr<state_t> state);

    std::shared_ptr<state_t> state_;
};

}
