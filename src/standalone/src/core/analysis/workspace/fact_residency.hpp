#pragma once

#include "../analysis_budget.hpp"

#include <array>
#include <cstdint>

namespace aida::analysis {

enum class fact_domain_t : std::uint8_t {
    instructions = 0,
    operand_facts,
    target_facts,
    edges,
    xrefs,
    blocks,
    functions,
    function_chunks,
    function_block_memberships,
    strings,
    symbols,
    coverage,
    count
};

inline constexpr std::size_t fact_domain_count =
    static_cast<std::size_t>(fact_domain_t::count);

inline constexpr const char* fact_domain_name(fact_domain_t domain) noexcept {
    switch (domain) {
    case fact_domain_t::instructions:
        return "instructions";
    case fact_domain_t::operand_facts:
        return "operand_facts";
    case fact_domain_t::target_facts:
        return "target_facts";
    case fact_domain_t::edges:
        return "edges";
    case fact_domain_t::xrefs:
        return "xrefs";
    case fact_domain_t::blocks:
        return "blocks";
    case fact_domain_t::functions:
        return "functions";
    case fact_domain_t::function_chunks:
        return "function_chunks";
    case fact_domain_t::function_block_memberships:
        return "function_block_memberships";
    case fact_domain_t::strings:
        return "strings";
    case fact_domain_t::symbols:
        return "symbols";
    case fact_domain_t::coverage:
        return "coverage";
    case fact_domain_t::count:
        break;
    }
    return "unknown";
}

enum class fact_residency_mode_t : std::uint8_t {
    resident = 0,
    paged = 1,
    absent = 2
};

struct fact_domain_projection_t {
    std::uint64_t record_count = 0;
    std::uint64_t record_bytes = 0;

    constexpr std::uint64_t projected_bytes() const noexcept {
        return record_bytes != 0 &&
                record_count > (0xFFFFFFFFFFFFFFFFULL / record_bytes)
            ? 0xFFFFFFFFFFFFFFFFULL
            : record_count * record_bytes;
    }
};

struct fact_domain_residency_t {
    fact_residency_mode_t mode = fact_residency_mode_t::resident;
    std::uint64_t projected_bytes = 0;
};

struct fact_residency_plan_t {
    std::array<fact_domain_residency_t, fact_domain_count> domains{};
    std::uint64_t resident_bytes = 0;
    std::uint64_t paged_bytes = 0;
    std::uint64_t budget_bytes = 0;

    constexpr bool any_paged() const noexcept {
        for (const auto& domain : domains)
            if (domain.mode == fact_residency_mode_t::paged)
                return true;
        return false;
    }
};

inline constexpr std::uint64_t fact_resident_budget_bytes(
    const host_memory_envelope_t& envelope) noexcept {
    constexpr std::uint64_t kFloorBytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    constexpr std::uint64_t kCeilingBytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
    const std::uint64_t scaled = envelope.usable_bytes / 6ULL;
    return scaled < kFloorBytes ? kFloorBytes
        : scaled > kCeilingBytes ? kCeilingBytes
        : scaled;
}

inline constexpr std::array<fact_domain_t, fact_domain_count>
    fact_domain_page_priority = {
    fact_domain_t::instructions,
    fact_domain_t::operand_facts,
    fact_domain_t::target_facts,
    fact_domain_t::edges,
    fact_domain_t::xrefs,
    fact_domain_t::coverage,
    fact_domain_t::function_block_memberships,
    fact_domain_t::function_chunks,
    fact_domain_t::blocks,
    fact_domain_t::functions,
    fact_domain_t::strings,
    fact_domain_t::symbols};

namespace detail {

inline constexpr bool fact_domain_priority_is_permutation() noexcept {
    for (std::size_t index = 0; index < fact_domain_count; ++index) {
        bool found = false;
        for (const auto domain : fact_domain_page_priority)
            if (static_cast<std::size_t>(domain) == index)
                found = true;
        if (!found)
            return false;
    }
    return true;
}

}

static_assert(fact_domain_page_priority.size() == fact_domain_count);
static_assert(detail::fact_domain_priority_is_permutation(),
    "fact_domain_page_priority must cover every fact_domain_t exactly once");

inline fact_residency_plan_t fact_residency_select(
    const std::array<fact_domain_projection_t, fact_domain_count>& projections,
    std::uint64_t resident_budget_bytes) noexcept {
    fact_residency_plan_t plan;
    plan.budget_bytes = resident_budget_bytes;
    std::uint64_t total_bytes = 0;
    for (std::size_t index = 0; index < fact_domain_count; ++index) {
        const auto projected = projections[index].projected_bytes();
        plan.domains[index].projected_bytes = projected;
        total_bytes = projected > 0xFFFFFFFFFFFFFFFFULL - total_bytes
            ? 0xFFFFFFFFFFFFFFFFULL
            : total_bytes + projected;
    }
    if (total_bytes <= resident_budget_bytes) {
        plan.resident_bytes = total_bytes;
        return plan;
    }
    std::uint64_t resident_bytes = total_bytes;
    for (const auto domain : fact_domain_page_priority) {
        if (resident_bytes <= resident_budget_bytes)
            break;
        auto& entry = plan.domains[static_cast<std::size_t>(domain)];
        if (entry.projected_bytes == 0) {
            entry.mode = fact_residency_mode_t::absent;
            continue;
        }
        entry.mode = fact_residency_mode_t::paged;
        resident_bytes = entry.projected_bytes >= resident_bytes
            ? 0
            : resident_bytes - entry.projected_bytes;
        plan.paged_bytes = entry.projected_bytes >
                0xFFFFFFFFFFFFFFFFULL - plan.paged_bytes
            ? 0xFFFFFFFFFFFFFFFFULL
            : plan.paged_bytes + entry.projected_bytes;
    }
    plan.resident_bytes = resident_bytes;
    return plan;
}

}
