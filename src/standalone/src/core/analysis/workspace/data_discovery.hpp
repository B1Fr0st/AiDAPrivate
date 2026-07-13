#pragma once

#include "byte_provider.hpp"
#include "compact_ir.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace aida::analysis {

struct data_pointer_seed_t {
    address_t slot;
    std::optional<address_t> target;
    data_candidate_kind_t kind = data_candidate_kind_t::referenced_storage;
    data_pointer_encoding_t encoding = data_pointer_encoding_t::absolute_virtual;
    std::uint8_t width_bytes = 0;
    std::int64_t addend = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool read_target_from_image = false;
};

struct data_discovery_limits_t {
    std::uint64_t max_candidates = 1ULL << 27;
    std::uint64_t max_pointer_facts = 1ULL << 27;
    std::uint64_t max_conflicts = 1ULL << 20;
    std::uint64_t max_pointer_seeds = 1ULL << 20;
    std::uint64_t max_pointer_scan_bytes = 1ULL << 34;
    std::uint64_t max_result_bytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t read_window_bytes = 4ULL * 1024ULL * 1024ULL;
    std::uint32_t cancellation_check_interval = 4096;
    bool scan_executable_regions = false;
    bool scan_unaligned_pointers = false;
};

struct data_discovery_result_t {
    std::vector<data_candidate_record_t> candidates;
    std::vector<data_pointer_fact_t> pointer_facts;
    std::vector<data_candidate_conflict_t> conflicts;
    std::uint64_t bytes_scanned = 0;
    std::uint64_t mapped_bytes = 0;
    std::uint64_t provider_leases = 0;
    std::uint64_t invalid_pointer_values = 0;
    std::uint64_t duplicate_candidates = 0;
    std::uint64_t duplicate_pointer_facts = 0;
};

class data_discovery_t final {
public:
    static workspace_result_t<data_discovery_result_t> discover(
        const workspace_image_t& image,
        const byte_provider_t& provider,
        const std::vector<instruction_record_t>& instructions,
        const std::vector<target_fact_t>& targets,
        const std::vector<data_pointer_seed_t>& pointer_seeds,
        const data_discovery_limits_t& limits,
        const cancellation_token_t& cancel = {});

    static workspace_result_t<data_discovery_result_t> discover(
        const workspace_image_t& image,
        const byte_provider_t& provider,
        const std::vector<instruction_record_t>& instructions,
        const std::vector<target_fact_t>& targets,
        const data_discovery_limits_t& limits,
        const cancellation_token_t& cancel = {});
};

}
