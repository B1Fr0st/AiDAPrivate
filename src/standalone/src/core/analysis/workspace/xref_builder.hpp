#pragma once

#include "byte_provider.hpp"
#include "compact_ir.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace aida::analysis {

enum class data_candidate_kind_t : std::uint8_t {
    relocation_slot = 0,
    import_address_slot,
    load_config_pointer,
    thread_local_storage,
    referenced_storage,
    in_image_pointer
};

struct data_candidate_record_t {
    entity_id_t id = 0;
    address_t address;
    std::uint64_t size = 0;
    data_candidate_kind_t kind = data_candidate_kind_t::referenced_storage;
    std::optional<address_t> target;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct xref_build_limits_t {
    std::uint64_t max_xrefs = 1ULL << 28;
    std::uint64_t max_data_candidates = 1ULL << 27;
    std::uint64_t max_pointer_scan_bytes = 1ULL << 34;
    std::uint64_t max_result_bytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t read_window_bytes = 4ULL * 1024ULL * 1024ULL;
    std::uint32_t cancellation_check_interval = 4096;
};

struct xref_build_result_t {
    std::vector<xref_record_t> xrefs;
    std::vector<data_candidate_record_t> data_candidates;
    std::uint64_t bytes_scanned = 0;
    std::uint64_t mapped_bytes = 0;
    std::uint64_t provider_leases = 0;
};

class xref_builder_t final {
public:
    static workspace_result_t<xref_build_result_t> build(
        const workspace_image_t& image,
        const byte_provider_t& provider,
        const std::vector<instruction_record_t>& instructions,
        const std::vector<operand_fact_t>& operands,
        const std::vector<target_fact_t>& targets,
        const xref_build_limits_t& limits,
        const cancellation_token_t& cancel);
};

}
