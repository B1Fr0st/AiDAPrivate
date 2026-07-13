#pragma once

#include "compact_ir.hpp"
#include "data_discovery.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <vector>

namespace aida::analysis {

struct elf_metadata_t;
struct pe_coff_normalized_record_t;

namespace readers {
struct macho_metadata_document_t;
namespace managed {
struct managed_artifact_t;
}
}

struct symbol_type_metadata_sources_t {
    const pe_coff_normalized_record_t* pe_coff = nullptr;
    const elf_metadata_t* elf = nullptr;
    const readers::macho_metadata_document_t* macho = nullptr;
    std::vector<const readers::managed::managed_artifact_t*> managed_artifacts;
};

struct symbol_type_candidate_limits_t {
    std::uint64_t max_symbols = 1ULL << 22;
    std::uint64_t max_type_candidates = 1ULL << 22;
    std::uint64_t max_type_references = 1ULL << 24;
    std::uint64_t max_conflicts = 1ULL << 20;
    std::uint64_t max_string_bytes = 512ULL * 1024ULL * 1024ULL;
    std::uint64_t max_result_bytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint32_t minimum_vtable_entries = 2;
    std::uint32_t maximum_vtable_entries = 4096;
    std::uint32_t cancellation_check_interval = 4096;
};

struct symbol_type_candidate_result_t {
    std::vector<symbol_record_t> symbols;
    std::vector<symbol_type_candidate_record_t> type_candidates;
    std::vector<type_reference_fact_t> type_references;
    std::vector<metadata_conflict_record_t> conflicts;
    std::uint64_t duplicate_symbols = 0;
    std::uint64_t duplicate_type_candidates = 0;
    std::uint64_t duplicate_type_references = 0;
};

class symbol_type_candidate_builder_t final {
public:
    static workspace_result_t<symbol_type_candidate_result_t> build(
        const workspace_image_t& image,
        const std::vector<function_record_t>& functions,
        const std::vector<data_candidate_record_t>& data_candidates,
        const symbol_type_metadata_sources_t& metadata,
        const symbol_type_candidate_limits_t& limits = {},
        const cancellation_token_t& cancel = {});
};

}
