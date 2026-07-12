#pragma once

#include "compact_ir.hpp"
#include "data_discovery.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <optional>
#include <string>
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

enum class metadata_provenance_t : std::uint8_t {
    unknown = 0,
    decoded = 1,
    relocation = 2,
    loader_symbol = 3,
    import_metadata = 4,
    export_metadata = 5,
    debug_metadata = 6,
    rtti = 7,
    vtable_validation = 8,
    objective_c_metadata = 9,
    swift_metadata = 10,
    managed_metadata = 11
};

std::uint8_t metadata_provenance_rank(metadata_provenance_t provenance) noexcept;

enum class symbol_type_candidate_kind_t : std::uint8_t {
    function_prototype = 0,
    import_prototype,
    global_object,
    pointer_object,
    rtti_type,
    virtual_table,
    type_information,
    objective_c_class,
    objective_c_protocol,
    objective_c_selector,
    swift_type,
    swift_protocol,
    managed_type,
    managed_method,
    managed_field,
    debug_type,
    metadata_region
};

enum class type_reference_kind_t : std::uint8_t {
    definition = 0,
    metadata_reference,
    inheritance,
    virtual_table_slot,
    protocol_conformance,
    managed_reference
};

struct symbol_type_candidate_record_t {
    entity_id_t id = 0;
    std::optional<address_t> address;
    std::optional<address_t> related_address;
    symbol_type_candidate_kind_t kind = symbol_type_candidate_kind_t::global_object;
    std::string display_name;
    std::string canonical_type;
    std::string source_key;
    metadata_provenance_t provenance = metadata_provenance_t::unknown;
    std::uint8_t confidence = 0;
    bool explicitly_unknown = true;
};

struct type_reference_fact_t {
    entity_id_t id = 0;
    std::optional<address_t> source;
    std::optional<address_t> target;
    entity_id_t source_entity = 0;
    entity_id_t target_entity = 0;
    type_reference_kind_t kind = type_reference_kind_t::metadata_reference;
    metadata_provenance_t provenance = metadata_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::string source_key;
};

enum class metadata_conflict_kind_t : std::uint8_t {
    symbol_kind = 0,
    type_kind,
    canonical_type,
    related_address
};

struct metadata_conflict_record_t {
    entity_id_t id = 0;
    std::optional<address_t> address;
    std::string identity;
    metadata_conflict_kind_t kind = metadata_conflict_kind_t::type_kind;
    std::string selected_value;
    std::string rejected_value;
    metadata_provenance_t selected_provenance = metadata_provenance_t::unknown;
    metadata_provenance_t rejected_provenance = metadata_provenance_t::unknown;
    std::uint8_t selected_confidence = 0;
    std::uint8_t rejected_confidence = 0;
};

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
