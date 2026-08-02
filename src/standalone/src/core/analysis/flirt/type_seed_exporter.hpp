#pragma once

#include "static_recognition_service.hpp"

#include "../decompiler/type_graph_builder.hpp"
#include "../workspace/type_recovery.hpp"
#include "../workspace/workspace_types.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace aida::analysis::static_recognition {

struct type_seed_export_options_t {
    std::uint8_t min_confidence = 70;
    std::uint32_t max_candidates = 512;
    std::uint32_t max_edges_per_candidate = 64;
    bool include_rtti = true;
    bool include_prototypes = true;
    bool include_structs = true;
};

std::vector<type_recovery_evidence_t>
make_static_rtti_evidence(const recognition_records_t& records,
                          std::uint64_t image_base);

workspace_result_t<std::vector<type_graph::type_seed_batch_t>>
make_recognition_seed_batches(const recognition_records_t& records,
                              const decompiler_entity_key_t& entity,
                              std::uint64_t generation,
                              const type_seed_export_options_t& options,
                              const type_recovery_result_t* recovered = nullptr);

}
