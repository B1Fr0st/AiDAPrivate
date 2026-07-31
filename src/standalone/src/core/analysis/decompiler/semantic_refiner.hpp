#pragma once

#include "triton_z3_adapter.hpp"
#include "pseudocode_readability.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace aida::analysis {

enum class semantic_refinement_status_t : std::uint8_t {
    completed = 1,
    completed_with_unknowns = 2,
    profile_rejected = 3,
    input_rejected = 4,
    adapter_denied = 5,
    cancelled = 6
};

struct semantic_refinement_query_t {
    std::uint64_t ordinal = 0;
    std::string stable_id;
    source_coordinate_t coordinate;
    triton_z3_static_ir_t static_ir;
    std::string refinement_key;
};

struct semantic_refinement_request_t {
    decompiler_profile_budget_t profile;
    hir_function_t function;
    std::vector<semantic_refinement_query_t> queries;
};

struct semantic_refinement_fact_t {
    std::uint64_t ordinal = 0;
    std::string stable_id;
    std::string refinement_key;
    source_coordinate_t coordinate;
    std::uint8_t confidence = 100;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::semantic_proof;
};

struct semantic_refinement_result_t {
    semantic_refinement_status_t status = semantic_refinement_status_t::input_rejected;
    decompiler_semantic_proof_availability_t availability =
        decompiler_semantic_proof_availability_t::not_requested;
    std::vector<semantic_refinement_fact_t> facts;
    std::vector<decompiler_unknown_t> unknowns;
    std::vector<decompiler_diagnostic_t> diagnostics;
    std::uint32_t adapter_invocations = 0;
};

struct semantic_refiner_execution_state_t;

class semantic_refiner_t final {
public:
    explicit semantic_refiner_t(std::shared_ptr<triton_z3_adapter_t> adapter = {});

    semantic_refinement_result_t refine(
        const semantic_refinement_request_t& request,
        const cancellation_token_t& cancel = {}) const;

private:
    std::shared_ptr<triton_z3_adapter_t> adapter_;
    std::shared_ptr<semantic_refiner_execution_state_t> execution_state_;
};

}
