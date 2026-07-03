#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>

namespace aida
{
namespace vuln
{
namespace chain
{

enum class chain_verdict_t
{
    confirmed,
    refuted,
    inconclusive,
    timeout,
    unsupported
};

enum class contract_proof_state_t
{
    proven,
    refuted,
    conditional,
    unknown,
    unsupported,
    timeout
};

enum class proof_level_t
{
    none,
    p0_schema,
    p1_corpus,
    p2_link_obligations,
    p3_boundary_contracts,
    p4_objective_semantics,
    p5_complete
};

enum class contract_fact_kind_t
{
    value,
    content,
    address,
    reg,
    stack,
    memory,
    alias,
    object_lifetime,
    control_authority,
    event,
    trigger,
    protocol,
    firmware,
    side_effect,
    objective,
    call,
    branch,
    return_state,
    solver,
    diagnostic
};

enum class contract_dimension_t
{
    value,
    identity,
    content,
    alias_set,
    object_lifetime,
    timing,
    authority_control,
    final_objective
};

enum class contract_criticality_t
{
    chain_critical,
    objective_critical,
    collateral,
    diagnostic
};

enum class failure_code_t
{
    none,
    invalid_chain_schema,
    ambiguous_corpus_binding,
    missing_corpus,
    stale_generation,
    analysis_unsettled,
    extractor_layer_failed,
    hexrays_unavailable,
    microcode_unavailable,
    unsupported_instruction,
    unsupported_helper,
    path_target_unreachable,
    reachable_set_incomplete,
    branch_required_direction_unsat,
    branch_required_direction_unknown,
    indirect_target_unproven,
    call_target_mismatch,
    abi_state_mismatch,
    register_clobber_unproven,
    postcondition_precondition_mismatch,
    content_provenance_mismatch,
    controlledness_unproven,
    alias_must_not_proven,
    self_reference_unproven,
    lifetime_order_unproven,
    address_knowledge_gap,
    allocator_reuse_unproven,
    callback_registration_unproven,
    trigger_path_not_reached,
    protocol_state_mismatch,
    protocol_length_mismatch,
    protocol_checksum_mismatch,
    firmware_dispatch_unproven,
    collateral_damage_unproven,
    fatal_side_effect,
    solver_timeout,
    solver_unknown,
    peer_unavailable,
    resource_exhausted,
    objective_not_achieved
};

struct chain_location_t
{
    std::string corpus_id;
    ea_t ea = BADADDR;
    uint64_t rva = 0;
    bool has_rva = false;
    std::string segment;
    std::string function_id;
    std::string instruction_id;
    std::string layer;
    std::string confidence;
};

struct evidence_t
{
    std::string evidence_id;
    std::string corpus_id;
    chain_location_t location;
    std::string layer;
    std::string lineage;
    std::string snippet;
    std::string snapshot_id;
    nlohmann::json payload = nlohmann::json::object();
};

struct chain_fact_t
{
    std::string fact_id;
    contract_fact_kind_t kind = contract_fact_kind_t::diagnostic;
    std::string subject;
    std::string predicate;
    nlohmann::json value = nlohmann::json::object();
    std::string phase;
    std::string producer;
    std::vector<evidence_t> evidence;
    contract_proof_state_t proof_state = contract_proof_state_t::unknown;
    contract_criticality_t criticality = contract_criticality_t::diagnostic;
};

struct state_contract_t
{
    std::string contract_id;
    contract_dimension_t dimension = contract_dimension_t::value;
    std::string subject;
    std::string predicate;
    nlohmann::json required = nlohmann::json::object();
    std::string consumer_link_id;
    contract_criticality_t criticality = contract_criticality_t::chain_critical;
    contract_proof_state_t declared_state = contract_proof_state_t::unknown;
    failure_code_t failure_when_unmet = failure_code_t::postcondition_precondition_mismatch;
};

struct contract_match_t
{
    std::string contract_id;
    std::string producer_fact_id;
    contract_dimension_t dimension = contract_dimension_t::value;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    contract_proof_state_t proof_state = contract_proof_state_t::unknown;
    failure_code_t failure = failure_code_t::none;
    bool acceptance_blocker = true;
    std::string rationale;
    nlohmann::json evidence = nlohmann::json::object();
};

struct contract_trace_state_t
{
    std::vector<chain_fact_t> facts;
    std::unordered_map<std::string, size_t> fact_index;
    std::unordered_map<std::string, size_t> phase_order;
    std::string state_id;
};

struct contract_evaluation_t
{
    chain_verdict_t verdict = chain_verdict_t::confirmed;
    proof_level_t proof_level = proof_level_t::none;
    std::vector<contract_match_t> matches;
    std::vector<failure_code_t> failures;
    bool has_acceptance_blocker = false;
};

const char* verdict_str(chain_verdict_t verdict);
const char* proof_state_str(contract_proof_state_t state);
const char* proof_level_str(proof_level_t level);
const char* fact_kind_str(contract_fact_kind_t kind);
const char* contract_dimension_str(contract_dimension_t dimension);
const char* criticality_str(contract_criticality_t criticality);
const char* failure_code_str(failure_code_t code);

chain_verdict_t combine_verdict(chain_verdict_t current, chain_verdict_t next);
bool proof_state_accepts(contract_proof_state_t state);
bool criticality_blocks_acceptance(contract_criticality_t criticality);
bool failure_blocks_acceptance(failure_code_t code);

contract_fact_kind_t parse_fact_kind(const std::string& value);
contract_proof_state_t parse_proof_state(const std::string& value);
contract_dimension_t parse_contract_dimension(const std::string& value);
contract_criticality_t parse_criticality(const std::string& value);
failure_code_t parse_failure_code(const std::string& value);

std::string stable_hash_hex(const std::string& input);
std::string canonical_json_hash(const nlohmann::json& value);

contract_trace_state_t make_trace_state(const std::vector<chain_fact_t>& facts);
contract_trace_state_t append_fact(const contract_trace_state_t& state, const chain_fact_t& fact);

chain_fact_t fact_from_json(const nlohmann::json& value,
                            const std::string& default_phase,
                            const std::string& default_producer);
state_contract_t contract_from_json(const nlohmann::json& value,
                                    const std::string& default_link_id,
                                    contract_dimension_t default_dimension);
std::vector<state_contract_t> contracts_from_json_array(const nlohmann::json& value,
                                                        const std::string& default_link_id,
                                                        contract_dimension_t default_dimension);

contract_match_t match_contract(const contract_trace_state_t& state, const state_contract_t& contract);
contract_evaluation_t match_contracts(const contract_trace_state_t& state,
                                      const std::vector<state_contract_t>& contracts,
                                      proof_level_t level);

nlohmann::json to_json(const chain_location_t& location);
nlohmann::json to_json(const evidence_t& evidence);
nlohmann::json to_json(const chain_fact_t& fact);
nlohmann::json to_json(const state_contract_t& contract);
nlohmann::json to_json(const contract_match_t& match);
nlohmann::json to_json(const contract_trace_state_t& state);
nlohmann::json to_json(const contract_evaluation_t& evaluation);

}
}
}
