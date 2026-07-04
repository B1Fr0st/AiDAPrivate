#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "chain_schema.hpp"
#include "chain_state.hpp"
#include "chain_state_contracts.hpp"

namespace aida
{
namespace vuln
{
namespace chain
{

enum class report_acceptance_t
{
    accepted,
    rejected,
    blocked
};

enum class report_proof_level_t
{
    p0_schema,
    p1_corpus,
    p2_extraction,
    p3_path,
    p4_state,
    p5_solver,
    p6_goal
};

enum class confidence_policy_t
{
    strict_proof_only,
    diagnostic_confidence_only
};

struct failure_record_t
{
    std::string code;
    bool acceptance_blocker = true;
    std::string summary;
    std::vector<std::string> fact_ids;
    std::vector<evidence_ref_t> evidence;
    nlohmann::json metadata = nlohmann::json::object();
};

struct refutation_record_t
{
    std::string refutation_id;
    std::string code;
    std::string producer_fact_id;
    std::string consumer_fact_id;
    std::string summary;
    std::vector<evidence_ref_t> evidence;
    nlohmann::json metadata = nlohmann::json::object();
};

struct boundary_matrix_entry_t
{
    std::string producer_link;
    std::string consumer_link;
    std::vector<std::string> requirements;
    std::vector<std::string> matches;
    std::vector<std::string> mismatches;
    std::vector<std::string> unproven;
    nlohmann::json content_provenance_matrix = nlohmann::json::array();
    nlohmann::json lifetime_temporal_matrix = nlohmann::json::array();
    nlohmann::json alias_matrix = nlohmann::json::array();
};

struct phase_status_t
{
    std::string phase;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    std::uint64_t elapsed_ms = 0;
    std::vector<failure_record_t> failures;
    nlohmann::json metadata = nlohmann::json::object();
};

struct link_report_t
{
    std::string link_id;
    link_role_t role = link_role_t::generic_transition;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    report_proof_level_t proof_level = report_proof_level_t::p0_schema;
    nlohmann::json entry_state_summary = nlohmann::json::object();
    nlohmann::json path_corridors = nlohmann::json::array();
    nlohmann::json branches = nlohmann::json::array();
    nlohmann::json calls = nlohmann::json::array();
    nlohmann::json effects = nlohmann::json::array();
    std::vector<side_effect_t> side_effects;
    std::vector<fact_t> postconditions;
    std::vector<fact_t> unproven_facts;
    std::vector<refutation_record_t> refutations;
};

struct objective_report_t
{
    std::string objective_id;
    objective_kind_t kind = objective_kind_t::custom;
    nlohmann::json operation_sequence = nlohmann::json::array();
    std::vector<std::string> required_fact_ids;
    std::vector<std::string> proven_fact_ids;
    std::vector<refutation_record_t> contradictions;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    nlohmann::json collateral_safety = nlohmann::json::object();
};

struct chain_report_t
{
    std::string schema = k_chain_report_schema;
    int version = k_chain_report_version;
    std::string report_id;
    std::string chain_id;
    std::string job_id;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    report_acceptance_t acceptance = report_acceptance_t::blocked;
    confidence_policy_t confidence = confidence_policy_t::strict_proof_only;
    report_proof_level_t proof_level_reached = report_proof_level_t::p0_schema;
    std::string refutation_level;
    std::string summary;
    failure_record_t first_failure;
    std::vector<fact_t> unproven_critical_facts;
    std::vector<corpus_record_t> corpus;
    std::vector<phase_status_t> phase_status;
    std::vector<link_report_t> links;
    std::vector<boundary_matrix_entry_t> boundaries;
    std::vector<objective_report_t> objectives;
    nlohmann::json trace_manifest = nlohmann::json::object();
    nlohmann::json fact_manifest = nlohmann::json::object();
    nlohmann::json solver_manifest = nlohmann::json::object();
    nlohmann::json resource_manifest = nlohmann::json::object();
    nlohmann::json generation_manifest = nlohmann::json::object();
    nlohmann::json budget_manifest = nlohmann::json::object();
    nlohmann::json diagnostics = nlohmann::json::object();
};

const char* to_string(chain_verdict_t value);
const char* to_string(report_acceptance_t value);
const char* to_string(report_proof_level_t value);
const char* to_string(confidence_policy_t value);

std::optional<chain_verdict_t> chain_verdict_from_string(const std::string& value);
std::optional<report_acceptance_t> report_acceptance_from_string(const std::string& value);
std::optional<report_proof_level_t> proof_level_from_string(const std::string& value);
std::optional<confidence_policy_t> confidence_policy_from_string(const std::string& value);

nlohmann::json to_json(const failure_record_t& value);
nlohmann::json to_json(const refutation_record_t& value);
nlohmann::json to_json(const boundary_matrix_entry_t& value);
nlohmann::json to_json(const phase_status_t& value);
nlohmann::json to_json(const link_report_t& value);
nlohmann::json to_json(const objective_report_t& value);
nlohmann::json to_json(const chain_report_t& value);

failure_record_t failure_from_validation(const validation_error_t& value);
chain_report_t make_schema_report(const chain_document_t& document, const validation_result_t& validation);
chain_report_t make_report_skeleton(const chain_document_t& document, const std::string& job_id);
void finalize_report_acceptance(chain_report_t& report);
validation_result_t validate_chain_report(const chain_report_t& report);
nlohmann::json report_machine_export(const chain_report_t& report);
validation_result_t chain_report_self_check();

}
}
}
