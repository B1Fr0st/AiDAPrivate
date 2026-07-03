#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>

#include "chain_budget.hpp"
#include "chain_solver.hpp"
#include "chain_state_contracts.hpp"

namespace aida
{
namespace vuln
{
namespace chain
{

struct verification_corpus_record_t
{
    std::string corpus_id;
    std::string kind;
    nlohmann::json identity = nlohmann::json::object();
    std::string availability;
    nlohmann::json loader_model = nlohmann::json::object();
    std::string trust;
    bool chain_critical = true;
};

struct verification_module_snapshot_t
{
    std::string snapshot_id;
    std::string root_filename;
    std::string input_path;
    std::string sha256;
    uint64_t image_base = 0;
    uint64_t min_ea = 0;
    uint64_t max_ea = 0;
    uint32_t pointer_width_bits = 0;
    std::string processor;
    std::string endianness;
    bool dll = false;
    bool kernel_mode = false;
    bool valid = false;
    std::string error;
};

struct verification_path_job_t
{
    std::string job_id;
    std::string link_id;
    size_t link_index = 0;
    std::vector<solver_obligation_t> branch_obligations;
    std::vector<state_contract_t> call_obligations;
    std::vector<state_contract_t> return_obligations;
    std::vector<state_contract_t> side_effect_obligations;
};

struct verification_chain_link_t
{
    std::string link_id;
    std::string role;
    nlohmann::json raw = nlohmann::json::object();
    std::vector<state_contract_t> preconditions;
    std::vector<chain_fact_t> produced_facts;
    std::vector<solver_obligation_t> solver_obligations;
    verification_path_job_t path_job;
};

struct verification_document_t
{
    std::string schema;
    std::string chain_id;
    std::string title;
    nlohmann::json target = nlohmann::json::object();
    std::vector<verification_corpus_record_t> corpus;
    std::vector<chain_fact_t> initial_facts;
    std::vector<verification_chain_link_t> links;
    std::vector<state_contract_t> objectives;
    nlohmann::json policies = nlohmann::json::object();
    nlohmann::json raw = nlohmann::json::object();
    std::string document_hash;
};

struct verification_request_t
{
    nlohmann::json document = nlohmann::json::object();
    budget_limits_t limits;
    cancellation_token_t cancellation;
    resume_cursor_t resume;
    bool capture_idb_snapshot = false;
};

struct verification_link_report_t
{
    std::string link_id;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    proof_level_t proof_level = proof_level_t::none;
    contract_evaluation_t preconditions;
    solver_batch_result_t solver;
    contract_evaluation_t calls;
    contract_evaluation_t returns;
    contract_evaluation_t side_effects;
    std::vector<chain_fact_t> produced_facts;
    std::vector<failure_code_t> failures;
};

struct verification_boundary_report_t
{
    std::string producer_link;
    std::string consumer_link;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    contract_evaluation_t requirements;
};

struct verification_objective_report_t
{
    std::string objective_id;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    contract_match_t match;
    failure_code_t failure = failure_code_t::none;
    nlohmann::json operation_evidence = nlohmann::json::object();
};

struct verification_report_t
{
    std::string report_id;
    std::string chain_id;
    std::string document_hash;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    proof_level_t proof_level = proof_level_t::none;
    job_record_t job;
    verification_module_snapshot_t module_snapshot;
    std::vector<failure_code_t> failures;
    std::vector<verification_link_report_t> links;
    std::vector<verification_boundary_report_t> boundaries;
    std::vector<verification_objective_report_t> objectives;
    contract_trace_state_t final_state;
    nlohmann::json diagnostics = nlohmann::json::object();
};

class ChainVerificationEngine
{
public:
    ChainVerificationEngine();
    ~ChainVerificationEngine();

    ChainVerificationEngine(const ChainVerificationEngine&) = delete;
    ChainVerificationEngine& operator=(const ChainVerificationEngine&) = delete;

    verification_report_t verify(const verification_request_t& request);
    bool normalize_document(const nlohmann::json& input,
                            verification_document_t& out,
                            std::vector<failure_code_t>& failures,
                            std::string& error) const;
    verification_module_snapshot_t capture_current_idb_snapshot() const;
    void cancel();
    size_t solver_cache_size() const;
    void clear_solver_cache();

private:
    struct impl_t;
    std::unique_ptr<impl_t> m_impl;
};

ChainVerificationEngine& engine();
std::vector<nlohmann::json> universal_synthetic_regression_specs();

nlohmann::json to_json(const verification_corpus_record_t& corpus);
nlohmann::json to_json(const verification_module_snapshot_t& snapshot);
nlohmann::json to_json(const verification_path_job_t& job);
nlohmann::json to_json(const verification_chain_link_t& link);
nlohmann::json to_json(const verification_document_t& document);
nlohmann::json to_json(const verification_request_t& request);
nlohmann::json to_json(const verification_link_report_t& report);
nlohmann::json to_json(const verification_boundary_report_t& report);
nlohmann::json to_json(const verification_objective_report_t& report);
nlohmann::json to_json(const verification_report_t& report);

}
}
}
