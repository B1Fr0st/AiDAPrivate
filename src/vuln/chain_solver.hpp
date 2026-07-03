#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "chain_budget.hpp"
#include "chain_state_contracts.hpp"
#include "smt_solver.hpp"

namespace aida
{
namespace vuln
{
namespace chain
{

enum class solver_obligation_kind_t
{
    branch,
    value,
    alias,
    protocol,
    objective,
    generic
};

enum class solver_expected_t
{
    sat,
    unsat
};

struct solver_obligation_t
{
    std::string obligation_id;
    solver_obligation_kind_t kind = solver_obligation_kind_t::generic;
    std::string link_id;
    std::string description;
    std::string smtlib2;
    solver_expected_t expected = solver_expected_t::sat;
    contract_criticality_t criticality = contract_criticality_t::chain_critical;
    contract_proof_state_t declared_state = contract_proof_state_t::unknown;
    failure_code_t unsat_failure = failure_code_t::branch_required_direction_unsat;
    failure_code_t unknown_failure = failure_code_t::branch_required_direction_unknown;
    uint32_t timeout_ms = 0;
};

struct solver_obligation_result_t
{
    std::string obligation_id;
    std::string query_id;
    solver_obligation_kind_t kind = solver_obligation_kind_t::generic;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    contract_proof_state_t proof_state = contract_proof_state_t::unknown;
    failure_code_t failure = failure_code_t::none;
    bool acceptance_blocker = true;
    uint64_t solve_ms = 0;
    bool cached = false;
    std::string rationale;
    smt::solve_result_t solver_result;
};

struct solver_batch_result_t
{
    chain_verdict_t verdict = chain_verdict_t::confirmed;
    std::vector<solver_obligation_result_t> results;
    std::vector<failure_code_t> failures;
    bool has_acceptance_blocker = false;
};

class chain_solver_t
{
public:
    explicit chain_solver_t(const budget_limits_t& limits = {});

    solver_obligation_result_t evaluate(const solver_obligation_t& obligation,
                                        budget_state_t& budget,
                                        const cancellation_token_t& token);

    solver_batch_result_t evaluate_all(const std::vector<solver_obligation_t>& obligations,
                                       budget_state_t& budget,
                                       const cancellation_token_t& token);

    void clear_cache();
    size_t cache_size() const;

private:
    budget_limits_t m_limits;
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, solver_obligation_result_t> m_cache;
};

solver_obligation_kind_t parse_solver_obligation_kind(const std::string& value);
solver_expected_t parse_solver_expected(const std::string& value);
const char* solver_obligation_kind_str(solver_obligation_kind_t kind);
const char* solver_expected_str(solver_expected_t expected);
solver_obligation_t solver_obligation_from_json(const nlohmann::json& value,
                                                const std::string& default_link_id,
                                                solver_obligation_kind_t default_kind);
nlohmann::json to_json(const solver_obligation_t& obligation);
nlohmann::json to_json(const solver_obligation_result_t& result);
nlohmann::json to_json(const solver_batch_result_t& result);

}
}
}
