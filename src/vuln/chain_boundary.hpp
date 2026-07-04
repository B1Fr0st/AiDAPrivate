#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "chain_state_contracts.hpp"
#include "chain_transfer.hpp"

namespace aida
{
namespace vuln
{
namespace chain
{

struct boundary_proof_t
{
    std::string producer_link;
    std::string consumer_link;
    chain_verdict_t verdict = chain_verdict_t::confirmed;
    contract_evaluation_t requirements;
    std::vector<transfer_issue_t> issues;
    nlohmann::json matrix = nlohmann::json::object();
};

boundary_proof_t evaluate_typed_boundary(const std::string& producer_link,
                                         const std::string& consumer_link,
                                         const contract_trace_state_t& state,
                                         const std::vector<state_contract_t>& consumer_requirements);

nlohmann::json to_json(const boundary_proof_t& proof);

}
}
}
