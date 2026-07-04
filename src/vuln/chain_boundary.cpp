#include "chain_boundary.hpp"

#include <utility>

namespace aida
{
namespace vuln
{
namespace chain
{
namespace
{

void append_issue(boundary_proof_t& proof, const contract_match_t& match)
{
    if (match.failure == failure_code_t::none)
        return;
    transfer_issue_t issue;
    issue.code = match.failure;
    issue.link_id = proof.consumer_link;
    issue.reason = match.rationale.empty() ? "typed boundary contract was not proven" : match.rationale;
    issue.acceptance_blocker = match.acceptance_blocker;
    issue.evidence = to_json(match);
    proof.issues.push_back(std::move(issue));
}

}

boundary_proof_t evaluate_typed_boundary(const std::string& producer_link,
                                         const std::string& consumer_link,
                                         const contract_trace_state_t& state,
                                         const std::vector<state_contract_t>& consumer_requirements)
{
    boundary_proof_t proof;
    proof.producer_link = producer_link;
    proof.consumer_link = consumer_link;
    proof.requirements = match_contracts(state, consumer_requirements, proof_level_t::p3_boundary_contracts);
    proof.verdict = proof.requirements.verdict;
    nlohmann::json matches = nlohmann::json::array();
    nlohmann::json mismatches = nlohmann::json::array();
    for (const contract_match_t& match : proof.requirements.matches)
    {
        if (match.verdict == chain_verdict_t::confirmed)
            matches.push_back(to_json(match));
        else
        {
            mismatches.push_back(to_json(match));
            append_issue(proof, match);
        }
    }
    proof.matrix = nlohmann::json{
        {"producer_link", producer_link},
        {"consumer_link", consumer_link},
        {"requirements", consumer_requirements.size()},
        {"matches", matches},
        {"mismatches", mismatches},
        {"acceptance_blocker", proof.requirements.has_acceptance_blocker}
    };
    return proof;
}

nlohmann::json to_json(const boundary_proof_t& proof)
{
    nlohmann::json issues = nlohmann::json::array();
    for (const transfer_issue_t& issue : proof.issues)
        issues.push_back(to_json(issue));
    return nlohmann::json{
        {"producer_link", proof.producer_link},
        {"consumer_link", proof.consumer_link},
        {"verdict", verdict_str(proof.verdict)},
        {"requirements", to_json(proof.requirements)},
        {"issues", issues},
        {"matrix", proof.matrix}
    };
}

}
}
}
