#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "chain_path_trace.hpp"
#include "chain_state_contracts.hpp"

namespace aida
{
namespace vuln
{
namespace chain
{

struct transfer_issue_t
{
    failure_code_t code = failure_code_t::none;
    std::string link_id;
    std::string reason;
    bool acceptance_blocker = true;
    nlohmann::json evidence = nlohmann::json::object();
};

struct transfer_request_t
{
    std::string link_id;
    std::string role;
    nlohmann::json link = nlohmann::json::object();
    nlohmann::json target = nlohmann::json::object();
    std::size_t link_index = 0;
};

struct transfer_proof_t
{
    std::string link_id;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    contract_trace_state_t state;
    std::vector<chain_fact_t> derived_facts;
    std::vector<state_contract_t> produced_contracts;
    std::vector<contract_match_t> produced_matches;
    std::vector<transfer_issue_t> issues;
    bool trace_present = false;
    bool trace_reached = false;
    bool trace_complete = false;
    bool unsupported_transfer = false;
    bool unresolved_indirect_target = false;
    bool fatal_or_poisoned = false;
    bool objective_proven = false;
    nlohmann::json evidence_manifest = nlohmann::json::object();
};

transfer_proof_t derive_transfer_proof(const transfer_request_t& request,
                                       const contract_trace_state_t& entry_state,
                                       const std::vector<chain_fact_t>& expected_facts);

state_contract_t contract_from_expected_fact(const chain_fact_t& fact, const std::string& consumer_link_id);
chain_verdict_t verdict_for_transfer_issues(const std::vector<transfer_issue_t>& issues);
nlohmann::json to_json(const transfer_issue_t& issue);
nlohmann::json to_json(const transfer_proof_t& proof);

}
}
}
