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

struct cross_domain_request_t
{
    std::string link_id;
    nlohmann::json link = nlohmann::json::object();
    nlohmann::json target = nlohmann::json::object();
    nlohmann::json corpus = nlohmann::json::array();
};

struct cross_domain_proof_t
{
    std::string link_id;
    chain_verdict_t verdict = chain_verdict_t::confirmed;
    std::vector<chain_fact_t> facts;
    std::vector<transfer_issue_t> issues;
    bool transition_present = false;
    bool abi_proven = false;
    bool peer_available = true;
    bool generation_current = true;
    bool import_export_proven = false;
    bool callback_or_event_proven = false;
    bool firmware_or_protocol_proven = false;
    bool cross_module_call_proven = false;
    nlohmann::json evidence = nlohmann::json::object();
};

cross_domain_proof_t evaluate_cross_domain_transition(const cross_domain_request_t& request,
                                                      const contract_trace_state_t& state);
nlohmann::json to_json(const cross_domain_proof_t& proof);

}
}
}
