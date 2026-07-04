#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "chain_state_contracts.hpp"

namespace aida
{
namespace vuln
{
namespace chain
{

struct alias_derivation_context_t
{
    std::string link_id;
    std::string phase;
    contract_criticality_t criticality = contract_criticality_t::chain_critical;
    contract_proof_state_t proof_state = contract_proof_state_t::unknown;
    nlohmann::json evidence = nlohmann::json::object();
};

std::vector<chain_fact_t> derive_alias_facts(const nlohmann::json& event, const alias_derivation_context_t& context);
bool alias_event_is_self_reference(const nlohmann::json& event);
std::string alias_event_subject(const nlohmann::json& event);
std::string alias_event_target(const nlohmann::json& event);

}
}
}
