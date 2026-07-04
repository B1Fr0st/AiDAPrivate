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

struct protocol_derivation_context_t
{
    std::string link_id;
    std::string phase;
    contract_criticality_t criticality = contract_criticality_t::chain_critical;
    contract_proof_state_t proof_state = contract_proof_state_t::unknown;
    nlohmann::json evidence = nlohmann::json::object();
};

std::vector<chain_fact_t> derive_protocol_facts(const nlohmann::json& event, const protocol_derivation_context_t& context);
std::vector<chain_fact_t> derive_firmware_facts(const nlohmann::json& event, const protocol_derivation_context_t& context);
bool protocol_event_has_verified_checksum(const nlohmann::json& event);

}
}
}
