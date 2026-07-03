#include "chain_state_contracts.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <sstream>

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

std::string lower_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string read_string(const nlohmann::json& value, const char* key, const std::string& fallback = {})
{
    if (!value.is_object() || !value.contains(key))
        return fallback;
    const auto& item = value.at(key);
    if (item.is_string())
        return item.get<std::string>();
    if (item.is_number_integer())
        return std::to_string(item.get<int64_t>());
    if (item.is_number_unsigned())
        return std::to_string(item.get<uint64_t>());
    if (item.is_boolean())
        return item.get<bool>() ? "true" : "false";
    return fallback;
}

uint64_t read_u64_any(const nlohmann::json& value, uint64_t fallback = 0)
{
    if (value.is_number_unsigned())
        return value.get<uint64_t>();
    if (value.is_number_integer())
        return static_cast<uint64_t>(value.get<int64_t>());
    if (!value.is_string())
        return fallback;
    std::string s = lower_copy(value.get<std::string>());
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && s[1] == 'x')
        base = 16;
    char* end = nullptr;
    const uint64_t out = _strtoui64(s.c_str(), &end, base);
    return end && *end == 0 ? out : fallback;
}

bool read_bool(const nlohmann::json& value, const char* key, bool fallback = false)
{
    if (!value.is_object() || !value.contains(key))
        return fallback;
    const auto& item = value.at(key);
    if (item.is_boolean())
        return item.get<bool>();
    if (item.is_string())
    {
        const std::string s = lower_copy(item.get<std::string>());
        return s == "true" || s == "yes" || s == "1" || s == "proven";
    }
    if (item.is_number_integer())
        return item.get<int64_t>() != 0;
    return fallback;
}

const nlohmann::json& fact_payload(const chain_fact_t& fact)
{
    if (fact.value.is_object() && fact.value.contains("value"))
        return fact.value.at("value");
    return fact.value;
}

bool json_value_equal(const nlohmann::json& a, const nlohmann::json& b)
{
    if (a == b)
        return true;
    if (a.is_string() && b.is_string())
        return lower_copy(a.get<std::string>()) == lower_copy(b.get<std::string>());
    if ((a.is_string() || a.is_number()) && (b.is_string() || b.is_number()))
    {
        const uint64_t sentinel = UINT64_MAX;
        const uint64_t av = read_u64_any(a, sentinel);
        const uint64_t bv = read_u64_any(b, sentinel);
        return av != sentinel && bv != sentinel && av == bv;
    }
    return false;
}

failure_code_t default_failure_for(contract_dimension_t dimension)
{
    switch (dimension)
    {
    case contract_dimension_t::value: return failure_code_t::postcondition_precondition_mismatch;
    case contract_dimension_t::identity: return failure_code_t::ambiguous_corpus_binding;
    case contract_dimension_t::content: return failure_code_t::content_provenance_mismatch;
    case contract_dimension_t::alias_set: return failure_code_t::alias_must_not_proven;
    case contract_dimension_t::object_lifetime: return failure_code_t::lifetime_order_unproven;
    case contract_dimension_t::timing: return failure_code_t::lifetime_order_unproven;
    case contract_dimension_t::authority_control: return failure_code_t::controlledness_unproven;
    case contract_dimension_t::final_objective: return failure_code_t::objective_not_achieved;
    }
    return failure_code_t::postcondition_precondition_mismatch;
}

chain_verdict_t verdict_from_unaccepted_state(contract_proof_state_t state)
{
    switch (state)
    {
    case contract_proof_state_t::timeout: return chain_verdict_t::timeout;
    case contract_proof_state_t::unsupported: return chain_verdict_t::unsupported;
    case contract_proof_state_t::refuted: return chain_verdict_t::refuted;
    case contract_proof_state_t::conditional:
    case contract_proof_state_t::unknown:
    case contract_proof_state_t::proven:
        return chain_verdict_t::inconclusive;
    }
    return chain_verdict_t::inconclusive;
}

bool content_is_controlled(const chain_fact_t& fact)
{
    if (!fact.value.is_object())
        return false;
    if (read_bool(fact.value, "controlled", false))
        return true;
    const std::string cls = lower_copy(read_string(fact.value, "content_class"));
    const std::string degree = lower_copy(read_string(fact.value, "control_degree"));
    return cls == "controlled" || cls == "symbolic_controlled" || degree == "full" || degree == "bounded";
}

bool content_is_zero(const chain_fact_t& fact)
{
    if (!fact.value.is_object())
        return false;
    const std::string cls = lower_copy(read_string(fact.value, "content_class"));
    return cls == "zero" || cls == "zero_bytes" || read_bool(fact.value, "zero", false);
}

bool proof_matches_declared(const chain_fact_t& fact, contract_match_t& out, failure_code_t failure)
{
    if (proof_state_accepts(fact.proof_state))
        return true;
    out.verdict = verdict_from_unaccepted_state(fact.proof_state);
    out.proof_state = fact.proof_state;
    out.failure = fact.proof_state == contract_proof_state_t::timeout ? failure_code_t::solver_timeout : failure;
    out.rationale = "candidate fact is not proven";
    return false;
}

bool fact_subject_predicate_match(const chain_fact_t& fact, const state_contract_t& contract)
{
    if (contract.required.is_object() && contract.required.contains("fact_id"))
    {
        const std::string fact_id = read_string(contract.required, "fact_id");
        if (!fact_id.empty())
            return fact.fact_id == fact_id;
    }
    if (!contract.subject.empty() && fact.subject != contract.subject)
        return false;
    if (!contract.predicate.empty() && fact.predicate != contract.predicate)
        return false;
    return true;
}

std::vector<const chain_fact_t*> candidate_facts(const contract_trace_state_t& state, const state_contract_t& contract)
{
    std::vector<const chain_fact_t*> out;
    for (const chain_fact_t& fact : state.facts)
    {
        if (fact_subject_predicate_match(fact, contract))
            out.push_back(&fact);
    }
    return out;
}

bool order_before(const contract_trace_state_t& state, const std::string& earlier, const std::string& later)
{
    const auto it_a = state.phase_order.find(earlier);
    const auto it_b = state.phase_order.find(later);
    if (it_a == state.phase_order.end() || it_b == state.phase_order.end())
        return false;
    return it_a->second < it_b->second;
}

contract_match_t make_unmatched(const state_contract_t& contract, failure_code_t failure, const std::string& rationale)
{
    contract_match_t out;
    out.contract_id = contract.contract_id;
    out.dimension = contract.dimension;
    out.verdict = chain_verdict_t::inconclusive;
    out.proof_state = contract_proof_state_t::unknown;
    out.failure = failure == failure_code_t::none ? default_failure_for(contract.dimension) : failure;
    out.acceptance_blocker = criticality_blocks_acceptance(contract.criticality);
    out.rationale = rationale;
    return out;
}

}

const char* verdict_str(chain_verdict_t verdict)
{
    switch (verdict)
    {
    case chain_verdict_t::confirmed: return "confirmed";
    case chain_verdict_t::refuted: return "refuted";
    case chain_verdict_t::inconclusive: return "inconclusive";
    case chain_verdict_t::timeout: return "timeout";
    case chain_verdict_t::unsupported: return "unsupported";
    }
    return "inconclusive";
}

const char* proof_state_str(contract_proof_state_t state)
{
    switch (state)
    {
    case contract_proof_state_t::proven: return "proven";
    case contract_proof_state_t::refuted: return "refuted";
    case contract_proof_state_t::conditional: return "conditional";
    case contract_proof_state_t::unknown: return "unknown";
    case contract_proof_state_t::unsupported: return "unsupported";
    case contract_proof_state_t::timeout: return "timeout";
    }
    return "unknown";
}

const char* proof_level_str(proof_level_t level)
{
    switch (level)
    {
    case proof_level_t::none: return "none";
    case proof_level_t::p0_schema: return "P0_schema";
    case proof_level_t::p1_corpus: return "P1_corpus";
    case proof_level_t::p2_link_obligations: return "P2_link_obligations";
    case proof_level_t::p3_boundary_contracts: return "P3_boundary_contracts";
    case proof_level_t::p4_objective_semantics: return "P4_objective_semantics";
    case proof_level_t::p5_complete: return "P5_complete";
    }
    return "none";
}

const char* fact_kind_str(contract_fact_kind_t kind)
{
    switch (kind)
    {
    case contract_fact_kind_t::value: return "value_fact";
    case contract_fact_kind_t::content: return "content_fact";
    case contract_fact_kind_t::address: return "address_fact";
    case contract_fact_kind_t::reg: return "register_fact";
    case contract_fact_kind_t::stack: return "stack_fact";
    case contract_fact_kind_t::memory: return "memory_fact";
    case contract_fact_kind_t::alias: return "alias_fact";
    case contract_fact_kind_t::object_lifetime: return "lifetime_fact";
    case contract_fact_kind_t::control_authority: return "control_authority_fact";
    case contract_fact_kind_t::event: return "event_fact";
    case contract_fact_kind_t::trigger: return "trigger_fact";
    case contract_fact_kind_t::protocol: return "protocol_fact";
    case contract_fact_kind_t::firmware: return "firmware_fact";
    case contract_fact_kind_t::side_effect: return "side_effect_fact";
    case contract_fact_kind_t::objective: return "objective_fact";
    case contract_fact_kind_t::call: return "call_fact";
    case contract_fact_kind_t::branch: return "branch_fact";
    case contract_fact_kind_t::return_state: return "return_fact";
    case contract_fact_kind_t::solver: return "solver_fact";
    case contract_fact_kind_t::diagnostic: return "diagnostic_fact";
    }
    return "diagnostic_fact";
}

const char* contract_dimension_str(contract_dimension_t dimension)
{
    switch (dimension)
    {
    case contract_dimension_t::value: return "value";
    case contract_dimension_t::identity: return "identity";
    case contract_dimension_t::content: return "content";
    case contract_dimension_t::alias_set: return "alias_set";
    case contract_dimension_t::object_lifetime: return "object_lifetime";
    case contract_dimension_t::timing: return "timing";
    case contract_dimension_t::authority_control: return "authority_control";
    case contract_dimension_t::final_objective: return "final_objective";
    }
    return "value";
}

const char* criticality_str(contract_criticality_t criticality)
{
    switch (criticality)
    {
    case contract_criticality_t::chain_critical: return "chain_critical";
    case contract_criticality_t::objective_critical: return "objective_critical";
    case contract_criticality_t::collateral: return "collateral";
    case contract_criticality_t::diagnostic: return "diagnostic";
    }
    return "diagnostic";
}

const char* failure_code_str(failure_code_t code)
{
    switch (code)
    {
    case failure_code_t::none: return "none";
    case failure_code_t::invalid_chain_schema: return "invalid_chain_schema";
    case failure_code_t::ambiguous_corpus_binding: return "ambiguous_corpus_binding";
    case failure_code_t::missing_corpus: return "missing_corpus";
    case failure_code_t::stale_generation: return "stale_generation";
    case failure_code_t::analysis_unsettled: return "analysis_unsettled";
    case failure_code_t::extractor_layer_failed: return "extractor_layer_failed";
    case failure_code_t::hexrays_unavailable: return "hexrays_unavailable";
    case failure_code_t::microcode_unavailable: return "microcode_unavailable";
    case failure_code_t::unsupported_instruction: return "unsupported_instruction";
    case failure_code_t::unsupported_helper: return "unsupported_helper";
    case failure_code_t::path_target_unreachable: return "path_target_unreachable";
    case failure_code_t::reachable_set_incomplete: return "reachable_set_incomplete";
    case failure_code_t::branch_required_direction_unsat: return "branch_required_direction_unsat";
    case failure_code_t::branch_required_direction_unknown: return "branch_required_direction_unknown";
    case failure_code_t::indirect_target_unproven: return "indirect_target_unproven";
    case failure_code_t::call_target_mismatch: return "call_target_mismatch";
    case failure_code_t::abi_state_mismatch: return "abi_state_mismatch";
    case failure_code_t::register_clobber_unproven: return "register_clobber_unproven";
    case failure_code_t::postcondition_precondition_mismatch: return "postcondition_precondition_mismatch";
    case failure_code_t::content_provenance_mismatch: return "content_provenance_mismatch";
    case failure_code_t::controlledness_unproven: return "controlledness_unproven";
    case failure_code_t::alias_must_not_proven: return "alias_must_not_proven";
    case failure_code_t::self_reference_unproven: return "self_reference_unproven";
    case failure_code_t::lifetime_order_unproven: return "lifetime_order_unproven";
    case failure_code_t::address_knowledge_gap: return "address_knowledge_gap";
    case failure_code_t::allocator_reuse_unproven: return "allocator_reuse_unproven";
    case failure_code_t::callback_registration_unproven: return "callback_registration_unproven";
    case failure_code_t::trigger_path_not_reached: return "trigger_path_not_reached";
    case failure_code_t::protocol_state_mismatch: return "protocol_state_mismatch";
    case failure_code_t::protocol_length_mismatch: return "protocol_length_mismatch";
    case failure_code_t::protocol_checksum_mismatch: return "protocol_checksum_mismatch";
    case failure_code_t::firmware_dispatch_unproven: return "firmware_dispatch_unproven";
    case failure_code_t::collateral_damage_unproven: return "collateral_damage_unproven";
    case failure_code_t::fatal_side_effect: return "fatal_side_effect";
    case failure_code_t::solver_timeout: return "solver_timeout";
    case failure_code_t::solver_unknown: return "solver_unknown";
    case failure_code_t::peer_unavailable: return "peer_unavailable";
    case failure_code_t::resource_exhausted: return "resource_exhausted";
    case failure_code_t::objective_not_achieved: return "objective_not_achieved";
    }
    return "none";
}

chain_verdict_t combine_verdict(chain_verdict_t current, chain_verdict_t next)
{
    if (current == chain_verdict_t::refuted || next == chain_verdict_t::refuted)
        return chain_verdict_t::refuted;
    if (current == chain_verdict_t::timeout || next == chain_verdict_t::timeout)
        return chain_verdict_t::timeout;
    if (current == chain_verdict_t::unsupported || next == chain_verdict_t::unsupported)
        return chain_verdict_t::unsupported;
    if (current == chain_verdict_t::inconclusive || next == chain_verdict_t::inconclusive)
        return chain_verdict_t::inconclusive;
    return chain_verdict_t::confirmed;
}

bool proof_state_accepts(contract_proof_state_t state)
{
    return state == contract_proof_state_t::proven;
}

bool criticality_blocks_acceptance(contract_criticality_t criticality)
{
    return criticality == contract_criticality_t::chain_critical || criticality == contract_criticality_t::objective_critical;
}

bool failure_blocks_acceptance(failure_code_t code)
{
    return code != failure_code_t::none;
}

contract_fact_kind_t parse_fact_kind(const std::string& value)
{
    const std::string s = lower_copy(value);
    if (s == "value" || s == "value_fact") return contract_fact_kind_t::value;
    if (s == "content" || s == "content_fact") return contract_fact_kind_t::content;
    if (s == "address" || s == "address_fact") return contract_fact_kind_t::address;
    if (s == "register" || s == "register_fact" || s == "reg") return contract_fact_kind_t::reg;
    if (s == "stack" || s == "stack_fact") return contract_fact_kind_t::stack;
    if (s == "memory" || s == "memory_fact") return contract_fact_kind_t::memory;
    if (s == "alias" || s == "alias_fact") return contract_fact_kind_t::alias;
    if (s == "lifetime" || s == "lifetime_fact" || s == "object_lifetime") return contract_fact_kind_t::object_lifetime;
    if (s == "control_authority" || s == "authority" || s == "control") return contract_fact_kind_t::control_authority;
    if (s == "event" || s == "event_fact") return contract_fact_kind_t::event;
    if (s == "trigger" || s == "trigger_fact") return contract_fact_kind_t::trigger;
    if (s == "protocol" || s == "protocol_fact") return contract_fact_kind_t::protocol;
    if (s == "firmware" || s == "firmware_fact") return contract_fact_kind_t::firmware;
    if (s == "side_effect" || s == "side_effect_fact") return contract_fact_kind_t::side_effect;
    if (s == "objective" || s == "objective_fact") return contract_fact_kind_t::objective;
    if (s == "call" || s == "call_fact") return contract_fact_kind_t::call;
    if (s == "branch" || s == "branch_fact") return contract_fact_kind_t::branch;
    if (s == "return" || s == "return_fact" || s == "return_state") return contract_fact_kind_t::return_state;
    if (s == "solver" || s == "solver_fact") return contract_fact_kind_t::solver;
    return contract_fact_kind_t::diagnostic;
}

contract_proof_state_t parse_proof_state(const std::string& value)
{
    const std::string s = lower_copy(value);
    if (s == "proven" || s == "confirmed" || s == "true") return contract_proof_state_t::proven;
    if (s == "refuted" || s == "false" || s == "contradicted") return contract_proof_state_t::refuted;
    if (s == "conditional") return contract_proof_state_t::conditional;
    if (s == "unsupported") return contract_proof_state_t::unsupported;
    if (s == "timeout" || s == "timed_out") return contract_proof_state_t::timeout;
    return contract_proof_state_t::unknown;
}

contract_dimension_t parse_contract_dimension(const std::string& value)
{
    const std::string s = lower_copy(value);
    if (s == "identity") return contract_dimension_t::identity;
    if (s == "content") return contract_dimension_t::content;
    if (s == "alias" || s == "alias_set") return contract_dimension_t::alias_set;
    if (s == "lifetime" || s == "object_lifetime") return contract_dimension_t::object_lifetime;
    if (s == "timing" || s == "temporal") return contract_dimension_t::timing;
    if (s == "authority" || s == "control" || s == "authority_control") return contract_dimension_t::authority_control;
    if (s == "objective" || s == "final_objective") return contract_dimension_t::final_objective;
    return contract_dimension_t::value;
}

contract_criticality_t parse_criticality(const std::string& value)
{
    const std::string s = lower_copy(value);
    if (s == "chain_critical" || s == "critical") return contract_criticality_t::chain_critical;
    if (s == "objective_critical") return contract_criticality_t::objective_critical;
    if (s == "collateral") return contract_criticality_t::collateral;
    return contract_criticality_t::diagnostic;
}

failure_code_t parse_failure_code(const std::string& value)
{
    const std::string s = lower_copy(value);
    for (int i = static_cast<int>(failure_code_t::none); i <= static_cast<int>(failure_code_t::objective_not_achieved); ++i)
    {
        const auto code = static_cast<failure_code_t>(i);
        if (s == failure_code_str(code))
            return code;
    }
    return failure_code_t::none;
}

std::string stable_hash_hex(const std::string& input)
{
    uint64_t hash = 1469598103934665603ull;
    for (unsigned char c : input)
    {
        hash ^= c;
        hash *= 1099511628211ull;
    }
    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << hash;
    return oss.str();
}

std::string canonical_json_hash(const nlohmann::json& value)
{
    return stable_hash_hex(value.dump());
}

contract_trace_state_t make_trace_state(const std::vector<chain_fact_t>& facts)
{
    contract_trace_state_t state;
    state.facts = facts;
    for (size_t i = 0; i < state.facts.size(); ++i)
    {
        chain_fact_t& fact = state.facts[i];
        if (fact.fact_id.empty())
            fact.fact_id = "fact_" + stable_hash_hex(to_json(fact).dump());
        state.fact_index[fact.fact_id] = i;
        if (!fact.phase.empty() && state.phase_order.find(fact.phase) == state.phase_order.end())
            state.phase_order[fact.phase] = state.phase_order.size();
    }
    nlohmann::json fact_array = nlohmann::json::array();
    for (const chain_fact_t& fact : state.facts)
        fact_array.push_back(to_json(fact));
    state.state_id = "state_" + stable_hash_hex(fact_array.dump());
    return state;
}

contract_trace_state_t append_fact(const contract_trace_state_t& state, const chain_fact_t& fact)
{
    std::vector<chain_fact_t> facts = state.facts;
    facts.push_back(fact);
    return make_trace_state(facts);
}

chain_fact_t fact_from_json(const nlohmann::json& value, const std::string& default_phase, const std::string& default_producer)
{
    chain_fact_t fact;
    if (!value.is_object())
    {
        fact.value = value;
        fact.phase = default_phase;
        fact.producer = default_producer;
        fact.fact_id = "fact_" + stable_hash_hex(value.dump() + default_phase + default_producer);
        return fact;
    }
    fact.fact_id = read_string(value, "fact_id", read_string(value, "id"));
    fact.kind = parse_fact_kind(read_string(value, "kind", read_string(value, "fact_kind", "diagnostic_fact")));
    fact.subject = read_string(value, "subject");
    fact.predicate = read_string(value, "predicate", read_string(value, "op"));
    if (value.contains("value"))
        fact.value = value.at("value");
    else if (value.contains("content"))
        fact.value = value.at("content");
    else
        fact.value = value;
    fact.phase = read_string(value, "phase", default_phase);
    fact.producer = read_string(value, "producer", default_producer);
    fact.proof_state = parse_proof_state(read_string(value, "proof_state", read_string(value, "state", "unknown")));
    fact.criticality = parse_criticality(read_string(value, "criticality", "diagnostic"));
    if (value.contains("evidence") && value.at("evidence").is_array())
    {
        for (const auto& item : value.at("evidence"))
        {
            evidence_t ev;
            ev.evidence_id = read_string(item, "evidence_id", read_string(item, "id"));
            ev.corpus_id = read_string(item, "corpus_id");
            ev.layer = read_string(item, "layer");
            ev.lineage = read_string(item, "lineage");
            ev.snippet = read_string(item, "snippet");
            ev.snapshot_id = read_string(item, "snapshot_id");
            ev.payload = item;
            fact.evidence.push_back(std::move(ev));
        }
    }
    if (fact.fact_id.empty())
        fact.fact_id = "fact_" + stable_hash_hex(to_json(fact).dump());
    return fact;
}

state_contract_t contract_from_json(const nlohmann::json& value, const std::string& default_link_id, contract_dimension_t default_dimension)
{
    state_contract_t contract;
    if (!value.is_object())
    {
        contract.required = value;
        contract.consumer_link_id = default_link_id;
        contract.dimension = default_dimension;
        contract.contract_id = "contract_" + stable_hash_hex(value.dump() + default_link_id);
        contract.failure_when_unmet = default_failure_for(contract.dimension);
        return contract;
    }
    contract.contract_id = read_string(value, "contract_id", read_string(value, "id"));
    contract.dimension = parse_contract_dimension(read_string(value, "dimension", contract_dimension_str(default_dimension)));
    contract.subject = read_string(value, "subject");
    contract.predicate = read_string(value, "predicate", read_string(value, "op"));
    if (value.contains("required"))
        contract.required = value.at("required");
    else if (value.contains("value"))
        contract.required = nlohmann::json{{"value", value.at("value")}};
    else
        contract.required = value;
    contract.consumer_link_id = read_string(value, "consumer_link_id", default_link_id);
    contract.criticality = parse_criticality(read_string(value, "criticality", "chain_critical"));
    contract.declared_state = parse_proof_state(read_string(value, "proof_state", "unknown"));
    contract.failure_when_unmet = parse_failure_code(read_string(value, "failure_when_unmet"));
    if (contract.failure_when_unmet == failure_code_t::none)
        contract.failure_when_unmet = default_failure_for(contract.dimension);
    if (contract.contract_id.empty())
        contract.contract_id = "contract_" + stable_hash_hex(to_json(contract).dump());
    return contract;
}

std::vector<state_contract_t> contracts_from_json_array(const nlohmann::json& value,
                                                        const std::string& default_link_id,
                                                        contract_dimension_t default_dimension)
{
    std::vector<state_contract_t> out;
    if (!value.is_array())
        return out;
    out.reserve(value.size());
    for (const auto& item : value)
        out.push_back(contract_from_json(item, default_link_id, default_dimension));
    return out;
}

contract_match_t match_contract(const contract_trace_state_t& state, const state_contract_t& contract)
{
    if (contract.dimension == contract_dimension_t::timing)
    {
        const std::string before = read_string(contract.required, "before", read_string(contract.required, "producer_before"));
        const std::string after = read_string(contract.required, "after", read_string(contract.required, "consumer_after"));
        if (!before.empty() && !after.empty() && order_before(state, before, after))
        {
            contract_match_t out;
            out.contract_id = contract.contract_id;
            out.dimension = contract.dimension;
            out.verdict = chain_verdict_t::confirmed;
            out.proof_state = contract_proof_state_t::proven;
            out.acceptance_blocker = false;
            out.rationale = "phase order proven";
            out.evidence = nlohmann::json{{"before", before}, {"after", after}};
            return out;
        }
        return make_unmatched(contract, contract.failure_when_unmet, "phase order not proven");
    }

    const auto candidates = candidate_facts(state, contract);
    if (candidates.empty())
        return make_unmatched(contract, contract.failure_when_unmet, "no producer fact satisfies subject and predicate");

    contract_match_t best = make_unmatched(contract, contract.failure_when_unmet, "candidate facts did not satisfy contract");
    for (const chain_fact_t* fact : candidates)
    {
        contract_match_t out;
        out.contract_id = contract.contract_id;
        out.producer_fact_id = fact->fact_id;
        out.dimension = contract.dimension;
        out.proof_state = fact->proof_state;
        out.acceptance_blocker = criticality_blocks_acceptance(contract.criticality);
        if (!proof_matches_declared(*fact, out, contract.failure_when_unmet))
        {
            best = combine_verdict(best.verdict, out.verdict) == out.verdict ? out : best;
            continue;
        }

        bool matched = false;
        failure_code_t failure = contract.failure_when_unmet;
        switch (contract.dimension)
        {
        case contract_dimension_t::value:
        {
            if (contract.required.is_object() && contract.required.contains("value"))
                matched = json_value_equal(fact_payload(*fact), contract.required.at("value"));
            else if (contract.required.is_object() && contract.required.contains("equals"))
                matched = json_value_equal(fact_payload(*fact), contract.required.at("equals"));
            else
                matched = true;
            failure = failure_code_t::postcondition_precondition_mismatch;
            break;
        }
        case contract_dimension_t::identity:
        {
            const std::string required_id = read_string(contract.required, "identity", read_string(contract.required, "corpus_id"));
            const std::string fact_id = read_string(fact->value, "identity", read_string(fact->value, "corpus_id"));
            matched = required_id.empty() || required_id == fact_id;
            failure = failure_code_t::ambiguous_corpus_binding;
            break;
        }
        case contract_dimension_t::content:
        {
            const bool needs_control = read_bool(contract.required, "controlled", false) ||
                                       lower_copy(read_string(contract.required, "content_class")) == "controlled";
            const std::string required_class = lower_copy(read_string(contract.required, "content_class"));
            const std::string fact_class = lower_copy(read_string(fact->value, "content_class"));
            if (needs_control && !content_is_controlled(*fact))
            {
                matched = false;
                failure = content_is_zero(*fact) ? failure_code_t::content_provenance_mismatch : failure_code_t::controlledness_unproven;
            }
            else
            {
                matched = required_class.empty() || required_class == fact_class || (required_class == "controlled" && content_is_controlled(*fact));
                failure = failure_code_t::content_provenance_mismatch;
            }
            break;
        }
        case contract_dimension_t::alias_set:
        {
            const std::string required_target = read_string(contract.required, "target", read_string(contract.required, "alias"));
            const std::string fact_target = read_string(fact->value, "target", read_string(fact->value, "alias"));
            const bool self_ref_required = read_bool(contract.required, "self_reference", false) || lower_copy(contract.predicate) == "self_reference";
            const bool self_ref_fact = read_bool(fact->value, "self_reference", false) || lower_copy(fact->predicate) == "self_reference";
            matched = self_ref_required ? self_ref_fact : (required_target.empty() || required_target == fact_target);
            failure = self_ref_required ? failure_code_t::self_reference_unproven : failure_code_t::alias_must_not_proven;
            break;
        }
        case contract_dimension_t::object_lifetime:
        {
            const std::string required_state = lower_copy(read_string(contract.required, "state", read_string(contract.required, "lifetime")));
            const std::string fact_state = lower_copy(read_string(fact->value, "state", read_string(fact->value, "lifetime")));
            matched = required_state.empty() || required_state == fact_state;
            const std::string after_phase = read_string(contract.required, "after_phase");
            if (matched && !after_phase.empty())
                matched = order_before(state, after_phase, fact->phase) || after_phase == fact->phase;
            failure = failure_code_t::lifetime_order_unproven;
            break;
        }
        case contract_dimension_t::authority_control:
        {
            const std::string authority = lower_copy(read_string(contract.required, "authority"));
            const std::string control = lower_copy(read_string(contract.required, "control", read_string(contract.required, "control_degree")));
            const std::string fact_authority = lower_copy(read_string(fact->value, "authority"));
            const std::string fact_control = lower_copy(read_string(fact->value, "control", read_string(fact->value, "control_degree")));
            matched = (authority.empty() || authority == fact_authority) && (control.empty() || control == fact_control);
            failure = failure_code_t::controlledness_unproven;
            break;
        }
        case contract_dimension_t::final_objective:
        {
            matched = true;
            if (contract.required.is_object() && contract.required.contains("achieved"))
                matched = read_bool(contract.required, "achieved", false) && read_bool(fact->value, "achieved", false);
            failure = failure_code_t::objective_not_achieved;
            break;
        }
        case contract_dimension_t::timing:
            matched = false;
            break;
        }

        if (matched)
        {
            out.verdict = chain_verdict_t::confirmed;
            out.proof_state = contract_proof_state_t::proven;
            out.failure = failure_code_t::none;
            out.acceptance_blocker = false;
            out.rationale = "contract satisfied";
            out.evidence = to_json(*fact);
            return out;
        }

        out.verdict = fact->proof_state == contract_proof_state_t::refuted ? chain_verdict_t::refuted : chain_verdict_t::inconclusive;
        out.proof_state = fact->proof_state == contract_proof_state_t::refuted ? contract_proof_state_t::refuted : contract_proof_state_t::unknown;
        out.failure = failure;
        out.rationale = "candidate fact contradicts or does not prove required state";
        out.evidence = to_json(*fact);
        best = out.verdict == chain_verdict_t::refuted ? out : best;
    }
    return best;
}

contract_evaluation_t match_contracts(const contract_trace_state_t& state,
                                      const std::vector<state_contract_t>& contracts,
                                      proof_level_t level)
{
    contract_evaluation_t out;
    out.proof_level = level;
    out.verdict = chain_verdict_t::confirmed;
    for (const state_contract_t& contract : contracts)
    {
        contract_match_t match = match_contract(state, contract);
        out.verdict = combine_verdict(out.verdict, match.verdict);
        if (match.failure != failure_code_t::none)
        {
            out.failures.push_back(match.failure);
            if (match.acceptance_blocker)
                out.has_acceptance_blocker = true;
        }
        out.matches.push_back(std::move(match));
    }
    if (out.has_acceptance_blocker && out.verdict == chain_verdict_t::confirmed)
        out.verdict = chain_verdict_t::inconclusive;
    return out;
}

nlohmann::json to_json(const chain_location_t& location)
{
    return nlohmann::json{
        {"corpus_id", location.corpus_id},
        {"ea", location.ea == BADADDR ? nlohmann::json(nullptr) : nlohmann::json(static_cast<uint64_t>(location.ea))},
        {"rva", location.has_rva ? nlohmann::json(location.rva) : nlohmann::json(nullptr)},
        {"segment", location.segment},
        {"function_id", location.function_id},
        {"instruction_id", location.instruction_id},
        {"layer", location.layer},
        {"confidence", location.confidence}
    };
}

nlohmann::json to_json(const evidence_t& evidence)
{
    return nlohmann::json{
        {"evidence_id", evidence.evidence_id},
        {"corpus_id", evidence.corpus_id},
        {"location", to_json(evidence.location)},
        {"layer", evidence.layer},
        {"lineage", evidence.lineage},
        {"snippet", evidence.snippet},
        {"snapshot_id", evidence.snapshot_id},
        {"payload", evidence.payload}
    };
}

nlohmann::json to_json(const chain_fact_t& fact)
{
    nlohmann::json ev = nlohmann::json::array();
    for (const evidence_t& item : fact.evidence)
        ev.push_back(to_json(item));
    return nlohmann::json{
        {"fact_id", fact.fact_id},
        {"kind", fact_kind_str(fact.kind)},
        {"subject", fact.subject},
        {"predicate", fact.predicate},
        {"value", fact.value},
        {"phase", fact.phase},
        {"producer", fact.producer},
        {"evidence", ev},
        {"proof_state", proof_state_str(fact.proof_state)},
        {"criticality", criticality_str(fact.criticality)}
    };
}

nlohmann::json to_json(const state_contract_t& contract)
{
    return nlohmann::json{
        {"contract_id", contract.contract_id},
        {"dimension", contract_dimension_str(contract.dimension)},
        {"subject", contract.subject},
        {"predicate", contract.predicate},
        {"required", contract.required},
        {"consumer_link_id", contract.consumer_link_id},
        {"criticality", criticality_str(contract.criticality)},
        {"declared_state", proof_state_str(contract.declared_state)},
        {"failure_when_unmet", failure_code_str(contract.failure_when_unmet)}
    };
}

nlohmann::json to_json(const contract_match_t& match)
{
    return nlohmann::json{
        {"contract_id", match.contract_id},
        {"producer_fact_id", match.producer_fact_id},
        {"dimension", contract_dimension_str(match.dimension)},
        {"verdict", verdict_str(match.verdict)},
        {"proof_state", proof_state_str(match.proof_state)},
        {"failure", failure_code_str(match.failure)},
        {"acceptance_blocker", match.acceptance_blocker},
        {"rationale", match.rationale},
        {"evidence", match.evidence}
    };
}

nlohmann::json to_json(const contract_trace_state_t& state)
{
    nlohmann::json facts = nlohmann::json::array();
    for (const chain_fact_t& fact : state.facts)
        facts.push_back(to_json(fact));
    nlohmann::json phases = nlohmann::json::object();
    for (const auto& kv : state.phase_order)
        phases[kv.first] = kv.second;
    return nlohmann::json{
        {"state_id", state.state_id},
        {"facts", facts},
        {"phase_order", phases}
    };
}

nlohmann::json to_json(const contract_evaluation_t& evaluation)
{
    nlohmann::json matches = nlohmann::json::array();
    for (const contract_match_t& match : evaluation.matches)
        matches.push_back(to_json(match));
    nlohmann::json failures = nlohmann::json::array();
    for (failure_code_t code : evaluation.failures)
        failures.push_back(failure_code_str(code));
    return nlohmann::json{
        {"verdict", verdict_str(evaluation.verdict)},
        {"proof_level", proof_level_str(evaluation.proof_level)},
        {"matches", matches},
        {"failures", failures},
        {"has_acceptance_blocker", evaluation.has_acceptance_blocker}
    };
}

}
}
}
