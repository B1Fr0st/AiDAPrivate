#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "chain_binary_corpus.hpp"
#include "chain_model.hpp"

namespace aida
{
namespace vuln
{
namespace chain
{

enum class alias_relation_kind_t
{
    must_alias,
    may_alias,
    no_alias,
    points_to,
    self_reference,
    unresolved
};

enum class lifetime_event_kind_t
{
    allocated,
    initialized,
    published,
    borrowed,
    freed,
    destructed,
    reclaimed,
    reused,
    dangling,
    address_discovered
};

enum class allocator_event_kind_t
{
    allocate,
    zero,
    fill,
    free,
    quarantine,
    recycle,
    size_class_change,
    metadata_write,
    reuse_blocked
};

enum class side_effect_kind_t
{
    read,
    write,
    call,
    branch,
    lock,
    unlock,
    refcount,
    allocation,
    free,
    callback_register,
    callback_invoke,
    protocol_emit,
    firmware_io,
    fastfail,
    bugcheck,
    exception,
    external
};

enum class side_effect_safety_t
{
    expected,
    benign,
    collateral_survivable,
    collateral_unproven,
    fatal
};

struct register_state_t
{
    std::string name;
    chain_value_t value;
    std::string abi_role;
    bool volatile_register = false;
    std::vector<evidence_ref_t> evidence;
};

struct memory_state_t
{
    std::string memory_id;
    canonical_address_t location;
    std::string object_id;
    std::string field_path;
    std::uint64_t width_bytes = 0;
    chain_value_t value;
    bool initialized = false;
    bool mapped = false;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    std::vector<evidence_ref_t> evidence;
};

struct alias_relation_t
{
    std::string alias_id;
    alias_relation_kind_t kind = alias_relation_kind_t::unresolved;
    nlohmann::json left = nlohmann::json::object();
    nlohmann::json right = nlohmann::json::object();
    proof_state_t proof_state = proof_state_t::unknown;
    fact_criticality_t criticality = fact_criticality_t::diagnostic;
    std::vector<evidence_ref_t> evidence;
};

struct lifetime_event_t
{
    std::string event_id;
    lifetime_event_kind_t kind = lifetime_event_kind_t::allocated;
    std::string object_id;
    std::string phase;
    std::uint64_t sequence = 0;
    canonical_address_t location;
    proof_state_t proof_state = proof_state_t::unknown;
    std::vector<evidence_ref_t> evidence;
};

struct allocator_event_t
{
    std::string event_id;
    allocator_event_kind_t kind = allocator_event_kind_t::allocate;
    std::string allocator_id;
    std::string object_id;
    std::uint64_t size = 0;
    std::string size_class;
    std::uint64_t sequence = 0;
    proof_state_t proof_state = proof_state_t::unknown;
    std::vector<evidence_ref_t> evidence;
    nlohmann::json metadata = nlohmann::json::object();
};

struct callback_event_t
{
    std::string callback_id;
    trigger_kind_t kind = trigger_kind_t::callback;
    std::string owner_object_id;
    std::string target_corpus_id;
    canonical_address_t registration_site;
    canonical_address_t invocation_site;
    chain_value_t target;
    proof_state_t registration_state = proof_state_t::unknown;
    proof_state_t invocation_state = proof_state_t::unknown;
    std::vector<evidence_ref_t> evidence;
};

struct side_effect_t
{
    std::string side_effect_id;
    side_effect_kind_t kind = side_effect_kind_t::external;
    side_effect_safety_t safety = side_effect_safety_t::collateral_unproven;
    std::string phase;
    canonical_address_t location;
    nlohmann::json subject = nlohmann::json::object();
    chain_value_t value;
    proof_state_t proof_state = proof_state_t::unknown;
    fact_criticality_t criticality = fact_criticality_t::diagnostic;
    std::vector<evidence_ref_t> evidence;
};

struct final_goal_state_t
{
    std::string objective_id;
    objective_kind_t kind = objective_kind_t::custom;
    proof_state_t proof_state = proof_state_t::unknown;
    std::vector<std::string> required_fact_ids;
    std::vector<std::string> proven_fact_ids;
    std::vector<std::string> contradiction_fact_ids;
    nlohmann::json metadata = nlohmann::json::object();
};

struct trace_state_t
{
    canonical_address_t pc;
    std::vector<canonical_address_t> call_stack;
    std::vector<register_state_t> registers;
    std::vector<memory_state_t> memory;
    std::vector<alias_relation_t> aliases;
    std::vector<lifetime_event_t> lifetimes;
    std::vector<allocator_event_t> allocator_events;
    std::vector<callback_event_t> callbacks;
    std::vector<side_effect_t> side_effects;
    std::vector<fact_t> facts;
    std::vector<assumption_t> assumptions;
    std::vector<final_goal_state_t> final_goals;
    nlohmann::json constraints = nlohmann::json::array();
    nlohmann::json metadata = nlohmann::json::object();
};

const char* to_string(alias_relation_kind_t value);
const char* to_string(lifetime_event_kind_t value);
const char* to_string(allocator_event_kind_t value);
const char* to_string(side_effect_kind_t value);
const char* to_string(side_effect_safety_t value);

std::optional<alias_relation_kind_t> alias_relation_kind_from_string(const std::string& value);
std::optional<lifetime_event_kind_t> lifetime_event_kind_from_string(const std::string& value);
std::optional<allocator_event_kind_t> allocator_event_kind_from_string(const std::string& value);
std::optional<side_effect_kind_t> side_effect_kind_from_string(const std::string& value);
std::optional<side_effect_safety_t> side_effect_safety_from_string(const std::string& value);

nlohmann::json to_json(const register_state_t& value);
nlohmann::json to_json(const memory_state_t& value);
nlohmann::json to_json(const alias_relation_t& value);
nlohmann::json to_json(const lifetime_event_t& value);
nlohmann::json to_json(const allocator_event_t& value);
nlohmann::json to_json(const callback_event_t& value);
nlohmann::json to_json(const side_effect_t& value);
nlohmann::json to_json(const final_goal_state_t& value);
nlohmann::json to_json(const trace_state_t& value);

bool from_json(const nlohmann::json& value, register_state_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, memory_state_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, alias_relation_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, lifetime_event_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, allocator_event_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, callback_event_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, side_effect_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, final_goal_state_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, trace_state_t& out, validation_result_t& errors, const std::string& path);

void add_fact(trace_state_t& state, fact_t fact);
std::vector<fact_t> critical_fact_blockers(const trace_state_t& state);
std::vector<assumption_t> critical_assumption_blockers(const trace_state_t& state);
std::vector<side_effect_t> fatal_or_unproven_side_effects(const trace_state_t& state);
bool trace_state_can_confirm(const trace_state_t& state);
validation_result_t validate_trace_state(const trace_state_t& state);
validation_result_t chain_state_self_check();

}
}
}
