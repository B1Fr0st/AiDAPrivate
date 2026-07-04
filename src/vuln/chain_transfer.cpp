#include "chain_transfer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <utility>

#include "chain_alias.hpp"
#include "chain_lifetime.hpp"
#include "chain_protocol.hpp"

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
        return std::to_string(item.get<std::int64_t>());
    if (item.is_number_unsigned())
        return std::to_string(item.get<std::uint64_t>());
    if (item.is_boolean())
        return item.get<bool>() ? "true" : "false";
    return fallback;
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
        const std::string text = lower_copy(item.get<std::string>());
        return text == "true" || text == "1" || text == "yes" || text == "proven" || text == "resolved" || text == "complete";
    }
    return fallback;
}

nlohmann::json array_or_empty(const nlohmann::json& object, const char* key)
{
    if (object.is_object() && object.contains(key) && object.at(key).is_array())
        return object.at(key);
    return nlohmann::json::array();
}

std::string nested_text(const nlohmann::json& value, const char* key)
{
    if (!value.is_object() || !value.contains(key))
        return {};
    const auto& item = value.at(key);
    if (item.is_string() || item.is_number_integer() || item.is_number_unsigned() || item.is_boolean())
        return read_string(value, key);
    if (item.is_object())
    {
        for (const char* nested : {"text", "subject", "target", "alias", "address_expr", "alias_class", "object_id", "field_path", "value", "name"})
        {
            const std::string text = read_string(item, nested);
            if (!text.empty())
                return text;
        }
    }
    return {};
}

std::string event_kind(const nlohmann::json& event)
{
    return lower_copy(read_string(event, "kind", read_string(event, "operation", read_string(event, "op", read_string(event, "effect")))));
}

std::string event_subject(const nlohmann::json& event)
{
    for (const char* key : {"subject", "destination", "dest", "target", "left", "slot", "pointer_slot", "field", "object", "register", "stack", "memory"})
    {
        const std::string text = nested_text(event, key);
        if (!text.empty())
            return text;
    }
    return {};
}

std::string event_source(const nlohmann::json& event)
{
    for (const char* key : {"source", "src", "from", "right", "value", "target", "address", "actual_source"})
    {
        const std::string text = nested_text(event, key);
        if (!text.empty())
            return text;
    }
    return {};
}

bool source_is_controlled(const nlohmann::json& event)
{
    if (read_bool(event, "controlled", false) || read_bool(event, "controlled_by_input", false))
        return true;
    if (event.is_object())
    {
        for (const char* key : {"source", "src", "destination", "dest", "value"})
        {
            if (!event.contains(key) || !event.at(key).is_object())
                continue;
            const auto& item = event.at(key);
            if (read_bool(item, "controlled", false) || read_bool(item, "controlled_by_input", false))
                return true;
            const std::string origin = lower_copy(read_string(item, "value_origin"));
            if (origin.find("input") != std::string::npos || origin.find("controlled") != std::string::npos)
                return true;
        }
    }
    const std::string combined = lower_copy(event.dump());
    return combined.find("systembuffer") != std::string::npos ||
           combined.find("type3inputbuffer") != std::string::npos ||
           combined.find("userbuffer") != std::string::npos ||
           combined.find("user_input") != std::string::npos ||
           combined.find("controlled") != std::string::npos;
}

bool source_is_zero(const nlohmann::json& event)
{
    if (read_bool(event, "zero", false))
        return true;
    if (event.is_object())
    {
        for (const char* key : {"source", "src", "value"})
        {
            if (!event.contains(key))
                continue;
            const auto& item = event.at(key);
            if (item.is_object())
            {
                const std::string origin = lower_copy(read_string(item, "value_origin"));
                if (origin == "constant_zero" || read_bool(item, "zero", false))
                    return true;
                if (read_bool(item, "concrete", false) && read_string(item, "concrete_value") == "0")
                    return true;
            }
            else if (item.is_number_integer() && item.get<std::int64_t>() == 0)
            {
                return true;
            }
            else if (item.is_number_unsigned() && item.get<std::uint64_t>() == 0)
            {
                return true;
            }
        }
    }
    const std::string origin = lower_copy(read_string(event, "value_origin"));
    return origin == "constant_zero" || origin == "zero_bytes";
}

bool has_source_backing(const nlohmann::json& event)
{
    if (!event.is_object())
        return false;
    if (event.contains("evidence") && (event.at("evidence").is_object() || event.at("evidence").is_array()) && !event.at("evidence").empty())
        return true;
    if (event.contains("location") && event.at("location").is_object())
    {
        const nlohmann::json& loc = event.at("location");
        if (!read_string(loc, "ea").empty() || !read_string(loc, "rva").empty() || !read_string(loc, "function_id").empty())
            return true;
    }
    for (const char* key : {"source_layer", "layer", "lineage", "evidence_id", "snapshot_id", "trace_id", "function_id", "ea", "rva"})
    {
        const std::string value = lower_copy(read_string(event, key));
        if (!value.empty() && value != "user_declared" && value != "declared" && value != "assumption")
            return true;
    }
    return false;
}

contract_proof_state_t proof_state_for_event(const nlohmann::json& event, bool trace_complete)
{
    if (event.is_object() && (event.contains("proof_state") || event.contains("state")))
    {
        const contract_proof_state_t state = parse_proof_state(read_string(event, "proof_state", read_string(event, "state", "unknown")));
        if (state == contract_proof_state_t::proven && !has_source_backing(event))
            return contract_proof_state_t::unknown;
        return state;
    }
    if (read_bool(event, "unsupported", false))
        return contract_proof_state_t::unsupported;
    if (read_bool(event, "unresolved", false))
        return contract_proof_state_t::unknown;
    return trace_complete ? contract_proof_state_t::proven : contract_proof_state_t::unknown;
}

contract_criticality_t criticality_for_event(const nlohmann::json& event)
{
    return parse_criticality(read_string(event, "criticality", "chain_critical"));
}

chain_fact_t make_fact(const transfer_request_t& request,
                       const nlohmann::json& event,
                       contract_fact_kind_t kind,
                       const std::string& subject,
                       const std::string& predicate,
                       nlohmann::json value,
                       contract_proof_state_t proof,
                       contract_criticality_t criticality)
{
    chain_fact_t fact;
    fact.kind = kind;
    fact.subject = subject;
    fact.predicate = predicate;
    fact.value = std::move(value);
    fact.phase = request.link_id;
    fact.producer = request.link_id;
    fact.proof_state = proof;
    fact.criticality = criticality;
    evidence_t ev;
    ev.evidence_id = "ev_" + stable_hash_hex(request.link_id + subject + predicate + event.dump());
    ev.layer = read_string(event, "source_layer", read_string(event, "layer", "transfer"));
    ev.lineage = read_string(event, "reason", "execution_transfer");
    ev.snippet = read_string(event, "operation", read_string(event, "kind", read_string(event, "text")));
    ev.payload = event;
    fact.evidence.push_back(std::move(ev));
    fact.fact_id = "derived_" + stable_hash_hex(request.link_id + fact_kind_str(kind) + subject + predicate + fact.value.dump());
    return fact;
}

void add_issue(transfer_proof_t& proof,
               failure_code_t code,
               const transfer_request_t& request,
               const std::string& reason,
               const nlohmann::json& evidence)
{
    if (code == failure_code_t::none)
        return;
    transfer_issue_t issue;
    issue.code = code;
    issue.link_id = request.link_id;
    issue.reason = reason;
    issue.acceptance_blocker = failure_blocks_acceptance(code);
    issue.evidence = evidence;
    proof.issues.push_back(std::move(issue));
    if (code == failure_code_t::unsupported_instruction || code == failure_code_t::unsupported_helper)
        proof.unsupported_transfer = true;
    if (code == failure_code_t::indirect_target_unproven)
        proof.unresolved_indirect_target = true;
    if (code == failure_code_t::fatal_side_effect)
        proof.fatal_or_poisoned = true;
}

bool append_fact_unique(transfer_proof_t& proof, const chain_fact_t& fact)
{
    const std::string key = fact.kind == contract_fact_kind_t::diagnostic ? fact.fact_id : fact_kind_str(fact.kind) + std::string("|") + fact.subject + "|" + fact.predicate + "|" + fact.value.dump();
    for (const auto& existing : proof.derived_facts)
    {
        const std::string existing_key = fact_kind_str(existing.kind) + std::string("|") + existing.subject + "|" + existing.predicate + "|" + existing.value.dump();
        if (existing_key == key || existing.fact_id == fact.fact_id)
            return false;
    }
    proof.derived_facts.push_back(fact);
    proof.state = append_fact(proof.state, fact);
    return true;
}

void append_generated_facts(transfer_proof_t& proof, const std::vector<chain_fact_t>& facts)
{
    for (const chain_fact_t& fact : facts)
        append_fact_unique(proof, fact);
}

void derive_value_content_memory(const transfer_request_t& request,
                                 const nlohmann::json& event,
                                 transfer_proof_t& proof,
                                 contract_proof_state_t event_proof,
                                 contract_criticality_t criticality)
{
    const std::string kind = event_kind(event);
    const std::string subject = event_subject(event);
    const std::string source = event_source(event);
    const bool is_copy = kind == "copy" || kind == "content_copy" || kind == "memcpy" || kind == "memory_copy" || kind == "memmove";
    const bool is_write = kind == "write" || kind == "store" || kind == "memory_write" || kind == "memory_copy" || kind == "memcpy" || kind == "memory_set" || kind == "memset" || kind == "zero";
    const bool is_read = kind == "read" || kind == "load" || kind == "memory_read";
    const bool is_zero = source_is_zero(event) || kind == "zero" || kind == "memset" || kind == "memory_set";
    const bool is_value = kind == "value" || kind == "assign" || kind == "move" || kind == "lea" || kind == "register" || kind == "reg";
    if (subject.empty())
        return;
    if (is_value || (!source.empty() && !is_read && !is_write && !is_copy))
    {
        nlohmann::json value = nlohmann::json::object();
        if (!source.empty())
            value["value"] = source;
        if (event.contains("value"))
            value["raw_value"] = event.at("value");
        append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::value, subject, "value", value, event_proof, criticality));
    }
    if (is_write)
    {
        nlohmann::json memory = nlohmann::json::object();
        memory["written"] = true;
        if (!source.empty())
            memory["value"] = source;
        if (is_zero)
            memory["zero"] = true;
        append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::memory, subject, "written", memory, event_proof, criticality));
    }
    if (is_read)
    {
        nlohmann::json memory = nlohmann::json::object();
        memory["read"] = true;
        if (!source.empty())
            memory["source"] = source;
        append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::memory, subject, "read", memory, event_proof, criticality));
    }
    if (is_copy || is_zero || source_is_controlled(event))
    {
        nlohmann::json content = nlohmann::json::object();
        if (is_zero)
        {
            content["content_class"] = "zero_bytes";
            content["zero"] = true;
            content["controlled"] = false;
        }
        else if (source_is_controlled(event))
        {
            content["content_class"] = "controlled";
            content["controlled"] = true;
            content["source"] = source;
        }
        else if (is_copy)
        {
            content["content_class"] = "copied_bytes";
            content["source"] = source;
        }
        append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::content, subject, "content", content, event_proof, criticality));
    }
}

void derive_register_stack(const transfer_request_t& request,
                           const nlohmann::json& event,
                           transfer_proof_t& proof,
                           contract_proof_state_t event_proof,
                           contract_criticality_t criticality)
{
    const std::string kind = event_kind(event);
    const std::string subject = event_subject(event);
    if (subject.empty())
        return;
    if (kind == "register" || kind == "reg" || kind == "register_write" || (event.is_object() && event.contains("register")))
    {
        nlohmann::json value = nlohmann::json::object();
        value["register"] = subject;
        const std::string source = event_source(event);
        if (!source.empty())
            value["value"] = source;
        append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::reg, subject, "register_state", value, event_proof, criticality));
    }
    if (kind == "stack" || kind == "stack_write" || kind == "stack_read" || event.contains("stack_delta"))
    {
        nlohmann::json value = nlohmann::json::object();
        value["stack"] = subject;
        const std::string delta = read_string(event, "stack_delta", read_string(event, "delta"));
        if (!delta.empty())
            value["stack_delta"] = delta;
        append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::stack, subject, "stack_state", value, event_proof, criticality));
    }
}

void derive_control_flow(const transfer_request_t& request,
                         const nlohmann::json& event,
                         transfer_proof_t& proof,
                         contract_proof_state_t event_proof,
                         contract_criticality_t criticality)
{
    const std::string kind = event_kind(event);
    if (kind == "branch" || event.contains("predicate_text") || event.contains("targets"))
    {
        const std::string subject = event_subject(event).empty() ? read_string(event, "text", read_string(event, "predicate_text", request.link_id + ".branch")) : event_subject(event);
        nlohmann::json value = nlohmann::json::object();
        value["predicate"] = read_string(event, "predicate_text", read_string(event, "predicate"));
        if (event.contains("targets"))
            value["targets"] = event.at("targets");
        append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::branch, subject, "branch_taken", value, event_proof, criticality));
    }
    if (kind == "call" || kind == "direct_call" || kind == "indirect_call" || event.contains("callee_name"))
    {
        const std::string subject = read_string(event, "callee_name", event_subject(event).empty() ? read_string(event, "operation", request.link_id + ".call") : event_subject(event));
        const bool resolved = read_bool(event, "resolved", !read_bool(event, "unresolved", false) && kind != "indirect_call");
        nlohmann::json value = nlohmann::json::object();
        value["resolved"] = resolved;
        value["target"] = read_string(event, "target", subject);
        value["call_kind"] = kind;
        append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::call, subject, "call_target", value, resolved ? event_proof : contract_proof_state_t::unknown, criticality));
        if (!resolved || kind == "indirect_call")
            add_issue(proof, failure_code_t::indirect_target_unproven, request, "call target is indirect or unresolved", event);
    }
    if (kind == "return" || kind == "return_value" || read_bool(event, "terminal", false))
    {
        const std::string subject = event_subject(event).empty() ? request.link_id + ".return" : event_subject(event);
        nlohmann::json value = nlohmann::json::object();
        value["terminal"] = read_bool(event, "terminal", kind == "return" || kind == "return_value");
        const std::string source = event_source(event);
        if (!source.empty())
            value["value"] = source;
        append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::return_state, subject, "return_state", value, event_proof, criticality));
    }
}

void derive_side_effect_state(const transfer_request_t& request,
                              const nlohmann::json& event,
                              transfer_proof_t& proof,
                              contract_proof_state_t event_proof,
                              contract_criticality_t criticality)
{
    const std::string kind = event_kind(event);
    if (kind == "poisoned_terminal" || kind == "fatal" || kind == "fastfail" || kind == "bugcheck" || read_bool(event, "fatal", false))
    {
        nlohmann::json value = nlohmann::json::object();
        value["fatal"] = true;
        value["kind"] = kind;
        append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::side_effect, request.link_id + ".fatal", "fatal", value, event_proof, criticality));
        add_issue(proof, failure_code_t::fatal_side_effect, request, "fatal or poisoned terminal side effect is proven", event);
    }
    if (kind == "unknown" || read_bool(event, "unsupported", false))
        add_issue(proof, failure_code_t::unsupported_instruction, request, "unsupported transfer effect", event);
}

void derive_objective(const transfer_request_t& request,
                      const nlohmann::json& event,
                      transfer_proof_t& proof,
                      contract_proof_state_t event_proof,
                      contract_criticality_t criticality)
{
    const std::string kind = event_kind(event);
    if (kind != "objective" && kind != "goal" && !event.contains("achieved"))
        return;
    const std::string subject = event_subject(event).empty() ? "goal" : event_subject(event);
    nlohmann::json value = nlohmann::json::object();
    value["achieved"] = read_bool(event, "achieved", event_proof == contract_proof_state_t::proven);
    if (event.contains("value"))
        value["value"] = event.at("value");
    append_fact_unique(proof, make_fact(request, event, contract_fact_kind_t::objective, subject, "achieved", value, event_proof, criticality));
    if (event_proof == contract_proof_state_t::proven && read_bool(value, "achieved", false))
        proof.objective_proven = true;
}

void derive_event(const transfer_request_t& request, const nlohmann::json& event, transfer_proof_t& proof, bool trace_complete)
{
    if (!event.is_object())
        return;
    const contract_proof_state_t event_proof = proof_state_for_event(event, trace_complete);
    const contract_criticality_t criticality = criticality_for_event(event);
    derive_value_content_memory(request, event, proof, event_proof, criticality);
    derive_register_stack(request, event, proof, event_proof, criticality);
    derive_control_flow(request, event, proof, event_proof, criticality);
    derive_side_effect_state(request, event, proof, event_proof, criticality);
    derive_objective(request, event, proof, event_proof, criticality);

    alias_derivation_context_t alias_context;
    alias_context.link_id = request.link_id;
    alias_context.phase = request.link_id;
    alias_context.criticality = criticality;
    alias_context.proof_state = event_proof;
    alias_context.evidence = event;
    append_generated_facts(proof, derive_alias_facts(event, alias_context));

    lifetime_derivation_context_t lifetime_context;
    lifetime_context.link_id = request.link_id;
    lifetime_context.phase = request.link_id;
    lifetime_context.criticality = criticality;
    lifetime_context.proof_state = event_proof;
    lifetime_context.evidence = event;
    append_generated_facts(proof, derive_lifetime_facts(event, lifetime_context));
    append_generated_facts(proof, derive_allocator_facts(event, lifetime_context));

    protocol_derivation_context_t protocol_context;
    protocol_context.link_id = request.link_id;
    protocol_context.phase = request.link_id;
    protocol_context.criticality = criticality;
    protocol_context.proof_state = event_proof;
    protocol_context.evidence = event;
    append_generated_facts(proof, derive_protocol_facts(event, protocol_context));
    append_generated_facts(proof, derive_firmware_facts(event, protocol_context));
}

void scan_steps(const transfer_request_t& request, const nlohmann::json& steps, transfer_proof_t& proof, bool trace_complete)
{
    if (!steps.is_array())
        return;
    for (const auto& step : steps)
    {
        if (!step.is_object())
            continue;
        nlohmann::json step_event = step;
        if (!step_event.contains("kind") && step_event.contains("text"))
            step_event["kind"] = read_string(step_event, "kind", "instruction");
        derive_event(request, step_event, proof, trace_complete);
        for (const auto& effect : array_or_empty(step, "side_effects"))
            derive_event(request, effect, proof, trace_complete);
        for (const auto& call : array_or_empty(step, "calls"))
        {
            nlohmann::json call_event = call;
            if (!call_event.contains("kind"))
                call_event["kind"] = read_string(call_event, "kind", read_bool(call_event, "resolved", false) ? "call" : "indirect_call");
            derive_event(request, call_event, proof, trace_complete);
        }
        for (const auto& branch : array_or_empty(step, "branches"))
        {
            nlohmann::json branch_event = branch;
            if (!branch_event.contains("kind"))
                branch_event["kind"] = "branch";
            derive_event(request, branch_event, proof, trace_complete);
        }
    }
}

void scan_trace_object(const transfer_request_t& request, const nlohmann::json& trace, transfer_proof_t& proof)
{
    if (!trace.is_object())
        return;
    proof.trace_present = true;
    const bool reached = read_bool(trace, "reached", false);
    const bool complete = read_bool(trace, "complete", false);
    proof.trace_reached = proof.trace_reached || reached;
    proof.trace_complete = proof.trace_complete || (reached && complete);
    if (!reached)
        add_issue(proof, failure_code_t::path_target_unreachable, request, read_string(trace, "reason", "path target not reached"), trace);
    if (reached && !complete)
        add_issue(proof, failure_code_t::reachable_set_incomplete, request, read_string(trace, "reason", "path reached with incomplete evidence"), trace);
    for (const auto& edge : array_or_empty(trace, "unresolved_edges"))
    {
        const std::string kind = lower_copy(read_string(edge, "kind"));
        const failure_code_t code = kind.find("call") != std::string::npos || kind.find("indirect") != std::string::npos
            ? failure_code_t::indirect_target_unproven
            : failure_code_t::reachable_set_incomplete;
        add_issue(proof, code, request, read_string(edge, "reason", "unresolved edge"), edge);
    }
    for (const auto& blocker : array_or_empty(trace, "branch_blockers"))
        add_issue(proof, failure_code_t::branch_required_direction_unknown, request, read_string(blocker, "reason", "branch direction is not proven"), blocker);
    scan_steps(request, array_or_empty(trace, "steps"), proof, reached && complete);
    for (const auto& attempt : array_or_empty(trace, "attempts"))
    {
        if (attempt.is_object() && attempt.contains("path"))
            scan_trace_object(request, attempt.at("path"), proof);
    }
}

void scan_direct_transfer_arrays(const transfer_request_t& request, transfer_proof_t& proof)
{
    for (const char* key : {"transfers", "execution_transfers", "derived_transfers", "transfer_events", "effects", "events"})
    {
        for (const auto& event : array_or_empty(request.link, key))
        {
            proof.trace_present = true;
            derive_event(request, event, proof, proof_state_for_event(event, false) == contract_proof_state_t::proven);
        }
    }
}

bool expected_fact_is_critical(const chain_fact_t& fact)
{
    return criticality_blocks_acceptance(fact.criticality);
}

failure_code_t failure_for_unproven_fact(const chain_fact_t& fact)
{
    if (fact.proof_state == contract_proof_state_t::timeout)
        return failure_code_t::solver_timeout;
    if (fact.proof_state == contract_proof_state_t::unsupported)
        return failure_code_t::unsupported_instruction;
    if (fact.kind == contract_fact_kind_t::alias)
        return lower_copy(fact.predicate) == "self_reference" ? failure_code_t::self_reference_unproven : failure_code_t::alias_must_not_proven;
    if (fact.kind == contract_fact_kind_t::object_lifetime)
        return failure_code_t::lifetime_order_unproven;
    if (fact.kind == contract_fact_kind_t::protocol)
        return failure_code_t::protocol_state_mismatch;
    if (fact.kind == contract_fact_kind_t::firmware)
        return failure_code_t::firmware_dispatch_unproven;
    if (fact.kind == contract_fact_kind_t::call)
        return failure_code_t::indirect_target_unproven;
    if (fact.kind == contract_fact_kind_t::branch)
        return failure_code_t::branch_required_direction_unknown;
    if (fact.kind == contract_fact_kind_t::objective)
        return failure_code_t::objective_not_achieved;
    if (fact.kind == contract_fact_kind_t::content)
        return failure_code_t::controlledness_unproven;
    return failure_code_t::postcondition_precondition_mismatch;
}

void evaluate_derived_fact_proof_states(const transfer_request_t& request, transfer_proof_t& proof)
{
    for (const chain_fact_t& fact : proof.derived_facts)
    {
        if (!expected_fact_is_critical(fact) || proof_state_accepts(fact.proof_state))
            continue;
        add_issue(proof, failure_for_unproven_fact(fact), request, "critical derived fact is not proven", to_json(fact));
    }
}

void evaluate_expected_facts(const transfer_request_t& request,
                             const std::vector<chain_fact_t>& expected_facts,
                             transfer_proof_t& proof)
{
    for (const chain_fact_t& expected : expected_facts)
    {
        state_contract_t contract = contract_from_expected_fact(expected, request.link_id);
        proof.produced_contracts.push_back(contract);
        contract_match_t match = match_contract(proof.state, contract);
        proof.produced_matches.push_back(match);
        if (match.failure != failure_code_t::none)
            add_issue(proof, match.failure, request, "expected postcondition was not derived from execution evidence", to_json(expected));
        if (expected_fact_is_critical(expected) && expected.proof_state != contract_proof_state_t::proven)
            add_issue(proof, expected.proof_state == contract_proof_state_t::timeout ? failure_code_t::solver_timeout : failure_code_t::controlledness_unproven, request, "declared postcondition is not a proven execution-derived fact", to_json(expected));
    }
}

}

state_contract_t contract_from_expected_fact(const chain_fact_t& fact, const std::string& consumer_link_id)
{
    state_contract_t contract;
    contract.contract_id = fact.fact_id.empty() ? "expected_" + stable_hash_hex(to_json(fact).dump()) : "expected_" + fact.fact_id;
    contract.subject = fact.subject;
    contract.predicate = fact.predicate;
    contract.required = fact.value;
    contract.consumer_link_id = consumer_link_id;
    contract.criticality = fact.criticality;
    contract.declared_state = fact.proof_state;
    switch (fact.kind)
    {
    case contract_fact_kind_t::content:
        contract.dimension = contract_dimension_t::content;
        contract.failure_when_unmet = failure_code_t::content_provenance_mismatch;
        break;
    case contract_fact_kind_t::alias:
    case contract_fact_kind_t::address:
        contract.dimension = contract_dimension_t::alias_set;
        contract.failure_when_unmet = lower_copy(fact.predicate) == "self_reference" ? failure_code_t::self_reference_unproven : failure_code_t::alias_must_not_proven;
        break;
    case contract_fact_kind_t::object_lifetime:
        contract.dimension = contract_dimension_t::object_lifetime;
        contract.failure_when_unmet = failure_code_t::lifetime_order_unproven;
        break;
    case contract_fact_kind_t::objective:
        contract.dimension = contract_dimension_t::final_objective;
        contract.failure_when_unmet = failure_code_t::objective_not_achieved;
        break;
    case contract_fact_kind_t::call:
        contract.dimension = contract_dimension_t::value;
        contract.required = nlohmann::json{{"value", fact.value}};
        contract.failure_when_unmet = failure_code_t::call_target_mismatch;
        break;
    case contract_fact_kind_t::protocol:
        contract.dimension = contract_dimension_t::value;
        contract.required = nlohmann::json{{"value", fact.value}};
        contract.failure_when_unmet = failure_code_t::protocol_state_mismatch;
        break;
    case contract_fact_kind_t::firmware:
        contract.dimension = contract_dimension_t::value;
        contract.required = nlohmann::json{{"value", fact.value}};
        contract.failure_when_unmet = failure_code_t::firmware_dispatch_unproven;
        break;
    case contract_fact_kind_t::side_effect:
        contract.dimension = contract_dimension_t::value;
        contract.required = nlohmann::json{{"value", fact.value}};
        contract.failure_when_unmet = failure_code_t::collateral_damage_unproven;
        break;
    default:
        contract.dimension = contract_dimension_t::value;
        contract.failure_when_unmet = failure_code_t::postcondition_precondition_mismatch;
        if (contract.required.is_object() && !contract.required.contains("value") && fact.kind != contract_fact_kind_t::content)
            contract.required = nlohmann::json{{"value", fact.value}};
        break;
    }
    return contract;
}

chain_verdict_t verdict_for_transfer_issues(const std::vector<transfer_issue_t>& issues)
{
    chain_verdict_t verdict = chain_verdict_t::confirmed;
    for (const transfer_issue_t& issue : issues)
    {
        chain_verdict_t next = chain_verdict_t::inconclusive;
        switch (issue.code)
        {
        case failure_code_t::fatal_side_effect:
        case failure_code_t::path_target_unreachable:
        case failure_code_t::objective_not_achieved:
        case failure_code_t::branch_required_direction_unsat:
        case failure_code_t::content_provenance_mismatch:
            next = chain_verdict_t::refuted;
            break;
        case failure_code_t::solver_timeout:
        case failure_code_t::resource_exhausted:
            next = chain_verdict_t::timeout;
            break;
        case failure_code_t::unsupported_instruction:
        case failure_code_t::unsupported_helper:
        case failure_code_t::extractor_layer_failed:
        case failure_code_t::peer_unavailable:
        case failure_code_t::stale_generation:
            next = chain_verdict_t::unsupported;
            break;
        default:
            next = chain_verdict_t::inconclusive;
            break;
        }
        verdict = combine_verdict(verdict, next);
    }
    return verdict;
}

transfer_proof_t derive_transfer_proof(const transfer_request_t& request,
                                       const contract_trace_state_t& entry_state,
                                       const std::vector<chain_fact_t>& expected_facts)
{
    transfer_proof_t proof;
    proof.link_id = request.link_id;
    proof.state = entry_state;
    scan_direct_transfer_arrays(request, proof);
    for (const char* key : {"path_trace", "trace", "execution_trace", "trigger_trace"})
    {
        if (request.link.is_object() && request.link.contains(key))
            scan_trace_object(request, request.link.at(key), proof);
    }
    scan_steps(request, array_or_empty(request.link, "steps"), proof, true);
    if (!proof.trace_present)
        add_issue(proof, failure_code_t::extractor_layer_failed, request, "link has no execution trace, transfer event, path trace, or trigger trace evidence", request.link);
    evaluate_derived_fact_proof_states(request, proof);
    evaluate_expected_facts(request, expected_facts, proof);
    proof.verdict = combine_verdict(verdict_for_transfer_issues(proof.issues), proof.produced_matches.empty() ? chain_verdict_t::confirmed : chain_verdict_t::confirmed);
    for (const contract_match_t& match : proof.produced_matches)
        proof.verdict = combine_verdict(proof.verdict, match.verdict);
    proof.evidence_manifest = nlohmann::json{
        {"trace_present", proof.trace_present},
        {"trace_reached", proof.trace_reached},
        {"trace_complete", proof.trace_complete},
        {"derived_fact_count", proof.derived_facts.size()},
        {"expected_fact_count", expected_facts.size()},
        {"issue_count", proof.issues.size()}
    };
    return proof;
}

nlohmann::json to_json(const transfer_issue_t& issue)
{
    return nlohmann::json{
        {"code", failure_code_str(issue.code)},
        {"link_id", issue.link_id},
        {"reason", issue.reason},
        {"acceptance_blocker", issue.acceptance_blocker},
        {"evidence", issue.evidence}
    };
}

nlohmann::json to_json(const transfer_proof_t& proof)
{
    nlohmann::json facts = nlohmann::json::array();
    for (const chain_fact_t& fact : proof.derived_facts)
        facts.push_back(to_json(fact));
    nlohmann::json contracts = nlohmann::json::array();
    for (const state_contract_t& contract : proof.produced_contracts)
        contracts.push_back(to_json(contract));
    nlohmann::json matches = nlohmann::json::array();
    for (const contract_match_t& match : proof.produced_matches)
        matches.push_back(to_json(match));
    nlohmann::json issues = nlohmann::json::array();
    for (const transfer_issue_t& issue : proof.issues)
        issues.push_back(to_json(issue));
    return nlohmann::json{
        {"link_id", proof.link_id},
        {"verdict", verdict_str(proof.verdict)},
        {"state", to_json(proof.state)},
        {"derived_facts", facts},
        {"produced_contracts", contracts},
        {"produced_matches", matches},
        {"issues", issues},
        {"trace_present", proof.trace_present},
        {"trace_reached", proof.trace_reached},
        {"trace_complete", proof.trace_complete},
        {"unsupported_transfer", proof.unsupported_transfer},
        {"unresolved_indirect_target", proof.unresolved_indirect_target},
        {"fatal_or_poisoned", proof.fatal_or_poisoned},
        {"objective_proven", proof.objective_proven},
        {"evidence_manifest", proof.evidence_manifest}
    };
}

}
}
}
