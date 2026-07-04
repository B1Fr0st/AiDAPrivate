#include "chain_cross_domain.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <utility>

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
        return text == "true" || text == "1" || text == "yes" || text == "proven" || text == "resolved" || text == "current" || text == "available";
    }
    return fallback;
}

nlohmann::json array_or_empty(const nlohmann::json& value, const char* key)
{
    if (value.is_object() && value.contains(key) && value.at(key).is_array())
        return value.at(key);
    return nlohmann::json::array();
}

nlohmann::json object_or_empty(const nlohmann::json& value, const char* key)
{
    if (value.is_object() && value.contains(key) && value.at(key).is_object())
        return value.at(key);
    return nlohmann::json::object();
}

bool has_source_backing(const nlohmann::json& value)
{
    if (!value.is_object())
        return false;
    if (value.contains("evidence") && (value.at("evidence").is_object() || value.at("evidence").is_array()) && !value.at("evidence").empty())
        return true;
    if (value.contains("location") && value.at("location").is_object())
    {
        const nlohmann::json& loc = value.at("location");
        if (!read_string(loc, "ea").empty() || !read_string(loc, "rva").empty() || !read_string(loc, "function_id").empty())
            return true;
    }
    for (const char* key : {"source_layer", "layer", "lineage", "evidence_id", "snapshot_id", "trace_id", "function_id", "ea", "rva"})
    {
        const std::string text = lower_copy(read_string(value, key));
        if (!text.empty() && text != "user_declared" && text != "declared" && text != "assumption")
            return true;
    }
    return false;
}

bool source_backed(const nlohmann::json& item, const nlohmann::json& parent)
{
    return has_source_backing(item) || has_source_backing(parent);
}

void add_issue(cross_domain_proof_t& proof,
               failure_code_t code,
               const cross_domain_request_t& request,
               const std::string& reason,
               const nlohmann::json& evidence)
{
    if (code == failure_code_t::none)
        return;
    transfer_issue_t issue;
    issue.code = code;
    issue.link_id = request.link_id;
    issue.reason = reason;
    issue.acceptance_blocker = true;
    issue.evidence = evidence;
    proof.issues.push_back(std::move(issue));
}

chain_fact_t make_fact(const cross_domain_request_t& request,
                       contract_fact_kind_t kind,
                       const std::string& subject,
                       const std::string& predicate,
                       nlohmann::json value,
                       const nlohmann::json& evidence)
{
    chain_fact_t fact;
    fact.kind = kind;
    fact.subject = subject;
    fact.predicate = predicate;
    fact.value = std::move(value);
    fact.phase = request.link_id;
    fact.producer = request.link_id;
    fact.proof_state = contract_proof_state_t::proven;
    fact.criticality = contract_criticality_t::chain_critical;
    evidence_t ev;
    ev.evidence_id = "ev_" + stable_hash_hex(request.link_id + subject + predicate + evidence.dump());
    ev.layer = read_string(evidence, "layer", "cross_domain");
    ev.lineage = read_string(evidence, "reason", "cross_domain_transition");
    ev.snippet = read_string(evidence, "operation", read_string(evidence, "kind"));
    ev.payload = evidence;
    fact.evidence.push_back(std::move(ev));
    fact.fact_id = "cross_" + stable_hash_hex(request.link_id + fact_kind_str(kind) + subject + predicate + fact.value.dump());
    return fact;
}

bool corpus_has_id(const nlohmann::json& corpus, const std::string& id)
{
    if (id.empty())
        return true;
    if (!corpus.is_array())
        return false;
    for (const auto& item : corpus)
    {
        if (!item.is_object())
            continue;
        if (read_string(item, "corpus_id", read_string(item, "id")) == id)
            return true;
    }
    return false;
}

void evaluate_peer(cross_domain_proof_t& proof, const cross_domain_request_t& request, const nlohmann::json& cross)
{
    const nlohmann::json peer = object_or_empty(cross, "peer");
    const std::string peer_id = read_string(peer, "peer_id", read_string(cross, "peer_id", read_string(cross, "target_corpus_id")));
    const bool missing = read_bool(peer, "missing", false) || read_bool(cross, "missing_peer", false) || !corpus_has_id(request.corpus, peer_id);
    if (missing)
    {
        proof.peer_available = false;
        add_issue(proof, failure_code_t::peer_unavailable, request, "required peer IDB or corpus is unavailable", peer.empty() ? cross : peer);
    }
    const bool stale = read_bool(peer, "stale", false) || read_bool(peer, "stale_generation", false) || read_bool(cross, "stale_generation", false);
    if (stale)
    {
        proof.generation_current = false;
        add_issue(proof, failure_code_t::stale_generation, request, "peer generation is stale", peer.empty() ? cross : peer);
    }
    if (!peer_id.empty() && !missing && !stale)
    {
        nlohmann::json value = nlohmann::json::object();
        value["peer_id"] = peer_id;
        value["generation_current"] = true;
        proof.facts.push_back(make_fact(request, contract_fact_kind_t::event, peer_id, "peer_available", value, peer.empty() ? cross : peer));
    }
}

void evaluate_abi(cross_domain_proof_t& proof, const cross_domain_request_t& request, const nlohmann::json& cross, const contract_trace_state_t& state)
{
    const nlohmann::json abi = object_or_empty(cross, "abi");
    if (abi.empty() && !cross.contains("abi_registers") && !cross.contains("calling_convention"))
        return;
    proof.transition_present = true;
    bool proven = (read_bool(abi, "proven", false) || read_bool(cross, "abi_proven", false)) && source_backed(abi.empty() ? cross : abi, cross);
    for (const auto& req : array_or_empty(abi, "requirements"))
    {
        state_contract_t contract = contract_from_json(req, request.link_id, contract_dimension_t::value);
        contract_match_t match = match_contract(state, contract);
        if (match.verdict != chain_verdict_t::confirmed)
            add_issue(proof, failure_code_t::abi_state_mismatch, request, "ABI requirement was not matched by current state", to_json(match));
        else
            proven = true;
    }
    if (!proven)
    {
        add_issue(proof, failure_code_t::abi_state_mismatch, request, "ABI transition proof is missing", abi.empty() ? cross : abi);
        return;
    }
    proof.abi_proven = true;
    nlohmann::json value = abi.empty() ? nlohmann::json::object() : abi;
    value["abi_proven"] = true;
    proof.facts.push_back(make_fact(request, contract_fact_kind_t::call, request.link_id + ".abi", "abi_transfer", value, abi.empty() ? cross : abi));
}

void evaluate_import_export(cross_domain_proof_t& proof, const cross_domain_request_t& request, const nlohmann::json& cross)
{
    for (const char* key : {"import_export", "import", "export"})
    {
        const nlohmann::json obj = object_or_empty(cross, key);
        if (obj.empty())
            continue;
        proof.transition_present = true;
        const bool resolved = read_bool(obj, "resolved", false) || read_bool(obj, "proven", false);
        if (!resolved || !source_backed(obj, cross))
        {
            add_issue(proof, failure_code_t::call_target_mismatch, request, resolved ? "source-backed import/export binding proof is missing" : "import/export binding is unresolved", obj);
            continue;
        }
        proof.import_export_proven = true;
        const std::string subject = read_string(obj, "symbol", read_string(obj, "name", request.link_id + ".import_export"));
        nlohmann::json value = obj;
        value["resolved"] = true;
        proof.facts.push_back(make_fact(request, contract_fact_kind_t::call, subject, "import_export_binding", value, obj));
    }
}

void evaluate_messages_callbacks(cross_domain_proof_t& proof, const cross_domain_request_t& request, const nlohmann::json& cross)
{
    for (const char* key : {"message", "event", "callback"})
    {
        const nlohmann::json obj = object_or_empty(cross, key);
        if (obj.empty())
            continue;
        proof.transition_present = true;
        const bool registered = read_bool(obj, "registered", read_bool(obj, "registration_proven", false));
        const bool invoked = read_bool(obj, "invoked", read_bool(obj, "invocation_proven", false));
        const bool delivered = read_bool(obj, "delivered", read_bool(obj, "proven", false));
        if (!(registered || delivered) || !(invoked || delivered) || !source_backed(obj, cross))
        {
            add_issue(proof, key[0] == 'c' ? failure_code_t::callback_registration_unproven : failure_code_t::trigger_path_not_reached, request, "message/event/callback transition is not source-proven", obj);
            continue;
        }
        proof.callback_or_event_proven = true;
        const std::string subject = read_string(obj, "id", read_string(obj, "name", request.link_id + "." + std::string(key)));
        nlohmann::json value = obj;
        value["delivered"] = true;
        proof.facts.push_back(make_fact(request, contract_fact_kind_t::event, subject, key, value, obj));
    }
}

void evaluate_firmware_protocol(cross_domain_proof_t& proof, const cross_domain_request_t& request, const nlohmann::json& cross)
{
    for (const char* key : {"protocol", "firmware", "interrupt"})
    {
        const nlohmann::json obj = object_or_empty(cross, key);
        if (obj.empty())
            continue;
        proof.transition_present = true;
        const bool proven = read_bool(obj, "proven", false) || read_bool(obj, "dispatch_proven", false) || read_bool(obj, "state_proven", false);
        if (!proven || !source_backed(obj, cross))
        {
            add_issue(proof, key[0] == 'p' ? failure_code_t::protocol_state_mismatch : failure_code_t::firmware_dispatch_unproven, request, proven ? "source-backed protocol/firmware/interrupt proof is missing" : "protocol/firmware/interrupt transition is not proven", obj);
            continue;
        }
        proof.firmware_or_protocol_proven = true;
        const std::string subject = read_string(obj, "id", read_string(obj, "name", request.link_id + "." + std::string(key)));
        nlohmann::json value = obj;
        value["proven"] = true;
        proof.facts.push_back(make_fact(request,
                                        key[0] == 'p' ? contract_fact_kind_t::protocol : contract_fact_kind_t::firmware,
                                        subject,
                                        key,
                                        value,
                                        obj));
    }
}

void evaluate_cross_module_calls(cross_domain_proof_t& proof, const cross_domain_request_t& request, const nlohmann::json& cross)
{
    for (const auto& call : array_or_empty(cross, "cross_module_calls"))
    {
        if (!call.is_object())
            continue;
        proof.transition_present = true;
        const bool resolved = read_bool(call, "resolved", false) || read_bool(call, "target_resolved", false);
        const bool abi = read_bool(call, "abi_proven", false);
        if (!resolved || !source_backed(call, cross))
        {
            add_issue(proof, failure_code_t::indirect_target_unproven, request, resolved ? "source-backed cross-module call target proof is missing" : "cross-module call target is unresolved", call);
            continue;
        }
        if (!abi)
        {
            add_issue(proof, failure_code_t::abi_state_mismatch, request, "cross-module call ABI proof is missing", call);
            continue;
        }
        proof.cross_module_call_proven = true;
        const std::string subject = read_string(call, "target", read_string(call, "callee", request.link_id + ".cross_call"));
        nlohmann::json value = call;
        value["resolved"] = true;
        value["abi_proven"] = true;
        proof.facts.push_back(make_fact(request, contract_fact_kind_t::call, subject, "cross_module_call", value, call));
    }
}

}

cross_domain_proof_t evaluate_cross_domain_transition(const cross_domain_request_t& request,
                                                      const contract_trace_state_t& state)
{
    cross_domain_proof_t proof;
    proof.link_id = request.link_id;
    nlohmann::json cross = object_or_empty(request.link, "cross_domain");
    if (cross.empty())
        cross = object_or_empty(request.link, "boundary_transition");
    if (cross.empty())
        cross = object_or_empty(request.link, "cross_transition");
    if (cross.empty())
    {
        proof.evidence = nlohmann::json{{"present", false}};
        return proof;
    }
    proof.transition_present = true;
    proof.evidence = cross;
    evaluate_peer(proof, request, cross);
    evaluate_abi(proof, request, cross, state);
    evaluate_import_export(proof, request, cross);
    evaluate_messages_callbacks(proof, request, cross);
    evaluate_firmware_protocol(proof, request, cross);
    evaluate_cross_module_calls(proof, request, cross);
    proof.verdict = verdict_for_transfer_issues(proof.issues);
    return proof;
}

nlohmann::json to_json(const cross_domain_proof_t& proof)
{
    nlohmann::json facts = nlohmann::json::array();
    for (const chain_fact_t& fact : proof.facts)
        facts.push_back(to_json(fact));
    nlohmann::json issues = nlohmann::json::array();
    for (const transfer_issue_t& issue : proof.issues)
        issues.push_back(to_json(issue));
    return nlohmann::json{
        {"link_id", proof.link_id},
        {"verdict", verdict_str(proof.verdict)},
        {"facts", facts},
        {"issues", issues},
        {"transition_present", proof.transition_present},
        {"abi_proven", proof.abi_proven},
        {"peer_available", proof.peer_available},
        {"generation_current", proof.generation_current},
        {"import_export_proven", proof.import_export_proven},
        {"callback_or_event_proven", proof.callback_or_event_proven},
        {"firmware_or_protocol_proven", proof.firmware_or_protocol_proven},
        {"cross_module_call_proven", proof.cross_module_call_proven},
        {"evidence", proof.evidence}
    };
}

}
}
}
