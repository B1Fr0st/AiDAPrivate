#include "chain_verifier.hpp"

#include "../multibinary_index.hpp"
#include "chain_extraction.hpp"
#include "chain_path_trace.hpp"

#include <unordered_map>

namespace aida
{
namespace vuln
{
namespace chain_verifier
{
namespace
{

using json = nlohmann::json;

std::string lowercase_ascii(std::string value)
{
    for (char& c : value)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
    }
    return value;
}

multibinary::project_io_result_t make_error(const std::string& code, const std::string& message, const json& data = json::object())
{
    multibinary::project_io_result_t r;
    r.ok = false;
    r.error_code = code;
    r.error_message = message;
    r.data = data;
    return r;
}

multibinary::project_io_result_t make_ok(const json& data)
{
    multibinary::project_io_result_t r;
    r.ok = true;
    r.data = data;
    return r;
}

std::string proof_state_of(const json& item)
{
    return lowercase_ascii(item.value("proof_state", item.value("state", std::string("unknown"))));
}

bool proven(const json& item)
{
    return proof_state_of(item) == "proven" || proof_state_of(item) == "confirmed";
}

std::string subject_of(const json& item)
{
    return item.value("subject", item.value("object", item.value("location", std::string())));
}

std::string predicate_of(const json& item)
{
    return item.value("predicate", item.value("kind", item.value("dimension", std::string())));
}

std::string fact_key(const json& item)
{
    return lowercase_ascii(subject_of(item) + "|" + predicate_of(item));
}

json fact_value(const json& item)
{
    if (item.contains("value"))
        return item["value"];
    if (item.contains("required"))
        return item["required"];
    if (item.contains("operation"))
        return item["operation"];
    return item;
}

json array_field(const json& object, const char* key)
{
    if (object.contains(key) && object[key].is_array())
        return object[key];
    return json::array();
}

void append_facts_from(const json& source, json& out)
{
    if (!source.is_object())
        return;
    for (const char* key : {"facts", "initial_facts", "postconditions", "produced_facts", "preconditions", "side_effects"})
    {
        if (source.contains(key) && source[key].is_array())
        {
            for (const json& item : source[key])
                if (item.is_object())
                    out.push_back(item);
        }
    }
}

json all_proven_facts_before_link(const json& chain, std::size_t link_index)
{
    json facts = json::array();
    append_facts_from(chain, facts);
    const json links = array_field(chain, "links");
    for (std::size_t i = 0; i < link_index && i < links.size(); ++i)
        append_facts_from(links[i], facts);
    json proven_facts = json::array();
    for (const json& fact : facts)
    {
        if (proven(fact))
            proven_facts.push_back(fact);
    }
    return proven_facts;
}

bool json_truthy_field(const json& value, const std::string& key)
{
    if (!value.is_object() || !value.contains(key))
        return false;
    const json& v = value[key];
    if (v.is_boolean())
        return v.get<bool>();
    if (v.is_string())
    {
        const std::string s = lowercase_ascii(v.get<std::string>());
        return s == "true" || s == "yes" || s == "controlled" || s == "self_reference" || s == "zero";
    }
    return false;
}

std::string content_class(const json& value)
{
    if (!value.is_object())
        return std::string();
    return lowercase_ascii(value.value("content_class", value.value("class", std::string())));
}

bool value_satisfies(const json& produced, const json& required)
{
    if (required.is_null() || required.empty())
        return true;
    if (produced == required)
        return true;
    if (required.is_object() && produced.is_object())
    {
        for (auto it = required.begin(); it != required.end(); ++it)
        {
            if (!produced.contains(it.key()))
                return false;
            if (produced[it.key()] != it.value())
                return false;
        }
        return true;
    }
    return false;
}

bool value_contradicts(const json& produced, const json& required, std::string& reason)
{
    if (!produced.is_object() || !required.is_object())
        return false;
    const bool required_controlled = json_truthy_field(required, "controlled") || content_class(required) == "controlled";
    const bool produced_zero = json_truthy_field(produced, "zero") || content_class(produced) == "zero" || content_class(produced) == "zero_bytes";
    if (required_controlled && produced_zero)
    {
        reason = "zero_content_does_not_satisfy_controlled_content";
        return true;
    }
    const bool required_self = json_truthy_field(required, "self_reference") || lowercase_ascii(required.value("alias", std::string())) == "self_reference";
    const bool produced_other_pointer = produced.contains("target")
        && lowercase_ascii(produced.value("target", std::string())).find("self") == std::string::npos;
    if (required_self && produced_other_pointer)
    {
        reason = "pointer_target_is_not_self_referential";
        return true;
    }
    if (required.contains("required_updated_location") && produced.contains("written_location"))
    {
        if (lowercase_ascii(required.value("required_updated_location", std::string())) != lowercase_ascii(produced.value("written_location", std::string())))
        {
            reason = "write_through_updated_the_wrong_location";
            return true;
        }
    }
    return false;
}

json evaluate_preconditions(const json& facts, const json& preconditions)
{
    json out;
    out["verdict"] = "confirmed";
    out["matches"] = json::array();
    out["missing"] = json::array();
    out["contradictions"] = json::array();
    std::unordered_map<std::string, std::vector<json>> by_key;
    for (const json& fact : facts)
        by_key[fact_key(fact)].push_back(fact);
    for (const json& pre : preconditions)
    {
        const std::string key = fact_key(pre);
        const json required = fact_value(pre);
        bool matched = false;
        bool contradicted = false;
        auto it = by_key.find(key);
        if (it != by_key.end())
        {
            for (const json& fact : it->second)
            {
                const json produced = fact_value(fact);
                std::string reason;
                if (value_contradicts(produced, required, reason))
                {
                    json c;
                    c["precondition"] = pre;
                    c["fact"] = fact;
                    c["reason"] = reason;
                    out["contradictions"].push_back(c);
                    contradicted = true;
                    continue;
                }
                if (value_satisfies(produced, required))
                {
                    out["matches"].push_back({{"precondition", pre}, {"fact", fact}});
                    matched = true;
                    break;
                }
            }
        }
        if (!matched && !contradicted)
            out["missing"].push_back(pre);
    }
    if (!out["contradictions"].empty())
        out["verdict"] = "refuted";
    else if (!out["missing"].empty())
        out["verdict"] = "inconclusive";
    return out;
}

json evaluate_boundary(const json& producer, const json& consumer)
{
    json out;
    out["producer_link_id"] = producer.value("id", producer.value("link_id", std::string()));
    out["consumer_link_id"] = consumer.value("id", consumer.value("link_id", std::string()));
    json facts = json::array();
    for (const json& fact : array_field(producer, "postconditions"))
        if (fact.is_object() && proven(fact))
            facts.push_back(fact);
    out["evaluation"] = evaluate_preconditions(facts, array_field(consumer, "preconditions"));
    out["verdict"] = out["evaluation"].value("verdict", std::string("inconclusive"));
    return out;
}

std::string module_ref_id(const json& ref)
{
    if (ref.is_string())
        return multibinary::sanitize_id_component(ref.get<std::string>());
    if (!ref.is_object())
        return std::string();
    if (ref.contains("module_id"))
        return multibinary::sanitize_id_component(ref.value("module_id", std::string()));
    if (ref.contains("corpus_id"))
        return multibinary::sanitize_id_component(ref.value("corpus_id", std::string()));
    return multibinary::canonical_module_id_from_json(ref);
}

std::unordered_map<std::string, json> module_map_from_project(const json& modules)
{
    std::unordered_map<std::string, json> out;
    if (!modules.is_array())
        return out;
    for (const json& module : modules)
        out[multibinary::canonical_module_id_from_json(module)] = module;
    return out;
}

json ensure_cross_graph(const std::string& project_id)
{
    multibinary::project_io_result_t cross = multibinary::load_project_cross_edges(project_id);
    if (!cross.ok)
        cross = multibinary::resolve_project_cross_edges(project_id);
    return cross.ok ? cross.data.value("graph", json::object()) : json::object({{"schema", multibinary::k_cross_edges_schema}, {"edges", json::array()}, {"unresolved", json::array()}, {"ambiguous", json::array()}, {"load_error", cross.error_code}});
}

bool edge_resolved(const json& cross_graph, const json& required_edge, json& evidence)
{
    const std::string source = required_edge.value("source_module_id", required_edge.value("from_module_id", std::string()));
    const std::string target = required_edge.value("target_module_id", required_edge.value("to_module_id", std::string()));
    const std::string name = lowercase_ascii(required_edge.value("name", required_edge.value("symbol", std::string())));
    for (const json& edge : cross_graph.value("edges", json::array()))
    {
        if (!source.empty() && edge.value("source_module_id", std::string()) != source)
            continue;
        if (!target.empty())
        {
            const json target_obj = edge.value("target", json::object());
            if (target_obj.value("module_id", target_obj.value("target_module_id", std::string())) != target)
                continue;
        }
        if (!name.empty())
        {
            const json imp = edge.value("import", json::object());
            if (lowercase_ascii(imp.value("name", imp.value("symbol", std::string()))) != name)
                continue;
        }
        evidence = edge;
        return edge.value("state", std::string()) == "resolved";
    }
    return false;
}

json array_or_empty(const json& value)
{
    return value.is_array() ? value : json::array();
}

void collect_trace_objects(const json& node, json& out)
{
    if (node.is_object())
    {
        const bool trace_like = node.contains("instructions")
            || node.contains("steps")
            || node.contains("calls")
            || node.contains("branches")
            || node.contains("unresolved_edges")
            || node.contains("branch_blockers")
            || node.contains("effects")
            || node.contains("side_effects")
            || node.contains("register_state")
            || node.contains("memory_state");
        if (trace_like)
            out.push_back(node);
        for (auto it = node.begin(); it != node.end(); ++it)
            collect_trace_objects(it.value(), out);
    }
    else if (node.is_array())
    {
        for (const json& item : node)
            collect_trace_objects(item, out);
    }
}

std::string address_module_id(const json& value)
{
    if (!value.is_object())
        return std::string();
    const std::string direct = value.value("module_id", value.value("corpus_id", std::string()));
    if (!direct.empty())
        return direct;
    if (value.contains("module") && value["module"].is_object())
        return value["module"].value("module_id", value["module"].value("corpus_id", std::string()));
    if (value.contains("address") && value["address"].is_object())
        return address_module_id(value["address"]);
    if (value.contains("target") && value["target"].is_object())
        return address_module_id(value["target"]);
    if (value.contains("start") && value["start"].is_object())
        return address_module_id(value["start"]);
    return std::string();
}

bool state_is_unknown_or_poison(const json& value, std::string& reason)
{
    if (!value.is_object())
        return false;
    const std::string state = lowercase_ascii(value.value("state", value.value("proof_state", value.value("value_class", std::string()))));
    const std::string klass = lowercase_ascii(value.value("class", value.value("content_class", std::string())));
    if (state == "unknown" || state == "unresolved" || klass == "unknown")
    {
        reason = "state_value_unknown";
        return true;
    }
    if (state == "poisoned" || klass == "poisoned")
    {
        reason = "state_value_poisoned";
        return true;
    }
    return false;
}

bool abi_transfer_proven(const json& link, const json& trace)
{
    if (link.contains("abi_transfer") && link["abi_transfer"].is_object() && proven(link["abi_transfer"]))
        return true;
    if (trace.contains("abi_transfer") && trace["abi_transfer"].is_object() && proven(trace["abi_transfer"]))
        return true;
    for (const json& fact : array_field(link, "facts"))
    {
        if (lowercase_ascii(fact.value("kind", fact.value("predicate", std::string()))) == "abi_transfer" && proven(fact))
            return true;
    }
    return false;
}

bool call_has_resolved_cross_edge(const json& cross_graph, const json& call, json& evidence)
{
    json required;
    const std::string source = address_module_id(call.value("callsite", json::object()));
    const std::string target = address_module_id(call.value("target", json::object()));
    if (!source.empty())
        required["source_module_id"] = source;
    if (!target.empty())
        required["target_module_id"] = target;
    const std::string symbol = call.value("callee_name", call.value("name", std::string()));
    if (!symbol.empty())
        required["symbol"] = symbol;
    if (required.empty())
        return false;
    return edge_resolved(cross_graph, required, evidence);
}

json evaluate_continuous_trace(const json& link,
                               const std::unordered_map<std::string, json>& module_by_id,
                               const json& cross_graph)
{
    json out;
    out["schema"] = "aida.multibinary.continuous_trace_evaluation.v1";
    out["verdict"] = "confirmed";
    out["trace_count"] = 0;
    out["instruction_count"] = 0;
    out["call_count"] = 0;
    out["branch_count"] = 0;
    out["memory_event_count"] = 0;
    out["register_event_count"] = 0;
    out["blockers"] = json::array();
    json traces = json::array();
    for (const char* key : {"trace", "path_trace", "path_evidence", "source_evidence", "function_snapshot", "extraction"})
    {
        if (link.contains(key))
            collect_trace_objects(link[key], traces);
    }
    out["trace_count"] = traces.size();
    if (traces.empty())
    {
        out["verdict"] = "inconclusive";
        out["blockers"].push_back({{"kind", "trace_evidence_missing"}, {"reason", "continuous verification requires source-backed instruction/path evidence"}});
        return out;
    }
    for (const json& trace : traces)
    {
        if (trace.contains("complete") && trace["complete"].is_boolean() && !trace["complete"].get<bool>())
            out["blockers"].push_back({{"kind", "trace_incomplete"}, {"trace_reason", trace.value("reason", std::string())}});
        for (const json& unresolved : array_or_empty(trace.value("unresolved_edges", json::array())))
            out["blockers"].push_back({{"kind", "unresolved_trace_edge"}, {"edge", unresolved}});
        for (const json& blocker : array_or_empty(trace.value("branch_blockers", json::array())))
            out["blockers"].push_back({{"kind", "branch_direction_unproven"}, {"blocker", blocker}});
        json instructions = array_or_empty(trace.value("instructions", json::array()));
        if (instructions.empty() && trace.contains("steps") && trace["steps"].is_array())
        {
            for (const json& step : trace["steps"])
            {
                json ins = step;
                if (!ins.contains("disassembly"))
                    ins["disassembly"] = step.value("text", std::string());
                instructions.push_back(ins);
            }
        }
        out["instruction_count"] = out.value("instruction_count", static_cast<std::size_t>(0)) + instructions.size();
        for (const json& ins : instructions)
        {
            if (ins.value("unknown_effect", false))
                out["blockers"].push_back({{"kind", "unknown_instruction_effect"}, {"instruction", ins}});
            if (ins.value("is_indirect", false) && (ins.value("is_call", false) || ins.value("kind", std::string()).find("indirect_call") != std::string::npos))
                out["blockers"].push_back({{"kind", "indirect_call_target_unproven"}, {"instruction", ins}});
        }
        json calls = array_or_empty(trace.value("calls", json::array()));
        if (trace.contains("steps") && trace["steps"].is_array())
        {
            for (const json& step : trace["steps"])
                for (const json& call : array_or_empty(step.value("calls", json::array())))
                    calls.push_back(call);
        }
        out["call_count"] = out.value("call_count", static_cast<std::size_t>(0)) + calls.size();
        for (const json& call : calls)
        {
            const bool resolved = call.value("resolved", false) || lowercase_ascii(call.value("resolution_quality", call.value("confidence", std::string()))) == "exact";
            const std::string kind = lowercase_ascii(call.value("kind", std::string()));
            if (!resolved || kind == "indirect")
                out["blockers"].push_back({{"kind", "call_target_unproven"}, {"call", call}});
            const std::string source_module = address_module_id(call.value("callsite", json::object()));
            const std::string target_module = address_module_id(call.value("target", json::object()));
            if (!source_module.empty() && !target_module.empty() && source_module != target_module)
            {
                json edge_evidence;
                if (!call_has_resolved_cross_edge(cross_graph, call, edge_evidence))
                    out["blockers"].push_back({{"kind", "cross_module_call_edge_unproven"}, {"call", call}});
                if (!abi_transfer_proven(link, trace))
                    out["blockers"].push_back({{"kind", "abi_transfer_unproven"}, {"call", call}});
                auto mit = module_by_id.find(target_module);
                if (mit == module_by_id.end() || mit->second.value("availability", std::string()) == "missing")
                    out["blockers"].push_back({{"kind", "peer_data_missing"}, {"target_module_id", target_module}, {"call", call}});
                else if (mit->second.value("live_instances", json::array()).empty())
                    out["blockers"].push_back({{"kind", "peer_data_missing"}, {"target_module_id", target_module}, {"reason", "target module has no live instance binding for ABI transfer"}});
            }
        }
        json branches = array_or_empty(trace.value("branches", json::array()));
        if (trace.contains("steps") && trace["steps"].is_array())
        {
            for (const json& step : trace["steps"])
                for (const json& branch : array_or_empty(step.value("branches", json::array())))
                    branches.push_back(branch);
        }
        out["branch_count"] = out.value("branch_count", static_cast<std::size_t>(0)) + branches.size();
        for (const json& branch : branches)
        {
            if (!branch.value("conditional", false))
                continue;
            if (!branch.value("direction_proven", false) && !proven(branch) && !branch.contains("chosen_target"))
                out["blockers"].push_back({{"kind", "branch_direction_unproven"}, {"branch", branch}});
        }
        json effects = array_or_empty(trace.value("effects", json::array()));
        if (trace.contains("side_effects") && trace["side_effects"].is_array())
        {
            for (const json& effect : trace["side_effects"])
                effects.push_back(effect);
        }
        if (trace.contains("steps") && trace["steps"].is_array())
        {
            for (const json& step : trace["steps"])
                for (const json& effect : array_or_empty(step.value("side_effects", json::array())))
                    effects.push_back(effect);
        }
        out["memory_event_count"] = out.value("memory_event_count", static_cast<std::size_t>(0)) + effects.size();
        for (const json& effect : effects)
        {
            const std::string safety = lowercase_ascii(effect.value("safety", effect.value("classification", effect.value("state", std::string()))));
            if (safety == "fatal" || safety == "poison" || safety == "poisoned" || safety == "bugcheck" || safety == "fastfail")
                out["blockers"].push_back({{"kind", "poison_side_effect"}, {"side_effect", effect}});
            if (effect.value("modeled", true) == false)
                out["blockers"].push_back({{"kind", "side_effect_not_modeled"}, {"side_effect", effect}});
        }
        for (const char* state_key : {"register_state", "memory_state"})
        {
            for (const json& state : array_or_empty(trace.value(state_key, json::array())))
            {
                if (std::string(state_key) == "register_state")
                    out["register_event_count"] = out.value("register_event_count", static_cast<std::size_t>(0)) + 1;
                else
                    out["memory_event_count"] = out.value("memory_event_count", static_cast<std::size_t>(0)) + 1;
                std::string reason;
                if (state_is_unknown_or_poison(state, reason))
                    out["blockers"].push_back({{"kind", reason}, {"state", state}});
            }
        }
    }
    bool refuted = false;
    for (const json& blocker : out["blockers"])
    {
        const std::string kind = blocker.value("kind", std::string());
        if (kind == "poison_side_effect" || kind == "state_value_poisoned")
            refuted = true;
    }
    if (refuted)
        out["verdict"] = "refuted";
    else if (!out["blockers"].empty())
        out["verdict"] = "inconclusive";
    return out;
}

json case_semantics_from_chain(const json& chain)
{
    json out;
    out["checks"] = json::array();
    const json links = array_field(chain, "links");
    for (std::size_t i = 1; i < links.size(); ++i)
    {
        json b = evaluate_boundary(links[i - 1], links[i]);
        if (b.value("verdict", std::string()) == "refuted")
        {
            const std::string reason = b["evaluation"]["contradictions"].empty()
                ? std::string()
                : b["evaluation"]["contradictions"].front().value("reason", std::string());
            if (reason == "zero_content_does_not_satisfy_controlled_content")
                out["checks"].push_back({{"case_id", "ntfs_etw_zero_vs_copy"}, {"verdict", "refuted"}, {"evidence", b}});
            if (reason == "pointer_target_is_not_self_referential")
                out["checks"].push_back({{"case_id", "afd_list_entry_guard"}, {"verdict", "refuted"}, {"evidence", b}});
            if (reason == "write_through_updated_the_wrong_location")
                out["checks"].push_back({{"case_id", "pvscan0_bad_pointer"}, {"verdict", "refuted"}, {"evidence", b}});
        }
        else if (b.value("verdict", std::string()) == "confirmed")
        {
            const std::string dump = lowercase_ascii(b.dump());
            if (dump.find("self_reference") != std::string::npos && dump.find("pvscan0") != std::string::npos)
                out["checks"].push_back({{"case_id", "pvscan0_self_reference"}, {"verdict", "confirmed"}, {"evidence", b}});
            if (dump.find("timer2") != std::string::npos && dump.find("self_reference") != std::string::npos)
                out["checks"].push_back({{"case_id", "afd_timer2_self_reference"}, {"verdict", "confirmed"}, {"evidence", b}});
        }
    }
    return out;
}

json builtin_case_study_fixtures()
{
    json fixtures = json::array();
    fixtures.push_back({
        {"case_id", "ntfs_etw_zero_vs_copy"},
        {"expected_verdict", "refuted"},
        {"required_source_evidence", json::array({"memmove_or_copy_write_content_class", "memset_or_zero_write_content_class", "etw_list_entry_requires_controlled_flink_blink"})},
        {"preconditions", json::array({
            {{"subject", "etw_list_entry"}, {"predicate", "content"}, {"required", {{"content_class", "controlled"}}}, {"proof_state", "proven"}}
        })},
        {"facts", json::array({
            {{"subject", "etw_list_entry"}, {"predicate", "content"}, {"value", {{"content_class", "zero"}}}, {"proof_state", "proven"}}
        })}
    });
    fixtures.push_back({
        {"case_id", "afd_list_entry_guard_without_timer2"},
        {"expected_verdict", "inconclusive"},
        {"required_source_evidence", json::array({"AfdCloseConnection LIST_ENTRY empty-list guard", "conn+0x48 self-reference", "conn+0x50 self-reference", "indirect call after guard"})},
        {"preconditions", json::array({
            {{"subject", "afd_connection_list_entry"}, {"predicate", "alias"}, {"required", {{"self_reference", true}}}, {"proof_state", "proven"}}
        })},
        {"facts", json::array()}
    });
    fixtures.push_back({
        {"case_id", "afd_list_entry_guard_with_timer2"},
        {"expected_verdict", "confirmed_when_source_evidence_matches"},
        {"required_source_evidence", json::array({"Timer2 LFH address discovery proves conn address", "conn+0x48 == &conn+0x48", "conn+0x50 == &conn+0x48", "call target resolved"})},
        {"preconditions", json::array({
            {{"subject", "afd_connection_list_entry"}, {"predicate", "alias"}, {"required", {{"self_reference", true}, {"source", "timer2_lfh"}}}, {"proof_state", "proven"}}
        })},
        {"facts", json::array({
            {{"subject", "afd_connection_list_entry"}, {"predicate", "alias"}, {"value", {{"self_reference", true}, {"source", "timer2_lfh"}}}, {"proof_state", "proven"}}
        })}
    });
    fixtures.push_back({
        {"case_id", "pvscan0_bad_pointer"},
        {"expected_verdict", "refuted"},
        {"required_source_evidence", json::array({"SetBitmapBits writes through [pvScan0]", "pvScan0 equals gpHandleManager", "next precondition requires pvScan0 update"})},
        {"preconditions", json::array({
            {{"subject", "pvScan0"}, {"predicate", "update"}, {"required", {{"required_updated_location", "pvScan0"}}}, {"proof_state", "proven"}}
        })},
        {"facts", json::array({
            {{"subject", "pvScan0"}, {"predicate", "update"}, {"value", {{"written_location", "gpHandleManager"}}}, {"proof_state", "proven"}}
        })}
    });
    fixtures.push_back({
        {"case_id", "pvscan0_self_reference"},
        {"expected_verdict", "confirmed_when_source_evidence_matches"},
        {"required_source_evidence", json::array({"fake bitmap object layout proven", "pvScan0 == &pvScan0", "SetBitmapBits source/destination preserved"})},
        {"preconditions", json::array({
            {{"subject", "pvScan0"}, {"predicate", "alias"}, {"required", {{"self_reference", true}}}, {"proof_state", "proven"}}
        })},
        {"facts", json::array({
            {{"subject", "pvScan0"}, {"predicate", "alias"}, {"value", {{"self_reference", true}}}, {"proof_state", "proven"}}
        })}
    });
    return fixtures;
}

}

multibinary::project_io_result_t verify_project_chain(const std::string& requested_project_id,
                                                      const json& chain,
                                                      const json& options)
{
    if (!chain.is_object())
        return make_error("bad_chain", "chain must be an object");
    const std::string project_id = requested_project_id.empty()
        ? chain.value("project_id", std::string())
        : requested_project_id;
    if (project_id.empty())
        return make_error("project_id_required", "project_id is required for project-wide verification");
    multibinary::project_io_result_t modules_loaded = multibinary::load_project_modules(project_id);
    if (!modules_loaded.ok)
        return modules_loaded;
    const json modules = modules_loaded.data.value("modules", json::array());
    const auto module_by_id = module_map_from_project(modules);
    const json cross_graph = ensure_cross_graph(project_id);
    json report;
    report["schema"] = k_project_chain_verifier_schema;
    report["project_id"] = project_id;
    report["chain_id"] = chain.value("chain_id", chain.value("id", std::string("chain_" + multibinary::stable_hash_hex(chain.dump()))));
    report["verdict"] = "confirmed";
    report["proof_level"] = "continuous_trace_fail_closed";
    report["links"] = json::array();
    report["boundaries"] = json::array();
    report["blockers"] = json::array();
    report["first_failure"] = nullptr;
    report["cross_edges"] = json::object({
        {"resolved_count", cross_graph.value("resolved_count", static_cast<std::size_t>(0))},
        {"ambiguous_count", cross_graph.value("ambiguous_count", static_cast<std::size_t>(0))},
        {"unresolved_count", cross_graph.value("unresolved_count", static_cast<std::size_t>(0))}
    });
    for (const json& mod_ref : array_field(chain, "modules"))
    {
        const std::string id = module_ref_id(mod_ref);
        if (id.empty())
            continue;
        auto it = module_by_id.find(id);
        if (it == module_by_id.end())
            report["blockers"].push_back({{"kind", "missing_module"}, {"module_id", id}});
        else if (it->second.value("availability", std::string()) == "missing")
            report["blockers"].push_back({{"kind", "missing_module"}, {"module_id", id}, {"module", it->second}});
    }
    const json links = array_field(chain, "links");
    for (std::size_t i = 0; i < links.size(); ++i)
    {
        const json& link = links[i];
        json link_report;
        link_report["link_id"] = link.value("id", link.value("link_id", "link_" + std::to_string(i)));
        link_report["verdict"] = "confirmed";
        link_report["blockers"] = json::array();
        std::string module_id;
        if (link.contains("module_ref"))
            module_id = module_ref_id(link["module_ref"]);
        else if (link.contains("module"))
            module_id = module_ref_id(link["module"]);
        if (!module_id.empty())
        {
            auto mit = module_by_id.find(module_id);
            if (mit == module_by_id.end() || mit->second.value("availability", std::string()) == "missing")
                link_report["blockers"].push_back({{"kind", "missing_module"}, {"module_id", module_id}});
        }
        const json facts_before = all_proven_facts_before_link(chain, i);
        json pre_eval = evaluate_preconditions(facts_before, array_field(link, "preconditions"));
        link_report["preconditions"] = pre_eval;
        if (pre_eval.value("verdict", std::string()) == "refuted")
            link_report["verdict"] = "refuted";
        else if (pre_eval.value("verdict", std::string()) != "confirmed")
            link_report["verdict"] = "inconclusive";
        if (link.contains("required_edges") && link["required_edges"].is_array())
        {
            link_report["required_edges"] = json::array();
            for (const json& required : link["required_edges"])
            {
                json evidence;
                const bool ok = edge_resolved(cross_graph, required, evidence);
                json item;
                item["required"] = required;
                item["resolved"] = ok;
                item["evidence"] = evidence.is_null() ? json::object() : evidence;
                if (!ok)
                {
                    item["blocker"] = true;
                    link_report["verdict"] = link_report.value("verdict", std::string()) == "refuted" ? "refuted" : "inconclusive";
                }
                link_report["required_edges"].push_back(item);
            }
        }
        json trace_eval = evaluate_continuous_trace(link, module_by_id, cross_graph);
        link_report["continuous_trace"] = trace_eval;
        const std::string trace_verdict = trace_eval.value("verdict", std::string("inconclusive"));
        if (trace_verdict == "refuted")
            link_report["verdict"] = "refuted";
        else if (trace_verdict != "confirmed" && link_report.value("verdict", std::string()) != "refuted")
            link_report["verdict"] = "inconclusive";
        for (const json& blocker : trace_eval.value("blockers", json::array()))
            link_report["blockers"].push_back(blocker);
        if (array_field(link, "postconditions").empty()
            && array_field(link, "produced_facts").empty()
            && array_field(link, "required_edges").empty()
            && !link.contains("source_evidence"))
        {
            link_report["blockers"].push_back({{"kind", "source_evidence_missing"}, {"reason", "link has no source-backed facts, path evidence, or required cross-edge evidence"}});
            if (link_report.value("verdict", std::string()) != "refuted")
                link_report["verdict"] = "inconclusive";
        }
        for (const json& side : array_field(link, "side_effects"))
        {
            const std::string safety = lowercase_ascii(side.value("safety", side.value("classification", std::string())));
            if ((safety == "fatal" || safety == "poison" || safety == "bugcheck" || safety == "fastfail") && proven(side))
            {
                link_report["verdict"] = "refuted";
                link_report["blockers"].push_back({{"kind", "poison_side_effect"}, {"side_effect", side}});
            }
        }
        if (!link_report["blockers"].empty())
        {
            for (const json& blocker : link_report["blockers"])
                report["blockers"].push_back({{"link_id", link_report["link_id"]}, {"blocker", blocker}});
        }
        report["links"].push_back(link_report);
        if (i > 0)
        {
            json boundary = evaluate_boundary(links[i - 1], link);
            report["boundaries"].push_back(boundary);
        }
    }
    for (const json& boundary : report["boundaries"])
    {
        const std::string verdict = boundary.value("verdict", std::string("inconclusive"));
        if (verdict == "refuted")
            report["blockers"].push_back({{"kind", "boundary_refuted"}, {"boundary", boundary}});
        else if (verdict != "confirmed")
            report["blockers"].push_back({{"kind", "boundary_unproven"}, {"boundary", boundary}});
    }
    for (const json& edge : cross_graph.value("ambiguous", json::array()))
        report["blockers"].push_back({{"kind", "ambiguous_cross_edge"}, {"edge", edge}});
    if (!options.value("allow_unresolved_cross_edges", false))
    {
        for (const json& edge : cross_graph.value("unresolved", json::array()))
            report["blockers"].push_back({{"kind", "unresolved_cross_edge"}, {"edge", edge}});
    }
    bool any_refuted = false;
    bool any_inconclusive = !report["blockers"].empty();
    for (const json& link : report["links"])
    {
        const std::string verdict = link.value("verdict", std::string("inconclusive"));
        if (verdict == "refuted")
            any_refuted = true;
        else if (verdict != "confirmed")
            any_inconclusive = true;
    }
    for (const json& boundary : report["boundaries"])
    {
        const std::string verdict = boundary.value("verdict", std::string("inconclusive"));
        if (verdict == "refuted")
            any_refuted = true;
        else if (verdict != "confirmed")
            any_inconclusive = true;
    }
    if (any_refuted)
        report["verdict"] = "refuted";
    else if (any_inconclusive || links.empty())
        report["verdict"] = "inconclusive";
    else
        report["verdict"] = "confirmed";
    if (!report["blockers"].empty())
        report["first_failure"] = report["blockers"].front();
    report["case_study_semantics"] = case_semantics_from_chain(chain);
    return make_ok(report);
}

multibinary::project_io_result_t run_case_study_regressions(const std::string& requested_project_id,
                                                            const json& payload)
{
    const json chain = payload.value("chain", json::object());
    const std::string project_id = requested_project_id.empty() ? payload.value("project_id", std::string()) : requested_project_id;
    json out;
    out["schema"] = "aida.multibinary.case_study_regressions.v1";
    out["project_id"] = project_id.empty() ? json(nullptr) : json(project_id);
    out["checks"] = json::array();
    out["fixtures"] = builtin_case_study_fixtures();
    if (chain.is_object() && !chain.empty())
    {
        multibinary::project_io_result_t verification = verify_project_chain(project_id, chain, payload.value("options", json::object()));
        if (!verification.ok)
            return verification;
        out["verification"] = verification.data;
        out["checks"] = verification.data.value("case_study_semantics", json::object()).value("checks", json::array());
    }
    if (payload.contains("source_checks") && payload["source_checks"].is_array())
    {
        for (const json& check : payload["source_checks"])
        {
            json facts = json::array();
            append_facts_from(check, facts);
            json eval = evaluate_preconditions(facts, array_field(check, "preconditions"));
            out["checks"].push_back({{"case_id", check.value("case_id", std::string("source_check"))}, {"verdict", eval.value("verdict", std::string("inconclusive"))}, {"evaluation", eval}});
        }
    }
    if (out["checks"].empty())
    {
        for (const json& fixture : out["fixtures"])
        {
            out["checks"].push_back({
                {"case_id", fixture.value("case_id", std::string())},
                {"verdict", "inconclusive"},
                {"reason", "source_evidence_required"},
                {"required_source_evidence", fixture.value("required_source_evidence", json::array())}
            });
        }
    }
    bool any_refuted = false;
    bool any_inconclusive = out["checks"].empty();
    for (const json& check : out["checks"])
    {
        const std::string verdict = check.value("verdict", check.value("status", std::string("inconclusive")));
        if (verdict == "refuted")
            any_refuted = true;
        else if (verdict != "confirmed")
            any_inconclusive = true;
    }
    out["verdict"] = any_refuted ? "refuted" : (any_inconclusive ? "inconclusive" : "confirmed");
    return make_ok(out);
}

}
}
}
