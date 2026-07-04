#include "chain_alias.hpp"

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
        return text == "true" || text == "1" || text == "yes" || text == "proven";
    }
    return fallback;
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
        for (const char* nested : {"text", "subject", "target", "alias", "address_expr", "alias_class", "object_id", "field_path", "value"})
        {
            const std::string text = read_string(item, nested);
            if (!text.empty())
                return text;
        }
    }
    return {};
}

chain_fact_t make_alias_fact(const nlohmann::json& event,
                             const alias_derivation_context_t& context,
                             const std::string& subject,
                             const std::string& predicate,
                             const nlohmann::json& value)
{
    chain_fact_t fact;
    fact.kind = contract_fact_kind_t::alias;
    fact.subject = subject;
    fact.predicate = predicate;
    fact.value = value;
    fact.phase = context.phase;
    fact.producer = context.link_id;
    fact.proof_state = context.proof_state;
    fact.criticality = context.criticality;
    if (!context.evidence.is_null() && !context.evidence.empty())
    {
        evidence_t ev;
        ev.evidence_id = "ev_" + stable_hash_hex(context.link_id + context.phase + predicate + context.evidence.dump());
        ev.layer = read_string(context.evidence, "source_layer", read_string(context.evidence, "layer", "transfer"));
        ev.lineage = read_string(context.evidence, "reason", "alias_transfer");
        ev.snippet = read_string(context.evidence, "operation", read_string(context.evidence, "provenance"));
        ev.payload = context.evidence;
        fact.evidence.push_back(std::move(ev));
    }
    else
    {
        evidence_t ev;
        ev.evidence_id = "ev_" + stable_hash_hex(context.link_id + context.phase + predicate + event.dump());
        ev.layer = "transfer";
        ev.lineage = "alias_transfer";
        ev.snippet = read_string(event, "operation", read_string(event, "kind"));
        ev.payload = event;
        fact.evidence.push_back(std::move(ev));
    }
    fact.fact_id = "alias_" + stable_hash_hex(fact.subject + fact.predicate + fact.value.dump() + fact.phase + fact.producer);
    return fact;
}

}

std::string alias_event_subject(const nlohmann::json& event)
{
    for (const char* key : {"subject", "destination", "dest", "left", "slot", "pointer_slot", "field", "object"})
    {
        const std::string text = nested_text(event, key);
        if (!text.empty())
            return text;
    }
    return {};
}

std::string alias_event_target(const nlohmann::json& event)
{
    for (const char* key : {"target", "right", "source", "src", "points_to", "alias", "value", "address"})
    {
        const std::string text = nested_text(event, key);
        if (!text.empty())
            return text;
    }
    return {};
}

bool alias_event_is_self_reference(const nlohmann::json& event)
{
    const std::string kind = lower_copy(read_string(event, "kind", read_string(event, "operation", read_string(event, "op"))));
    const std::string predicate = lower_copy(read_string(event, "predicate"));
    if (read_bool(event, "self_reference", false) || kind == "self_reference" || predicate == "self_reference")
        return true;
    const std::string subject = alias_event_subject(event);
    const std::string target = alias_event_target(event);
    return !subject.empty() && lower_copy(subject) == lower_copy(target);
}

std::vector<chain_fact_t> derive_alias_facts(const nlohmann::json& event, const alias_derivation_context_t& context)
{
    std::vector<chain_fact_t> facts;
    const std::string subject = alias_event_subject(event);
    if (subject.empty())
        return facts;
    const std::string target = alias_event_target(event);
    const bool self_reference = alias_event_is_self_reference(event);
    if (self_reference)
    {
        nlohmann::json value = nlohmann::json::object();
        value["self_reference"] = true;
        if (!target.empty())
            value["target"] = target;
        facts.push_back(make_alias_fact(event, context, subject, "self_reference", value));
    }
    if (!target.empty())
    {
        nlohmann::json value = nlohmann::json::object();
        value["target"] = target;
        value["points_to"] = target;
        value["self_reference"] = self_reference;
        facts.push_back(make_alias_fact(event, context, subject, "points_to", value));
    }
    return facts;
}

}
}
}
