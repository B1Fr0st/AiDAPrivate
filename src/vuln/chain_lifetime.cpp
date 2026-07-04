#include "chain_lifetime.hpp"

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

std::string nested_text(const nlohmann::json& value, const char* key)
{
    if (!value.is_object() || !value.contains(key))
        return {};
    const auto& item = value.at(key);
    if (item.is_string() || item.is_number_integer() || item.is_number_unsigned() || item.is_boolean())
        return read_string(value, key);
    if (item.is_object())
    {
        for (const char* nested : {"text", "object_id", "field_path", "alias_class", "address_expr", "value", "target", "subject"})
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
    return lower_copy(read_string(event, "kind", read_string(event, "operation", read_string(event, "op"))));
}

std::string lifetime_state_for_kind(const std::string& kind)
{
    if (kind == "allocation" || kind == "allocate" || kind == "alloc" || kind == "new" || kind == "heapalloc")
        return "allocated";
    if (kind == "initialize" || kind == "initialized" || kind == "init" || kind == "zero" || kind == "memset" || kind == "memory_set")
        return "initialized";
    if (kind == "publish" || kind == "published")
        return "published";
    if (kind == "borrow" || kind == "borrowed")
        return "borrowed";
    if (kind == "free" || kind == "free_object" || kind == "delete" || kind == "heapfree")
        return "freed";
    if (kind == "reclaim" || kind == "reclaimed")
        return "reclaimed";
    if (kind == "reuse" || kind == "reused")
        return "reused";
    if (kind == "dangling")
        return "dangling";
    if (kind == "address_discovery" || kind == "address_discovered" || kind == "discover_address")
        return "address_discovered";
    return {};
}

std::string allocator_kind_for_event(const std::string& kind)
{
    if (kind == "allocation" || kind == "allocate" || kind == "alloc" || kind == "new" || kind == "heapalloc")
        return "allocate";
    if (kind == "zero" || kind == "memset" || kind == "memory_set")
        return "zero";
    if (kind == "fill")
        return "fill";
    if (kind == "free" || kind == "free_object" || kind == "delete" || kind == "heapfree")
        return "free";
    if (kind == "quarantine")
        return "quarantine";
    if (kind == "recycle")
        return "recycle";
    if (kind == "size_class_change")
        return "size_class_change";
    if (kind == "metadata_write")
        return "metadata_write";
    if (kind == "reuse_blocked")
        return "reuse_blocked";
    return {};
}

chain_fact_t make_fact(const nlohmann::json& event,
                       const lifetime_derivation_context_t& context,
                       contract_fact_kind_t kind,
                       const std::string& subject,
                       const std::string& predicate,
                       nlohmann::json value)
{
    chain_fact_t fact;
    fact.kind = kind;
    fact.subject = subject;
    fact.predicate = predicate;
    fact.value = std::move(value);
    fact.phase = context.phase;
    fact.producer = context.link_id;
    fact.proof_state = context.proof_state;
    fact.criticality = context.criticality;
    evidence_t ev;
    ev.evidence_id = "ev_" + stable_hash_hex(context.link_id + context.phase + subject + predicate + event.dump());
    ev.layer = read_string(context.evidence, "source_layer", read_string(context.evidence, "layer", "transfer"));
    ev.lineage = read_string(context.evidence, "reason", "lifetime_transfer");
    ev.snippet = read_string(context.evidence, "operation", read_string(event, "operation", read_string(event, "kind")));
    ev.payload = context.evidence.empty() ? event : context.evidence;
    fact.evidence.push_back(std::move(ev));
    fact.fact_id = "lifetime_" + stable_hash_hex(fact.subject + fact.predicate + fact.value.dump() + fact.phase + fact.producer);
    return fact;
}

}

std::string lifetime_event_subject(const nlohmann::json& event)
{
    for (const char* key : {"object_id", "object", "subject", "destination", "dest", "target", "allocation", "pointer", "address"})
    {
        const std::string text = nested_text(event, key);
        if (!text.empty())
            return text;
    }
    return {};
}

std::vector<chain_fact_t> derive_lifetime_facts(const nlohmann::json& event, const lifetime_derivation_context_t& context)
{
    std::vector<chain_fact_t> facts;
    const std::string kind = event_kind(event);
    const std::string state = read_string(event, "state", lifetime_state_for_kind(kind));
    if (state.empty())
        return facts;
    const std::string subject = lifetime_event_subject(event);
    if (subject.empty())
        return facts;
    nlohmann::json value = nlohmann::json::object();
    value["state"] = state;
    value["lifetime"] = state;
    value["event_kind"] = kind;
    const std::string sequence = read_string(event, "sequence", read_string(event, "order"));
    if (!sequence.empty())
        value["sequence"] = sequence;
    facts.push_back(make_fact(event, context, contract_fact_kind_t::object_lifetime, subject, "lifetime", value));
    return facts;
}

std::vector<chain_fact_t> derive_allocator_facts(const nlohmann::json& event, const lifetime_derivation_context_t& context)
{
    std::vector<chain_fact_t> facts;
    const std::string kind = allocator_kind_for_event(event_kind(event));
    if (kind.empty())
        return facts;
    const std::string subject = lifetime_event_subject(event);
    if (subject.empty())
        return facts;
    nlohmann::json value = nlohmann::json::object();
    value["allocator_event"] = kind;
    value["state"] = kind;
    const std::string size = read_string(event, "size", read_string(event, "width", read_string(event, "bytes")));
    if (!size.empty())
        value["size"] = size;
    const std::string allocator = read_string(event, "allocator", read_string(event, "allocator_id"));
    if (!allocator.empty())
        value["allocator_id"] = allocator;
    facts.push_back(make_fact(event, context, contract_fact_kind_t::object_lifetime, subject, "allocator", value));
    return facts;
}

}
}
}
