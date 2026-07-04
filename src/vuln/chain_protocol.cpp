#include "chain_protocol.hpp"

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
        return text == "true" || text == "1" || text == "yes" || text == "valid" || text == "verified" || text == "proven";
    }
    return fallback;
}

std::string event_kind(const nlohmann::json& event)
{
    return lower_copy(read_string(event, "kind", read_string(event, "operation", read_string(event, "op"))));
}

std::string subject_for_event(const nlohmann::json& event)
{
    for (const char* key : {"protocol_id", "message", "event", "subject", "destination", "target", "channel", "packet", "frame", "firmware", "interrupt"})
    {
        const std::string text = read_string(event, key);
        if (!text.empty())
            return text;
        if (event.is_object() && event.contains(key) && event.at(key).is_object())
        {
            const auto& item = event.at(key);
            for (const char* nested : {"id", "name", "text", "target", "address", "vector"})
            {
                const std::string nested_text = read_string(item, nested);
                if (!nested_text.empty())
                    return nested_text;
            }
        }
    }
    return {};
}

chain_fact_t make_fact(const nlohmann::json& event,
                       const protocol_derivation_context_t& context,
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
    ev.lineage = read_string(context.evidence, "reason", "protocol_transfer");
    ev.snippet = read_string(context.evidence, "operation", read_string(event, "operation", read_string(event, "kind")));
    ev.payload = context.evidence.empty() ? event : context.evidence;
    fact.evidence.push_back(std::move(ev));
    fact.fact_id = std::string(kind == contract_fact_kind_t::firmware ? "firmware_" : "protocol_") +
                   stable_hash_hex(fact.subject + fact.predicate + fact.value.dump() + fact.phase + fact.producer);
    return fact;
}

void append_if_present(std::vector<chain_fact_t>& facts,
                       const nlohmann::json& event,
                       const protocol_derivation_context_t& context,
                       const std::string& subject,
                       const char* key,
                       const char* predicate)
{
    const std::string text = read_string(event, key);
    if (text.empty())
        return;
    nlohmann::json value = nlohmann::json::object();
    value[key] = text;
    facts.push_back(make_fact(event, context, contract_fact_kind_t::protocol, subject, predicate, value));
}

}

bool protocol_event_has_verified_checksum(const nlohmann::json& event)
{
    if (read_bool(event, "checksum_validated", false) || read_bool(event, "checksum_verified", false) || read_bool(event, "checksum_ok", false))
        return true;
    if (event.is_object() && event.contains("checksum") && event.at("checksum").is_object())
        return read_bool(event.at("checksum"), "validated", false) || read_bool(event.at("checksum"), "verified", false);
    return false;
}

std::vector<chain_fact_t> derive_protocol_facts(const nlohmann::json& event, const protocol_derivation_context_t& context)
{
    std::vector<chain_fact_t> facts;
    const std::string kind = event_kind(event);
    const bool protocol_kind = kind.find("protocol") != std::string::npos ||
                               kind.find("message") != std::string::npos ||
                               kind.find("packet") != std::string::npos ||
                               kind.find("emit") != std::string::npos ||
                               event.contains("protocol_state") ||
                               event.contains("protocol_id") ||
                               event.contains("checksum") ||
                               event.contains("length");
    if (!protocol_kind)
        return facts;
    const std::string subject = subject_for_event(event);
    if (subject.empty())
        return facts;
    append_if_present(facts, event, context, subject, "protocol_state", "state");
    append_if_present(facts, event, context, subject, "state", "state");
    append_if_present(facts, event, context, subject, "length", "length");
    append_if_present(facts, event, context, subject, "message_type", "message_type");
    if (protocol_event_has_verified_checksum(event))
    {
        nlohmann::json value = nlohmann::json::object();
        value["checksum_validated"] = true;
        if (event.contains("checksum"))
            value["checksum"] = event.at("checksum");
        facts.push_back(make_fact(event, context, contract_fact_kind_t::protocol, subject, "checksum", value));
    }
    return facts;
}

std::vector<chain_fact_t> derive_firmware_facts(const nlohmann::json& event, const protocol_derivation_context_t& context)
{
    std::vector<chain_fact_t> facts;
    const std::string kind = event_kind(event);
    const bool firmware_kind = kind.find("firmware") != std::string::npos ||
                               kind.find("interrupt") != std::string::npos ||
                               kind.find("smi") != std::string::npos ||
                               kind.find("ioctl") != std::string::npos ||
                               event.contains("firmware_dispatch") ||
                               event.contains("interrupt_vector");
    if (!firmware_kind)
        return facts;
    const std::string subject = subject_for_event(event);
    if (subject.empty())
        return facts;
    nlohmann::json value = nlohmann::json::object();
    value["dispatch_proven"] = read_bool(event, "dispatch_proven", context.proof_state == contract_proof_state_t::proven);
    value["firmware_dispatch"] = read_string(event, "firmware_dispatch", read_string(event, "dispatch", kind));
    const std::string vector = read_string(event, "interrupt_vector", read_string(event, "vector"));
    if (!vector.empty())
        value["interrupt_vector"] = vector;
    facts.push_back(make_fact(event, context, contract_fact_kind_t::firmware, subject, "dispatch", value));
    return facts;
}

}
}
}
