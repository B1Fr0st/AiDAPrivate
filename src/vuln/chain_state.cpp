#include "chain_state.hpp"

#include <unordered_set>
#include <utility>

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

template <typename EnumT>
struct enum_name_t
{
    EnumT value;
    const char* name;
};

constexpr enum_name_t<alias_relation_kind_t> k_alias_names[] = {
    {alias_relation_kind_t::must_alias, "must_alias"},
    {alias_relation_kind_t::may_alias, "may_alias"},
    {alias_relation_kind_t::no_alias, "no_alias"},
    {alias_relation_kind_t::points_to, "points_to"},
    {alias_relation_kind_t::self_reference, "self_reference"},
    {alias_relation_kind_t::unresolved, "unresolved"},
};

constexpr enum_name_t<lifetime_event_kind_t> k_lifetime_names[] = {
    {lifetime_event_kind_t::allocated, "allocated"},
    {lifetime_event_kind_t::initialized, "initialized"},
    {lifetime_event_kind_t::published, "published"},
    {lifetime_event_kind_t::borrowed, "borrowed"},
    {lifetime_event_kind_t::freed, "freed"},
    {lifetime_event_kind_t::destructed, "destructed"},
    {lifetime_event_kind_t::reclaimed, "reclaimed"},
    {lifetime_event_kind_t::reused, "reused"},
    {lifetime_event_kind_t::dangling, "dangling"},
    {lifetime_event_kind_t::address_discovered, "address_discovered"},
};

constexpr enum_name_t<allocator_event_kind_t> k_allocator_names[] = {
    {allocator_event_kind_t::allocate, "allocate"},
    {allocator_event_kind_t::zero, "zero"},
    {allocator_event_kind_t::fill, "fill"},
    {allocator_event_kind_t::free, "free"},
    {allocator_event_kind_t::quarantine, "quarantine"},
    {allocator_event_kind_t::recycle, "recycle"},
    {allocator_event_kind_t::size_class_change, "size_class_change"},
    {allocator_event_kind_t::metadata_write, "metadata_write"},
    {allocator_event_kind_t::reuse_blocked, "reuse_blocked"},
};

constexpr enum_name_t<side_effect_kind_t> k_side_effect_names[] = {
    {side_effect_kind_t::read, "read"},
    {side_effect_kind_t::write, "write"},
    {side_effect_kind_t::call, "call"},
    {side_effect_kind_t::branch, "branch"},
    {side_effect_kind_t::lock, "lock"},
    {side_effect_kind_t::unlock, "unlock"},
    {side_effect_kind_t::refcount, "refcount"},
    {side_effect_kind_t::allocation, "allocation"},
    {side_effect_kind_t::free, "free"},
    {side_effect_kind_t::callback_register, "callback_register"},
    {side_effect_kind_t::callback_invoke, "callback_invoke"},
    {side_effect_kind_t::protocol_emit, "protocol_emit"},
    {side_effect_kind_t::firmware_io, "firmware_io"},
    {side_effect_kind_t::fastfail, "fastfail"},
    {side_effect_kind_t::bugcheck, "bugcheck"},
    {side_effect_kind_t::exception, "exception"},
    {side_effect_kind_t::external, "external"},
};

constexpr enum_name_t<side_effect_safety_t> k_side_effect_safety_names[] = {
    {side_effect_safety_t::expected, "expected"},
    {side_effect_safety_t::benign, "benign"},
    {side_effect_safety_t::collateral_survivable, "collateral_survivable"},
    {side_effect_safety_t::collateral_unproven, "collateral_unproven"},
    {side_effect_safety_t::fatal, "fatal"},
};

template <typename EnumT, std::size_t N>
const char* enum_to_string(EnumT value, const enum_name_t<EnumT> (&items)[N], const char* fallback)
{
    for (const auto& item : items)
    {
        if (item.value == value)
            return item.name;
    }
    return fallback;
}

template <typename EnumT, std::size_t N>
std::optional<EnumT> enum_from_string(const std::string& value, const enum_name_t<EnumT> (&items)[N])
{
    for (const auto& item : items)
    {
        if (value == item.name)
            return item.value;
    }
    return std::nullopt;
}

bool require_object(const nlohmann::json& value, validation_result_t& errors, const std::string& path)
{
    if (value.is_object())
        return true;
    errors.add("invalid_type", path, "expected object");
    return false;
}

bool read_string_field(const nlohmann::json& value,
                       const char* key,
                       std::string& out,
                       validation_result_t& errors,
                       const std::string& path,
                       bool required)
{
    auto it = value.find(key);
    if (it == value.end())
    {
        if (required)
            errors.add("missing_required_field", path + "/" + key, "field is required");
        return !required;
    }
    if (!it->is_string())
    {
        errors.add("invalid_type", path + "/" + key, "expected string");
        return false;
    }
    out = it->get<std::string>();
    if (required && out.empty())
    {
        errors.add("invalid_id", path + "/" + key, "string must not be empty");
        return false;
    }
    return true;
}

bool read_bool_field(const nlohmann::json& value,
                     const char* key,
                     bool& out,
                     validation_result_t& errors,
                     const std::string& path)
{
    auto it = value.find(key);
    if (it == value.end())
        return true;
    if (!it->is_boolean())
    {
        errors.add("invalid_type", path + "/" + key, "expected boolean");
        return false;
    }
    out = it->get<bool>();
    return true;
}

bool read_u64_field(const nlohmann::json& value,
                    const char* key,
                    std::uint64_t& out,
                    validation_result_t& errors,
                    const std::string& path)
{
    auto it = value.find(key);
    if (it == value.end())
        return true;
    if (!parse_u64_json(*it, out))
    {
        errors.add("invalid_integer", path + "/" + key, "expected unsigned integer or hex string");
        return false;
    }
    return true;
}

template <typename T>
bool read_enum_field(const nlohmann::json& value,
                     const char* key,
                     T& out,
                     std::optional<T> (*from_string_fn)(const std::string&),
                     validation_result_t& errors,
                     const std::string& path,
                     bool required)
{
    auto it = value.find(key);
    if (it == value.end())
    {
        if (required)
            errors.add("missing_required_field", path + "/" + key, "field is required");
        return !required;
    }
    if (!it->is_string())
    {
        errors.add("invalid_type", path + "/" + key, "expected string enum");
        return false;
    }
    const std::string text = it->get<std::string>();
    auto parsed = from_string_fn(text);
    if (!parsed)
    {
        errors.add("invalid_enum", path + "/" + key, "invalid enum value '" + text + "'");
        return false;
    }
    out = *parsed;
    return true;
}

template <typename T, typename Reader>
bool read_array(const nlohmann::json& value,
                const char* key,
                std::vector<T>& out,
                Reader reader,
                validation_result_t& errors,
                const std::string& path)
{
    auto it = value.find(key);
    if (it == value.end())
        return true;
    if (!it->is_array())
    {
        errors.add("invalid_type", path + "/" + key, "expected array");
        return false;
    }
    bool ok = true;
    out.clear();
    out.reserve(it->size());
    for (std::size_t i = 0; i < it->size(); ++i)
    {
        T item;
        if (!reader((*it)[i], item, errors, path + "/" + key + "/" + std::to_string(i)))
            ok = false;
        out.push_back(std::move(item));
    }
    return ok;
}

bool read_canonical_address_field(const nlohmann::json& value,
                                  const char* key,
                                  canonical_address_t& out,
                                  validation_result_t& errors,
                                  const std::string& path)
{
    auto it = value.find(key);
    if (it == value.end())
        return true;
    return from_json(*it, out, errors, path + "/" + key);
}

bool read_chain_value_field(const nlohmann::json& value,
                            const char* key,
                            chain_value_t& out,
                            validation_result_t& errors,
                            const std::string& path)
{
    auto it = value.find(key);
    if (it == value.end())
        return true;
    return from_json(*it, out, errors, path + "/" + key);
}

bool read_evidence_item(const nlohmann::json& value, evidence_ref_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_fact_item(const nlohmann::json& value, fact_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_assumption_item(const nlohmann::json& value, assumption_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_register_item(const nlohmann::json& value, register_state_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_memory_item(const nlohmann::json& value, memory_state_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_alias_item(const nlohmann::json& value, alias_relation_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_lifetime_item(const nlohmann::json& value, lifetime_event_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_allocator_item(const nlohmann::json& value, allocator_event_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_callback_item(const nlohmann::json& value, callback_event_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_side_effect_item(const nlohmann::json& value, side_effect_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_goal_item(const nlohmann::json& value, final_goal_state_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

template <typename T>
void push_json_array(nlohmann::json& j, const char* key, const std::vector<T>& values)
{
    j[key] = nlohmann::json::array();
    for (const auto& value : values)
        j[key].push_back(to_json(value));
}

bool critical_proof_blocks(proof_state_t state, fact_criticality_t criticality)
{
    const bool critical = criticality == fact_criticality_t::chain_critical
        || criticality == fact_criticality_t::objective_critical;
    return critical && state != proof_state_t::proven;
}

}

const char* to_string(alias_relation_kind_t value)
{
    return enum_to_string(value, k_alias_names, "unresolved");
}

const char* to_string(lifetime_event_kind_t value)
{
    return enum_to_string(value, k_lifetime_names, "allocated");
}

const char* to_string(allocator_event_kind_t value)
{
    return enum_to_string(value, k_allocator_names, "allocate");
}

const char* to_string(side_effect_kind_t value)
{
    return enum_to_string(value, k_side_effect_names, "external");
}

const char* to_string(side_effect_safety_t value)
{
    return enum_to_string(value, k_side_effect_safety_names, "collateral_unproven");
}

std::optional<alias_relation_kind_t> alias_relation_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_alias_names);
}

std::optional<lifetime_event_kind_t> lifetime_event_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_lifetime_names);
}

std::optional<allocator_event_kind_t> allocator_event_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_allocator_names);
}

std::optional<side_effect_kind_t> side_effect_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_side_effect_names);
}

std::optional<side_effect_safety_t> side_effect_safety_from_string(const std::string& value)
{
    return enum_from_string(value, k_side_effect_safety_names);
}

nlohmann::json to_json(const register_state_t& value)
{
    nlohmann::json j;
    j["name"] = value.name;
    j["value"] = to_json(value.value);
    j["abi_role"] = value.abi_role;
    j["volatile_register"] = value.volatile_register;
    push_json_array(j, "evidence", value.evidence);
    return j;
}

nlohmann::json to_json(const memory_state_t& value)
{
    nlohmann::json j;
    j["memory_id"] = value.memory_id;
    j["location"] = to_json(value.location);
    j["object_id"] = value.object_id;
    j["field_path"] = value.field_path;
    j["width_bytes"] = value.width_bytes;
    j["value"] = to_json(value.value);
    j["initialized"] = value.initialized;
    j["mapped"] = value.mapped;
    j["readable"] = value.readable;
    j["writable"] = value.writable;
    j["executable"] = value.executable;
    push_json_array(j, "evidence", value.evidence);
    return j;
}

nlohmann::json to_json(const alias_relation_t& value)
{
    nlohmann::json j;
    j["alias_id"] = value.alias_id;
    j["kind"] = to_string(value.kind);
    j["left"] = value.left;
    j["right"] = value.right;
    j["proof_state"] = to_string(value.proof_state);
    j["criticality"] = to_string(value.criticality);
    push_json_array(j, "evidence", value.evidence);
    return j;
}

nlohmann::json to_json(const lifetime_event_t& value)
{
    nlohmann::json j;
    j["event_id"] = value.event_id;
    j["kind"] = to_string(value.kind);
    j["object_id"] = value.object_id;
    j["phase"] = value.phase;
    j["sequence"] = value.sequence;
    j["location"] = to_json(value.location);
    j["proof_state"] = to_string(value.proof_state);
    push_json_array(j, "evidence", value.evidence);
    return j;
}

nlohmann::json to_json(const allocator_event_t& value)
{
    nlohmann::json j;
    j["event_id"] = value.event_id;
    j["kind"] = to_string(value.kind);
    j["allocator_id"] = value.allocator_id;
    j["object_id"] = value.object_id;
    j["size"] = value.size;
    j["size_class"] = value.size_class;
    j["sequence"] = value.sequence;
    j["proof_state"] = to_string(value.proof_state);
    push_json_array(j, "evidence", value.evidence);
    j["metadata"] = value.metadata;
    return j;
}

nlohmann::json to_json(const callback_event_t& value)
{
    nlohmann::json j;
    j["callback_id"] = value.callback_id;
    j["kind"] = to_string(value.kind);
    j["owner_object_id"] = value.owner_object_id;
    j["target_corpus_id"] = value.target_corpus_id;
    j["registration_site"] = to_json(value.registration_site);
    j["invocation_site"] = to_json(value.invocation_site);
    j["target"] = to_json(value.target);
    j["registration_state"] = to_string(value.registration_state);
    j["invocation_state"] = to_string(value.invocation_state);
    push_json_array(j, "evidence", value.evidence);
    return j;
}

nlohmann::json to_json(const side_effect_t& value)
{
    nlohmann::json j;
    j["side_effect_id"] = value.side_effect_id;
    j["kind"] = to_string(value.kind);
    j["safety"] = to_string(value.safety);
    j["phase"] = value.phase;
    j["location"] = to_json(value.location);
    j["subject"] = value.subject;
    j["value"] = to_json(value.value);
    j["proof_state"] = to_string(value.proof_state);
    j["criticality"] = to_string(value.criticality);
    push_json_array(j, "evidence", value.evidence);
    return j;
}

nlohmann::json to_json(const final_goal_state_t& value)
{
    return nlohmann::json{
        {"objective_id", value.objective_id},
        {"kind", to_string(value.kind)},
        {"proof_state", to_string(value.proof_state)},
        {"required_fact_ids", value.required_fact_ids},
        {"proven_fact_ids", value.proven_fact_ids},
        {"contradiction_fact_ids", value.contradiction_fact_ids},
        {"metadata", value.metadata},
    };
}

nlohmann::json to_json(const trace_state_t& value)
{
    nlohmann::json j;
    j["pc"] = to_json(value.pc);
    push_json_array(j, "call_stack", value.call_stack);
    push_json_array(j, "registers", value.registers);
    push_json_array(j, "memory", value.memory);
    push_json_array(j, "aliases", value.aliases);
    push_json_array(j, "lifetimes", value.lifetimes);
    push_json_array(j, "allocator_events", value.allocator_events);
    push_json_array(j, "callbacks", value.callbacks);
    push_json_array(j, "side_effects", value.side_effects);
    push_json_array(j, "facts", value.facts);
    push_json_array(j, "assumptions", value.assumptions);
    push_json_array(j, "final_goals", value.final_goals);
    j["constraints"] = value.constraints;
    j["metadata"] = value.metadata;
    return j;
}

bool from_json(const nlohmann::json& value, register_state_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    bool ok = true;
    ok = read_string_field(value, "name", out.name, errors, path, true) && ok;
    ok = read_chain_value_field(value, "value", out.value, errors, path) && ok;
    ok = read_string_field(value, "abi_role", out.abi_role, errors, path, false) && ok;
    ok = read_bool_field(value, "volatile_register", out.volatile_register, errors, path) && ok;
    ok = read_array(value, "evidence", out.evidence, read_evidence_item, errors, path) && ok;
    return ok;
}

bool from_json(const nlohmann::json& value, memory_state_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    bool ok = true;
    ok = read_string_field(value, "memory_id", out.memory_id, errors, path, false) && ok;
    ok = read_canonical_address_field(value, "location", out.location, errors, path) && ok;
    ok = read_string_field(value, "object_id", out.object_id, errors, path, false) && ok;
    ok = read_string_field(value, "field_path", out.field_path, errors, path, false) && ok;
    ok = read_u64_field(value, "width_bytes", out.width_bytes, errors, path) && ok;
    ok = read_chain_value_field(value, "value", out.value, errors, path) && ok;
    ok = read_bool_field(value, "initialized", out.initialized, errors, path) && ok;
    ok = read_bool_field(value, "mapped", out.mapped, errors, path) && ok;
    ok = read_bool_field(value, "readable", out.readable, errors, path) && ok;
    ok = read_bool_field(value, "writable", out.writable, errors, path) && ok;
    ok = read_bool_field(value, "executable", out.executable, errors, path) && ok;
    ok = read_array(value, "evidence", out.evidence, read_evidence_item, errors, path) && ok;
    if (out.memory_id.empty())
        out.memory_id = stable_id("memory", to_json(out));
    return ok;
}

bool from_json(const nlohmann::json& value, alias_relation_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    bool ok = true;
    ok = read_string_field(value, "alias_id", out.alias_id, errors, path, false) && ok;
    ok = read_enum_field(value, "kind", out.kind, alias_relation_kind_from_string, errors, path, false) && ok;
    auto left = value.find("left");
    if (left != value.end())
        out.left = *left;
    auto right = value.find("right");
    if (right != value.end())
        out.right = *right;
    ok = read_enum_field(value, "proof_state", out.proof_state, proof_state_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "criticality", out.criticality, fact_criticality_from_string, errors, path, false) && ok;
    ok = read_array(value, "evidence", out.evidence, read_evidence_item, errors, path) && ok;
    if (out.alias_id.empty())
        out.alias_id = stable_id("alias", to_json(out));
    return ok;
}

bool from_json(const nlohmann::json& value, lifetime_event_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    bool ok = true;
    ok = read_string_field(value, "event_id", out.event_id, errors, path, false) && ok;
    ok = read_enum_field(value, "kind", out.kind, lifetime_event_kind_from_string, errors, path, false) && ok;
    ok = read_string_field(value, "object_id", out.object_id, errors, path, true) && ok;
    ok = read_string_field(value, "phase", out.phase, errors, path, false) && ok;
    ok = read_u64_field(value, "sequence", out.sequence, errors, path) && ok;
    ok = read_canonical_address_field(value, "location", out.location, errors, path) && ok;
    ok = read_enum_field(value, "proof_state", out.proof_state, proof_state_from_string, errors, path, false) && ok;
    ok = read_array(value, "evidence", out.evidence, read_evidence_item, errors, path) && ok;
    if (out.event_id.empty())
        out.event_id = stable_id("lifetime", to_json(out));
    return ok;
}

bool from_json(const nlohmann::json& value, allocator_event_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    bool ok = true;
    ok = read_string_field(value, "event_id", out.event_id, errors, path, false) && ok;
    ok = read_enum_field(value, "kind", out.kind, allocator_event_kind_from_string, errors, path, false) && ok;
    ok = read_string_field(value, "allocator_id", out.allocator_id, errors, path, false) && ok;
    ok = read_string_field(value, "object_id", out.object_id, errors, path, false) && ok;
    ok = read_u64_field(value, "size", out.size, errors, path) && ok;
    ok = read_string_field(value, "size_class", out.size_class, errors, path, false) && ok;
    ok = read_u64_field(value, "sequence", out.sequence, errors, path) && ok;
    ok = read_enum_field(value, "proof_state", out.proof_state, proof_state_from_string, errors, path, false) && ok;
    ok = read_array(value, "evidence", out.evidence, read_evidence_item, errors, path) && ok;
    auto meta = value.find("metadata");
    if (meta != value.end())
        out.metadata = *meta;
    if (out.event_id.empty())
        out.event_id = stable_id("allocator_event", to_json(out));
    return ok;
}

bool from_json(const nlohmann::json& value, callback_event_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    bool ok = true;
    ok = read_string_field(value, "callback_id", out.callback_id, errors, path, false) && ok;
    ok = read_enum_field(value, "kind", out.kind, trigger_kind_from_string, errors, path, false) && ok;
    ok = read_string_field(value, "owner_object_id", out.owner_object_id, errors, path, false) && ok;
    ok = read_string_field(value, "target_corpus_id", out.target_corpus_id, errors, path, false) && ok;
    ok = read_canonical_address_field(value, "registration_site", out.registration_site, errors, path) && ok;
    ok = read_canonical_address_field(value, "invocation_site", out.invocation_site, errors, path) && ok;
    ok = read_chain_value_field(value, "target", out.target, errors, path) && ok;
    ok = read_enum_field(value, "registration_state", out.registration_state, proof_state_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "invocation_state", out.invocation_state, proof_state_from_string, errors, path, false) && ok;
    ok = read_array(value, "evidence", out.evidence, read_evidence_item, errors, path) && ok;
    if (out.callback_id.empty())
        out.callback_id = stable_id("callback", to_json(out));
    return ok;
}

bool from_json(const nlohmann::json& value, side_effect_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    bool ok = true;
    ok = read_string_field(value, "side_effect_id", out.side_effect_id, errors, path, false) && ok;
    ok = read_enum_field(value, "kind", out.kind, side_effect_kind_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "safety", out.safety, side_effect_safety_from_string, errors, path, false) && ok;
    ok = read_string_field(value, "phase", out.phase, errors, path, false) && ok;
    ok = read_canonical_address_field(value, "location", out.location, errors, path) && ok;
    auto subject = value.find("subject");
    if (subject != value.end())
        out.subject = *subject;
    ok = read_chain_value_field(value, "value", out.value, errors, path) && ok;
    ok = read_enum_field(value, "proof_state", out.proof_state, proof_state_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "criticality", out.criticality, fact_criticality_from_string, errors, path, false) && ok;
    ok = read_array(value, "evidence", out.evidence, read_evidence_item, errors, path) && ok;
    if (out.side_effect_id.empty())
        out.side_effect_id = stable_id("side_effect", to_json(out));
    return ok;
}

bool from_json(const nlohmann::json& value, final_goal_state_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    bool ok = true;
    ok = read_string_field(value, "objective_id", out.objective_id, errors, path, true) && ok;
    ok = read_enum_field(value, "kind", out.kind, objective_kind_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "proof_state", out.proof_state, proof_state_from_string, errors, path, false) && ok;
    auto read_ids = [&](const char* key, std::vector<std::string>& dest) {
        auto it = value.find(key);
        if (it == value.end())
            return true;
        if (!it->is_array())
        {
            errors.add("invalid_type", path + "/" + key, "expected string array");
            return false;
        }
        bool local_ok = true;
        dest.clear();
        for (std::size_t i = 0; i < it->size(); ++i)
        {
            if (!(*it)[i].is_string())
            {
                errors.add("invalid_type", path + "/" + key + "/" + std::to_string(i), "expected string");
                local_ok = false;
            }
            else
            {
                dest.push_back((*it)[i].get<std::string>());
            }
        }
        return local_ok;
    };
    ok = read_ids("required_fact_ids", out.required_fact_ids) && ok;
    ok = read_ids("proven_fact_ids", out.proven_fact_ids) && ok;
    ok = read_ids("contradiction_fact_ids", out.contradiction_fact_ids) && ok;
    auto meta = value.find("metadata");
    if (meta != value.end())
        out.metadata = *meta;
    return ok;
}

bool from_json(const nlohmann::json& value, trace_state_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    bool ok = true;
    ok = read_canonical_address_field(value, "pc", out.pc, errors, path) && ok;
    ok = read_array(value, "call_stack", out.call_stack, [](const nlohmann::json& v, canonical_address_t& a, validation_result_t& e, const std::string& p) { return from_json(v, a, e, p); }, errors, path) && ok;
    ok = read_array(value, "registers", out.registers, read_register_item, errors, path) && ok;
    ok = read_array(value, "memory", out.memory, read_memory_item, errors, path) && ok;
    ok = read_array(value, "aliases", out.aliases, read_alias_item, errors, path) && ok;
    ok = read_array(value, "lifetimes", out.lifetimes, read_lifetime_item, errors, path) && ok;
    ok = read_array(value, "allocator_events", out.allocator_events, read_allocator_item, errors, path) && ok;
    ok = read_array(value, "callbacks", out.callbacks, read_callback_item, errors, path) && ok;
    ok = read_array(value, "side_effects", out.side_effects, read_side_effect_item, errors, path) && ok;
    ok = read_array(value, "facts", out.facts, read_fact_item, errors, path) && ok;
    ok = read_array(value, "assumptions", out.assumptions, read_assumption_item, errors, path) && ok;
    ok = read_array(value, "final_goals", out.final_goals, read_goal_item, errors, path) && ok;
    auto constraints = value.find("constraints");
    if (constraints != value.end())
    {
        if (!constraints->is_array())
        {
            errors.add("invalid_type", path + "/constraints", "expected array");
            ok = false;
        }
        else
        {
            out.constraints = *constraints;
        }
    }
    auto meta = value.find("metadata");
    if (meta != value.end())
        out.metadata = *meta;
    return ok;
}

void add_fact(trace_state_t& state, fact_t fact)
{
    assign_fact_id_if_missing(fact);
    state.facts.push_back(std::move(fact));
}

std::vector<fact_t> critical_fact_blockers(const trace_state_t& state)
{
    std::vector<fact_t> out;
    for (const auto& f : state.facts)
    {
        if (critical_fact_blocks_confirmation(f))
            out.push_back(f);
    }
    for (const auto& a : state.aliases)
    {
        if (critical_proof_blocks(a.proof_state, a.criticality))
        {
            fact_t f;
            f.fact_id = a.alias_id;
            f.kind = fact_kind_t::alias_fact;
            f.subject = nlohmann::json{{"left", a.left}, {"right", a.right}};
            f.predicate = to_string(a.kind);
            f.proof_state = a.proof_state;
            f.criticality = a.criticality;
            f.evidence = a.evidence;
            out.push_back(std::move(f));
        }
    }
    for (const auto& se : state.side_effects)
    {
        if (critical_proof_blocks(se.proof_state, se.criticality) || se.safety == side_effect_safety_t::fatal)
        {
            fact_t f;
            f.fact_id = se.side_effect_id;
            f.kind = fact_kind_t::side_effect_fact;
            f.subject = se.subject;
            f.predicate = to_string(se.kind);
            f.value = se.value;
            f.proof_state = se.safety == side_effect_safety_t::fatal ? proof_state_t::refuted : se.proof_state;
            f.criticality = se.criticality;
            f.evidence = se.evidence;
            out.push_back(std::move(f));
        }
    }
    for (const auto& goal : state.final_goals)
    {
        if (goal.proof_state != proof_state_t::proven)
        {
            fact_t f;
            f.fact_id = goal.objective_id;
            f.kind = fact_kind_t::objective_fact;
            f.subject = nlohmann::json{{"objective_id", goal.objective_id}};
            f.predicate = to_string(goal.kind);
            f.proof_state = goal.proof_state;
            f.criticality = fact_criticality_t::objective_critical;
            out.push_back(std::move(f));
        }
    }
    return out;
}

std::vector<assumption_t> critical_assumption_blockers(const trace_state_t& state)
{
    std::vector<assumption_t> out;
    for (const auto& a : state.assumptions)
    {
        if (assumption_blocks_confirmation(a))
            out.push_back(a);
    }
    return out;
}

std::vector<side_effect_t> fatal_or_unproven_side_effects(const trace_state_t& state)
{
    std::vector<side_effect_t> out;
    for (const auto& se : state.side_effects)
    {
        if (se.safety == side_effect_safety_t::fatal
            || se.safety == side_effect_safety_t::collateral_unproven
            || se.proof_state == proof_state_t::unknown
            || se.proof_state == proof_state_t::unsupported
            || se.proof_state == proof_state_t::timeout)
        {
            out.push_back(se);
        }
    }
    return out;
}

bool trace_state_can_confirm(const trace_state_t& state)
{
    return critical_fact_blockers(state).empty()
        && critical_assumption_blockers(state).empty()
        && fatal_or_unproven_side_effects(state).empty();
}

validation_result_t validate_trace_state(const trace_state_t& state)
{
    validation_result_t result;
    std::unordered_set<std::string> fact_ids;
    for (std::size_t i = 0; i < state.facts.size(); ++i)
    {
        const auto& f = state.facts[i];
        const std::string path = "/facts/" + std::to_string(i);
        if (f.fact_id.empty())
            result.add("missing_required_field", path + "/fact_id", "fact id is required");
        else if (!fact_ids.insert(f.fact_id).second)
            result.add("duplicate_id", path + "/fact_id", "duplicate fact id");
        if (critical_fact_blocks_confirmation(f))
            result.add("critical_fact_unproven", path + "/proof_state", "critical fact is not proven");
    }
    for (std::size_t i = 0; i < state.assumptions.size(); ++i)
    {
        if (assumption_blocks_confirmation(state.assumptions[i]))
            result.add("critical_assumption_unproven", "/assumptions/" + std::to_string(i) + "/proof_state", "critical assumption is not proven");
    }
    for (std::size_t i = 0; i < state.side_effects.size(); ++i)
    {
        const auto& se = state.side_effects[i];
        if (se.safety == side_effect_safety_t::fatal)
            result.add("fatal_side_effect", "/side_effects/" + std::to_string(i) + "/safety", "fatal side effect blocks confirmation");
        else if (se.safety == side_effect_safety_t::collateral_unproven)
            result.add("collateral_damage_unproven", "/side_effects/" + std::to_string(i) + "/safety", "collateral safety is unproven");
    }
    for (std::size_t i = 0; i < state.final_goals.size(); ++i)
    {
        if (state.final_goals[i].proof_state != proof_state_t::proven)
            result.add("objective_not_achieved", "/final_goals/" + std::to_string(i) + "/proof_state", "final goal is not proven");
    }
    return result;
}

validation_result_t chain_state_self_check()
{
    trace_state_t state;
    fact_t unknown;
    unknown.kind = fact_kind_t::content_fact;
    unknown.subject = nlohmann::json{{"object", "input"}};
    unknown.predicate = "controlled";
    unknown.value.kind = value_kind_t::unknown;
    unknown.proof_state = proof_state_t::unknown;
    unknown.criticality = fact_criticality_t::chain_critical;
    add_fact(state, unknown);
    validation_result_t result = validate_trace_state(state);
    if (result.ok())
        result.add("self_check_failed", "/facts/0/proof_state", "unknown critical fact did not block confirmation");
    state.facts[0].proof_state = proof_state_t::proven;
    state.facts[0].value.kind = value_kind_t::bytes;
    state.facts[0].value.bytes = {0x41, 0x42};
    state.final_goals.push_back(final_goal_state_t{"goal_self_check", objective_kind_t::memory_write, proof_state_t::proven, {state.facts[0].fact_id}, {state.facts[0].fact_id}, {}, nlohmann::json::object()});
    if (!trace_state_can_confirm(state))
        result.add("self_check_failed", "/final_goals/0", "proven critical state did not confirm");
    return result;
}

}
}
}
