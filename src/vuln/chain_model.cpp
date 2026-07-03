#include "chain_model.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <limits>
#include <sstream>
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

constexpr enum_name_t<validation_severity_t> k_validation_severity_names[] = {
    {validation_severity_t::error, "error"},
    {validation_severity_t::warning, "warning"},
};

constexpr enum_name_t<proof_state_t> k_proof_state_names[] = {
    {proof_state_t::proven, "proven"},
    {proof_state_t::refuted, "refuted"},
    {proof_state_t::conditional, "conditional"},
    {proof_state_t::unknown, "unknown"},
    {proof_state_t::unsupported, "unsupported"},
    {proof_state_t::timeout, "timeout"},
};

constexpr enum_name_t<fact_criticality_t> k_fact_criticality_names[] = {
    {fact_criticality_t::chain_critical, "chain_critical"},
    {fact_criticality_t::objective_critical, "objective_critical"},
    {fact_criticality_t::collateral, "collateral"},
    {fact_criticality_t::diagnostic, "diagnostic"},
};

constexpr enum_name_t<fact_kind_t> k_fact_kind_names[] = {
    {fact_kind_t::value_fact, "value_fact"},
    {fact_kind_t::content_fact, "content_fact"},
    {fact_kind_t::address_fact, "address_fact"},
    {fact_kind_t::register_fact, "register_fact"},
    {fact_kind_t::stack_fact, "stack_fact"},
    {fact_kind_t::memory_fact, "memory_fact"},
    {fact_kind_t::alias_fact, "alias_fact"},
    {fact_kind_t::lifetime_fact, "lifetime_fact"},
    {fact_kind_t::allocator_fact, "allocator_fact"},
    {fact_kind_t::callback_fact, "callback_fact"},
    {fact_kind_t::trigger_fact, "trigger_fact"},
    {fact_kind_t::protocol_fact, "protocol_fact"},
    {fact_kind_t::firmware_fact, "firmware_fact"},
    {fact_kind_t::side_effect_fact, "side_effect_fact"},
    {fact_kind_t::objective_fact, "objective_fact"},
    {fact_kind_t::assumption_fact, "assumption_fact"},
    {fact_kind_t::boundary_fact, "boundary_fact"},
};

constexpr enum_name_t<value_kind_t> k_value_kind_names[] = {
    {value_kind_t::unknown, "unknown"},
    {value_kind_t::concrete, "concrete"},
    {value_kind_t::symbolic, "symbolic"},
    {value_kind_t::range, "range"},
    {value_kind_t::bytes, "bytes"},
    {value_kind_t::zero_bytes, "zero_bytes"},
    {value_kind_t::constant_bytes, "constant_bytes"},
    {value_kind_t::copied_bytes, "copied_bytes"},
    {value_kind_t::transformed_bytes, "transformed_bytes"},
    {value_kind_t::checksum_constrained, "checksum_constrained"},
    {value_kind_t::encrypted_unknown, "encrypted_unknown"},
    {value_kind_t::compressed_unknown, "compressed_unknown"},
    {value_kind_t::module_rva, "module_rva"},
    {value_kind_t::object_pointer, "object_pointer"},
    {value_kind_t::self_reference, "self_reference"},
    {value_kind_t::poisoned, "poisoned"},
};

constexpr enum_name_t<provenance_kind_t> k_provenance_kind_names[] = {
    {provenance_kind_t::user_input, "user_input"},
    {provenance_kind_t::file_input, "file_input"},
    {provenance_kind_t::network_input, "network_input"},
    {provenance_kind_t::protocol_field, "protocol_field"},
    {provenance_kind_t::copy, "copy"},
    {provenance_kind_t::decode, "decode"},
    {provenance_kind_t::transform, "transform"},
    {provenance_kind_t::decompression, "decompression"},
    {provenance_kind_t::decryption, "decryption"},
    {provenance_kind_t::checksum, "checksum"},
    {provenance_kind_t::allocator_zero, "allocator_zero"},
    {provenance_kind_t::memset_zero, "memset_zero"},
    {provenance_kind_t::constant, "constant"},
    {provenance_kind_t::dynamic_trace, "dynamic_trace"},
    {provenance_kind_t::user_declared, "user_declared"},
    {provenance_kind_t::unknown, "unknown"},
};

constexpr enum_name_t<link_role_t> k_link_role_names[] = {
    {link_role_t::generic_transition, "generic_transition"},
    {link_role_t::parser, "parser"},
    {link_role_t::allocator, "allocator"},
    {link_role_t::lifetime, "lifetime"},
    {link_role_t::callback_registration, "callback_registration"},
    {link_role_t::trigger_dispatch, "trigger_dispatch"},
    {link_role_t::memory_write, "memory_write"},
    {link_role_t::memory_read, "memory_read"},
    {link_role_t::branch_gate, "branch_gate"},
    {link_role_t::indirect_call, "indirect_call"},
    {link_role_t::protocol_transition, "protocol_transition"},
    {link_role_t::firmware_dispatch, "firmware_dispatch"},
    {link_role_t::final_objective, "final_objective"},
};

constexpr enum_name_t<objective_kind_t> k_objective_kind_names[] = {
    {objective_kind_t::memory_write, "memory_write"},
    {objective_kind_t::memory_read, "memory_read"},
    {objective_kind_t::control_flow, "control_flow"},
    {objective_kind_t::callback_invocation, "callback_invocation"},
    {objective_kind_t::privilege_transition, "privilege_transition"},
    {objective_kind_t::protocol_state, "protocol_state"},
    {objective_kind_t::firmware_state, "firmware_state"},
    {objective_kind_t::data_exfiltration, "data_exfiltration"},
    {objective_kind_t::denial_of_service, "denial_of_service"},
    {objective_kind_t::custom, "custom"},
};

constexpr enum_name_t<trigger_kind_t> k_trigger_kind_names[] = {
    {trigger_kind_t::api_call, "api_call"},
    {trigger_kind_t::syscall, "syscall"},
    {trigger_kind_t::ioctl, "ioctl"},
    {trigger_kind_t::interrupt, "interrupt"},
    {trigger_kind_t::timer, "timer"},
    {trigger_kind_t::message_queue, "message_queue"},
    {trigger_kind_t::gui_callback, "gui_callback"},
    {trigger_kind_t::signal_handler, "signal_handler"},
    {trigger_kind_t::rpc_dispatch, "rpc_dispatch"},
    {trigger_kind_t::protocol_transition, "protocol_transition"},
    {trigger_kind_t::firmware_hook, "firmware_hook"},
    {trigger_kind_t::destructor, "destructor"},
    {trigger_kind_t::finalizer, "finalizer"},
    {trigger_kind_t::callback, "callback"},
    {trigger_kind_t::state_machine, "state_machine"},
    {trigger_kind_t::custom, "custom"},
};

constexpr enum_name_t<budget_phase_t> k_budget_phase_names[] = {
    {budget_phase_t::schema, "schema"},
    {budget_phase_t::extraction, "extraction"},
    {budget_phase_t::path, "path"},
    {budget_phase_t::state, "state"},
    {budget_phase_t::solver, "solver"},
    {budget_phase_t::report, "report"},
    {budget_phase_t::total, "total"},
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

bool read_u32_field(const nlohmann::json& value,
                    const char* key,
                    std::uint32_t& out,
                    validation_result_t& errors,
                    const std::string& path)
{
    auto tmp = static_cast<std::uint64_t>(out);
    if (!read_u64_field(value, key, tmp, errors, path))
        return false;
    if (tmp > std::numeric_limits<std::uint32_t>::max())
    {
        errors.add("integer_out_of_range", path + "/" + key, "value exceeds uint32");
        return false;
    }
    out = static_cast<std::uint32_t>(tmp);
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

bool no_unknown_fields(const nlohmann::json& value,
                       const std::unordered_set<std::string>& allowed,
                       validation_result_t& errors,
                       const std::string& path)
{
    bool ok = true;
    for (auto it = value.begin(); it != value.end(); ++it)
    {
        if (allowed.find(it.key()) == allowed.end())
        {
            errors.add("unknown_field", path + "/" + it.key(), "unknown field");
            ok = false;
        }
    }
    return ok;
}

template <typename T>
bool read_array(const nlohmann::json& value,
                const char* key,
                std::vector<T>& out,
                bool (*reader)(const nlohmann::json&, T&, validation_result_t&, const std::string&),
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
        const std::string item_path = path + "/" + key + "/" + std::to_string(i);
        if (!reader((*it)[i], item, errors, item_path))
            ok = false;
        out.push_back(std::move(item));
    }
    return ok;
}

bool read_fact_array_item(const nlohmann::json& value, fact_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_assumption_array_item(const nlohmann::json& value, assumption_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_budget_array_item(const nlohmann::json& value, chain_budget_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_evidence_array_item(const nlohmann::json& value, evidence_ref_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_provenance_array_item(const nlohmann::json& value, data_provenance_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

std::uint64_t fnv1a64(const std::string& input, std::uint64_t seed)
{
    std::uint64_t h = seed;
    for (unsigned char c : input)
    {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

std::string hex_bytes(const std::vector<std::uint8_t>& bytes)
{
    static const char k_hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes)
    {
        out.push_back(k_hex[b >> 4]);
        out.push_back(k_hex[b & 0x0F]);
    }
    return out;
}

std::vector<std::uint8_t> bytes_from_hex(const std::string& text)
{
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    if ((text.size() % 2) != 0)
        return out;
    out.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2)
    {
        int hi = nibble(text[i]);
        int lo = nibble(text[i + 1]);
        if (hi < 0 || lo < 0)
        {
            out.clear();
            return out;
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

}

bool validation_result_t::ok() const
{
    for (const auto& e : errors)
    {
        if (e.severity == validation_severity_t::error)
            return false;
    }
    return true;
}

bool validation_result_t::has_blocker() const
{
    for (const auto& e : errors)
    {
        if (e.acceptance_blocker)
            return true;
    }
    return false;
}

void validation_result_t::add(std::string code,
                              std::string path,
                              std::string message,
                              validation_severity_t severity,
                              bool acceptance_blocker)
{
    validation_error_t e;
    e.code = std::move(code);
    e.path = std::move(path);
    e.message = std::move(message);
    e.severity = severity;
    e.acceptance_blocker = acceptance_blocker;
    errors.push_back(std::move(e));
}

const char* to_string(validation_severity_t value)
{
    return enum_to_string(value, k_validation_severity_names, "error");
}

const char* to_string(proof_state_t value)
{
    return enum_to_string(value, k_proof_state_names, "unknown");
}

const char* to_string(fact_criticality_t value)
{
    return enum_to_string(value, k_fact_criticality_names, "diagnostic");
}

const char* to_string(fact_kind_t value)
{
    return enum_to_string(value, k_fact_kind_names, "value_fact");
}

const char* to_string(value_kind_t value)
{
    return enum_to_string(value, k_value_kind_names, "unknown");
}

const char* to_string(provenance_kind_t value)
{
    return enum_to_string(value, k_provenance_kind_names, "unknown");
}

const char* to_string(link_role_t value)
{
    return enum_to_string(value, k_link_role_names, "generic_transition");
}

const char* to_string(objective_kind_t value)
{
    return enum_to_string(value, k_objective_kind_names, "custom");
}

const char* to_string(trigger_kind_t value)
{
    return enum_to_string(value, k_trigger_kind_names, "custom");
}

const char* to_string(budget_phase_t value)
{
    return enum_to_string(value, k_budget_phase_names, "total");
}

std::optional<proof_state_t> proof_state_from_string(const std::string& value)
{
    return enum_from_string(value, k_proof_state_names);
}

std::optional<fact_criticality_t> fact_criticality_from_string(const std::string& value)
{
    return enum_from_string(value, k_fact_criticality_names);
}

std::optional<fact_kind_t> fact_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_fact_kind_names);
}

std::optional<value_kind_t> value_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_value_kind_names);
}

std::optional<provenance_kind_t> provenance_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_provenance_kind_names);
}

std::optional<link_role_t> link_role_from_string(const std::string& value)
{
    return enum_from_string(value, k_link_role_names);
}

std::optional<objective_kind_t> objective_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_objective_kind_names);
}

std::optional<trigger_kind_t> trigger_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_trigger_kind_names);
}

std::optional<budget_phase_t> budget_phase_from_string(const std::string& value)
{
    return enum_from_string(value, k_budget_phase_names);
}

nlohmann::json to_json(const validation_error_t& value)
{
    return nlohmann::json{
        {"code", value.code},
        {"path", value.path},
        {"message", value.message},
        {"severity", to_string(value.severity)},
        {"acceptance_blocker", value.acceptance_blocker},
    };
}

nlohmann::json to_json(const validation_result_t& value)
{
    nlohmann::json errors = nlohmann::json::array();
    for (const auto& e : value.errors)
        errors.push_back(to_json(e));
    return nlohmann::json{{"ok", value.ok()}, {"errors", std::move(errors)}};
}

nlohmann::json to_json(const chain_budget_t& value)
{
    return nlohmann::json{
        {"phase", to_string(value.phase)},
        {"timeout_ms", value.timeout_ms},
        {"max_items", value.max_items},
        {"max_bytes", value.max_bytes},
    };
}

nlohmann::json to_json(const evidence_ref_t& value)
{
    nlohmann::json j;
    j["evidence_id"] = value.evidence_id;
    j["corpus_id"] = value.corpus_id;
    j["function_id"] = value.function_id;
    j["ea"] = value.ea;
    j["rva"] = value.rva;
    j["layer"] = value.layer;
    j["lineage"] = value.lineage;
    j["snippet"] = value.snippet;
    j["snapshot_id"] = value.snapshot_id;
    return j;
}

nlohmann::json to_json(const data_provenance_t& value)
{
    nlohmann::json j;
    j["kind"] = to_string(value.kind);
    j["source_id"] = value.source_id;
    j["producer_operation"] = value.producer_operation;
    j["transform"] = value.transform;
    j["encoding"] = value.encoding;
    j["endianness"] = value.endianness;
    j["control_degree"] = value.control_degree;
    j["checksum_validated"] = value.checksum_validated;
    j["decompressed"] = value.decompressed;
    j["decrypted"] = value.decrypted;
    j["metadata"] = value.metadata;
    return j;
}

nlohmann::json to_json(const chain_value_t& value)
{
    nlohmann::json j;
    j["kind"] = to_string(value.kind);
    j["width_bits"] = value.width_bits;
    if (value.kind == value_kind_t::concrete)
        j["concrete"] = hex_u64(value.concrete);
    else
        j["concrete"] = value.concrete;
    j["min_value"] = value.min_value;
    j["max_value"] = value.max_value;
    j["text"] = value.text;
    j["corpus_id"] = value.corpus_id;
    j["rva"] = value.rva;
    j["object_id"] = value.object_id;
    j["field_path"] = value.field_path;
    j["bytes_hex"] = hex_bytes(value.bytes);
    j["provenance"] = nlohmann::json::array();
    for (const auto& p : value.provenance)
        j["provenance"].push_back(to_json(p));
    j["attributes"] = value.attributes;
    return j;
}

nlohmann::json to_json(const fact_t& value)
{
    nlohmann::json j;
    j["fact_id"] = value.fact_id;
    j["kind"] = to_string(value.kind);
    j["subject"] = value.subject;
    j["predicate"] = value.predicate;
    j["value"] = to_json(value.value);
    j["phase"] = value.phase;
    j["producer"] = value.producer;
    j["evidence"] = nlohmann::json::array();
    for (const auto& e : value.evidence)
        j["evidence"].push_back(to_json(e));
    j["proof_state"] = to_string(value.proof_state);
    j["criticality"] = to_string(value.criticality);
    j["metadata"] = value.metadata;
    return j;
}

nlohmann::json to_json(const assumption_t& value)
{
    return nlohmann::json{
        {"assumption_id", value.assumption_id},
        {"text", value.text},
        {"required_fact_ids", value.required_fact_ids},
        {"criticality", to_string(value.criticality)},
        {"proof_state", to_string(value.proof_state)},
        {"metadata", value.metadata},
    };
}

nlohmann::json to_json(const trigger_spec_t& value)
{
    nlohmann::json j;
    j["trigger_id"] = value.trigger_id;
    j["kind"] = to_string(value.kind);
    j["source"] = value.source;
    j["must_reach"] = value.must_reach;
    j["preconditions"] = nlohmann::json::array();
    for (const auto& f : value.preconditions)
        j["preconditions"].push_back(to_json(f));
    j["postconditions"] = nlohmann::json::array();
    for (const auto& f : value.postconditions)
        j["postconditions"].push_back(to_json(f));
    j["dispatch"] = value.dispatch;
    j["metadata"] = value.metadata;
    return j;
}

nlohmann::json to_json(const link_spec_t& value)
{
    nlohmann::json j;
    j["link_id"] = value.link_id;
    j["role"] = to_string(value.role);
    j["corpus_id"] = value.corpus_id;
    j["description"] = value.description;
    j["entry"] = value.entry;
    j["trigger"] = to_json(value.trigger);
    j["preconditions"] = nlohmann::json::array();
    for (const auto& f : value.preconditions)
        j["preconditions"].push_back(to_json(f));
    j["postconditions"] = nlohmann::json::array();
    for (const auto& f : value.postconditions)
        j["postconditions"].push_back(to_json(f));
    j["facts"] = nlohmann::json::array();
    for (const auto& f : value.facts)
        j["facts"].push_back(to_json(f));
    j["assumptions"] = nlohmann::json::array();
    for (const auto& a : value.assumptions)
        j["assumptions"].push_back(to_json(a));
    j["budgets"] = nlohmann::json::array();
    for (const auto& b : value.budgets)
        j["budgets"].push_back(to_json(b));
    j["policy"] = value.policy;
    j["metadata"] = value.metadata;
    return j;
}

nlohmann::json to_json(const objective_spec_t& value)
{
    nlohmann::json j;
    j["objective_id"] = value.objective_id;
    j["kind"] = to_string(value.kind);
    j["description"] = value.description;
    j["required_fact_ids"] = value.required_fact_ids;
    j["required_facts"] = nlohmann::json::array();
    for (const auto& f : value.required_facts)
        j["required_facts"].push_back(to_json(f));
    j["goal"] = to_json(value.goal);
    j["operation_sequence"] = value.operation_sequence;
    j["metadata"] = value.metadata;
    return j;
}

nlohmann::json to_json(const target_model_t& value)
{
    return nlohmann::json{
        {"architecture", value.architecture},
        {"platform", value.platform},
        {"endianness", value.endianness},
        {"pointer_width_bits", value.pointer_width_bits},
        {"environment", value.environment},
    };
}

nlohmann::json to_json(const verification_policy_t& value)
{
    return nlohmann::json{
        {"allow_recorded_only_corpus", value.allow_recorded_only_corpus},
        {"allow_user_declared_noncritical", value.allow_user_declared_noncritical},
        {"require_loaded_critical_corpus", value.require_loaded_critical_corpus},
        {"reject_unknown_critical_facts", value.reject_unknown_critical_facts},
        {"reject_conditional_critical_facts", value.reject_conditional_critical_facts},
        {"reject_timeout_critical_facts", value.reject_timeout_critical_facts},
        {"max_total_ms", value.max_total_ms},
        {"max_path_depth", value.max_path_depth},
        {"max_call_depth", value.max_call_depth},
        {"max_solver_ms", value.max_solver_ms},
        {"extensions", value.extensions},
    };
}

bool from_json(const nlohmann::json& value, chain_budget_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"phase", "timeout_ms", "max_items", "max_bytes"}, errors, path);
    bool ok = true;
    ok = read_enum_field(value, "phase", out.phase, budget_phase_from_string, errors, path, false) && ok;
    ok = read_u64_field(value, "timeout_ms", out.timeout_ms, errors, path) && ok;
    ok = read_u64_field(value, "max_items", out.max_items, errors, path) && ok;
    ok = read_u64_field(value, "max_bytes", out.max_bytes, errors, path) && ok;
    return ok;
}

bool from_json(const nlohmann::json& value, evidence_ref_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"evidence_id", "corpus_id", "function_id", "ea", "rva", "layer", "lineage", "snippet", "snapshot_id"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "evidence_id", out.evidence_id, errors, path, false) && ok;
    ok = read_string_field(value, "corpus_id", out.corpus_id, errors, path, false) && ok;
    ok = read_string_field(value, "function_id", out.function_id, errors, path, false) && ok;
    ok = read_string_field(value, "ea", out.ea, errors, path, false) && ok;
    ok = read_string_field(value, "rva", out.rva, errors, path, false) && ok;
    ok = read_string_field(value, "layer", out.layer, errors, path, false) && ok;
    ok = read_string_field(value, "lineage", out.lineage, errors, path, false) && ok;
    ok = read_string_field(value, "snippet", out.snippet, errors, path, false) && ok;
    ok = read_string_field(value, "snapshot_id", out.snapshot_id, errors, path, false) && ok;
    if (out.evidence_id.empty())
        out.evidence_id = stable_id("evidence", value);
    return ok;
}

bool from_json(const nlohmann::json& value, data_provenance_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"kind", "source_id", "producer_operation", "transform", "encoding", "endianness", "control_degree", "checksum_validated", "decompressed", "decrypted", "metadata"}, errors, path);
    bool ok = true;
    ok = read_enum_field(value, "kind", out.kind, provenance_kind_from_string, errors, path, false) && ok;
    ok = read_string_field(value, "source_id", out.source_id, errors, path, false) && ok;
    ok = read_string_field(value, "producer_operation", out.producer_operation, errors, path, false) && ok;
    ok = read_string_field(value, "transform", out.transform, errors, path, false) && ok;
    ok = read_string_field(value, "encoding", out.encoding, errors, path, false) && ok;
    ok = read_string_field(value, "endianness", out.endianness, errors, path, false) && ok;
    ok = read_string_field(value, "control_degree", out.control_degree, errors, path, false) && ok;
    ok = read_bool_field(value, "checksum_validated", out.checksum_validated, errors, path) && ok;
    ok = read_bool_field(value, "decompressed", out.decompressed, errors, path) && ok;
    ok = read_bool_field(value, "decrypted", out.decrypted, errors, path) && ok;
    auto meta = value.find("metadata");
    if (meta != value.end())
    {
        if (!meta->is_object())
        {
            errors.add("invalid_type", path + "/metadata", "expected object");
            ok = false;
        }
        else
        {
            out.metadata = *meta;
        }
    }
    return ok;
}

bool from_json(const nlohmann::json& value, chain_value_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"kind", "width_bits", "concrete", "min_value", "max_value", "text", "corpus_id", "rva", "object_id", "field_path", "bytes", "bytes_hex", "provenance", "attributes"}, errors, path);
    bool ok = true;
    ok = read_enum_field(value, "kind", out.kind, value_kind_from_string, errors, path, false) && ok;
    ok = read_u32_field(value, "width_bits", out.width_bits, errors, path) && ok;
    ok = read_u64_field(value, "concrete", out.concrete, errors, path) && ok;
    ok = read_u64_field(value, "min_value", out.min_value, errors, path) && ok;
    ok = read_u64_field(value, "max_value", out.max_value, errors, path) && ok;
    ok = read_string_field(value, "text", out.text, errors, path, false) && ok;
    ok = read_string_field(value, "corpus_id", out.corpus_id, errors, path, false) && ok;
    ok = read_string_field(value, "rva", out.rva, errors, path, false) && ok;
    ok = read_string_field(value, "object_id", out.object_id, errors, path, false) && ok;
    ok = read_string_field(value, "field_path", out.field_path, errors, path, false) && ok;
    auto bytes = value.find("bytes");
    if (bytes != value.end())
    {
        if (!bytes->is_array())
        {
            errors.add("invalid_type", path + "/bytes", "expected byte array");
            ok = false;
        }
        else
        {
            out.bytes.clear();
            out.bytes.reserve(bytes->size());
            for (std::size_t i = 0; i < bytes->size(); ++i)
            {
                std::uint64_t b = 0;
                if (!parse_u64_json((*bytes)[i], b) || b > 0xFF)
                {
                    errors.add("invalid_byte", path + "/bytes/" + std::to_string(i), "expected byte value");
                    ok = false;
                }
                else
                {
                    out.bytes.push_back(static_cast<std::uint8_t>(b));
                }
            }
        }
    }
    auto bytes_hex_it = value.find("bytes_hex");
    if (bytes_hex_it != value.end())
    {
        if (!bytes_hex_it->is_string())
        {
            errors.add("invalid_type", path + "/bytes_hex", "expected hex string");
            ok = false;
        }
        else
        {
            out.bytes = bytes_from_hex(bytes_hex_it->get<std::string>());
            if (!bytes_hex_it->get<std::string>().empty() && out.bytes.empty())
            {
                errors.add("invalid_hex", path + "/bytes_hex", "invalid byte hex string");
                ok = false;
            }
        }
    }
    ok = read_array(value, "provenance", out.provenance, read_provenance_array_item, errors, path) && ok;
    auto attrs = value.find("attributes");
    if (attrs != value.end())
    {
        if (!attrs->is_object())
        {
            errors.add("invalid_type", path + "/attributes", "expected object");
            ok = false;
        }
        else
        {
            out.attributes = *attrs;
        }
    }
    return ok;
}

bool from_json(const nlohmann::json& value, fact_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"fact_id", "kind", "subject", "predicate", "value", "phase", "producer", "evidence", "proof_state", "criticality", "metadata"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "fact_id", out.fact_id, errors, path, false) && ok;
    ok = read_enum_field(value, "kind", out.kind, fact_kind_from_string, errors, path, true) && ok;
    auto subject = value.find("subject");
    if (subject == value.end())
    {
        errors.add("missing_required_field", path + "/subject", "field is required");
        ok = false;
    }
    else
    {
        out.subject = *subject;
    }
    ok = read_string_field(value, "predicate", out.predicate, errors, path, true) && ok;
    auto val = value.find("value");
    if (val == value.end())
    {
        errors.add("missing_required_field", path + "/value", "field is required");
        ok = false;
    }
    else
    {
        ok = from_json(*val, out.value, errors, path + "/value") && ok;
    }
    ok = read_string_field(value, "phase", out.phase, errors, path, false) && ok;
    ok = read_string_field(value, "producer", out.producer, errors, path, false) && ok;
    ok = read_array(value, "evidence", out.evidence, read_evidence_array_item, errors, path) && ok;
    ok = read_enum_field(value, "proof_state", out.proof_state, proof_state_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "criticality", out.criticality, fact_criticality_from_string, errors, path, false) && ok;
    auto meta = value.find("metadata");
    if (meta != value.end())
    {
        if (!meta->is_object())
        {
            errors.add("invalid_type", path + "/metadata", "expected object");
            ok = false;
        }
        else
        {
            out.metadata = *meta;
        }
    }
    assign_fact_id_if_missing(out);
    return ok;
}

bool from_json(const nlohmann::json& value, assumption_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"assumption_id", "text", "required_fact_ids", "criticality", "proof_state", "metadata"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "assumption_id", out.assumption_id, errors, path, false) && ok;
    ok = read_string_field(value, "text", out.text, errors, path, true) && ok;
    auto ids = value.find("required_fact_ids");
    if (ids != value.end())
    {
        if (!ids->is_array())
        {
            errors.add("invalid_type", path + "/required_fact_ids", "expected string array");
            ok = false;
        }
        else
        {
            out.required_fact_ids.clear();
            for (std::size_t i = 0; i < ids->size(); ++i)
            {
                if (!(*ids)[i].is_string())
                {
                    errors.add("invalid_type", path + "/required_fact_ids/" + std::to_string(i), "expected string");
                    ok = false;
                }
                else
                {
                    out.required_fact_ids.push_back((*ids)[i].get<std::string>());
                }
            }
        }
    }
    ok = read_enum_field(value, "criticality", out.criticality, fact_criticality_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "proof_state", out.proof_state, proof_state_from_string, errors, path, false) && ok;
    auto meta = value.find("metadata");
    if (meta != value.end())
    {
        if (!meta->is_object())
        {
            errors.add("invalid_type", path + "/metadata", "expected object");
            ok = false;
        }
        else
        {
            out.metadata = *meta;
        }
    }
    assign_assumption_id_if_missing(out);
    return ok;
}

bool from_json(const nlohmann::json& value, trigger_spec_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"trigger_id", "kind", "source", "must_reach", "preconditions", "postconditions", "dispatch", "metadata"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "trigger_id", out.trigger_id, errors, path, false) && ok;
    ok = read_enum_field(value, "kind", out.kind, trigger_kind_from_string, errors, path, false) && ok;
    auto source = value.find("source");
    if (source != value.end())
        out.source = *source;
    auto must_reach = value.find("must_reach");
    if (must_reach != value.end())
        out.must_reach = *must_reach;
    ok = read_array(value, "preconditions", out.preconditions, read_fact_array_item, errors, path) && ok;
    ok = read_array(value, "postconditions", out.postconditions, read_fact_array_item, errors, path) && ok;
    auto dispatch = value.find("dispatch");
    if (dispatch != value.end())
        out.dispatch = *dispatch;
    auto meta = value.find("metadata");
    if (meta != value.end())
    {
        if (!meta->is_object())
        {
            errors.add("invalid_type", path + "/metadata", "expected object");
            ok = false;
        }
        else
        {
            out.metadata = *meta;
        }
    }
    if (out.trigger_id.empty())
        out.trigger_id = stable_id("trigger", to_json(out));
    return ok;
}

bool from_json(const nlohmann::json& value, link_spec_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"link_id", "id", "role", "corpus_id", "module_id", "description", "entry", "trigger", "preconditions", "postconditions", "facts", "assumptions", "budgets", "policy", "metadata"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "link_id", out.link_id, errors, path, false) && ok;
    if (out.link_id.empty())
        ok = read_string_field(value, "id", out.link_id, errors, path, true) && ok;
    ok = read_enum_field(value, "role", out.role, link_role_from_string, errors, path, false) && ok;
    ok = read_string_field(value, "corpus_id", out.corpus_id, errors, path, false) && ok;
    if (out.corpus_id.empty())
        ok = read_string_field(value, "module_id", out.corpus_id, errors, path, false) && ok;
    ok = read_string_field(value, "description", out.description, errors, path, false) && ok;
    auto entry = value.find("entry");
    if (entry != value.end())
        out.entry = *entry;
    auto trigger = value.find("trigger");
    if (trigger != value.end())
        ok = from_json(*trigger, out.trigger, errors, path + "/trigger") && ok;
    ok = read_array(value, "preconditions", out.preconditions, read_fact_array_item, errors, path) && ok;
    ok = read_array(value, "postconditions", out.postconditions, read_fact_array_item, errors, path) && ok;
    ok = read_array(value, "facts", out.facts, read_fact_array_item, errors, path) && ok;
    ok = read_array(value, "assumptions", out.assumptions, read_assumption_array_item, errors, path) && ok;
    ok = read_array(value, "budgets", out.budgets, read_budget_array_item, errors, path) && ok;
    auto policy = value.find("policy");
    if (policy != value.end())
    {
        if (!policy->is_object())
        {
            errors.add("invalid_type", path + "/policy", "expected object");
            ok = false;
        }
        else
        {
            out.policy = *policy;
        }
    }
    auto meta = value.find("metadata");
    if (meta != value.end())
    {
        if (!meta->is_object())
        {
            errors.add("invalid_type", path + "/metadata", "expected object");
            ok = false;
        }
        else
        {
            out.metadata = *meta;
        }
    }
    if (out.link_id.empty())
        errors.add("invalid_id", path + "/link_id", "link id must not be empty");
    return ok;
}

bool from_json(const nlohmann::json& value, objective_spec_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"objective_id", "id", "kind", "description", "required_fact_ids", "required_facts", "goal", "operation_sequence", "metadata"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "objective_id", out.objective_id, errors, path, false) && ok;
    if (out.objective_id.empty())
        ok = read_string_field(value, "id", out.objective_id, errors, path, true) && ok;
    ok = read_enum_field(value, "kind", out.kind, objective_kind_from_string, errors, path, false) && ok;
    ok = read_string_field(value, "description", out.description, errors, path, false) && ok;
    auto ids = value.find("required_fact_ids");
    if (ids != value.end())
    {
        if (!ids->is_array())
        {
            errors.add("invalid_type", path + "/required_fact_ids", "expected string array");
            ok = false;
        }
        else
        {
            out.required_fact_ids.clear();
            for (std::size_t i = 0; i < ids->size(); ++i)
            {
                if (!(*ids)[i].is_string())
                {
                    errors.add("invalid_type", path + "/required_fact_ids/" + std::to_string(i), "expected string");
                    ok = false;
                }
                else
                {
                    out.required_fact_ids.push_back((*ids)[i].get<std::string>());
                }
            }
        }
    }
    ok = read_array(value, "required_facts", out.required_facts, read_fact_array_item, errors, path) && ok;
    auto goal = value.find("goal");
    if (goal != value.end())
        ok = from_json(*goal, out.goal, errors, path + "/goal") && ok;
    auto ops = value.find("operation_sequence");
    if (ops != value.end())
    {
        if (!ops->is_array())
        {
            errors.add("invalid_type", path + "/operation_sequence", "expected array");
            ok = false;
        }
        else
        {
            out.operation_sequence = *ops;
        }
    }
    auto meta = value.find("metadata");
    if (meta != value.end())
    {
        if (!meta->is_object())
        {
            errors.add("invalid_type", path + "/metadata", "expected object");
            ok = false;
        }
        else
        {
            out.metadata = *meta;
        }
    }
    if (out.objective_id.empty())
        errors.add("invalid_id", path + "/objective_id", "objective id must not be empty");
    return ok;
}

bool from_json(const nlohmann::json& value, target_model_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"architecture", "platform", "endianness", "pointer_width_bits", "environment"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "architecture", out.architecture, errors, path, false) && ok;
    ok = read_string_field(value, "platform", out.platform, errors, path, false) && ok;
    ok = read_string_field(value, "endianness", out.endianness, errors, path, false) && ok;
    ok = read_u32_field(value, "pointer_width_bits", out.pointer_width_bits, errors, path) && ok;
    auto env = value.find("environment");
    if (env != value.end())
    {
        if (!env->is_object())
        {
            errors.add("invalid_type", path + "/environment", "expected object");
            ok = false;
        }
        else
        {
            out.environment = *env;
        }
    }
    return ok;
}

bool from_json(const nlohmann::json& value, verification_policy_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"allow_recorded_only_corpus", "allow_user_declared_noncritical", "require_loaded_critical_corpus", "reject_unknown_critical_facts", "reject_conditional_critical_facts", "reject_timeout_critical_facts", "max_total_ms", "max_path_depth", "max_call_depth", "max_solver_ms", "extensions"}, errors, path);
    bool ok = true;
    ok = read_bool_field(value, "allow_recorded_only_corpus", out.allow_recorded_only_corpus, errors, path) && ok;
    ok = read_bool_field(value, "allow_user_declared_noncritical", out.allow_user_declared_noncritical, errors, path) && ok;
    ok = read_bool_field(value, "require_loaded_critical_corpus", out.require_loaded_critical_corpus, errors, path) && ok;
    ok = read_bool_field(value, "reject_unknown_critical_facts", out.reject_unknown_critical_facts, errors, path) && ok;
    ok = read_bool_field(value, "reject_conditional_critical_facts", out.reject_conditional_critical_facts, errors, path) && ok;
    ok = read_bool_field(value, "reject_timeout_critical_facts", out.reject_timeout_critical_facts, errors, path) && ok;
    ok = read_u64_field(value, "max_total_ms", out.max_total_ms, errors, path) && ok;
    ok = read_u64_field(value, "max_path_depth", out.max_path_depth, errors, path) && ok;
    ok = read_u64_field(value, "max_call_depth", out.max_call_depth, errors, path) && ok;
    ok = read_u64_field(value, "max_solver_ms", out.max_solver_ms, errors, path) && ok;
    auto ext = value.find("extensions");
    if (ext != value.end())
    {
        if (!ext->is_object())
        {
            errors.add("invalid_type", path + "/extensions", "expected object");
            ok = false;
        }
        else
        {
            out.extensions = *ext;
        }
    }
    return ok;
}

std::string stable_id(const std::string& prefix, const nlohmann::json& canonical_payload)
{
    return stable_id_from_text(prefix, canonical_payload.dump());
}

std::string stable_id_from_text(const std::string& prefix, const std::string& text)
{
    const std::uint64_t h1 = fnv1a64(text, 1469598103934665603ULL);
    const std::uint64_t h2 = fnv1a64(text, 1099511628211ULL ^ static_cast<std::uint64_t>(text.size()));
    std::ostringstream ss;
    ss << normalize_id_component(prefix) << "_";
    ss << std::hex << std::setfill('0') << std::nouppercase << std::setw(16) << h1;
    ss << std::setw(16) << h2;
    return ss.str();
}

std::string hex_u64(std::uint64_t value)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << value;
    return ss.str();
}

std::uint64_t now_ms()
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

bool parse_u64_json(const nlohmann::json& value, std::uint64_t& out)
{
    if (value.is_number_unsigned())
    {
        out = value.get<std::uint64_t>();
        return true;
    }
    if (value.is_number_integer())
    {
        const auto s = value.get<std::int64_t>();
        if (s < 0)
            return false;
        out = static_cast<std::uint64_t>(s);
        return true;
    }
    if (value.is_string())
    {
        const std::string text = value.get<std::string>();
        if (text.empty())
            return false;
        char* endp = nullptr;
        const std::uint64_t parsed = _strtoui64(text.c_str(), &endp, 0);
        if (endp == text.c_str() || *endp != '\0')
            return false;
        out = parsed;
        return true;
    }
    return false;
}

std::string normalize_id_component(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (unsigned char c : value)
    {
        if (c >= 'A' && c <= 'Z')
            out.push_back(static_cast<char>(c - 'A' + 'a'));
        else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')
            out.push_back(static_cast<char>(c));
        else if (c == '-' || c == '.' || c == ' ' || c == ':' || c == '/')
            out.push_back('_');
    }
    while (!out.empty() && out.front() == '_')
        out.erase(out.begin());
    while (!out.empty() && out.back() == '_')
        out.pop_back();
    if (out.empty())
        out = "id";
    return out;
}

bool critical_fact_blocks_confirmation(const fact_t& fact)
{
    const bool critical = fact.criticality == fact_criticality_t::chain_critical
        || fact.criticality == fact_criticality_t::objective_critical;
    if (!critical)
        return false;
    return fact.proof_state != proof_state_t::proven;
}

bool assumption_blocks_confirmation(const assumption_t& assumption)
{
    const bool critical = assumption.criticality == fact_criticality_t::chain_critical
        || assumption.criticality == fact_criticality_t::objective_critical;
    if (!critical)
        return false;
    return assumption.proof_state != proof_state_t::proven;
}

void assign_fact_id_if_missing(fact_t& fact)
{
    if (!fact.fact_id.empty())
        return;
    nlohmann::json canonical;
    canonical["kind"] = to_string(fact.kind);
    canonical["subject"] = fact.subject;
    canonical["predicate"] = fact.predicate;
    canonical["value"] = to_json(fact.value);
    canonical["phase"] = fact.phase;
    canonical["producer"] = fact.producer;
    canonical["proof_state"] = to_string(fact.proof_state);
    canonical["criticality"] = to_string(fact.criticality);
    fact.fact_id = stable_id("fact", canonical);
}

void assign_assumption_id_if_missing(assumption_t& assumption)
{
    if (!assumption.assumption_id.empty())
        return;
    nlohmann::json canonical;
    canonical["text"] = assumption.text;
    canonical["required_fact_ids"] = assumption.required_fact_ids;
    canonical["criticality"] = to_string(assumption.criticality);
    canonical["proof_state"] = to_string(assumption.proof_state);
    assumption.assumption_id = stable_id("assumption", canonical);
}

}
}
}
