#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>

namespace aida
{
namespace vuln
{
namespace chain
{

inline constexpr const char* k_chain_document_schema = "aida_chain_document_v2";
inline constexpr const char* k_chain_report_schema = "chain_verification_report_v2";
inline constexpr int k_chain_document_version = 2;
inline constexpr int k_chain_report_version = 2;

enum class validation_severity_t
{
    error,
    warning
};

struct validation_error_t
{
    std::string code;
    std::string path;
    std::string message;
    validation_severity_t severity = validation_severity_t::error;
    bool acceptance_blocker = true;
};

struct validation_result_t
{
    std::vector<validation_error_t> errors;

    bool ok() const;
    bool has_blocker() const;
    void add(std::string code,
             std::string path,
             std::string message,
             validation_severity_t severity = validation_severity_t::error,
             bool acceptance_blocker = true);
};

enum class proof_state_t
{
    proven,
    refuted,
    conditional,
    unknown,
    unsupported,
    timeout
};

enum class fact_criticality_t
{
    chain_critical,
    objective_critical,
    collateral,
    diagnostic
};

enum class fact_kind_t
{
    value_fact,
    content_fact,
    address_fact,
    register_fact,
    stack_fact,
    memory_fact,
    alias_fact,
    lifetime_fact,
    allocator_fact,
    callback_fact,
    trigger_fact,
    protocol_fact,
    firmware_fact,
    side_effect_fact,
    objective_fact,
    assumption_fact,
    boundary_fact
};

enum class value_kind_t
{
    unknown,
    concrete,
    symbolic,
    range,
    bytes,
    zero_bytes,
    constant_bytes,
    copied_bytes,
    transformed_bytes,
    checksum_constrained,
    encrypted_unknown,
    compressed_unknown,
    module_rva,
    object_pointer,
    self_reference,
    poisoned
};

enum class provenance_kind_t
{
    user_input,
    file_input,
    network_input,
    protocol_field,
    copy,
    decode,
    transform,
    decompression,
    decryption,
    checksum,
    allocator_zero,
    memset_zero,
    constant,
    dynamic_trace,
    user_declared,
    unknown
};

enum class link_role_t
{
    generic_transition,
    parser,
    allocator,
    lifetime,
    callback_registration,
    trigger_dispatch,
    memory_write,
    memory_read,
    branch_gate,
    indirect_call,
    protocol_transition,
    firmware_dispatch,
    final_objective
};

enum class objective_kind_t
{
    memory_write,
    memory_read,
    control_flow,
    callback_invocation,
    privilege_transition,
    protocol_state,
    firmware_state,
    data_exfiltration,
    denial_of_service,
    custom
};

enum class trigger_kind_t
{
    api_call,
    syscall,
    ioctl,
    interrupt,
    timer,
    message_queue,
    gui_callback,
    signal_handler,
    rpc_dispatch,
    protocol_transition,
    firmware_hook,
    destructor,
    finalizer,
    callback,
    state_machine,
    custom
};

enum class budget_phase_t
{
    schema,
    extraction,
    path,
    state,
    solver,
    report,
    total
};

struct chain_budget_t
{
    budget_phase_t phase = budget_phase_t::total;
    std::uint64_t timeout_ms = 0;
    std::uint64_t max_items = 0;
    std::uint64_t max_bytes = 0;
};

struct evidence_ref_t
{
    std::string evidence_id;
    std::string corpus_id;
    std::string function_id;
    std::string ea;
    std::string rva;
    std::string layer;
    std::string lineage;
    std::string snippet;
    std::string snapshot_id;
};

struct data_provenance_t
{
    provenance_kind_t kind = provenance_kind_t::unknown;
    std::string source_id;
    std::string producer_operation;
    std::string transform;
    std::string encoding;
    std::string endianness;
    std::string control_degree;
    bool checksum_validated = false;
    bool decompressed = false;
    bool decrypted = false;
    nlohmann::json metadata = nlohmann::json::object();
};

struct chain_value_t
{
    value_kind_t kind = value_kind_t::unknown;
    std::uint32_t width_bits = 0;
    std::uint64_t concrete = 0;
    std::uint64_t min_value = 0;
    std::uint64_t max_value = 0;
    std::string text;
    std::string corpus_id;
    std::string rva;
    std::string object_id;
    std::string field_path;
    std::vector<std::uint8_t> bytes;
    std::vector<data_provenance_t> provenance;
    nlohmann::json attributes = nlohmann::json::object();
};

struct fact_t
{
    std::string fact_id;
    fact_kind_t kind = fact_kind_t::value_fact;
    nlohmann::json subject = nlohmann::json::object();
    std::string predicate;
    chain_value_t value;
    std::string phase;
    std::string producer;
    std::vector<evidence_ref_t> evidence;
    proof_state_t proof_state = proof_state_t::unknown;
    fact_criticality_t criticality = fact_criticality_t::diagnostic;
    nlohmann::json metadata = nlohmann::json::object();
};

struct assumption_t
{
    std::string assumption_id;
    std::string text;
    std::vector<std::string> required_fact_ids;
    fact_criticality_t criticality = fact_criticality_t::chain_critical;
    proof_state_t proof_state = proof_state_t::conditional;
    nlohmann::json metadata = nlohmann::json::object();
};

struct trigger_spec_t
{
    std::string trigger_id;
    trigger_kind_t kind = trigger_kind_t::custom;
    nlohmann::json source = nlohmann::json::object();
    nlohmann::json must_reach = nlohmann::json::object();
    std::vector<fact_t> preconditions;
    std::vector<fact_t> postconditions;
    nlohmann::json dispatch = nlohmann::json::object();
    nlohmann::json metadata = nlohmann::json::object();
};

struct link_spec_t
{
    std::string link_id;
    link_role_t role = link_role_t::generic_transition;
    std::string corpus_id;
    std::string description;
    nlohmann::json entry = nlohmann::json::object();
    trigger_spec_t trigger;
    std::vector<fact_t> preconditions;
    std::vector<fact_t> postconditions;
    std::vector<fact_t> facts;
    std::vector<assumption_t> assumptions;
    std::vector<chain_budget_t> budgets;
    nlohmann::json policy = nlohmann::json::object();
    nlohmann::json metadata = nlohmann::json::object();
};

struct objective_spec_t
{
    std::string objective_id;
    objective_kind_t kind = objective_kind_t::custom;
    std::string description;
    std::vector<std::string> required_fact_ids;
    std::vector<fact_t> required_facts;
    chain_value_t goal;
    nlohmann::json operation_sequence = nlohmann::json::array();
    nlohmann::json metadata = nlohmann::json::object();
};

struct target_model_t
{
    std::string architecture = "unknown";
    std::string platform = "unknown";
    std::string endianness = "unknown";
    std::uint32_t pointer_width_bits = 0;
    nlohmann::json environment = nlohmann::json::object();
};

struct verification_policy_t
{
    bool allow_recorded_only_corpus = true;
    bool allow_user_declared_noncritical = true;
    bool require_loaded_critical_corpus = true;
    bool reject_unknown_critical_facts = true;
    bool reject_conditional_critical_facts = true;
    bool reject_timeout_critical_facts = true;
    std::uint64_t max_total_ms = 120000;
    std::uint64_t max_path_depth = 64;
    std::uint64_t max_call_depth = 8;
    std::uint64_t max_solver_ms = 5000;
    nlohmann::json extensions = nlohmann::json::object();
};

const char* to_string(validation_severity_t value);
const char* to_string(proof_state_t value);
const char* to_string(fact_criticality_t value);
const char* to_string(fact_kind_t value);
const char* to_string(value_kind_t value);
const char* to_string(provenance_kind_t value);
const char* to_string(link_role_t value);
const char* to_string(objective_kind_t value);
const char* to_string(trigger_kind_t value);
const char* to_string(budget_phase_t value);

std::optional<proof_state_t> proof_state_from_string(const std::string& value);
std::optional<fact_criticality_t> fact_criticality_from_string(const std::string& value);
std::optional<fact_kind_t> fact_kind_from_string(const std::string& value);
std::optional<value_kind_t> value_kind_from_string(const std::string& value);
std::optional<provenance_kind_t> provenance_kind_from_string(const std::string& value);
std::optional<link_role_t> link_role_from_string(const std::string& value);
std::optional<objective_kind_t> objective_kind_from_string(const std::string& value);
std::optional<trigger_kind_t> trigger_kind_from_string(const std::string& value);
std::optional<budget_phase_t> budget_phase_from_string(const std::string& value);

nlohmann::json to_json(const validation_error_t& value);
nlohmann::json to_json(const validation_result_t& value);
nlohmann::json to_json(const chain_budget_t& value);
nlohmann::json to_json(const evidence_ref_t& value);
nlohmann::json to_json(const data_provenance_t& value);
nlohmann::json to_json(const chain_value_t& value);
nlohmann::json to_json(const fact_t& value);
nlohmann::json to_json(const assumption_t& value);
nlohmann::json to_json(const trigger_spec_t& value);
nlohmann::json to_json(const link_spec_t& value);
nlohmann::json to_json(const objective_spec_t& value);
nlohmann::json to_json(const target_model_t& value);
nlohmann::json to_json(const verification_policy_t& value);

bool from_json(const nlohmann::json& value, chain_budget_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, evidence_ref_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, data_provenance_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, chain_value_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, fact_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, assumption_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, trigger_spec_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, link_spec_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, objective_spec_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, target_model_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, verification_policy_t& out, validation_result_t& errors, const std::string& path);

std::string stable_id(const std::string& prefix, const nlohmann::json& canonical_payload);
std::string stable_id_from_text(const std::string& prefix, const std::string& text);
std::string hex_u64(std::uint64_t value);
std::uint64_t now_ms();
bool parse_u64_json(const nlohmann::json& value, std::uint64_t& out);
std::string normalize_id_component(const std::string& value);
bool critical_fact_blocks_confirmation(const fact_t& fact);
bool assumption_blocks_confirmation(const assumption_t& assumption);
void assign_fact_id_if_missing(fact_t& fact);
void assign_assumption_id_if_missing(assumption_t& assumption);

}
}
}
