#include "routing_extensions.hpp"

#include "../ida_contracts_generated.hpp"
#include "../../calculator_tool.hpp"
#include "../../ida_compat_schemas.hpp"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <iterator>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>

namespace aida::standalone::mcp::compat::handlers {

namespace {

using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;

using validation_failure_t = std::optional<json>;

protocol::tool_effect_t protocol_effect(contract_effect_t effect) {
    switch (effect) {
    case contract_effect_t::workspace_read:
        return protocol::tool_effect_t::workspace_read;
    case contract_effect_t::workspace_checkpoint:
        return protocol::tool_effect_t::workspace_checkpoint;
    case contract_effect_t::workspace_overlay_mutation:
        return protocol::tool_effect_t::workspace_overlay_mutation;
    case contract_effect_t::debugger_read:
        return protocol::tool_effect_t::debugger_read;
    case contract_effect_t::debugger_control:
        return protocol::tool_effect_t::debugger_control;
    case contract_effect_t::debugger_write:
        return protocol::tool_effect_t::debugger_write;
    case contract_effect_t::isolated_python:
        return protocol::tool_effect_t::isolated_python;
    case contract_effect_t::registry_read:
        return protocol::tool_effect_t::registry_read;
    }
    throw std::runtime_error("routing metadata has an unknown contract effect");
}

protocol::effect_lock_t protocol_lock(contract_lock_t lock) {
    switch (lock) {
    case contract_lock_t::workspace_shared:
        return protocol::effect_lock_t::workspace_shared;
    case contract_lock_t::workspace_checkpoint:
        return protocol::effect_lock_t::workspace_checkpoint;
    case contract_lock_t::workspace_overlay_transaction:
        return protocol::effect_lock_t::workspace_overlay_transaction;
    case contract_lock_t::debugger_lane:
        return protocol::effect_lock_t::debugger_lane;
    case contract_lock_t::python_worker:
        return protocol::effect_lock_t::python_worker;
    case contract_lock_t::registry_read:
        return protocol::effect_lock_t::registry_read;
    }
    throw std::runtime_error("routing metadata has an unknown contract lock");
}

extension_lane_t lane_for_effect(protocol::tool_effect_t effect) noexcept {
    switch (effect) {
    case protocol::tool_effect_t::workspace_read:
    case protocol::tool_effect_t::registry_read:
        return extension_lane_t::registry_read;
    case protocol::tool_effect_t::workspace_checkpoint:
    case protocol::tool_effect_t::workspace_overlay_mutation:
        return extension_lane_t::workspace_analysis;
    case protocol::tool_effect_t::debugger_read:
    case protocol::tool_effect_t::debugger_control:
    case protocol::tool_effect_t::debugger_write:
        return extension_lane_t::workspace_analysis;
    case protocol::tool_effect_t::isolated_python:
        return extension_lane_t::local_calculator;
    case protocol::tool_effect_t::unspecified:
        return extension_lane_t::local_calculator;
    }
    return extension_lane_t::registry_read;
}

routing_metadata_t metadata_from_descriptor(const contract_descriptor_t& descriptor) {
    routing_metadata_t meta;
    meta.name.assign(descriptor.name.data(), descriptor.name.size());
    meta.target_requirement = descriptor.target_dependent
        ? protocol::target_requirement_t::optional
        : protocol::target_requirement_t::independent;
    meta.accepts_pid = descriptor.accepts_pid;
    meta.accepts_bin_name = descriptor.accepts_bin_name;
    meta.effect = protocol_effect(descriptor.effect);
    meta.lock = protocol_lock(descriptor.lock);
    meta.read_only = descriptor.read_only;
    meta.unsafe = descriptor.unsafe;
    meta.archive_backed = descriptor.archive_backed;
    meta.is_extension = false;
    meta.lane = lane_for_effect(meta.effect);
    return meta;
}

routing_metadata_t metadata_for_extension(std::string_view name) {
    routing_metadata_t meta;
    meta.name.assign(name.data(), name.size());
    meta.archive_backed = false;
    meta.is_extension = true;
    if (name == "analyze_funcs") {
        meta.target_requirement = protocol::target_requirement_t::optional;
        meta.accepts_pid = true;
        meta.accepts_bin_name = true;
        meta.effect = protocol::tool_effect_t::workspace_overlay_mutation;
        meta.lock = protocol::effect_lock_t::workspace_overlay_transaction;
        meta.read_only = false;
        meta.lane = extension_lane_t::workspace_analysis;
    } else if (name == "find_insns") {
        meta.target_requirement = protocol::target_requirement_t::optional;
        meta.accepts_pid = true;
        meta.accepts_bin_name = true;
        meta.effect = protocol::tool_effect_t::workspace_read;
        meta.lock = protocol::effect_lock_t::workspace_shared;
        meta.read_only = true;
        meta.lane = extension_lane_t::workspace_instruction_scan;
    } else if (name == "calculator" || name == "calculate") {
        meta.target_requirement = protocol::target_requirement_t::independent;
        meta.accepts_pid = false;
        meta.accepts_bin_name = false;
        meta.effect = protocol::tool_effect_t::registry_read;
        meta.lock = protocol::effect_lock_t::registry_read;
        meta.read_only = true;
        meta.lane = extension_lane_t::local_calculator;
    } else {
        throw std::runtime_error("routing metadata extension name is not retained");
    }
    return meta;
}

bool valid_limits(const routing_extension_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 && limits.max_request_bytes <= 1024U * 1024U &&
        limits.max_response_bytes != 0 && limits.max_response_bytes <= 16U * 1024U * 1024U &&
        limits.max_selector_bytes != 0 && limits.max_selector_bytes <= 1024U &&
        limits.max_execution_time.count() > 0 && limits.max_execution_time.count() <= 120000;
}

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_routing_extension"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_routing_extension"},
        {"field", std::move(path)},
        {"reason", "maximum_exceeded"},
        {"maximum", maximum},
        {"actual", actual},
    };
}

std::optional<std::uint64_t> unsigned_integer(const json& value) noexcept {
    try {
        if (value.is_number_unsigned()) {
            return value.get<std::uint64_t>();
        }
        if (value.is_number_integer()) {
            const auto signed_value = value.get<std::int64_t>();
            if (signed_value >= 0) {
                return static_cast<std::uint64_t>(signed_value);
            }
        }
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

validation_failure_t bounded_text(const json& value, std::string path,
                                 std::size_t maximum, bool allow_empty) {
    if (!value.is_string()) {
        return invalid_value(std::move(path), "string_required", value);
    }
    const auto& text = value.get_ref<const std::string&>();
    if (!allow_empty && text.empty()) {
        return invalid_value(std::move(path), "nonempty_string_required", value);
    }
    if (text.size() > maximum) {
        return exceeded_value(
            std::move(path), static_cast<std::uint64_t>(maximum),
            static_cast<std::uint64_t>(text.size()));
    }
    return std::nullopt;
}

validation_failure_t bounded_member_text(const json& object, std::string_view field,
                                        std::string path_prefix, std::size_t maximum,
                                        bool allow_empty) {
    const auto found = object.find(std::string(field));
    if (found == object.end()) {
        return std::nullopt;
    }
    const std::string path = path_prefix.empty()
        ? std::string(field)
        : path_prefix + "." + std::string(field);
    return bounded_text(*found, path, maximum, allow_empty);
}

validation_failure_t validate_routing_bounds(const json& arguments,
                                            const routing_extension_limits_t& limits) {
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        const auto value = unsigned_integer(*pid);
        if (!value || *value == 0 || *value > (std::numeric_limits<std::uint32_t>::max)()) {
            return invalid_value("pid", "valid_process_id_required", *pid);
        }
    }
    if (const auto bin_name = arguments.find("bin_name"); bin_name != arguments.end()) {
        if (auto failure = bounded_text(
                *bin_name, "bin_name", limits.max_selector_bytes, false)) {
            return failure;
        }
    }
    return std::nullopt;
}

validation_failure_t validate_list_instances(const json& arguments,
                                            const routing_extension_limits_t& limits) {
    if (auto failure = bounded_member_text(
            arguments, "filter", {}, limits.max_selector_bytes, true)) {
        return failure;
    }
    return std::nullopt;
}

validation_failure_t validate_tool_bounds(std::string_view name, const json& arguments,
                                         const routing_extension_limits_t& limits) {
    if (name == "list_instances") {
        return validate_list_instances(arguments, limits);
    }
    if (name == "analyze_funcs" || name == "find_insns") {
        return validate_routing_bounds(arguments, limits);
    }
    if (name == "calculator" || name == "calculate") {
        return std::nullopt;
    }
    return invalid_value("tool", "routing_extension_not_registered", std::string(name));
}



result_error_code_t adapter_error_code(adapter_error_code_t code) noexcept {
    switch (code) {
    case adapter_error_code_t::invalid_request:
        return result_error_code_t::invalid_input;
    case adapter_error_code_t::target_resolution_failed:
        return result_error_code_t::target_policy_rejected;
    case adapter_error_code_t::operation_not_permitted:
    case adapter_error_code_t::effect_policy_failed:
    case adapter_error_code_t::effect_lock_busy:
        return result_error_code_t::effect_policy_rejected;
    case adapter_error_code_t::none:
    case adapter_error_code_t::contract_not_found:
    case adapter_error_code_t::backend_unavailable:
    case adapter_error_code_t::backend_rejected:
    case adapter_error_code_t::live_snapshot_denied:
    case adapter_error_code_t::live_snapshot_bounds:
    case adapter_error_code_t::live_snapshot_invalid:
        return result_error_code_t::handler_failed;
    }
    return result_error_code_t::handler_failed;
}

mcp_result_t adapter_failure(const adapter_error_t& error) {
    return mcp_result_t::failure(
        adapter_error_code(error.code),
        "Routing extension workspace adapter rejected the request.",
        json{
            {"phase", "workspace_adapter"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

const contract_descriptor_t& extension_adapter_descriptor(std::string_view name) {
    static constexpr std::array<contract_descriptor_t, 2> descriptors{{
        {
            "analyze_funcs", "", "", "", "",
            "aida::standalone::mcp::compat::adapters::analyze_funcs",
            "retained-aida-extension", 0,
            contract_effect_t::workspace_overlay_mutation,
            contract_lock_t::workspace_overlay_transaction,
            false, true, true, true, false, false,
        },
        {
            "find_insns", "", "", "", "",
            "aida::standalone::mcp::compat::adapters::find_insns",
            "retained-aida-extension", 0,
            contract_effect_t::workspace_read,
            contract_lock_t::workspace_shared,
            false, true, true, true, true, false,
        },
    }};
    const auto found = std::find_if(
        descriptors.begin(), descriptors.end(),
        [name](const contract_descriptor_t& descriptor) { return descriptor.name == name; });
    if (found == descriptors.end()) {
        throw std::runtime_error("retained workspace extension descriptor is unavailable");
    }
    return *found;
}

mcp_result_t target_failure(const target_resolution_error_t& error) {
    return mcp_result_t::failure(
        result_error_code_t::target_policy_rejected,
        "Routing extension target resolution failed.",
        json{
            {"phase", "extension_target_resolution"},
            {"target_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

mcp_result_t effect_failure(const effect_policy_error_t& error) {
    return mcp_result_t::failure(
        result_error_code_t::effect_policy_rejected,
        "Routing extension effect policy rejected the request.",
        json{
            {"phase", "extension_effect_lock"},
            {"effect_code", std::string(error.stable_code)},
        });
}

result_error_code_t retained_calculator_error_code(std::string_view code) noexcept {
    if (code == "CANCELLED" || code == "DEADLINE_EXCEEDED") {
        return result_error_code_t::cancelled;
    }
    if (code == "ARITY_ERROR" || code == "DOMAIN_ERROR" ||
        code == "INVALID_ARGUMENT" || code == "LIMIT_EXCEEDED" ||
        code == "MAPPING_NOT_FOUND" || code == "MAPPING_REQUIRED" ||
        code == "PARSE_ERROR" || code == "RANGE_ERROR" ||
        code == "TYPE_ERROR" || code == "UNKNOWN_FUNCTION" ||
        code == "UNKNOWN_IDENTIFIER") {
        return result_error_code_t::invalid_input;
    }
    return result_error_code_t::handler_failed;
}

std::uint64_t retained_calculator_deadline(std::chrono::milliseconds maximum) noexcept {
    const std::uint64_t now = static_cast<std::uint64_t>(::GetTickCount64());
    const auto timeout_count = maximum.count();
    const auto bounded = static_cast<std::uint64_t>(timeout_count > 0 ? timeout_count : 1);
    const std::uint64_t local = now > (std::numeric_limits<std::uint64_t>::max)() - bounded
        ? (std::numeric_limits<std::uint64_t>::max)()
        : now + bounded;
    const std::uint64_t active = mcp_standalone::current_call_deadline_ms();
    return active == 0 ? local : (std::min)(active, local);
}

mcp_result_t invoke_retained_calculator(
    std::string_view name,
    const json& arguments,
    const protocol::cancellation_token_t& cancellation,
    std::chrono::milliseconds maximum_execution_time) {
    auto cancellation_state = cancellation.state();
    mcp_standalone::workspace_request_context_t context;
    context.cancellation = cancellation_state.get();
    context.deadline_ms = retained_calculator_deadline(maximum_execution_time);
    context.tool_name.assign(name.data(), name.size());
    auto result = mcp_standalone::ida_compat::tool_calculate(arguments, context);
    if (!result.success) {
        return mcp_result_t::failure(
            retained_calculator_error_code(result.error_code),
            result.text.empty() ? "Retained calculator rejected the request." : result.text,
            json{
                {"phase", "retained_calculator"},
                {"retained_error_code", result.error_code},
                {"retained_error_details", result.error_details},
            });
    }
    if (!result.data.is_object()) {
        return mcp_result_t::failure(
            result_error_code_t::invalid_output,
            "Retained calculator returned non-object structured output.",
            json{{"phase", "retained_calculator_output"}});
    }
    std::string payload = result.text.empty() ? result.data.dump() : std::move(result.text);
    return mcp_result_t::success(
        std::move(payload), std::move(result.data),
        json{{"retained_handler", "mcp_standalone::ida_compat::tool_calculate"}});
}

json list_instances_input_schema() {
    return json{
        {"type", "object"},
        {"properties", json::object()},
        {"required", json::array()},
    };
}

json list_instances_output_schema() {
    return json{
        {"type", "object"},
        {"properties", json{
            {"instances", json{
                {"type", "array"},
                {"items", json{
                    {"type", "object"},
                    {"properties", json{
                        {"pid", json{{"type", "integer"}}},
                        {"bin_name", json{{"type", "string"}}},
                    }},
                    {"required", json::array({"pid", "bin_name"})},
                    {"additionalProperties", false},
                }},
            }},
        }},
        {"required", json::array({"instances"})},
    };
}

json analyze_funcs_input_schema() {
    const auto* schema = mcp_standalone::ida_compat::find_schema("analyze_funcs");
    if (schema == nullptr) {
        throw std::runtime_error("retained analyze_funcs schema is unavailable");
    }
    return *schema;
}

json analyze_funcs_output_schema() {
    return json{{"type", "object"}};
}

json find_insns_input_schema() {
    const auto* schema = mcp_standalone::ida_compat::find_schema("find_insns");
    if (schema == nullptr) {
        throw std::runtime_error("retained find_insns schema is unavailable");
    }
    return *schema;
}

json find_insns_output_schema() {
    return json{{"type", "object"}};
}

json calculator_input_schema() {
    const auto* schema = mcp_standalone::ida_compat::find_schema("calculate");
    if (schema == nullptr) {
        throw std::runtime_error("retained calculator schema is unavailable");
    }
    return *schema;
}

json calculator_output_schema() {
    return json{{"type", "object"}};
}

struct extension_contract_spec_t {
    std::string_view name;
    std::string_view description;
    json (*input_schema)() = nullptr;
    json (*output_schema)() = nullptr;
    protocol::target_requirement_t target_requirement;
    bool accepts_pid;
    bool accepts_bin_name;
    protocol::tool_effect_t effect;
    protocol::effect_lock_t lock;
    bool read_only;
};

const extension_contract_spec_t& extension_spec(std::string_view name) {
    static const extension_contract_spec_t specs[] = {
        {k_extension_tool_list_instances,
         "List all available target instances from the proxy resolver.",
         list_instances_input_schema, list_instances_output_schema,
         protocol::target_requirement_t::independent, false, false,
         protocol::tool_effect_t::registry_read, protocol::effect_lock_t::registry_read, true},
        {k_extension_tool_analyze_funcs,
         "Analyze one or more functions through the retained reversible workspace mutation.",
         analyze_funcs_input_schema, analyze_funcs_output_schema,
         protocol::target_requirement_t::optional, true, true,
         protocol::tool_effect_t::workspace_overlay_mutation,
         protocol::effect_lock_t::workspace_overlay_transaction, false},
        {k_extension_tool_find_insns,
         "Find instructions through the retained bounded workspace formatter.",
         find_insns_input_schema, find_insns_output_schema,
         protocol::target_requirement_t::optional, true, true,
         protocol::tool_effect_t::workspace_read, protocol::effect_lock_t::workspace_shared, true},
        {k_extension_tool_calculator,
         "ida-pro-mcp compatible calculator.",
         calculator_input_schema, calculator_output_schema,
         protocol::target_requirement_t::independent, false, false,
         protocol::tool_effect_t::registry_read, protocol::effect_lock_t::registry_read, true},
        {k_extension_tool_calculate,
         "Safe target-independent integer, bytes, hash, floating-point, and address mapping calculator",
         calculator_input_schema, calculator_output_schema,
         protocol::target_requirement_t::independent, false, false,
         protocol::tool_effect_t::registry_read, protocol::effect_lock_t::registry_read, true},
    };
    for (const auto& spec : specs) {
        if (spec.name == name) {
            return spec;
        }
    }
    throw std::runtime_error("routing extension spec not found for " + std::string(name));
}

protocol::tool_contract_t make_extension_contract(std::string_view name) {
    const auto& spec = extension_spec(name);
    protocol::tool_contract_t contract;
    contract.name.assign(name.data(), name.size());
    contract.description.assign(spec.description.data(), spec.description.size());
    contract.input_schema = spec.input_schema();
    contract.output_schema = spec.output_schema();
    contract.annotations = json::object();
    contract.target_policy.requirement = spec.target_requirement;
    contract.target_policy.accepts_pid = spec.accepts_pid;
    contract.target_policy.accepts_bin_name = spec.accepts_bin_name;
    contract.effect_policy.effect = spec.effect;
    contract.effect_policy.lock = spec.lock;
    contract.effect_policy.read_only = spec.read_only;
    contract.effect_policy.unsafe = false;
    return contract;
}



}

const std::array<std::string_view, k_routing_extension_tool_count>&
routing_extension_tool_names() noexcept {
    return k_routing_extension_names;
}

const std::vector<routing_metadata_t>& routing_metadata_inventory() {
    static const std::vector<routing_metadata_t> inventory = []() {
        std::vector<routing_metadata_t> result;
        result.reserve(k_union_tool_count);
        std::set<std::string> names;
        const auto* archive = aida::standalone::mcp::compat::contracts();
        const std::size_t archive_count = aida::standalone::mcp::compat::contract_count();
        if (archive == nullptr || archive_count != k_compatibility_tool_count) {
            throw std::runtime_error("routing metadata archive inventory count mismatch");
        }
        for (std::size_t index = 0; index < archive_count; ++index) {
            if (!names.emplace(archive[index].name).second) {
                throw std::runtime_error("routing metadata archive inventory contains duplicate names");
            }
            result.push_back(metadata_from_descriptor(archive[index]));
        }
        for (const auto ext_name : k_aida_extension_names) {
            if (!names.emplace(ext_name).second) {
                throw std::runtime_error("routing metadata extension inventory overlaps compatibility names");
            }
            result.push_back(metadata_for_extension(ext_name));
        }
        if (result.size() != k_union_tool_count || names.size() != k_union_tool_count) {
            throw std::runtime_error("routing metadata union inventory count mismatch");
        }
        return result;
    }();
    return inventory;
}

const std::vector<std::string_view>& routing_metadata_names() {
    static const std::vector<std::string_view> names = []() {
        const auto& inventory = routing_metadata_inventory();
        std::vector<std::string_view> result;
        result.reserve(inventory.size());
        for (const auto& metadata : inventory) {
            result.emplace_back(metadata.name);
        }
        return result;
    }();
    return names;
}

const routing_metadata_t* find_routing_metadata(std::string_view name) {
    const auto& inventory = routing_metadata_inventory();
    const auto found = std::find_if(
        inventory.begin(), inventory.end(),
        [name](const routing_metadata_t& meta) { return meta.name == name; });
    return found == inventory.end() ? nullptr : &*found;
}

std::size_t routing_metadata_count() {
    return routing_metadata_names().size();
}

routing_extensions_t::routing_extensions_t(target_resolver_t& resolver,
                                           effect_lock_manager_t& lock_manager,
                                           routing_extension_workspace_handlers_t workspace_handlers,
                                           protocol::schema_runtime_t& schemas,
                                           routing_extension_limits_t limits)
    : resolver_(resolver), lock_manager_(lock_manager),
      workspace_handlers_(std::move(workspace_handlers)), schemas_(schemas),
      limits_(std::move(limits)) {
    if (!valid_limits(limits_)) {
        throw std::invalid_argument(
            "routing extension limits are invalid or weaken pinned maxima");
    }
    if (!workspace_handlers_.analyze_funcs || !workspace_handlers_.find_insns) {
        throw std::invalid_argument("retained workspace extension handlers are incomplete");
    }
    for (std::size_t index = 0; index < k_routing_extension_names.size(); ++index) {
        const auto name = k_routing_extension_names[index];
        contracts_[index] = make_extension_contract(name);
        const auto validation = protocol::validate_tool_contract(contracts_[index], schemas_);
        if (!validation.valid) {
            throw std::runtime_error(
                "routing extension contract validation failed for " + std::string(name) +
                ": " + validation.reason);
        }
        const auto* metadata = find_routing_metadata(name);
        if (metadata == nullptr || metadata->target_requirement != contracts_[index].target_policy.requirement ||
            metadata->accepts_pid != contracts_[index].target_policy.accepts_pid ||
            metadata->accepts_bin_name != contracts_[index].target_policy.accepts_bin_name ||
            metadata->effect != contracts_[index].effect_policy.effect ||
            metadata->lock != contracts_[index].effect_policy.lock ||
            metadata->read_only != contracts_[index].effect_policy.read_only) {
            throw std::runtime_error(
                "routing extension metadata differs from contract for " + std::string(name));
        }
    }
    refresh_known_instances(resolver_.snapshot());
}

std::size_t routing_extensions_t::size() const noexcept {
    return contracts_.size();
}

const protocol::tool_contract_t& routing_extensions_t::contract_at(std::size_t index) const {
    return contracts_.at(index);
}

const protocol::tool_contract_t* routing_extensions_t::find(std::string_view name) const noexcept {
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    return found == contracts_.end() ? nullptr : &*found;
}

const routing_extension_limits_t& routing_extensions_t::limits() const noexcept {
    return limits_;
}

protocol::mcp_result_t routing_extensions_t::invoke(
    std::string_view name, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const routing_extension_invocation_options_t& options,
    const protocol::json& aida_metadata) const {
    if (!aida_metadata.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::internal_error,
            "Routing extension provenance metadata must be a JSON object.",
            protocol::json{{"field", "aida_metadata"}});
    }
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    if (found == contracts_.end()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "Routing extension tool is not registered in the extension contract group.",
            protocol::json{{"tool", std::string(name)}},
            aida_metadata);
    }
    const std::size_t index = static_cast<std::size_t>(std::distance(contracts_.begin(), found));
    return protocol::invoke_tool_contract(
        *found,
        arguments,
        [this, index, &options](const protocol::json& validated_arguments,
                                 const protocol::cancellation_token_t& token) {
            return dispatch(index, validated_arguments, token, options);
        },
        schemas_,
        cancellation,
        aida_metadata);
}

protocol::mcp_result_t routing_extensions_t::dispatch(
    std::size_t index, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const routing_extension_invocation_options_t& options) const {
    const auto name = k_routing_extension_names.at(index);
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Routing extension invocation was cancelled before dispatch.",
            protocol::json{{"phase", "routing_pre_dispatch"}});
    }

    std::string serialized;
    try {
        serialized = arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Routing extension arguments cannot be serialized.",
            protocol::json{{"phase", "routing_serialization"}});
    }
    if (serialized.size() > limits_.max_request_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Routing extension request exceeds the bounded adapter quota.",
            exceeded_value(
                "request_bytes",
                static_cast<std::uint64_t>(limits_.max_request_bytes),
                static_cast<std::uint64_t>(serialized.size())));
    }
    if (auto failure = validate_tool_bounds(name, arguments, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Routing extension arguments violate the bounded adapter policy.",
            *failure);
    }

    if (name == "list_instances") {
        return handle_list_instances(arguments, cancellation);
    }
    if (name == "analyze_funcs") {
        return handle_analyze_funcs(arguments, cancellation, options);
    }
    if (name == "find_insns") {
        return handle_find_insns(arguments, cancellation, options);
    }
    if (name == "calculator") {
        return handle_calculator(arguments, cancellation);
    }
    if (name == "calculate") {
        return handle_calculate(arguments, cancellation);
    }
    return protocol::mcp_result_t::failure(
        protocol::result_error_code_t::invalid_contract,
        "Routing extension tool is not dispatched.",
        protocol::json{{"tool", std::string(name)}});
}

routing_extensions_t::known_instance_key_t routing_extensions_t::known_instance_key(
    const target_record_t& target) noexcept {
    return {
        target.target_id,
        target.process_creation_identity,
        target.generation,
        target.attach_generation,
    };
}

void routing_extensions_t::refresh_known_instances(
    const std::vector<target_record_t>& active) const {
    std::lock_guard<std::mutex> lock(known_instances_mutex_);
    for (auto& entry : known_instances_) {
        entry.second.retired = true;
    }
    for (const auto& target : active) {
        known_instances_[known_instance_key(target)] = known_instance_t{target, false};
    }
}

protocol::mcp_result_t routing_extensions_t::handle_list_instances(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "list_instances was cancelled before resolver snapshot.",
            protocol::json{{"phase", "list_instances_pre_snapshot"}});
    }

    const auto targets = resolver_.snapshot();
    refresh_known_instances(targets);

    json instances = json::array();
    json instance_identities = json::array();
    std::string filter;
    bool include_retired = false;
    if (const auto filter_val = arguments.find("filter"); filter_val != arguments.end()) {
        filter = filter_val->get<std::string>();
    }
    if (const auto retired_val = arguments.find("include_retired");
        retired_val != arguments.end()) {
        include_retired = retired_val->get<bool>();
    }

    std::size_t known_target_count = 0;
    {
        std::lock_guard<std::mutex> lock(known_instances_mutex_);
        known_target_count = known_instances_.size();
        for (const auto& entry : known_instances_) {
            const auto& known = entry.second;
            const auto& target = known.target;
            if (known.retired && !include_retired) {
                continue;
            }
            if (!filter.empty() && target.bin_name.find(filter) == std::string::npos) {
                continue;
            }
            instances.push_back(json{
                {"pid", target.pid},
                {"bin_name", target.bin_name},
            });
            instance_identities.push_back(json{
                {"target_id", target.target_id},
                {"pid", target.pid},
                {"bin_name", target.bin_name},
                {"generation", target.generation},
                {"attach_generation", target.attach_generation},
                {"live", target.live},
                {"retired", known.retired},
                {"snapshot_stale", target.live &&
                    (known.retired || !target.live_snapshot_permitted)},
                {"process_creation_identity", target.process_creation_identity},
                {"revision", target.revision},
            });
        }
    }

    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "list_instances was cancelled after resolver snapshot.",
            protocol::json{{"phase", "list_instances_post_snapshot"}});
    }

    json output{{"instances", std::move(instances)}};

    std::string payload = output.dump();
    return protocol::mcp_result_t::success(
        std::move(payload),
        std::move(output),
        protocol::json{
            {"resolver_target_count", targets.size()},
            {"known_target_count", known_target_count},
            {"include_retired", include_retired},
            {"instance_identities", std::move(instance_identities)},
        });
}

protocol::mcp_result_t routing_extensions_t::route_workspace_extension(
    std::string_view name,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const routing_extension_invocation_options_t& options) const {
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Routing extension was cancelled before target resolution.",
            protocol::json{{"phase", "extension_pre_route"}, {"tool", std::string(name)}});
    }

    const auto& descriptor = extension_adapter_descriptor(name);
    const auto policy = effect_policy_for(descriptor);
    if (!policy) {
        return effect_failure(policy.error);
    }

    adapter_request_t request;
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        const auto value = unsigned_integer(*pid);
        if (value) {
            request.target.pid = static_cast<std::uint32_t>(*value);
        }
    }
    if (const auto bin_name = arguments.find("bin_name"); bin_name != arguments.end()) {
        request.target.bin_name = bin_name->get<std::string>();
    }
    try {
        request.payload = arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Routing extension backend arguments cannot be serialized.",
            protocol::json{{"phase", "extension_serialization"}, {"tool", std::string(name)}});
    }
    request.expected_generation = options.expected_generation;
    const auto maximum_deadline = std::chrono::steady_clock::now() + limits_.max_execution_time;
    request.deadline = options.deadline.has_value()
        ? (std::min)(*options.deadline, maximum_deadline)
        : maximum_deadline;

    auto resolution = resolver_.resolve(request.target, request.expected_generation);
    if (!resolution) {
        return target_failure(resolution.error());
    }
    auto resolved = std::move(resolution).take_value();
    auto lease = lock_manager_.acquire(
        policy.value(), resolved.target().target_id, request.deadline);
    if (!lease) {
        return effect_failure(lease.error);
    }
    auto pin = resolver_.pin_current(resolved, request.expected_generation);
    if (!pin) {
        return target_failure(pin.error);
    }

    const adapter_handler_t* handler = nullptr;
    if (name == k_extension_tool_analyze_funcs) {
        handler = &workspace_handlers_.analyze_funcs;
    } else if (name == k_extension_tool_find_insns) {
        handler = &workspace_handlers_.find_insns;
    }
    if (handler == nullptr || !*handler) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::handler_failed,
            "Retained workspace extension handler is unavailable.",
            protocol::json{{"phase", "extension_backend"}, {"tool", std::string(name)}});
    }

    const adapter_call_context_t context{
        &descriptor,
        std::optional<target_resolution_t>{pin.pin.resolution()},
        policy.value(),
    };
    auto adapter_result = (*handler)(context, request);
    if (!adapter_result) {
        return adapter_failure(adapter_result.error());
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Routing extension was cancelled during retained handler execution.",
            protocol::json{{"phase", "extension_post_adapter"}, {"tool", std::string(name)}});
    }

    auto response = std::move(adapter_result).take_value();
    if (response.payload.empty()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Retained workspace extension response is empty.",
            invalid_value("response_bytes", "nonempty_response_required", 0));
    }
    if (response.payload.size() > limits_.max_response_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Retained workspace extension response violates the output byte quota.",
            exceeded_value(
                "response_bytes",
                static_cast<std::uint64_t>(limits_.max_response_bytes),
                static_cast<std::uint64_t>(response.payload.size())));
    }
    protocol::json structured = protocol::json::parse(response.payload, nullptr, false);
    if (structured.is_discarded() || !structured.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Retained workspace extension returned malformed structured output.",
            protocol::json{{"phase", "extension_output_parse"},
                           {"tool", std::string(name)},
                           {"response_bytes", response.payload.size()}});
    }

    const std::size_t response_bytes = response.payload.size();
    return protocol::mcp_result_t::success(
        std::move(response.payload),
        std::move(structured),
        protocol::json{
            {"adapter_truncated", response.truncated},
            {"adapter_response_bytes", response_bytes},
            {"retained_extension", std::string(name)},
            {"target_id", resolved.target().target_id},
            {"target_generation", resolved.target().generation},
        });
}

protocol::mcp_result_t routing_extensions_t::handle_analyze_funcs(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const routing_extension_invocation_options_t& options) const {
    return route_workspace_extension(
        k_extension_tool_analyze_funcs, arguments, cancellation, options);
}

protocol::mcp_result_t routing_extensions_t::handle_find_insns(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const routing_extension_invocation_options_t& options) const {
    return route_workspace_extension(
        k_extension_tool_find_insns, arguments, cancellation, options);
}

protocol::mcp_result_t routing_extensions_t::handle_calculator(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    return invoke_retained_calculator(
        k_extension_tool_calculator, arguments, cancellation, limits_.max_execution_time);
}

protocol::mcp_result_t routing_extensions_t::handle_calculate(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    return invoke_retained_calculator(
        k_extension_tool_calculate, arguments, cancellation, limits_.max_execution_time);
}

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t list_instances(
    const handlers::routing_extensions_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata) {
    return handlers.invoke("list_instances", arguments, cancellation, {}, aida_metadata);
}

protocol::mcp_result_t analyze_funcs(
    const handlers::routing_extensions_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::routing_extension_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("analyze_funcs", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t find_insns(
    const handlers::routing_extensions_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::routing_extension_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("find_insns", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t calculator(
    const handlers::routing_extensions_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata) {
    return handlers.invoke("calculator", arguments, cancellation, {}, aida_metadata);
}

protocol::mcp_result_t calculate(
    const handlers::routing_extensions_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata) {
    return handlers.invoke("calculate", arguments, cancellation, {}, aida_metadata);
}

}
