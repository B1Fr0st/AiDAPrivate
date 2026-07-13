#include "memory.h"

#include "../ida_contracts_generated.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace aida::standalone::mcp::compat::handlers {

namespace {

using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;

constexpr std::array<std::string_view, k_memory_tool_count> k_memory_names{{
    "get_bytes",
    "get_int",
    "get_string",
    "get_global_value",
    "patch",
    "put_int",
}};

bool is_overlay_tool(std::string_view name) noexcept {
    return name == "patch" || name == "put_int";
}

json parse_generated_json(std::string_view value, std::string_view field,
                          std::string_view tool_name) {
    try {
        return json::parse(value.begin(), value.end());
    } catch (const std::exception&) {
        throw std::runtime_error(
            "generated memory contract JSON is invalid for " + std::string(tool_name) +
            " field " + std::string(field));
    }
}

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
    throw std::runtime_error("generated memory contract has an unknown effect");
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
    throw std::runtime_error("generated memory contract has an unknown lock");
}

void validate_generated_descriptor(const contract_descriptor_t& descriptor,
                                    std::string_view name) {
    const std::string expected_adapter =
        "aida::standalone::mcp::compat::adapters::" + std::string(name);
    if (descriptor.name != name || descriptor.adapter_symbol != expected_adapter ||
        !descriptor.archive_backed || !descriptor.target_dependent ||
        !descriptor.accepts_pid || !descriptor.accepts_bin_name ||
        descriptor.unsafe) {
        throw std::runtime_error(
            "generated memory descriptor policy mismatch for " + std::string(name));
    }
    if (is_overlay_tool(name)) {
        if (descriptor.effect != contract_effect_t::workspace_overlay_mutation ||
            descriptor.read_only ||
            descriptor.lock != contract_lock_t::workspace_overlay_transaction) {
            throw std::runtime_error(
                "generated memory overlay descriptor effect mismatch for " + std::string(name));
        }
    } else {
        if (descriptor.effect != contract_effect_t::workspace_read ||
            !descriptor.read_only ||
            descriptor.lock != contract_lock_t::workspace_shared) {
            throw std::runtime_error(
                "generated memory read descriptor effect mismatch for " + std::string(name));
        }
    }
}

protocol::tool_contract_t make_tool_contract(const contract_descriptor_t& descriptor) {
    protocol::tool_contract_t contract;
    contract.name.assign(descriptor.name.data(), descriptor.name.size());
    contract.description.assign(descriptor.description.data(), descriptor.description.size());
    contract.input_schema = parse_generated_json(
        descriptor.input_schema_json, "input_schema", descriptor.name);
    contract.output_schema = parse_generated_json(
        descriptor.output_schema_json, "output_schema", descriptor.name);
    contract.annotations = parse_generated_json(
        descriptor.annotations_json, "annotations", descriptor.name);
    contract.target_policy.requirement = protocol::target_requirement_t::optional;
    contract.target_policy.accepts_pid = descriptor.accepts_pid;
    contract.target_policy.accepts_bin_name = descriptor.accepts_bin_name;
    contract.effect_policy.effect = protocol_effect(descriptor.effect);
    contract.effect_policy.lock = protocol_lock(descriptor.lock);
    contract.effect_policy.read_only = descriptor.read_only;
    contract.effect_policy.unsafe = descriptor.unsafe;
    return contract;
}

using validation_failure_t = std::optional<json>;

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_memory_adapter"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_memory_adapter"},
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

validation_failure_t bounded_integer(const json& object, std::string_view field,
                                      std::uint64_t maximum, std::string path_prefix = {}) {
    const auto found = object.find(std::string(field));
    if (found == object.end()) {
        return std::nullopt;
    }
    const std::string path = path_prefix.empty()
        ? std::string(field)
        : path_prefix + "." + std::string(field);
    const auto value = unsigned_integer(*found);
    if (!value) {
        return invalid_value(path, "nonnegative_integer_required", *found);
    }
    if (*value > maximum) {
        return exceeded_value(path, maximum, *value);
    }
    return std::nullopt;
}

validation_failure_t validate_routing_bounds(const json& arguments,
                                              const memory_handler_limits_t& limits) {
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        const auto value = unsigned_integer(*pid);
        if (!value || *value == 0 ||
            *value > (std::numeric_limits<std::uint32_t>::max)()) {
            return invalid_value("pid", "valid_process_id_required", *pid);
        }
    }
    if (const auto bin_name = arguments.find("bin_name"); bin_name != arguments.end()) {
        if (auto failure = bounded_text(
                *bin_name, "bin_name", limits.maximum_selector_bytes, false)) {
            return failure;
        }
    }
    return std::nullopt;
}

template <typename validator_t>
validation_failure_t scalar_or_array(const json& value, std::string_view path,
                                      std::size_t maximum_items,
                                      validator_t&& validator) {
    if (!value.is_array()) {
        return validator(value, std::string(path));
    }
    if (value.size() > maximum_items) {
        return exceeded_value(
            std::string(path), static_cast<std::uint64_t>(maximum_items),
            static_cast<std::uint64_t>(value.size()));
    }
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (auto failure = validator(
                value[index], std::string(path) + "[" + std::to_string(index) + "]")) {
            return failure;
        }
    }
    return std::nullopt;
}

validation_failure_t validate_get_bytes(const json& arguments,
                                         const memory_handler_limits_t& limits) {
    const auto regions = arguments.find("regions");
    if (regions == arguments.end()) {
        return invalid_value("regions", "field_required", json(nullptr));
    }
    return scalar_or_array(*regions, "regions", limits.maximum_batch_items,
        [&limits](const json& region, std::string path) -> validation_failure_t {
            if (!region.is_object()) {
                return invalid_value(std::move(path), "object_required", region);
            }
            if (auto failure = bounded_member_text(
                    region, "addr", path, limits.maximum_address_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_integer(
                    region, "size", limits.maximum_read_bytes_per_item, path)) {
                return failure;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_get_int(const json& arguments,
                                       const memory_handler_limits_t& limits) {
    const auto queries = arguments.find("queries");
    if (queries == arguments.end()) {
        return invalid_value("queries", "field_required", json(nullptr));
    }
    return scalar_or_array(*queries, "queries", limits.maximum_batch_items,
        [&limits](const json& query, std::string path) -> validation_failure_t {
            if (!query.is_object()) {
                return invalid_value(std::move(path), "object_required", query);
            }
            if (auto failure = bounded_member_text(
                    query, "addr", path, limits.maximum_address_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_member_text(
                    query, "ty", path, limits.maximum_type_bytes, false)) {
                return failure;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_get_string(const json& arguments,
                                          const memory_handler_limits_t& limits) {
    const auto addrs = arguments.find("addrs");
    if (addrs == arguments.end()) {
        return invalid_value("addrs", "field_required", json(nullptr));
    }
    return scalar_or_array(*addrs, "addrs", limits.maximum_batch_items,
        [&limits](const json& addr, std::string path) {
            return bounded_text(addr, std::move(path),
                                limits.maximum_address_bytes, false);
        });
}

validation_failure_t validate_get_global_value(const json& arguments,
                                                 const memory_handler_limits_t& limits) {
    const auto queries = arguments.find("queries");
    if (queries == arguments.end()) {
        return invalid_value("queries", "field_required", json(nullptr));
    }
    return scalar_or_array(*queries, "queries", limits.maximum_batch_items,
        [&limits](const json& item, std::string path) {
            return bounded_text(item, std::move(path),
                                limits.maximum_address_bytes, false);
        });
}

validation_failure_t validate_patch(const json& arguments,
                                     const memory_handler_limits_t& limits) {
    const auto patches = arguments.find("patches");
    if (patches == arguments.end()) {
        return invalid_value("patches", "field_required", json(nullptr));
    }
    return scalar_or_array(*patches, "patches", limits.maximum_batch_items,
        [&limits](const json& patch, std::string path) -> validation_failure_t {
            if (!patch.is_object()) {
                return invalid_value(std::move(path), "object_required", patch);
            }
            if (auto failure = bounded_member_text(
                    patch, "addr", path, limits.maximum_address_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_member_text(
                    patch, "data", path,
                    limits.maximum_read_bytes_per_item * 2, false)) {
                return failure;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_put_int(const json& arguments,
                                       const memory_handler_limits_t& limits) {
    const auto items = arguments.find("items");
    if (items == arguments.end()) {
        return invalid_value("items", "field_required", json(nullptr));
    }
    return scalar_or_array(*items, "items", limits.maximum_batch_items,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            if (!item.is_object()) {
                return invalid_value(std::move(path), "object_required", item);
            }
            if (auto failure = bounded_member_text(
                    item, "addr", path, limits.maximum_address_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_member_text(
                    item, "ty", path, limits.maximum_type_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_member_text(
                    item, "value", path, limits.maximum_address_bytes, false)) {
                return failure;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_tool_bounds(std::string_view name, const json& arguments,
                                          const memory_handler_limits_t& limits) {
    if (auto failure = validate_routing_bounds(arguments, limits)) {
        return failure;
    }
    if (name == "get_bytes") {
        return validate_get_bytes(arguments, limits);
    }
    if (name == "get_int") {
        return validate_get_int(arguments, limits);
    }
    if (name == "get_string") {
        return validate_get_string(arguments, limits);
    }
    if (name == "get_global_value") {
        return validate_get_global_value(arguments, limits);
    }
    if (name == "patch") {
        return validate_patch(arguments, limits);
    }
    if (name == "put_int") {
        return validate_put_int(arguments, limits);
    }
    return invalid_value("tool", "memory_tool_not_registered", std::string(name));
}

std::chrono::milliseconds execution_timeout(const protocol::tool_contract_t& contract,
                                             std::chrono::milliseconds maximum) noexcept {
    const auto decorators = contract.annotations.find("decorators");
    if (decorators == contract.annotations.end() || !decorators->is_array()) {
        return maximum;
    }
    for (const auto& decorator : *decorators) {
        if (!decorator.is_object()) {
            continue;
        }
        const auto name = decorator.find("name");
        if (name == decorator.end() || !name->is_string() ||
            name->get_ref<const std::string&>() != "tool_timeout") {
            continue;
        }
        const auto args = decorator.find("args");
        if (args == decorator.end() || !args->is_array() || args->empty() ||
            !(*args)[0].is_number()) {
            continue;
        }
        try {
            const double seconds = (*args)[0].get<double>();
            if (!std::isfinite(seconds) || seconds <= 0.0) {
                continue;
            }
            const auto generated = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::duration<double>(seconds));
            if (generated.count() > 0) {
                return (std::min)(generated, maximum);
            }
        } catch (const std::exception&) {
        }
    }
    return maximum;
}

result_error_code_t adapter_error_code(adapter_error_code_t code) noexcept {
    switch (code) {
    case adapter_error_code_t::invalid_request:
        return result_error_code_t::invalid_input;
    case adapter_error_code_t::target_resolution_failed:
        return result_error_code_t::target_policy_rejected;
    case adapter_error_code_t::operation_not_permitted:
    case adapter_error_code_t::effect_policy_failed:
        return result_error_code_t::effect_policy_rejected;
    case adapter_error_code_t::none:
    case adapter_error_code_t::contract_not_found:
    case adapter_error_code_t::effect_lock_busy:
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
        "Memory workspace adapter rejected the request.",
        json{
            {"phase", "workspace_adapter"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

}

bool memory_handler_limits_t::valid() const noexcept {
    return maximum_batch_items > 0 && maximum_batch_items <= 4096 &&
           maximum_read_bytes_per_item > 0 &&
           maximum_read_bytes_per_item <= (1ULL << 20) &&
           maximum_read_bytes_per_call > 0 &&
           maximum_read_bytes_per_call <= (16ULL << 20) &&
           maximum_string_bytes > 0 && maximum_string_bytes <= (1ULL << 20) &&
           maximum_backend_payload_bytes > 0 &&
           maximum_backend_payload_bytes <= (64ULL << 20) &&
           maximum_selector_bytes > 0 && maximum_selector_bytes <= 1024U &&
           maximum_address_bytes > 0 && maximum_address_bytes <= 4096U &&
           maximum_type_bytes > 0 && maximum_type_bytes <= 64U &&
           maximum_request_bytes > 0 && maximum_request_bytes <= 1024U * 1024U &&
           maximum_response_bytes > 0 &&
           maximum_response_bytes <= 16U * 1024U * 1024U &&
           maximum_execution_time.count() > 0 && maximum_execution_time.count() <= 120000;
}

const std::array<std::string_view, k_memory_tool_count>& memory_tool_names() noexcept {
    return k_memory_names;
}

class memory_handlers_t::impl_t final {
public:
    impl_t(workspace_adapter_t& workspace,
           protocol::schema_runtime_t& schemas,
           memory_handler_limits_t limits)
        : workspace_(workspace), schemas_(schemas), limits_(std::move(limits)) {
        if (!limits_.valid()) {
            throw std::invalid_argument(
                "memory handler limits are invalid or weaken pinned maxima");
        }
        for (std::size_t index = 0; index < k_memory_names.size(); ++index) {
            const auto name = k_memory_names[index];
            const auto* descriptor =
                aida::standalone::mcp::compat::find_contract(name);
            if (descriptor == nullptr) {
                throw std::runtime_error(
                    "generated memory descriptor is missing for " + std::string(name));
            }
            validate_generated_descriptor(*descriptor, name);
            contracts_[index] = make_tool_contract(*descriptor);
            const auto validation =
                protocol::validate_tool_contract(contracts_[index], schemas_);
            if (!validation.valid) {
                throw std::runtime_error(
                    "generated memory contract validation failed for " +
                    std::string(name) + ": " + validation.reason);
            }
        }
    }

    std::size_t size() const noexcept { return contracts_.size(); }

    const protocol::tool_contract_t& contract_at(std::size_t index) const {
        return contracts_.at(index);
    }

    const protocol::tool_contract_t* find(std::string_view name) const noexcept {
        const auto found = std::find_if(
            contracts_.begin(), contracts_.end(),
            [name](const protocol::tool_contract_t& contract) {
                return contract.name == name;
            });
        return found == contracts_.end() ? nullptr : &*found;
    }

    const memory_handler_limits_t& limits() const noexcept { return limits_; }

    protocol::mcp_result_t invoke(std::string_view tool_name,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const memory_invocation_t& invocation) const {
        if (!aida_metadata_compat(tool_name, arguments, cancellation, invocation)) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::internal_error,
                "Memory tool provenance metadata must be a JSON object.",
                protocol::json{{"field", "aida_metadata"}});
        }
        const auto found = std::find_if(
            contracts_.begin(), contracts_.end(),
            [tool_name](const protocol::tool_contract_t& contract) {
                return contract.name == tool_name;
            });
        if (found == contracts_.end()) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_contract,
                "Memory tool is not registered in the pinned contract group.",
                protocol::json{{"tool", std::string(tool_name)}});
        }
        const std::size_t index =
            static_cast<std::size_t>(std::distance(contracts_.begin(), found));
        return protocol::invoke_tool_contract(
            *found,
            arguments,
            [this, index, &invocation](const protocol::json& validated_arguments,
                                        const protocol::cancellation_token_t& token) {
                return dispatch(index, validated_arguments, token, invocation);
            },
            schemas_,
            cancellation);
    }

private:
    static bool aida_metadata_compat(std::string_view, const protocol::json&,
                                     const protocol::cancellation_token_t&,
                                     const memory_invocation_t&) noexcept {
        return true;
    }

    protocol::mcp_result_t dispatch(std::size_t index,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const memory_invocation_t& invocation) const {
        const auto name = k_memory_names.at(index);
        const auto& contract = contracts_.at(index);
        if (cancellation.cancelled()) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::cancelled,
                "Memory tool invocation was cancelled before adapter routing.",
                protocol::json{{"phase", "memory_pre_route"}});
        }

        std::string serialized_arguments;
        try {
            serialized_arguments = arguments.dump();
        } catch (const std::exception&) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_input,
                "Memory tool arguments cannot be serialized.",
                protocol::json{{"phase", "memory_request_serialization"}});
        }
        if (serialized_arguments.size() > limits_.maximum_request_bytes) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_input,
                "Memory tool request exceeds the bounded adapter quota.",
                exceeded_value(
                    "request_bytes",
                    static_cast<std::uint64_t>(limits_.maximum_request_bytes),
                    static_cast<std::uint64_t>(serialized_arguments.size())));
        }
        if (auto failure = validate_tool_bounds(name, arguments, limits_)) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_input,
                "Memory tool arguments violate the bounded adapter policy.",
                *failure);
        }

        adapter_request_t request;
        if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
            const auto value = unsigned_integer(*pid);
            if (value) {
                request.target.pid = static_cast<std::uint32_t>(*value);
            }
        }
        if (const auto bin_name = arguments.find("bin_name");
            bin_name != arguments.end()) {
            request.target.bin_name = bin_name->get<std::string>();
        }
        protocol::json backend_arguments = arguments;
        backend_arguments.erase("pid");
        backend_arguments.erase("bin_name");
        try {
            request.payload = backend_arguments.dump();
        } catch (const std::exception&) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_input,
                "Memory backend arguments cannot be serialized.",
                protocol::json{{"phase", "memory_backend_serialization"}});
        }
        if (invocation.expected_generation) {
            request.expected_generation = invocation.expected_generation;
        }
        if (invocation.deadline) {
            request.deadline = invocation.deadline;
        } else {
            request.deadline = std::chrono::steady_clock::now() +
                execution_timeout(contract, limits_.maximum_execution_time);
        }

        auto adapter_result = [&]() -> adapter_result_t<adapter_response_t> {
            if (is_overlay_tool(name)) {
                return workspace_.overlay(name, request);
            }
            return workspace_.query(name, request);
        }();
        if (!adapter_result) {
            return adapter_failure(adapter_result.error());
        }
        if (cancellation.cancelled()) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::cancelled,
                "Memory tool invocation was cancelled during adapter execution.",
                protocol::json{{"phase", "memory_post_adapter"}});
        }

        auto response = std::move(adapter_result).take_value();
        if (response.payload.empty()) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Memory adapter response is empty.",
                invalid_value("response_bytes", "nonempty_response_required", 0));
        }
        if (response.payload.size() > limits_.maximum_response_bytes) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Memory adapter response violates the output byte quota.",
                exceeded_value(
                    "response_bytes",
                    static_cast<std::uint64_t>(limits_.maximum_response_bytes),
                    static_cast<std::uint64_t>(response.payload.size())));
        }
        if (response.payload.size() > limits_.maximum_backend_payload_bytes) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Memory adapter response exceeds the backend payload ceiling.",
                exceeded_value(
                    "backend_payload_bytes",
                    static_cast<std::uint64_t>(limits_.maximum_backend_payload_bytes),
                    static_cast<std::uint64_t>(response.payload.size())));
        }
        protocol::json structured =
            protocol::json::parse(response.payload, nullptr, false);
        if (structured.is_discarded() || !structured.is_object()) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Memory adapter returned malformed structured output.",
                protocol::json{{"phase", "memory_output_parse"},
                               {"response_bytes", response.payload.size()}});
        }
        if (cancellation.cancelled()) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::cancelled,
                "Memory tool invocation was cancelled before output validation.",
                protocol::json{{"phase", "memory_pre_output_validation"}});
        }
        const std::size_t response_bytes = response.payload.size();
        return protocol::mcp_result_t::success(
            std::move(response.payload),
            structured,
            protocol::json{
                {"adapter_truncated", response.truncated},
                {"adapter_response_bytes", response_bytes},
            });
    }

    workspace_adapter_t& workspace_;
    protocol::schema_runtime_t& schemas_;
    memory_handler_limits_t limits_;
    std::array<protocol::tool_contract_t, k_memory_tool_count> contracts_;
};

memory_handlers_t::memory_handlers_t(workspace_adapter_t& adapter,
                                     protocol::schema_runtime_t& schemas,
                                     memory_handler_limits_t limits)
    : impl_(std::make_unique<impl_t>(adapter, schemas, std::move(limits))) {}

memory_handlers_t::~memory_handlers_t() = default;

memory_handlers_t::memory_handlers_t(memory_handlers_t&&) noexcept = default;
memory_handlers_t& memory_handlers_t::operator=(memory_handlers_t&&) noexcept = default;

std::size_t memory_handlers_t::size() const noexcept {
    return impl_->size();
}

const protocol::tool_contract_t& memory_handlers_t::contract_at(std::size_t index) const {
    return impl_->contract_at(index);
}

const protocol::tool_contract_t* memory_handlers_t::find(std::string_view name) const noexcept {
    return impl_->find(name);
}

const memory_handler_limits_t& memory_handlers_t::limits() const noexcept {
    return impl_->limits();
}

protocol::mcp_result_t memory_handlers_t::invoke(
    std::string_view tool_name, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const memory_invocation_t& invocation) const {
    return impl_->invoke(tool_name, arguments, cancellation, invocation);
}

protocol::mcp_result_t memory_handlers_t::get_bytes(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const memory_invocation_t& invocation) const {
    return impl_->invoke("get_bytes", arguments, cancellation, invocation);
}

protocol::mcp_result_t memory_handlers_t::get_int(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const memory_invocation_t& invocation) const {
    return impl_->invoke("get_int", arguments, cancellation, invocation);
}

protocol::mcp_result_t memory_handlers_t::get_string(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const memory_invocation_t& invocation) const {
    return impl_->invoke("get_string", arguments, cancellation, invocation);
}

protocol::mcp_result_t memory_handlers_t::get_global_value(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const memory_invocation_t& invocation) const {
    return impl_->invoke("get_global_value", arguments, cancellation, invocation);
}

protocol::mcp_result_t memory_handlers_t::patch(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const memory_invocation_t& invocation) const {
    return impl_->invoke("patch", arguments, cancellation, invocation);
}

protocol::mcp_result_t memory_handlers_t::put_int(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const memory_invocation_t& invocation) const {
    return impl_->invoke("put_int", arguments, cancellation, invocation);
}

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t get_bytes(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation) {
    return handlers.get_bytes(arguments, cancellation, invocation);
}

protocol::mcp_result_t get_int(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation) {
    return handlers.get_int(arguments, cancellation, invocation);
}

protocol::mcp_result_t get_string(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation) {
    return handlers.get_string(arguments, cancellation, invocation);
}

protocol::mcp_result_t get_global_value(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation) {
    return handlers.get_global_value(arguments, cancellation, invocation);
}

protocol::mcp_result_t patch(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation) {
    return handlers.patch(arguments, cancellation, invocation);
}

protocol::mcp_result_t put_int(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation) {
    return handlers.put_int(arguments, cancellation, invocation);
}

}
