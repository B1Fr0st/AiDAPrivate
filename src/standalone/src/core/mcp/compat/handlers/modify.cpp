#include "modify.hpp"

#include "../ida_contracts_generated.hpp"

#include <algorithm>
#include <cmath>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>

namespace aida::standalone::mcp::compat::handlers {

namespace {

using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;

constexpr std::array<std::string_view, k_modify_tool_count> k_modify_names{{
    "set_comments",
    "append_comments",
    "rename",
    "define_code",
    "define_func",
    "undefine",
    "make_data",
    "patch_asm",
    "force_recompile",
    "set_op_type",
    "set_type",
}};

json parse_generated_json(std::string_view value, std::string_view field,
                          std::string_view tool_name) {
    try {
        return json::parse(value.begin(), value.end());
    } catch (const std::exception&) {
        throw std::runtime_error(
            "generated modify contract JSON is invalid for " + std::string(tool_name) +
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
    throw std::runtime_error("generated modify contract has an unknown effect");
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
    throw std::runtime_error("generated modify contract has an unknown lock");
}

void validate_generated_descriptor(const contract_descriptor_t& descriptor,
                                    std::string_view name) {
    const std::string expected_adapter =
        "aida::standalone::mcp::compat::adapters::" + std::string(name);
    if (descriptor.name != name || descriptor.adapter_symbol != expected_adapter ||
        !descriptor.archive_backed || !descriptor.target_dependent ||
        !descriptor.accepts_pid || !descriptor.accepts_bin_name ||
        descriptor.read_only || descriptor.unsafe ||
        descriptor.effect != contract_effect_t::workspace_overlay_mutation ||
        descriptor.lock != contract_lock_t::workspace_overlay_transaction) {
        throw std::runtime_error(
            "generated modify descriptor policy mismatch for " + std::string(name));
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

bool valid_limits(const modify_handler_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 &&
        limits.max_request_bytes <= 1024U * 1024U &&
        limits.max_response_bytes != 0 &&
        limits.max_response_bytes <= 16U * 1024U * 1024U &&
        limits.max_selector_bytes != 0 && limits.max_selector_bytes <= 1024U &&
        limits.max_address_bytes != 0 && limits.max_address_bytes <= 4096U &&
        limits.max_batch_items != 0 && limits.max_batch_items <= 4096U &&
        limits.max_comment_bytes != 0 && limits.max_comment_bytes <= 4096U &&
        limits.max_data_bytes != 0 && limits.max_data_bytes <= 1024U * 1024U &&
        limits.max_type_bytes != 0 && limits.max_type_bytes <= 4096U &&
        limits.max_asm_bytes != 0 && limits.max_asm_bytes <= 4096U &&
        limits.max_rename_batch_items != 0 && limits.max_rename_batch_items <= 4096U &&
        limits.max_name_bytes != 0 && limits.max_name_bytes <= 4096U &&
        limits.max_type_batch_items != 0 && limits.max_type_batch_items <= 4096U &&
        limits.max_op_kind_bytes != 0 && limits.max_op_kind_bytes <= 64U &&
        limits.max_execution_time.count() > 0 && limits.max_execution_time.count() <= 60000;
}

using validation_failure_t = std::optional<json>;

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_modify_adapter"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_modify_adapter"},
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
                                              const modify_handler_limits_t& limits) {
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        const auto value = unsigned_integer(*pid);
        if (!value || *value == 0 ||
            *value > (std::numeric_limits<std::uint32_t>::max)()) {
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

validation_failure_t require_array(const json& value, std::string_view path,
                                    std::size_t maximum_items) {
    if (!value.is_array()) {
        return invalid_value(std::string(path), "array_required", value);
    }
    if (value.size() > maximum_items) {
        return exceeded_value(
            std::string(path), static_cast<std::uint64_t>(maximum_items),
            static_cast<std::uint64_t>(value.size()));
    }
    return std::nullopt;
}

validation_failure_t validate_item_array(const json& arguments, std::string_view field,
                                          std::size_t max_items,
                                          const modify_handler_limits_t& limits,
                                          bool check_addr = true) {
    const auto found = arguments.find(std::string(field));
    if (found == arguments.end()) {
        return invalid_value(std::string(field), "field_required", json(nullptr));
    }
    if (auto failure = require_array(*found, field, max_items)) {
        return failure;
    }
    for (std::size_t index = 0; index < found->size(); ++index) {
        const std::string path = std::string(field) + "[" + std::to_string(index) + "]";
        const auto& item = (*found)[index];
        if (!item.is_object()) {
            return invalid_value(path, "object_required", item);
        }
        if (check_addr) {
            if (auto failure = bounded_member_text(
                    item, "addr", path, limits.max_address_bytes, false)) {
                return failure;
            }
        }
    }
    return std::nullopt;
}

validation_failure_t validate_tool_bounds(std::string_view name, const json& arguments,
                                          const modify_handler_limits_t& limits) {
    if (auto failure = validate_routing_bounds(arguments, limits)) {
        return failure;
    }
    if (name == "set_comments" || name == "append_comments") {
        if (auto failure = validate_item_array(arguments, "items",
                                                 limits.max_batch_items, limits)) {
            return failure;
        }
        const auto& items = arguments.at("items");
        for (std::size_t i = 0; i < items.size(); ++i) {
            const std::string path = "items[" + std::to_string(i) + "]";
            if (auto failure = bounded_member_text(
                    items[i], "comment", path, limits.max_comment_bytes, false)) {
                return failure;
            }
        }
        return std::nullopt;
    }
    if (name == "rename") {
        const auto batch = arguments.find("batch");
        if (batch == arguments.end() || !batch->is_object()) {
            return invalid_value("batch", "object_required",
                                  batch == arguments.end() ? json(nullptr) : *batch);
        }
        const auto func = batch->find("func");
        if (func == batch->end() || !func->is_array()) {
            return invalid_value("batch.func", "array_required",
                                  func == batch->end() ? json(nullptr) : *func);
        }
        if (func->size() > limits.max_rename_batch_items) {
            return exceeded_value("batch.func",
                                   static_cast<std::uint64_t>(limits.max_rename_batch_items),
                                   static_cast<std::uint64_t>(func->size()));
        }
        for (std::size_t i = 0; i < func->size(); ++i) {
            const std::string path = "batch.func[" + std::to_string(i) + "]";
            const auto& item = (*func)[i];
            if (!item.is_object()) {
                return invalid_value(path, "object_required", item);
            }
            if (auto failure = bounded_member_text(
                    item, "addr", path, limits.max_address_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_member_text(
                    item, "name", path, limits.max_name_bytes, false)) {
                return failure;
            }
        }
        return std::nullopt;
    }
    if (name == "define_code" || name == "define_func") {
        return validate_item_array(arguments, "items", limits.max_batch_items, limits);
    }
    if (name == "undefine") {
        if (auto failure = validate_item_array(arguments, "items",
                                                 limits.max_batch_items, limits)) {
            return failure;
        }
        const auto& items = arguments.at("items");
        for (std::size_t i = 0; i < items.size(); ++i) {
            const std::string path = "items[" + std::to_string(i) + "]";
            if (auto failure = bounded_integer(
                    items[i], "size", limits.max_data_bytes, path)) {
                return failure;
            }
        }
        return std::nullopt;
    }
    if (name == "make_data") {
        if (auto failure = validate_item_array(arguments, "items",
                                                 limits.max_batch_items, limits)) {
            return failure;
        }
        const auto& items = arguments.at("items");
        for (std::size_t i = 0; i < items.size(); ++i) {
            const std::string path = "items[" + std::to_string(i) + "]";
            if (auto failure = bounded_member_text(
                    items[i], "type", path, limits.max_type_bytes, false)) {
                return failure;
            }
        }
        return std::nullopt;
    }
    if (name == "patch_asm") {
        if (auto failure = validate_item_array(arguments, "items",
                                                 limits.max_batch_items, limits)) {
            return failure;
        }
        const auto& items = arguments.at("items");
        for (std::size_t i = 0; i < items.size(); ++i) {
            const std::string path = "items[" + std::to_string(i) + "]";
            if (auto failure = bounded_member_text(
                    items[i], "asm", path, limits.max_asm_bytes, false)) {
                return failure;
            }
        }
        return std::nullopt;
    }
    if (name == "force_recompile") {
        const auto found = arguments.find("items");
        if (found == arguments.end()) {
            return invalid_value("items", "field_required", json(nullptr));
        }
        if (!found->is_array()) {
            return invalid_value("items", "array_required", *found);
        }
        if (found->size() > limits.max_batch_items) {
            return exceeded_value("items",
                                   static_cast<std::uint64_t>(limits.max_batch_items),
                                   static_cast<std::uint64_t>(found->size()));
        }
        for (std::size_t i = 0; i < found->size(); ++i) {
            const std::string path = "items[" + std::to_string(i) + "]";
            const auto& item = (*found)[i];
            if (!item.is_object()) {
                return invalid_value(path, "object_required", item);
            }
            if (auto failure = bounded_member_text(
                    item, "addr", path, limits.max_address_bytes, false)) {
                return failure;
            }
        }
        return std::nullopt;
    }
    if (name == "set_op_type") {
        if (auto failure = validate_item_array(arguments, "items",
                                                 limits.max_batch_items, limits)) {
            return failure;
        }
        const auto& items = arguments.at("items");
        for (std::size_t i = 0; i < items.size(); ++i) {
            const std::string path = "items[" + std::to_string(i) + "]";
            if (auto failure = bounded_member_text(
                    items[i], "kind", path, limits.max_op_kind_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_integer(
                    items[i], "op_n", (std::numeric_limits<std::uint64_t>::max)(), path)) {
                return failure;
            }
        }
        return std::nullopt;
    }
    if (name == "set_type") {
        const auto found = arguments.find("edits");
        if (found == arguments.end()) {
            return invalid_value("edits", "field_required", json(nullptr));
        }
        if (auto failure = require_array(*found, "edits", limits.max_type_batch_items)) {
            return failure;
        }
        for (std::size_t i = 0; i < found->size(); ++i) {
            const std::string path = "edits[" + std::to_string(i) + "]";
            const auto& item = (*found)[i];
            if (!item.is_object()) {
                return invalid_value(path, "object_required", item);
            }
            if (auto failure = bounded_member_text(
                    item, "addr", path, limits.max_address_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_member_text(
                    item, "ty", path, limits.max_type_bytes, false)) {
                return failure;
            }
        }
        return std::nullopt;
    }
    return invalid_value("tool", "modify_tool_not_registered", std::string(name));
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
        "Modify workspace adapter rejected the request.",
        json{
            {"phase", "workspace_adapter"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

}

const std::array<std::string_view, k_modify_tool_count>& modify_tool_names() noexcept {
    return k_modify_names;
}

modify_handlers_t::modify_handlers_t(workspace_adapter_t& workspace,
                                      protocol::schema_runtime_t& schemas,
                                      modify_handler_limits_t limits)
    : workspace_(workspace), schemas_(schemas), limits_(std::move(limits)) {
    if (!valid_limits(limits_)) {
        throw std::invalid_argument(
            "modify handler limits are invalid or weaken pinned maxima");
    }
    for (std::size_t index = 0; index < k_modify_names.size(); ++index) {
        const auto name = k_modify_names[index];
        const auto* descriptor =
            aida::standalone::mcp::compat::find_contract(name);
        if (descriptor == nullptr) {
            throw std::runtime_error(
                "generated modify descriptor is missing for " + std::string(name));
        }
        validate_generated_descriptor(*descriptor, name);
        contracts_[index] = make_tool_contract(*descriptor);
        const auto validation = protocol::validate_tool_contract(contracts_[index], schemas_);
        if (!validation.valid) {
            throw std::runtime_error(
                "generated modify contract validation failed for " + std::string(name) +
                ": " + validation.reason);
        }
    }
}

std::size_t modify_handlers_t::size() const noexcept {
    return contracts_.size();
}

const protocol::tool_contract_t& modify_handlers_t::contract_at(std::size_t index) const {
    return contracts_.at(index);
}

const protocol::tool_contract_t* modify_handlers_t::find(std::string_view name) const noexcept {
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    return found == contracts_.end() ? nullptr : &*found;
}

const modify_handler_limits_t& modify_handlers_t::limits() const noexcept {
    return limits_;
}

protocol::mcp_result_t modify_handlers_t::invoke(
    std::string_view name, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata) const {
    if (!aida_metadata.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::internal_error,
            "Modify tool provenance metadata must be a JSON object.",
            protocol::json{{"field", "aida_metadata"}});
    }
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    if (found == contracts_.end()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "Modify tool is not registered in the pinned contract group.",
            protocol::json{{"tool", std::string(name)}},
            aida_metadata);
    }
    const std::size_t index = static_cast<std::size_t>(std::distance(contracts_.begin(), found));
    return protocol::invoke_tool_contract(
        *found,
        arguments,
        [this, index](const protocol::json& validated_arguments,
                       const protocol::cancellation_token_t& token) {
            return dispatch(index, validated_arguments, token);
        },
        schemas_,
        cancellation,
        aida_metadata);
}

protocol::mcp_result_t modify_handlers_t::dispatch(
    std::size_t index, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    const auto name = k_modify_names.at(index);
    const auto& contract = contracts_.at(index);
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Modify tool invocation was cancelled before adapter routing.",
            protocol::json{{"phase", "modify_pre_route"}});
    }

    std::string serialized_arguments;
    try {
        serialized_arguments = arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Modify tool arguments cannot be serialized.",
            protocol::json{{"phase", "modify_request_serialization"}});
    }
    if (serialized_arguments.size() > limits_.max_request_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Modify tool request exceeds the bounded adapter quota.",
            exceeded_value(
                "request_bytes",
                static_cast<std::uint64_t>(limits_.max_request_bytes),
                static_cast<std::uint64_t>(serialized_arguments.size())));
    }
    if (auto failure = validate_tool_bounds(name, arguments, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Modify tool arguments violate the bounded adapter policy.",
            *failure);
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
    protocol::json backend_arguments = arguments;
    backend_arguments.erase("pid");
    backend_arguments.erase("bin_name");
    try {
        request.payload = backend_arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Modify backend arguments cannot be serialized.",
            protocol::json{{"phase", "modify_backend_serialization"}});
    }
    request.deadline = std::chrono::steady_clock::now() +
        execution_timeout(contract, limits_.max_execution_time);

    auto adapter_result = workspace_.overlay(name, request);
    if (!adapter_result) {
        return adapter_failure(adapter_result.error());
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Modify tool invocation was cancelled during adapter execution.",
            protocol::json{{"phase", "modify_post_adapter"}});
    }

    auto response = std::move(adapter_result).take_value();
    if (response.payload.empty()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Modify adapter response is empty.",
            invalid_value("response_bytes", "nonempty_response_required", 0));
    }
    if (response.payload.size() > limits_.max_response_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Modify adapter response violates the output byte quota.",
            exceeded_value(
                "response_bytes",
                static_cast<std::uint64_t>(limits_.max_response_bytes),
                static_cast<std::uint64_t>(response.payload.size())));
    }
    protocol::json structured = protocol::json::parse(response.payload, nullptr, false);
    if (structured.is_discarded() || !structured.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Modify adapter returned malformed structured output.",
            protocol::json{{"phase", "modify_output_parse"},
                           {"response_bytes", response.payload.size()}});
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Modify tool invocation was cancelled before output validation.",
            protocol::json{{"phase", "modify_pre_output_validation"}});
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

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t set_comments(const handlers::modify_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata) {
    return handlers.invoke("set_comments", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t append_comments(const handlers::modify_handlers_t& handlers,
                                       const protocol::json& arguments,
                                       const protocol::cancellation_token_t& cancellation,
                                       const protocol::json& aida_metadata) {
    return handlers.invoke("append_comments", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t rename(const handlers::modify_handlers_t& handlers,
                              const protocol::json& arguments,
                              const protocol::cancellation_token_t& cancellation,
                              const protocol::json& aida_metadata) {
    return handlers.invoke("rename", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t define_code(const handlers::modify_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("define_code", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t define_func(const handlers::modify_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("define_func", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t undefine(const handlers::modify_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const protocol::json& aida_metadata) {
    return handlers.invoke("undefine", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t make_data(const handlers::modify_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const protocol::json& aida_metadata) {
    return handlers.invoke("make_data", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t patch_asm(const handlers::modify_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const protocol::json& aida_metadata) {
    return handlers.invoke("patch_asm", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t force_recompile(const handlers::modify_handlers_t& handlers,
                                       const protocol::json& arguments,
                                       const protocol::cancellation_token_t& cancellation,
                                       const protocol::json& aida_metadata) {
    return handlers.invoke("force_recompile", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t set_op_type(const handlers::modify_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("set_op_type", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t set_type(const handlers::modify_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const protocol::json& aida_metadata) {
    return handlers.invoke("set_type", arguments, cancellation, aida_metadata);
}

}
