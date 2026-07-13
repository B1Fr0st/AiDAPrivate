#include "debugger.hpp"

#include "../ida_contracts_generated.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace aida::standalone::mcp::compat::handlers {

namespace {

using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;

enum class debugger_effect_category_t : std::uint8_t {
    read,
    control,
    write,
};

constexpr std::array<std::string_view, k_debugger_tool_count> k_debugger_names{{
    "dbg_add_bp",
    "dbg_bps",
    "dbg_continue",
    "dbg_delete_bp",
    "dbg_exit",
    "dbg_gpregs",
    "dbg_gpregs_remote",
    "dbg_read",
    "dbg_regs",
    "dbg_regs_all",
    "dbg_regs_named",
    "dbg_regs_named_remote",
    "dbg_regs_remote",
    "dbg_run_to",
    "dbg_set_bp_condition",
    "dbg_stacktrace",
    "dbg_start",
    "dbg_status",
    "dbg_step_into",
    "dbg_step_over",
    "dbg_toggle_bp",
    "dbg_write",
}};

constexpr std::array<debugger_effect_category_t, k_debugger_tool_count> k_debugger_categories{{
    debugger_effect_category_t::control,
    debugger_effect_category_t::read,
    debugger_effect_category_t::control,
    debugger_effect_category_t::control,
    debugger_effect_category_t::control,
    debugger_effect_category_t::read,
    debugger_effect_category_t::read,
    debugger_effect_category_t::read,
    debugger_effect_category_t::read,
    debugger_effect_category_t::read,
    debugger_effect_category_t::read,
    debugger_effect_category_t::read,
    debugger_effect_category_t::read,
    debugger_effect_category_t::control,
    debugger_effect_category_t::control,
    debugger_effect_category_t::read,
    debugger_effect_category_t::control,
    debugger_effect_category_t::read,
    debugger_effect_category_t::control,
    debugger_effect_category_t::control,
    debugger_effect_category_t::control,
    debugger_effect_category_t::write,
}};

bool requires_approval(std::string_view name) noexcept {
    for (std::size_t index = 0; index < k_debugger_tool_count; ++index) {
        if (k_debugger_names[index] == name) {
            return k_debugger_categories[index] != debugger_effect_category_t::read;
        }
    }
    return false;
}

json parse_generated_json(std::string_view value, std::string_view field,
                          std::string_view tool_name) {
    try {
        return json::parse(value.begin(), value.end());
    } catch (const std::exception&) {
        throw std::runtime_error(
            "generated debugger contract JSON is invalid for " + std::string(tool_name) +
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
    throw std::runtime_error("generated debugger contract has an unknown effect");
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
    throw std::runtime_error("generated debugger contract has an unknown lock");
}

void validate_generated_descriptor(const contract_descriptor_t& descriptor,
                                    std::string_view name,
                                    debugger_effect_category_t category) {
    const std::string expected_adapter =
        "aida::standalone::mcp::compat::adapters::" + std::string(name);
    if (descriptor.name != name || descriptor.adapter_symbol != expected_adapter ||
        !descriptor.archive_backed || !descriptor.target_dependent ||
        !descriptor.accepts_pid || !descriptor.accepts_bin_name ||
        descriptor.unsafe != true ||
        descriptor.lock != contract_lock_t::debugger_lane) {
        throw std::runtime_error(
            "generated debugger descriptor policy mismatch for " + std::string(name));
    }
    switch (category) {
    case debugger_effect_category_t::write:
        if (descriptor.effect != contract_effect_t::debugger_write || descriptor.read_only) {
            throw std::runtime_error(
                "generated debugger write descriptor effect mismatch for " + std::string(name));
        }
        break;
    case debugger_effect_category_t::control:
        if (descriptor.effect != contract_effect_t::debugger_control || descriptor.read_only) {
            throw std::runtime_error(
                "generated debugger control descriptor effect mismatch for " + std::string(name));
        }
        break;
    case debugger_effect_category_t::read:
        if (descriptor.effect != contract_effect_t::debugger_read || !descriptor.read_only) {
            throw std::runtime_error(
                "generated debugger read descriptor effect mismatch for " + std::string(name));
        }
        break;
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
    contract.target_policy.requirement = protocol::target_requirement_t::required;
    contract.target_policy.accepts_pid = descriptor.accepts_pid;
    contract.target_policy.accepts_bin_name = descriptor.accepts_bin_name;
    contract.effect_policy.effect = protocol_effect(descriptor.effect);
    contract.effect_policy.lock = protocol_lock(descriptor.lock);
    contract.effect_policy.read_only = descriptor.read_only;
    contract.effect_policy.unsafe = descriptor.unsafe;
    return contract;
}

bool valid_limits(const debugger_handler_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 &&
        limits.max_request_bytes <= 256U * 1024U &&
        limits.max_response_bytes != 0 &&
        limits.max_response_bytes <= 4U * 1024U * 1024U &&
        limits.max_selector_bytes != 0 && limits.max_selector_bytes <= 512U &&
        limits.max_address_bytes != 0 && limits.max_address_bytes <= 32U &&
        limits.max_register_name_bytes != 0 &&
        limits.max_register_name_bytes <= 64U &&
        limits.max_register_value_bytes != 0 &&
        limits.max_register_value_bytes <= 512U &&
        limits.max_condition_bytes != 0 && limits.max_condition_bytes <= 4096U &&
        limits.max_language_bytes != 0 && limits.max_language_bytes <= 64U &&
        limits.max_symbol_bytes != 0 && limits.max_symbol_bytes <= 4096U &&
        limits.max_breakpoints != 0 && limits.max_breakpoints <= 256U &&
        limits.max_threads != 0 && limits.max_threads <= 64U &&
        limits.max_registers_per_thread != 0 &&
        limits.max_registers_per_thread <= 256U &&
        limits.max_stack_frames != 0 && limits.max_stack_frames <= 512U &&
        limits.max_read_regions != 0 && limits.max_read_regions <= 64U &&
        limits.max_read_bytes_per_region != 0 &&
        limits.max_read_bytes_per_region <= 64U * 1024U &&
        limits.max_read_bytes_total != 0 &&
        limits.max_read_bytes_total <= 1024U * 1024U &&
        limits.max_write_regions != 0 && limits.max_write_regions <= 32U &&
        limits.max_write_bytes_per_region != 0 &&
        limits.max_write_bytes_per_region <= 4U * 1024U &&
        limits.max_write_bytes_total != 0 &&
        limits.max_write_bytes_total <= 64U * 1024U &&
        limits.max_approval_source_bytes != 0 &&
        limits.max_approval_source_bytes <= 128U &&
        limits.max_execution_time.count() > 0 && limits.max_execution_time.count() <= 15000;
}

using validation_failure_t = std::optional<json>;

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_debugger_adapter"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_debugger_adapter"},
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

int hex_nibble(char value) noexcept {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

bool is_hex_separator(char value) noexcept {
    return std::isspace(static_cast<unsigned char>(value)) != 0 ||
        value == ',' || value == ':' || value == '_' || value == '-';
}

validation_failure_t count_hex_bytes(const json& value, std::string path,
                                     std::uint64_t maximum,
                                     std::uint64_t& byte_count) {
    if (!value.is_string()) {
        return invalid_value(std::move(path), "string_required", value);
    }
    const auto& text = value.get_ref<const std::string&>();
    byte_count = 0;
    int high_nibble = -1;
    for (std::size_t index = 0; index < text.size(); ++index) {
        const char character = text[index];
        if (is_hex_separator(character)) {
            if (high_nibble != -1) {
                return invalid_value(std::move(path), "incomplete_hex_byte", value);
            }
            continue;
        }
        if (character == '0' && index + 1 < text.size() &&
            (text[index + 1] == 'x' || text[index + 1] == 'X') &&
            high_nibble == -1) {
            ++index;
            continue;
        }
        const int nibble = hex_nibble(character);
        if (nibble < 0) {
            return invalid_value(std::move(path), "hexadecimal_bytes_required", value);
        }
        if (high_nibble == -1) {
            high_nibble = nibble;
            continue;
        }
        if (byte_count >= maximum) {
            return exceeded_value(std::move(path), maximum, byte_count + 1U);
        }
        ++byte_count;
        high_nibble = -1;
    }
    if (high_nibble != -1) {
        return invalid_value(std::move(path), "incomplete_hex_byte", value);
    }
    if (byte_count == 0) {
        return invalid_value(std::move(path), "nonempty_hex_bytes_required", value);
    }
    return std::nullopt;
}

validation_failure_t add_to_aggregate(std::uint64_t& aggregate,
                                      std::uint64_t amount,
                                      std::uint64_t maximum,
                                      std::string path) {
    const auto maximum_value = (std::numeric_limits<std::uint64_t>::max)();
    if (aggregate > maximum || amount > maximum - aggregate) {
        const std::uint64_t actual = amount > maximum_value - aggregate
            ? maximum_value
            : aggregate + amount;
        return exceeded_value(std::move(path), maximum, actual);
    }
    aggregate += amount;
    return std::nullopt;
}

validation_failure_t validate_routing_bounds(const json& arguments,
                                              const debugger_handler_limits_t& limits) {
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

validation_failure_t validate_address_collection(const json& value, std::string_view path,
                                                  const debugger_handler_limits_t& limits) {
    return scalar_or_array(value, path, limits.max_breakpoints,
        [&limits](const json& item, std::string item_path) {
            return bounded_text(item, std::move(item_path), limits.max_address_bytes, false);
        });
}

validation_failure_t validate_thread_ids(const json& value, std::string_view path,
                                          const debugger_handler_limits_t& limits) {
    return scalar_or_array(value, path, limits.max_threads,
        [&limits](const json& item, std::string item_path) {
            const auto v = unsigned_integer(item);
            if (!v || *v == 0) {
                return invalid_value(std::move(item_path), "valid_thread_id_required", item);
            }
            return validation_failure_t{std::nullopt};
        });
}

validation_failure_t validate_read_regions(const json& value,
                                            const debugger_handler_limits_t& limits) {
    std::uint64_t aggregate = 0;
    return scalar_or_array(value, "regions", limits.max_read_regions,
        [&limits, &aggregate](const json& region,
                              std::string path) -> validation_failure_t {
            if (!region.is_object()) {
                return invalid_value(std::move(path), "object_required", region);
            }
            if (auto failure = bounded_member_text(
                    region, "addr", path, limits.max_address_bytes, false)) {
                return failure;
            }
            const auto size = region.find("size");
            const auto parsed_size = size == region.end()
                ? std::optional<std::uint64_t>{}
                : unsigned_integer(*size);
            if (!parsed_size || *parsed_size == 0) {
                return invalid_value(
                    path + ".size", "positive_integer_required",
                    size == region.end() ? json(nullptr) : *size);
            }
            if (*parsed_size > limits.max_read_bytes_per_region) {
                return exceeded_value(path + ".size",
                                      limits.max_read_bytes_per_region,
                                      *parsed_size);
            }
            if (auto failure = add_to_aggregate(
                    aggregate, *parsed_size, limits.max_read_bytes_total,
                    "aggregate_read_bytes")) {
                return failure;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_write_regions(const json& value,
                                             const debugger_handler_limits_t& limits) {
    std::uint64_t aggregate = 0;
    return scalar_or_array(value, "regions", limits.max_write_regions,
        [&limits, &aggregate](const json& region,
                              std::string path) -> validation_failure_t {
            if (!region.is_object()) {
                return invalid_value(std::move(path), "object_required", region);
            }
            if (auto failure = bounded_member_text(
                    region, "addr", path, limits.max_address_bytes, false)) {
                return failure;
            }
            const auto data = region.find("data");
            if (data == region.end()) {
                return invalid_value(path + ".data", "field_required", json(nullptr));
            }
            if (auto failure = bounded_text(
                    *data, path + ".data",
                    limits.max_write_bytes_per_region * 3U, false)) {
                return failure;
            }
            std::uint64_t byte_count = 0;
            if (auto failure = count_hex_bytes(
                    *data, path + ".data",
                    limits.max_write_bytes_per_region, byte_count)) {
                return failure;
            }
            if (auto failure = add_to_aggregate(
                    aggregate, byte_count, limits.max_write_bytes_total,
                    "aggregate_write_bytes")) {
                return failure;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_bp_condition_items(const json& value,
                                                  const debugger_handler_limits_t& limits) {
    return scalar_or_array(value, "items", limits.max_breakpoints,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            if (!item.is_object()) {
                return invalid_value(std::move(path), "object_required", item);
            }
            if (auto failure = bounded_member_text(
                    item, "addr", path, limits.max_address_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_member_text(
                    item, "condition", path, limits.max_condition_bytes, true)) {
                return failure;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_toggle_bp_items(const json& value,
                                               const debugger_handler_limits_t& limits) {
    return scalar_or_array(value, "items", limits.max_breakpoints,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            if (!item.is_object()) {
                return invalid_value(std::move(path), "object_required", item);
            }
            if (auto failure = bounded_member_text(
                    item, "addr", path, limits.max_address_bytes, false)) {
                return failure;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_register_names(const json& value, std::string_view path,
                                              const debugger_handler_limits_t& limits) {
    return bounded_text(value, std::string(path), limits.max_register_name_bytes, false);
}

validation_failure_t validate_tool_bounds(std::string_view name, const json& arguments,
                                          const debugger_handler_limits_t& limits) {
    if (auto failure = validate_routing_bounds(arguments, limits)) {
        return failure;
    }
    if (name == "dbg_add_bp" || name == "dbg_delete_bp") {
        return validate_address_collection(arguments.at("addrs"), "addrs", limits);
    }
    if (name == "dbg_bps" || name == "dbg_continue" || name == "dbg_exit" ||
        name == "dbg_gpregs" || name == "dbg_regs" || name == "dbg_regs_all" ||
        name == "dbg_stacktrace" || name == "dbg_start" || name == "dbg_status" ||
        name == "dbg_step_into" || name == "dbg_step_over") {
        return std::nullopt;
    }
    if (name == "dbg_gpregs_remote" || name == "dbg_regs_remote") {
        const auto tids = arguments.find("tids");
        if (tids == arguments.end()) {
            return std::nullopt;
        }
        return validate_thread_ids(*tids, "tids", limits);
    }
    if (name == "dbg_read") {
        return validate_read_regions(arguments.at("regions"), limits);
    }
    if (name == "dbg_regs" || name == "dbg_regs_all" || name == "dbg_regs_remote" ||
        name == "dbg_gpregs" || name == "dbg_gpregs_remote") {
        return std::nullopt;
    }
    if (name == "dbg_regs_named") {
        return validate_register_names(arguments.at("register_names"), "register_names", limits);
    }
    if (name == "dbg_regs_named_remote") {
        if (auto failure = bounded_integer(arguments, "thread_id",
                                             (std::numeric_limits<std::uint64_t>::max)())) {
            return failure;
        }
        return validate_register_names(arguments.at("register_names"), "register_names", limits);
    }
    if (name == "dbg_run_to") {
        return bounded_member_text(arguments, "addr", {}, limits.max_address_bytes, false);
    }
    if (name == "dbg_set_bp_condition") {
        return validate_bp_condition_items(arguments.at("items"), limits);
    }
    if (name == "dbg_toggle_bp") {
        return validate_toggle_bp_items(arguments.at("items"), limits);
    }
    if (name == "dbg_write") {
        return validate_write_regions(arguments.at("regions"), limits);
    }
    return invalid_value("tool", "debugger_tool_not_registered", std::string(name));
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
        "Debugger workspace adapter rejected the request.",
        json{
            {"phase", "workspace_adapter"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

}

const std::array<std::string_view, k_debugger_tool_count>& debugger_tool_names() noexcept {
    return k_debugger_names;
}

debugger_handlers_t::debugger_handlers_t(workspace_adapter_t& workspace,
                                          debugger_lane_t& lane,
                                          protocol::schema_runtime_t& schemas,
                                          debugger_handler_limits_t limits)
    : workspace_(workspace), lane_(lane), schemas_(schemas), limits_(std::move(limits)) {
    if (!valid_limits(limits_)) {
        throw std::invalid_argument(
            "debugger handler limits are invalid or weaken pinned maxima");
    }
    for (std::size_t index = 0; index < k_debugger_names.size(); ++index) {
        const auto name = k_debugger_names[index];
        const auto* descriptor =
            aida::standalone::mcp::compat::find_contract(name);
        if (descriptor == nullptr) {
            throw std::runtime_error(
                "generated debugger descriptor is missing for " + std::string(name));
        }
        validate_generated_descriptor(*descriptor, name, k_debugger_categories[index]);
        contracts_[index] = make_tool_contract(*descriptor);
        const auto validation = protocol::validate_tool_contract(contracts_[index], schemas_);
        if (!validation.valid) {
            throw std::runtime_error(
                "generated debugger contract validation failed for " + std::string(name) +
                ": " + validation.reason);
        }
    }
}

std::size_t debugger_handlers_t::size() const noexcept {
    return contracts_.size();
}

const protocol::tool_contract_t& debugger_handlers_t::contract_at(std::size_t index) const {
    return contracts_.at(index);
}

const protocol::tool_contract_t* debugger_handlers_t::find(std::string_view name) const noexcept {
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    return found == contracts_.end() ? nullptr : &*found;
}

const debugger_handler_limits_t& debugger_handlers_t::limits() const noexcept {
    return limits_;
}

protocol::mcp_result_t debugger_handlers_t::invoke(
    std::string_view name, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const debugger_effect_approval_t& approval,
    const protocol::json& aida_metadata) const {
    if (!aida_metadata.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::internal_error,
            "Debugger tool provenance metadata must be a JSON object.",
            protocol::json{{"field", "aida_metadata"}});
    }
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    if (found == contracts_.end()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "Debugger tool is not registered in the pinned contract group.",
            protocol::json{{"tool", std::string(name)}},
            aida_metadata);
    }
    if (requires_approval(name) && !approval.granted) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::effect_policy_rejected,
            "Debugger effect approval was denied for a control or write tool.",
            protocol::json{
                {"phase", "debugger_approval_gate"},
                {"tool", std::string(name)},
                {"approval_required", true},
                {"approval_granted", false},
            },
            aida_metadata);
    }
    if (requires_approval(name) &&
        (approval.approval_id == 0 || approval.source.empty() ||
         approval.source.size() > limits_.max_approval_source_bytes)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::effect_policy_rejected,
            "Debugger effect approval identity is invalid.",
            protocol::json{
                {"phase", "debugger_approval_gate"},
                {"tool", std::string(name)},
                {"approval_required", true},
                {"approval_id_valid", approval.approval_id != 0},
                {"approval_source_bytes", approval.source.size()},
                {"approval_source_maximum", limits_.max_approval_source_bytes},
            },
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

protocol::mcp_result_t debugger_handlers_t::dispatch(
    std::size_t index, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    const auto name = k_debugger_names.at(index);
    const auto& contract = contracts_.at(index);
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Debugger tool invocation was cancelled before adapter routing.",
            protocol::json{{"phase", "debugger_pre_route"}});
    }

    std::string serialized_arguments;
    try {
        serialized_arguments = arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Debugger tool arguments cannot be serialized.",
            protocol::json{{"phase", "debugger_request_serialization"}});
    }
    if (serialized_arguments.size() > limits_.max_request_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Debugger tool request exceeds the bounded adapter quota.",
            exceeded_value(
                "request_bytes",
                static_cast<std::uint64_t>(limits_.max_request_bytes),
                static_cast<std::uint64_t>(serialized_arguments.size())));
    }
    if (auto failure = validate_tool_bounds(name, arguments, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Debugger tool arguments violate the bounded adapter policy.",
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
            "Debugger backend arguments cannot be serialized.",
            protocol::json{{"phase", "debugger_backend_serialization"}});
    }
    request.deadline = std::chrono::steady_clock::now() +
        execution_timeout(contract, limits_.max_execution_time);

    const auto lane_scope = lane_.bind(cancellation);
    (void)lane_scope;
    auto adapter_result = workspace_.debug(name, request);
    if (!adapter_result) {
        return adapter_failure(adapter_result.error());
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Debugger tool invocation was cancelled during adapter execution.",
            protocol::json{{"phase", "debugger_post_adapter"}});
    }

    auto response = std::move(adapter_result).take_value();
    if (response.payload.empty()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Debugger adapter response is empty.",
            invalid_value("response_bytes", "nonempty_response_required", 0));
    }
    if (response.payload.size() > limits_.max_response_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Debugger adapter response violates the output byte quota.",
            exceeded_value(
                "response_bytes",
                static_cast<std::uint64_t>(limits_.max_response_bytes),
                static_cast<std::uint64_t>(response.payload.size())));
    }
    protocol::json structured = protocol::json::parse(response.payload, nullptr, false);
    if (structured.is_discarded() || !structured.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Debugger adapter returned malformed structured output.",
            protocol::json{{"phase", "debugger_output_parse"},
                           {"response_bytes", response.payload.size()}});
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Debugger tool invocation was cancelled before output validation.",
            protocol::json{{"phase", "debugger_pre_output_validation"}});
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

protocol::mcp_result_t dbg_add_bp(const handlers::debugger_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const handlers::debugger_effect_approval_t& approval,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_add_bp", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_bps(const handlers::debugger_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const handlers::debugger_effect_approval_t& approval,
                                const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_bps", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_continue(const handlers::debugger_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const handlers::debugger_effect_approval_t& approval,
                                     const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_continue", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_delete_bp(const handlers::debugger_handlers_t& handlers,
                                      const protocol::json& arguments,
                                      const protocol::cancellation_token_t& cancellation,
                                      const handlers::debugger_effect_approval_t& approval,
                                      const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_delete_bp", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_exit(const handlers::debugger_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const handlers::debugger_effect_approval_t& approval,
                                 const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_exit", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_gpregs(const handlers::debugger_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const handlers::debugger_effect_approval_t& approval,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_gpregs", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_gpregs_remote(const handlers::debugger_handlers_t& handlers,
                                          const protocol::json& arguments,
                                          const protocol::cancellation_token_t& cancellation,
                                          const handlers::debugger_effect_approval_t& approval,
                                          const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_gpregs_remote", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_read(const handlers::debugger_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const handlers::debugger_effect_approval_t& approval,
                                 const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_read", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_regs(const handlers::debugger_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const handlers::debugger_effect_approval_t& approval,
                                 const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_regs", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_regs_all(const handlers::debugger_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const handlers::debugger_effect_approval_t& approval,
                                     const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_regs_all", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_regs_named(const handlers::debugger_handlers_t& handlers,
                                       const protocol::json& arguments,
                                       const protocol::cancellation_token_t& cancellation,
                                       const handlers::debugger_effect_approval_t& approval,
                                       const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_regs_named", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_regs_named_remote(const handlers::debugger_handlers_t& handlers,
                                              const protocol::json& arguments,
                                              const protocol::cancellation_token_t& cancellation,
                                              const handlers::debugger_effect_approval_t& approval,
                                              const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_regs_named_remote", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_regs_remote(const handlers::debugger_handlers_t& handlers,
                                        const protocol::json& arguments,
                                        const protocol::cancellation_token_t& cancellation,
                                        const handlers::debugger_effect_approval_t& approval,
                                        const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_regs_remote", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_run_to(const handlers::debugger_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const handlers::debugger_effect_approval_t& approval,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_run_to", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_set_bp_condition(const handlers::debugger_handlers_t& handlers,
                                             const protocol::json& arguments,
                                             const protocol::cancellation_token_t& cancellation,
                                             const handlers::debugger_effect_approval_t& approval,
                                             const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_set_bp_condition", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_stacktrace(const handlers::debugger_handlers_t& handlers,
                                       const protocol::json& arguments,
                                       const protocol::cancellation_token_t& cancellation,
                                       const handlers::debugger_effect_approval_t& approval,
                                       const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_stacktrace", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_start(const handlers::debugger_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const handlers::debugger_effect_approval_t& approval,
                                  const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_start", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_status(const handlers::debugger_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const handlers::debugger_effect_approval_t& approval,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_status", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_step_into(const handlers::debugger_handlers_t& handlers,
                                      const protocol::json& arguments,
                                      const protocol::cancellation_token_t& cancellation,
                                      const handlers::debugger_effect_approval_t& approval,
                                      const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_step_into", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_step_over(const handlers::debugger_handlers_t& handlers,
                                      const protocol::json& arguments,
                                      const protocol::cancellation_token_t& cancellation,
                                      const handlers::debugger_effect_approval_t& approval,
                                      const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_step_over", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_toggle_bp(const handlers::debugger_handlers_t& handlers,
                                      const protocol::json& arguments,
                                      const protocol::cancellation_token_t& cancellation,
                                      const handlers::debugger_effect_approval_t& approval,
                                      const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_toggle_bp", arguments, cancellation, approval, aida_metadata);
}

protocol::mcp_result_t dbg_write(const handlers::debugger_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const handlers::debugger_effect_approval_t& approval,
                                  const protocol::json& aida_metadata) {
    return handlers.invoke("dbg_write", arguments, cancellation, approval, aida_metadata);
}

}
