#include "stack.hpp"

#include "../ida_contracts_generated.hpp"
#include "../../../analysis/workspace/calling_convention.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cmath>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::standalone::mcp::compat::handlers {

namespace {

using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;

constexpr std::array<std::string_view, k_stack_tool_count> k_stack_names{{
    "stack_frame",
    "declare_stack",
    "delete_stack",
}};

using validation_failure_t = std::optional<json>;

json parse_generated_json(std::string_view value, std::string_view field,
                          std::string_view tool_name) {
    try {
        return json::parse(value.begin(), value.end());
    } catch (const std::exception&) {
        throw std::runtime_error(
            "generated stack contract JSON is invalid for " + std::string(tool_name) +
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
    throw std::runtime_error("generated stack contract has an unknown effect");
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
    throw std::runtime_error("generated stack contract has an unknown lock");
}

bool is_read_tool(std::string_view name) noexcept {
    return name == "stack_frame";
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
            "generated stack descriptor policy mismatch for " + std::string(name));
    }
    if (is_read_tool(name)) {
        if (descriptor.effect != contract_effect_t::workspace_read ||
            descriptor.lock != contract_lock_t::workspace_shared ||
            !descriptor.read_only) {
            throw std::runtime_error(
                "generated stack read descriptor effect/lock mismatch for " + std::string(name));
        }
    } else {
        if (descriptor.effect != contract_effect_t::workspace_overlay_mutation ||
            descriptor.lock != contract_lock_t::workspace_overlay_transaction ||
            descriptor.read_only) {
            throw std::runtime_error(
                "generated stack mutation descriptor effect/lock mismatch for " + std::string(name));
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

bool valid_limits(const stack_handler_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 && limits.max_request_bytes <= 1024U * 1024U &&
        limits.max_response_bytes != 0 && limits.max_response_bytes <= 16U * 1024U * 1024U &&
        limits.max_selector_bytes != 0 && limits.max_selector_bytes <= 1024U &&
        limits.max_address_bytes != 0 && limits.max_address_bytes <= 4096U &&
        limits.max_name_bytes != 0 && limits.max_name_bytes <= 4096U &&
        limits.max_type_bytes != 0 && limits.max_type_bytes <= 16384U &&
        limits.max_offset_bytes != 0 && limits.max_offset_bytes <= 64U &&
        limits.max_batch_items != 0 && limits.max_batch_items <= 256U &&
        limits.max_addrs != 0 && limits.max_addrs <= 256U &&
        limits.max_execution_time.count() > 0 && limits.max_execution_time.count() <= 120000;
}

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_stack_adapter"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_stack_adapter"},
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

validation_failure_t required_member_text(const json& object, std::string_view field,
                                         std::string path_prefix, std::size_t maximum,
                                         bool allow_empty) {
    const auto found = object.find(std::string(field));
    if (found == object.end()) {
        const std::string path = path_prefix.empty()
            ? std::string(field)
            : path_prefix + "." + std::string(field);
        return invalid_value(path, "required_field_missing", nullptr);
    }
    const std::string path = path_prefix.empty()
        ? std::string(field)
        : path_prefix + "." + std::string(field);
    return bounded_text(*found, path, maximum, allow_empty);
}

validation_failure_t validate_routing_bounds(const json& arguments,
                                            const stack_handler_limits_t& limits) {
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

validation_failure_t validate_stack_frame(const json& arguments,
                                         const stack_handler_limits_t& limits) {
    const auto addrs = arguments.find("addrs");
    if (addrs == arguments.end()) {
        return invalid_value("addrs", "required_field_missing", nullptr);
    }
    return scalar_or_array(*addrs, "addrs", limits.max_addrs,
        [&limits](const json& item, std::string path) {
            return bounded_text(item, std::move(path), limits.max_address_bytes, false);
        });
}

validation_failure_t validate_declare_item(const json& item, std::string path,
                                           const stack_handler_limits_t& limits) {
    if (!item.is_object()) {
        return invalid_value(std::move(path), "object_required", item);
    }
    if (auto failure = required_member_text(
            item, "addr", path, limits.max_address_bytes, false)) {
        return failure;
    }
    if (auto failure = required_member_text(
            item, "offset", path, limits.max_offset_bytes, false)) {
        return failure;
    }
    if (auto failure = required_member_text(
            item, "name", path, limits.max_name_bytes, false)) {
        return failure;
    }
    if (auto failure = required_member_text(
            item, "ty", path, limits.max_type_bytes, false)) {
        return failure;
    }
    return std::nullopt;
}

validation_failure_t validate_declare_stack(const json& arguments,
                                           const stack_handler_limits_t& limits) {
    const auto items = arguments.find("items");
    if (items == arguments.end()) {
        return invalid_value("items", "required_field_missing", nullptr);
    }
    return scalar_or_array(*items, "items", limits.max_batch_items,
        [&limits](const json& item, std::string path) {
            return validate_declare_item(item, std::move(path), limits);
        });
}

validation_failure_t validate_delete_item(const json& item, std::string path,
                                          const stack_handler_limits_t& limits) {
    if (!item.is_object()) {
        return invalid_value(std::move(path), "object_required", item);
    }
    if (auto failure = required_member_text(
            item, "addr", path, limits.max_address_bytes, false)) {
        return failure;
    }
    if (auto failure = required_member_text(
            item, "name", path, limits.max_name_bytes, false)) {
        return failure;
    }
    return std::nullopt;
}

validation_failure_t validate_delete_stack(const json& arguments,
                                          const stack_handler_limits_t& limits) {
    const auto items = arguments.find("items");
    if (items == arguments.end()) {
        return invalid_value("items", "required_field_missing", nullptr);
    }
    return scalar_or_array(*items, "items", limits.max_batch_items,
        [&limits](const json& item, std::string path) {
            return validate_delete_item(item, std::move(path), limits);
        });
}

validation_failure_t validate_tool_bounds(std::string_view name, const json& arguments,
                                         const stack_handler_limits_t& limits) {
    if (auto failure = validate_routing_bounds(arguments, limits)) {
        return failure;
    }
    if (name == "stack_frame") {
        return validate_stack_frame(arguments, limits);
    }
    if (name == "declare_stack") {
        return validate_declare_stack(arguments, limits);
    }
    if (name == "delete_stack") {
        return validate_delete_stack(arguments, limits);
    }
    return invalid_value("tool", "stack_tool_not_registered", std::string(name));
}

std::optional<std::uint64_t> parse_unsigned_text(std::string_view text) noexcept {
    if (text.empty() || text.front() == '+' || text.front() == '-') {
        return std::nullopt;
    }
    int base = 10;
    if (text.size() > 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2U);
        base = 16;
    }
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

std::optional<std::int64_t> parse_signed_offset(std::string_view text) noexcept {
    if (text.empty()) {
        return std::nullopt;
    }
    bool negative = false;
    if (text.front() == '+' || text.front() == '-') {
        negative = text.front() == '-';
        text.remove_prefix(1U);
    }
    int base = 10;
    if (text.size() > 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2U);
        base = 16;
    }
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t magnitude = 0;
    const auto parsed = std::from_chars(
        text.data(), text.data() + text.size(), magnitude, base);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    const std::uint64_t positive_limit =
        static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
    if (!negative) {
        return magnitude <= positive_limit
            ? std::optional<std::int64_t>(static_cast<std::int64_t>(magnitude))
            : std::nullopt;
    }
    const std::uint64_t negative_limit = positive_limit + 1U;
    if (magnitude > negative_limit) {
        return std::nullopt;
    }
    if (magnitude == negative_limit) {
        return (std::numeric_limits<std::int64_t>::min)();
    }
    return -static_cast<std::int64_t>(magnitude);
}

std::string format_signed_offset(std::int64_t value) {
    const bool negative = value < 0;
    const std::uint64_t magnitude = negative
        ? static_cast<std::uint64_t>(-(value + 1)) + 1U
        : static_cast<std::uint64_t>(value);
    std::array<char, 32> buffer{};
    const auto formatted = std::to_chars(
        buffer.data(), buffer.data() + buffer.size(), magnitude, 16);
    if (formatted.ec != std::errc{}) {
        throw std::runtime_error("stack offset formatting failed");
    }
    std::string result = negative ? "-0x" : "0x";
    result.append(buffer.data(), formatted.ptr);
    return result;
}

std::string normalized_type_name(std::string_view type_name) {
    std::string normalized;
    normalized.reserve(type_name.size());
    bool previous_space = false;
    for (const char value : type_name) {
        const auto byte = static_cast<unsigned char>(value);
        if (std::isspace(byte) != 0) {
            if (!normalized.empty() && !previous_space) {
                normalized.push_back(' ');
            }
            previous_space = true;
            continue;
        }
        normalized.push_back(static_cast<char>(std::tolower(byte)));
        previous_space = false;
    }
    while (!normalized.empty() && normalized.back() == ' ') {
        normalized.pop_back();
    }
    if (!normalized.empty() && normalized.front() == ' ') {
        normalized.erase(normalized.begin());
    }
    return normalized;
}

std::uint64_t estimated_type_size(std::string_view type_name) noexcept {
    try {
        std::string normalized = normalized_type_name(type_name);
        if (normalized.empty()) {
            return 1U;
        }
        static constexpr std::array<std::string_view, 3> qualifiers{{
            "const ", "volatile ", "__unaligned ",
        }};
        for (bool changed = true; changed;) {
            changed = false;
            for (const std::string_view qualifier : qualifiers) {
                if (normalized.rfind(qualifier, 0U) == 0U) {
                    normalized.erase(0U, qualifier.size());
                    changed = true;
                }
            }
        }
        if (normalized.empty()) {
            return 1U;
        }
        const auto close = normalized.rfind(']');
        const auto open = normalized.rfind('[');
        if (close == normalized.size() - 1U && open != std::string::npos && open < close) {
            const auto count = parse_unsigned_text(
                std::string_view(normalized).substr(open + 1U, close - open - 1U));
            if (count && *count != 0U) {
                const std::uint64_t element = estimated_type_size(
                    std::string_view(normalized).substr(0U, open));
                if (element <= (std::numeric_limits<std::uint64_t>::max)() / *count) {
                    return element * *count;
                }
            }
            return (std::numeric_limits<std::uint64_t>::max)();
        }
        if (normalized.back() == '*') {
            return 8U;
        }
        static const std::unordered_map<std::string, std::uint64_t> sizes{
            {"bool", 1U}, {"char", 1U}, {"signed char", 1U}, {"byte", 1U},
            {"unsigned char", 1U}, {"int8_t", 1U}, {"uint8_t", 1U},
            {"__int8", 1U}, {"unsigned __int8", 1U},
            {"short", 2U}, {"short int", 2U}, {"signed short", 2U},
            {"unsigned short", 2U}, {"int16_t", 2U}, {"uint16_t", 2U},
            {"__int16", 2U}, {"unsigned __int16", 2U}, {"word", 2U},
            {"wchar_t", 2U}, {"int", 4U}, {"signed", 4U}, {"dword", 4U},
            {"signed int", 4U}, {"unsigned", 4U}, {"unsigned int", 4U},
            {"long", 4U}, {"long int", 4U}, {"unsigned long", 4U},
            {"int32_t", 4U}, {"uint32_t", 4U}, {"__int32", 4U},
            {"unsigned __int32", 4U}, {"float", 4U},
            {"long long", 8U}, {"long long int", 8U},
            {"unsigned long long", 8U}, {"int64_t", 8U}, {"uint64_t", 8U},
            {"double", 8U}, {"long double", 8U}, {"__int64", 8U},
            {"unsigned __int64", 8U}, {"qword", 8U},
        };
        const auto found = sizes.find(normalized);
        return found == sizes.end() ? 1U : found->second;
    } catch (const std::exception&) {
        return 1U;
    }
}

std::optional<analysis::fact_provenance_t> parse_provenance(
    std::string_view value) noexcept {
    using analysis::fact_provenance_t;
    static constexpr std::array<std::pair<std::string_view, fact_provenance_t>, 13> values{{
        {"unknown", fact_provenance_t::unknown},
        {"gap_recovery", fact_provenance_t::gap_recovery},
        {"linear_validation", fact_provenance_t::linear_validation},
        {"recursive_decode", fact_provenance_t::recursive_decode},
        {"relocation", fact_provenance_t::relocation},
        {"call_target", fact_provenance_t::call_target},
        {"export_entry", fact_provenance_t::export_entry},
        {"tls_entry", fact_provenance_t::tls_entry},
        {"image_entry", fact_provenance_t::image_entry},
        {"unwind_metadata", fact_provenance_t::unwind_metadata},
        {"debug_symbol", fact_provenance_t::debug_symbol},
        {"user_definition", fact_provenance_t::user_definition},
        {"decompiler_feedback", fact_provenance_t::decompiler_feedback},
    }};
    const auto found = std::find_if(
        values.begin(), values.end(),
        [value](const auto& item) { return item.first == value; });
    return found == values.end()
        ? std::nullopt
        : std::optional<fact_provenance_t>(found->second);
}

std::string_view provenance_name(analysis::fact_provenance_t value) noexcept {
    using analysis::fact_provenance_t;
    switch (value) {
    case fact_provenance_t::unknown: return "unknown";
    case fact_provenance_t::gap_recovery: return "gap_recovery";
    case fact_provenance_t::linear_validation: return "linear_validation";
    case fact_provenance_t::recursive_decode: return "recursive_decode";
    case fact_provenance_t::relocation: return "relocation";
    case fact_provenance_t::call_target: return "call_target";
    case fact_provenance_t::export_entry: return "export_entry";
    case fact_provenance_t::tls_entry: return "tls_entry";
    case fact_provenance_t::image_entry: return "image_entry";
    case fact_provenance_t::unwind_metadata: return "unwind_metadata";
    case fact_provenance_t::debug_symbol: return "debug_symbol";
    case fact_provenance_t::user_definition: return "user_definition";
    case fact_provenance_t::decompiler_feedback: return "decompiler_feedback";
    }
    return "unknown";
}

std::optional<analysis::stack_slot_kind_t> parse_slot_kind(
    std::string_view value) noexcept {
    using analysis::stack_slot_kind_t;
    if (value == "unknown" || value == "declared") return stack_slot_kind_t::unknown;
    if (value == "argument") return stack_slot_kind_t::argument;
    if (value == "local") return stack_slot_kind_t::local;
    if (value == "spill") return stack_slot_kind_t::spill;
    if (value == "saved_register") return stack_slot_kind_t::saved_register;
    if (value == "outgoing_argument") return stack_slot_kind_t::outgoing_argument;
    return std::nullopt;
}

std::string_view slot_kind_name(analysis::stack_slot_kind_t value) noexcept {
    using analysis::stack_slot_kind_t;
    switch (value) {
    case stack_slot_kind_t::unknown: return "unknown";
    case stack_slot_kind_t::argument: return "argument";
    case stack_slot_kind_t::local: return "local";
    case stack_slot_kind_t::spill: return "spill";
    case stack_slot_kind_t::saved_register: return "saved_register";
    case stack_slot_kind_t::outgoing_argument: return "outgoing_argument";
    }
    return "unknown";
}

struct typed_stack_slot_t final {
    analysis::stack_slot_t slot;
    std::optional<std::string> name;
    std::optional<std::string> type;
    std::string source;
};

struct typed_stack_frame_t final {
    std::string requested_address;
    std::string function;
    std::string state;
    analysis::cc_abi_t abi = analysis::cc_abi_t::unknown;
    std::uint8_t confidence = 0;
    analysis::stack_frame_info_t frame;
    std::vector<typed_stack_slot_t> slots;
    std::uint64_t instructions_analyzed = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    bool bounded = false;
};

validation_failure_t require_response_string(
    const json& object, const char* field, std::string path,
    std::size_t maximum, std::string& output) {
    const auto found = object.find(field);
    if (found == object.end()) {
        return invalid_value(path + "." + field, "required_field_missing", nullptr);
    }
    if (auto failure = bounded_text(
            *found, path + "." + field, maximum, false)) {
        return failure;
    }
    output = found->get<std::string>();
    return std::nullopt;
}

validation_failure_t require_response_unsigned(
    const json& object, const char* field, std::string path,
    std::uint64_t maximum, std::uint64_t& output) {
    const auto found = object.find(field);
    if (found == object.end()) {
        return invalid_value(path + "." + field, "required_field_missing", nullptr);
    }
    const auto value = unsigned_integer(*found);
    if (!value || *value > maximum) {
        return invalid_value(path + "." + field, "bounded_unsigned_integer_required", *found);
    }
    output = *value;
    return std::nullopt;
}

validation_failure_t require_response_signed(
    const json& object, const char* field, std::string path,
    std::int64_t& output) {
    const auto found = object.find(field);
    if (found == object.end()) {
        return invalid_value(path + "." + field, "required_field_missing", nullptr);
    }
    try {
        if (found->is_number_integer()) {
            output = found->get<std::int64_t>();
            return std::nullopt;
        }
    } catch (const std::exception&) {
    }
    return invalid_value(path + "." + field, "signed_integer_required", *found);
}

validation_failure_t require_response_bool(
    const json& object, const char* field, std::string path, bool& output) {
    const auto found = object.find(field);
    if (found == object.end()) {
        return invalid_value(path + "." + field, "required_field_missing", nullptr);
    }
    if (!found->is_boolean()) {
        return invalid_value(path + "." + field, "boolean_required", *found);
    }
    output = found->get<bool>();
    return std::nullopt;
}

validation_failure_t parse_typed_stack_frame(
    const json& response, std::string requested_address,
    const stack_handler_limits_t& limits, typed_stack_frame_t& output) {
    if (!response.is_object()) {
        return invalid_value("response", "object_required", response);
    }
    const auto metadata = response.find("_meta");
    if (metadata == response.end() || !metadata->is_object()) {
        return invalid_value("response._meta", "object_required", nullptr);
    }
    const auto aida = metadata->find("aida");
    if (aida == metadata->end() || !aida->is_object()) {
        return invalid_value("response._meta.aida", "object_required", nullptr);
    }
    const auto adapter = aida->find("adapter");
    if (adapter == aida->end() || !adapter->is_string() ||
        adapter->get_ref<const std::string&>() != "ida_compat_read") {
        return invalid_value(
            "response._meta.aida.adapter", "typed_read_adapter_required",
            adapter == aida->end() ? json(nullptr) : *adapter);
    }
    if (auto failure = require_response_unsigned(
            *aida, "analysis_revision", "response._meta.aida",
            (std::numeric_limits<std::uint64_t>::max)(), output.analysis_revision)) {
        return failure;
    }
    if (auto failure = require_response_unsigned(
            *aida, "overlay_revision", "response._meta.aida",
            (std::numeric_limits<std::uint64_t>::max)(), output.overlay_revision)) {
        return failure;
    }
    std::string target_kind;
    if (auto failure = require_response_string(
            *aida, "target_kind", "response._meta.aida", 32U, target_kind)) {
        return failure;
    }
    if (target_kind != "static") {
        return invalid_value(
            "response._meta.aida.target_kind", "static_typed_frame_required",
            target_kind);
    }

    output.requested_address = std::move(requested_address);
    if (auto failure = require_response_string(
            response, "function", "response", limits.max_address_bytes, output.function)) {
        return failure;
    }
    if (!parse_unsigned_text(output.function)) {
        return invalid_value(
            "response.function", "canonical_address_string_required", output.function);
    }
    if (auto failure = require_response_string(
            response, "state", "response", 64U, output.state)) {
        return failure;
    }
    if (output.state != "unknown" && output.state != "abstained" &&
        output.state != "inferred" && output.state != "conflicted") {
        return invalid_value(
            "response.state", "known_inference_state_required", output.state);
    }
    std::uint64_t abi = 0;
    if (auto failure = require_response_unsigned(
            response, "abi", "response",
            static_cast<std::uint64_t>(analysis::cc_abi_t::managed_dalvik_identity), abi)) {
        return failure;
    }
    output.abi = static_cast<analysis::cc_abi_t>(abi);
    std::uint64_t confidence = 0;
    if (auto failure = require_response_unsigned(
            response, "confidence", "response", 100U, confidence)) {
        return failure;
    }
    output.confidence = static_cast<std::uint8_t>(confidence);
    if (auto failure = require_response_unsigned(
            response, "frame_size", "response",
            (std::numeric_limits<std::uint64_t>::max)(), output.frame.frame_size)) {
        return failure;
    }
    if (auto failure = require_response_bool(
            response, "frame_size_known", "response", output.frame.frame_size_known)) {
        return failure;
    }
    if (auto failure = require_response_unsigned(
            response, "observed_stack_extent", "response",
            (std::numeric_limits<std::uint64_t>::max)(), output.frame.observed_stack_extent)) {
        return failure;
    }
    std::uint64_t stack_pointer_reg = 0;
    if (auto failure = require_response_unsigned(
            response, "stack_pointer_reg", "response",
            (std::numeric_limits<std::uint16_t>::max)(), stack_pointer_reg)) {
        return failure;
    }
    output.frame.stack_pointer_reg = static_cast<std::uint16_t>(stack_pointer_reg);
    std::uint64_t frame_pointer_reg = 0;
    if (auto failure = require_response_unsigned(
            response, "frame_pointer_reg", "response",
            (std::numeric_limits<std::uint16_t>::max)(), frame_pointer_reg)) {
        return failure;
    }
    output.frame.frame_pointer_reg = static_cast<std::uint16_t>(frame_pointer_reg);
    if (auto failure = require_response_bool(
            response, "uses_frame_pointer", "response", output.frame.uses_frame_pointer)) {
        return failure;
    }
    if (auto failure = require_response_bool(
            response, "has_shadow_space", "response", output.frame.has_shadow_space)) {
        return failure;
    }
    if (auto failure = require_response_unsigned(
            response, "shadow_space_size", "response",
            (std::numeric_limits<std::uint64_t>::max)(), output.frame.shadow_space_size)) {
        return failure;
    }
    std::string prologue_end;
    if (auto failure = require_response_string(
            response, "prologue_end", "response", limits.max_address_bytes, prologue_end)) {
        return failure;
    }
    const auto parsed_prologue = parse_unsigned_text(prologue_end);
    if (!parsed_prologue) {
        return invalid_value("response.prologue_end", "address_string_required", prologue_end);
    }
    output.frame.prologue_end_rva = *parsed_prologue;
    std::string epilogue_start;
    if (auto failure = require_response_string(
            response, "epilogue_start", "response", limits.max_address_bytes, epilogue_start)) {
        return failure;
    }
    const auto parsed_epilogue = parse_unsigned_text(epilogue_start);
    if (!parsed_epilogue) {
        return invalid_value("response.epilogue_start", "address_string_required", epilogue_start);
    }
    output.frame.epilogue_start_rva = *parsed_epilogue;

    const auto slots = response.find("slots");
    if (slots == response.end() || !slots->is_array()) {
        return invalid_value("response.slots", "array_required",
                             slots == response.end() ? json(nullptr) : *slots);
    }
    output.slots.clear();
    output.frame.slots.clear();
    output.slots.reserve(slots->size());
    output.frame.slots.reserve(slots->size());
    for (std::size_t index = 0; index < slots->size(); ++index) {
        const json& source = (*slots)[index];
        const std::string path = "response.slots[" + std::to_string(index) + "]";
        if (!source.is_object()) {
            return invalid_value(path, "object_required", source);
        }
        typed_stack_slot_t record;
        if (auto failure = require_response_signed(
                source, "offset", path, record.slot.offset)) {
            return failure;
        }
        if (auto failure = require_response_unsigned(
                source, "size", path, (std::numeric_limits<std::uint64_t>::max)(),
                record.slot.size)) {
            return failure;
        }
        std::uint64_t base_reg = 0;
        if (auto failure = require_response_unsigned(
                source, "base_reg", path,
                (std::numeric_limits<std::uint16_t>::max)(), base_reg)) {
            return failure;
        }
        record.slot.base_reg = static_cast<std::uint16_t>(base_reg);
        std::uint64_t access_width = 0;
        if (auto failure = require_response_unsigned(
                source, "access_width_bits", path,
                (std::numeric_limits<std::uint16_t>::max)(), access_width)) {
            return failure;
        }
        record.slot.access_width_bits = static_cast<std::uint16_t>(access_width);
        std::string kind;
        if (auto failure = require_response_string(source, "kind", path, 64U, kind)) {
            return failure;
        }
        const auto parsed_kind = parse_slot_kind(kind);
        if (!parsed_kind) {
            return invalid_value(path + ".kind", "known_stack_slot_kind_required", kind);
        }
        record.slot.kind = *parsed_kind;
        std::string provenance;
        if (auto failure = require_response_string(
                source, "provenance", path, 64U, provenance)) {
            return failure;
        }
        const auto parsed_provenance = parse_provenance(provenance);
        if (!parsed_provenance) {
            return invalid_value(path + ".provenance", "known_provenance_required", provenance);
        }
        record.slot.provenance = *parsed_provenance;
        std::uint64_t slot_confidence = 0;
        if (auto failure = require_response_unsigned(
                source, "confidence", path, 100U, slot_confidence)) {
            return failure;
        }
        record.slot.confidence = static_cast<std::uint8_t>(slot_confidence);
        for (const auto& field : std::array<std::pair<const char*, bool*>, 6>{{
                 {"is_argument", &record.slot.is_argument},
                 {"is_spill", &record.slot.is_spill},
                 {"is_local", &record.slot.is_local},
                 {"is_saved_register", &record.slot.is_saved_register},
                 {"read", &record.slot.read},
                 {"written", &record.slot.written},
             }}) {
            if (auto failure = require_response_bool(source, field.first, path, *field.second)) {
                return failure;
            }
        }
        if (auto failure = require_response_string(
                source, "source", path, 64U, record.source)) {
            return failure;
        }
        if (record.source != "inferred" && record.source != "inferred_and_declared" &&
            record.source != "declared") {
            return invalid_value(path + ".source", "known_slot_source_required", record.source);
        }
        const auto name = source.find("name");
        const auto type = source.find("type");
        if ((name == source.end()) != (type == source.end())) {
            return invalid_value(path, "name_and_type_must_be_paired", source);
        }
        const bool declared_source = record.source != "inferred";
        if (declared_source != (name != source.end())) {
            return invalid_value(
                path, "slot_source_and_declaration_mismatch", source);
        }
        if (name != source.end()) {
            if (auto failure = bounded_text(
                    *name, path + ".name", limits.max_name_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_text(
                    *type, path + ".type", limits.max_type_bytes, false)) {
                return failure;
            }
            record.name = name->get<std::string>();
            record.type = type->get<std::string>();
        }
        output.frame.slots.push_back(record.slot);
        output.slots.push_back(std::move(record));
    }
    std::uint64_t slot_count = 0;
    if (auto failure = require_response_unsigned(
            response, "slot_count", "response",
            (std::numeric_limits<std::uint64_t>::max)(), slot_count)) {
        return failure;
    }
    if (slot_count != output.slots.size()) {
        return invalid_value("response.slot_count", "slot_count_mismatch", slot_count);
    }

    const auto saved_registers = response.find("saved_registers");
    if (saved_registers == response.end() || !saved_registers->is_array()) {
        return invalid_value(
            "response.saved_registers", "array_required",
            saved_registers == response.end() ? json(nullptr) : *saved_registers);
    }
    output.frame.preserved_registers.clear();
    output.frame.preserved_registers.reserve(saved_registers->size());
    for (std::size_t index = 0; index < saved_registers->size(); ++index) {
        const json& source = (*saved_registers)[index];
        const std::string path = "response.saved_registers[" + std::to_string(index) + "]";
        if (!source.is_object()) {
            return invalid_value(path, "object_required", source);
        }
        analysis::preserved_register_t record;
        std::uint64_t reg = 0;
        if (auto failure = require_response_unsigned(
                source, "reg", path, (std::numeric_limits<std::uint16_t>::max)(), reg)) {
            return failure;
        }
        record.reg = static_cast<std::uint16_t>(reg);
        if (auto failure = require_response_bool(source, "saved", path, record.saved)) {
            return failure;
        }
        if (auto failure = require_response_bool(source, "restored", path, record.restored)) {
            return failure;
        }
        std::string save_address;
        if (auto failure = require_response_string(
                source, "save_address", path, limits.max_address_bytes, save_address)) {
            return failure;
        }
        const auto parsed_save = parse_unsigned_text(save_address);
        if (!parsed_save) {
            return invalid_value(path + ".save_address", "address_string_required", save_address);
        }
        record.save_rva = *parsed_save;
        std::string restore_address;
        if (auto failure = require_response_string(
                source, "restore_address", path, limits.max_address_bytes, restore_address)) {
            return failure;
        }
        const auto parsed_restore = parse_unsigned_text(restore_address);
        if (!parsed_restore) {
            return invalid_value(path + ".restore_address", "address_string_required", restore_address);
        }
        record.restore_rva = *parsed_restore;
        std::string provenance;
        if (auto failure = require_response_string(
                source, "provenance", path, 64U, provenance)) {
            return failure;
        }
        const auto parsed_provenance = parse_provenance(provenance);
        if (!parsed_provenance) {
            return invalid_value(path + ".provenance", "known_provenance_required", provenance);
        }
        record.provenance = *parsed_provenance;
        std::uint64_t register_confidence = 0;
        if (auto failure = require_response_unsigned(
                source, "confidence", path, 100U, register_confidence)) {
            return failure;
        }
        record.confidence = static_cast<std::uint8_t>(register_confidence);
        output.frame.preserved_registers.push_back(record);
    }
    std::uint64_t saved_register_count = 0;
    if (auto failure = require_response_unsigned(
            response, "saved_register_count", "response",
            (std::numeric_limits<std::uint64_t>::max)(), saved_register_count)) {
        return failure;
    }
    if (saved_register_count != output.frame.preserved_registers.size()) {
        return invalid_value(
            "response.saved_register_count", "saved_register_count_mismatch",
            saved_register_count);
    }
    if (auto failure = require_response_bool(response, "bounded", "response", output.bounded)) {
        return failure;
    }
    return require_response_unsigned(
        response, "instructions_analyzed", "response",
        (std::numeric_limits<std::uint64_t>::max)(), output.instructions_analyzed);
}

std::string unsigned_hex(std::uint64_t value) {
    std::array<char, 32> buffer{};
    const auto formatted = std::to_chars(
        buffer.data(), buffer.data() + buffer.size(), value, 16);
    if (formatted.ec != std::errc{}) {
        throw std::runtime_error("stack address formatting failed");
    }
    std::string result = "0x";
    result.append(buffer.data(), formatted.ptr);
    return result;
}

json typed_frame_metadata(const typed_stack_frame_t& value) {
    json slots = json::array();
    for (const auto& record : value.slots) {
        json slot{
            {"offset", record.slot.offset},
            {"size", record.slot.size},
            {"base_reg", record.slot.base_reg},
            {"access_width_bits", record.slot.access_width_bits},
            {"kind", record.source == "declared"
                ? std::string("declared")
                : std::string(slot_kind_name(record.slot.kind))},
            {"provenance", std::string(provenance_name(record.slot.provenance))},
            {"confidence", record.slot.confidence},
            {"is_argument", record.slot.is_argument},
            {"is_spill", record.slot.is_spill},
            {"is_local", record.slot.is_local},
            {"is_saved_register", record.slot.is_saved_register},
            {"read", record.slot.read},
            {"written", record.slot.written},
            {"source", record.source},
        };
        if (record.name) slot["name"] = *record.name;
        if (record.type) slot["type"] = *record.type;
        slots.push_back(std::move(slot));
    }
    json saved_registers = json::array();
    for (const auto& record : value.frame.preserved_registers) {
        saved_registers.push_back({
            {"reg", record.reg},
            {"saved", record.saved},
            {"restored", record.restored},
            {"save_address", unsigned_hex(record.save_rva)},
            {"restore_address", unsigned_hex(record.restore_rva)},
            {"provenance", std::string(provenance_name(record.provenance))},
            {"confidence", record.confidence},
        });
    }
    return {
        {"requested_address", value.requested_address},
        {"function", value.function},
        {"state", value.state},
        {"abi", static_cast<std::uint64_t>(value.abi)},
        {"confidence", value.confidence},
        {"frame_size", value.frame.frame_size},
        {"frame_size_known", value.frame.frame_size_known},
        {"observed_stack_extent", value.frame.observed_stack_extent},
        {"stack_pointer_reg", value.frame.stack_pointer_reg},
        {"frame_pointer_reg", value.frame.frame_pointer_reg},
        {"uses_frame_pointer", value.frame.uses_frame_pointer},
        {"has_shadow_space", value.frame.has_shadow_space},
        {"shadow_space_size", value.frame.shadow_space_size},
        {"prologue_end", unsigned_hex(value.frame.prologue_end_rva)},
        {"epilogue_start", unsigned_hex(value.frame.epilogue_start_rva)},
        {"slots", std::move(slots)},
        {"saved_registers", std::move(saved_registers)},
        {"bounded", value.bounded},
        {"instructions_analyzed", value.instructions_analyzed},
        {"analysis_revision", value.analysis_revision},
        {"overlay_revision", value.overlay_revision},
    };
}

std::uint64_t effective_slot_size(const typed_stack_slot_t& slot) noexcept;

json generated_frame_result(const typed_stack_frame_t& frame) {
    json variables = json::array();
    for (const auto& record : frame.slots) {
        if (!record.name || !record.type) {
            continue;
        }
        variables.push_back({
            {"name", *record.name},
            {"offset", format_signed_offset(record.slot.offset)},
            {"size", std::to_string(effective_slot_size(record))},
            {"type", *record.type},
        });
    }
    return {
        {"addr", frame.requested_address},
        {"vars", std::move(variables)},
    };
}

struct stack_interval_t final {
    std::int64_t begin = 0;
    std::int64_t end = 0;
};

std::optional<stack_interval_t> stack_interval(
    std::int64_t offset, std::uint64_t size) noexcept {
    if (size == 0U) {
        size = 1U;
    }
    if (size > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
        return std::nullopt;
    }
    const auto signed_size = static_cast<std::int64_t>(size);
    if (offset > (std::numeric_limits<std::int64_t>::max)() - signed_size) {
        return std::nullopt;
    }
    return stack_interval_t{offset, offset + signed_size};
}

bool intervals_overlap(const stack_interval_t& lhs, const stack_interval_t& rhs) noexcept {
    return lhs.begin < rhs.end && rhs.begin < lhs.end;
}

std::uint64_t effective_slot_size(const typed_stack_slot_t& slot) noexcept {
    if (slot.slot.size != 0U) {
        return slot.slot.size;
    }
    if (slot.slot.access_width_bits != 0U) {
        return (slot.slot.access_width_bits + 7U) / 8U;
    }
    return slot.type ? estimated_type_size(*slot.type) : 1U;
}

std::vector<json> item_list(const json& value) {
    if (!value.is_array()) {
        return {value};
    }
    return std::vector<json>(value.begin(), value.end());
}

struct overlay_receipt_t final {
    std::uint64_t transaction_id = 0;
    std::uint64_t operations = 0;
    std::uint64_t revision_before = 0;
    std::uint64_t revision_after = 0;
};

validation_failure_t validate_overlay_receipt(
    std::string_view tool, const json& response, std::size_t expected_operations,
    std::uint64_t expected_revision, overlay_receipt_t& receipt) {
    if (!response.is_object()) {
        return invalid_value("response", "object_required", response);
    }
    const json* proof = nullptr;
    bool legacy = false;
    const auto explicit_proof = response.find("_aida_overlay");
    if (explicit_proof != response.end()) {
        if (!explicit_proof->is_object()) {
            return invalid_value(
                "response._aida_overlay", "object_required", *explicit_proof);
        }
        proof = &*explicit_proof;
    } else {
        const auto metadata = response.find("_meta");
        if (metadata != response.end() && metadata->is_object()) {
            const auto aida = metadata->find("aida");
            if (aida != metadata->end() && aida->is_object()) {
                proof = &*aida;
                legacy = true;
            }
        }
    }
    if (proof == nullptr) {
        return invalid_value("response.overlay_receipt", "receipt_required", nullptr);
    }
    const auto string_field = [proof](const char* primary, const char* fallback = nullptr)
        -> std::optional<std::string> {
        auto found = proof->find(primary);
        if (found == proof->end() && fallback != nullptr) found = proof->find(fallback);
        return found != proof->end() && found->is_string()
            ? std::optional<std::string>(found->get<std::string>())
            : std::nullopt;
    };
    const auto bool_field = [proof](const char* field) -> std::optional<bool> {
        const auto found = proof->find(field);
        return found != proof->end() && found->is_boolean()
            ? std::optional<bool>(found->get<bool>())
            : std::nullopt;
    };
    const auto unsigned_field = [&response, proof](const char* field)
        -> std::optional<std::uint64_t> {
        const auto value = response.find(field);
        if (value != response.end()) return unsigned_integer(*value);
        const auto fallback = proof->find(field);
        return fallback == proof->end() ? std::nullopt : unsigned_integer(*fallback);
    };
    const auto bool_response_field = [&response, proof](const char* field)
        -> std::optional<bool> {
        const json* value = nullptr;
        const auto direct = response.find(field);
        if (direct != response.end()) value = &*direct;
        const auto fallback = proof->find(field);
        if (value == nullptr && fallback != proof->end()) value = &*fallback;
        return value != nullptr && value->is_boolean()
            ? std::optional<bool>(value->get<bool>())
            : std::nullopt;
    };

    const auto proof_tool = string_field("tool");
    if (!proof_tool || *proof_tool != tool) {
        return invalid_value(
            "response.overlay_receipt.tool", "tool_mismatch",
            proof_tool ? json(*proof_tool) : json(nullptr));
    }
    const auto mode = string_field("mode", "mutation_mode");
    if (!mode || *mode != "reversible_overlay") {
        return invalid_value(
            "response.overlay_receipt.mode", "reversible_overlay_required",
            mode ? json(*mode) : json(nullptr));
    }
    const auto adapter = string_field("adapter");
    const auto live_write = bool_field("live_write");
    const auto ui_switched = bool_field("ui_switched");
    if (!live_write || *live_write || !ui_switched || *ui_switched) {
        return invalid_value("response.overlay_receipt", "isolated_overlay_required", *proof);
    }
    const auto target_file_write = bool_field("target_file_write");
    const bool isolated_target_file = target_file_write
        ? !*target_file_write
        : legacy && adapter && *adapter == "ida_compat_mut";
    if (!isolated_target_file) {
        return invalid_value(
            "response.overlay_receipt.target_file_write", "verified_false_required",
            target_file_write ? json(*target_file_write) : json(nullptr));
    }
    const auto non_overlapping = bool_field("non_overlapping");
    const bool verified_non_overlap = non_overlapping
        ? *non_overlapping
        : legacy && adapter && *adapter == "ida_compat_mut";
    if (!verified_non_overlap) {
        return invalid_value(
            "response.overlay_receipt.non_overlapping", "verified_true_required",
            non_overlapping ? json(*non_overlapping) : json(nullptr));
    }
    const auto committed = bool_response_field("committed");
    if (!committed || !*committed) {
        return invalid_value(
            "response.overlay_receipt.committed", "true_required",
            committed ? json(*committed) : json(nullptr));
    }
    const auto operations = unsigned_field("operations");
    if (!operations || *operations != expected_operations) {
        return invalid_value(
            "response.overlay_receipt.operations", "operation_count_mismatch",
            operations ? json(*operations) : json(nullptr));
    }
    const auto transaction_id = unsigned_field("transaction_id");
    if (!transaction_id || *transaction_id == 0U) {
        return invalid_value(
            "response.overlay_receipt.transaction_id", "positive_integer_required",
            transaction_id ? json(*transaction_id) : json(nullptr));
    }
    auto before = unsigned_field("revision_before");
    const auto after = unsigned_field("revision_after");
    const auto revision = unsigned_field("revision");
    if (!before && legacy) {
        const auto overlay_revision = proof->find("overlay_revision");
        if (overlay_revision != proof->end()) {
            before = unsigned_integer(*overlay_revision);
        }
    }
    if (!before) {
        return invalid_value(
            "response.overlay_receipt.revision_before",
            "verified_revision_required", nullptr);
    }
    receipt.revision_before = *before;
    receipt.revision_after = after.value_or(revision.value_or(0U));
    if (receipt.revision_before != expected_revision) {
        return invalid_value(
            "response.overlay_receipt.revision_before", "revision_mismatch",
            json{{"expected", expected_revision}, {"actual", receipt.revision_before}});
    }
    if (receipt.revision_after <= receipt.revision_before) {
        return invalid_value(
            "response.overlay_receipt.revision_after", "revision_must_advance",
            receipt.revision_after);
    }
    if (legacy) {
        const auto item_count = unsigned_field("item_count");
        const auto items = response.find("items");
        if (!item_count || *item_count != expected_operations ||
            items == response.end() || !items->is_array() ||
            items->size() != expected_operations ||
            std::any_of(items->begin(), items->end(), [](const json& item) {
                if (!item.is_object()) return true;
                const auto success = item.find("success");
                return success == item.end() || !success->is_boolean() ||
                    !success->get<bool>();
            })) {
            return invalid_value(
                "response.items", "successful_item_receipts_required",
                items == response.end() ? json(nullptr) : *items);
        }
    }
    receipt.transaction_id = *transaction_id;
    receipt.operations = *operations;
    return std::nullopt;
}

json overlay_receipt_metadata(std::string_view tool, const overlay_receipt_t& receipt) {
    return {
        {"tool", std::string(tool)},
        {"mode", "reversible_overlay"},
        {"transaction_id", receipt.transaction_id},
        {"operations", receipt.operations},
        {"revision_before", receipt.revision_before},
        {"revision_after", receipt.revision_after},
        {"committed", true},
        {"non_overlapping", true},
        {"live_write", false},
        {"target_file_write", false},
        {"ui_switched", false},
    };
}

struct frame_query_outcome_t final {
    std::optional<typed_stack_frame_t> frame;
    std::optional<adapter_error_t> adapter_error;
    validation_failure_t output_failure;
    std::size_t response_bytes = 0;
    bool cancelled = false;
};

frame_query_outcome_t query_typed_frame(
    workspace_adapter_t& workspace, const target_selector_t& target,
    const std::optional<std::uint64_t>& expected_generation,
    const std::chrono::steady_clock::time_point deadline,
    const protocol::cancellation_token_t& cancellation,
    const stack_handler_limits_t& limits, const std::string& address) {
    frame_query_outcome_t outcome;
    if (cancellation.cancelled()) {
        outcome.cancelled = true;
        return outcome;
    }
    adapter_request_t request;
    request.target = target;
    request.expected_generation = expected_generation;
    request.deadline = deadline;
    try {
        request.payload = json{{"address", address}, {"include_saved_regs", true}}.dump();
    } catch (const std::exception&) {
        outcome.output_failure = invalid_value(
            "request.address", "backend_request_serialization_failed", address);
        return outcome;
    }
    auto result = workspace.query("stack_frame", request);
    if (!result) {
        outcome.adapter_error = result.error();
        return outcome;
    }
    if (cancellation.cancelled()) {
        outcome.cancelled = true;
        return outcome;
    }
    auto response = std::move(result).take_value();
    outcome.response_bytes = response.payload.size();
    if (response.truncated) {
        outcome.output_failure = invalid_value(
            "response", "typed_frame_must_not_be_truncated", true);
        return outcome;
    }
    if (response.payload.empty()) {
        outcome.output_failure = invalid_value(
            "response_bytes", "nonempty_response_required", 0);
        return outcome;
    }
    if (response.payload.size() > limits.max_response_bytes) {
        outcome.output_failure = exceeded_value(
            "response_bytes", static_cast<std::uint64_t>(limits.max_response_bytes),
            static_cast<std::uint64_t>(response.payload.size()));
        return outcome;
    }
    json structured = json::parse(response.payload, nullptr, false);
    if (structured.is_discarded()) {
        outcome.output_failure = invalid_value(
            "response", "valid_json_object_required", nullptr);
        return outcome;
    }
    typed_stack_frame_t frame;
    if (auto failure = parse_typed_stack_frame(
            structured, address, limits, frame)) {
        outcome.output_failure = std::move(failure);
        return outcome;
    }
    outcome.frame = std::move(frame);
    return outcome;
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
        const auto arguments = decorator.find("args");
        if (arguments == decorator.end() || !arguments->is_array() || arguments->empty() ||
            !(*arguments)[0].is_number()) {
            continue;
        }
        try {
            const double seconds = (*arguments)[0].get<double>();
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
        "Stack workspace adapter rejected the request.",
        json{
            {"phase", "workspace_adapter"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

}

const std::array<std::string_view, k_stack_tool_count>& stack_tool_names() noexcept {
    return k_stack_names;
}

stack_handlers_t::stack_handlers_t(workspace_adapter_t& workspace,
                                   protocol::schema_runtime_t& schemas,
                                   stack_handler_limits_t limits)
    : workspace_(workspace), schemas_(schemas), limits_(std::move(limits)) {
    if (!valid_limits(limits_)) {
        throw std::invalid_argument("stack handler limits are invalid or weaken pinned maxima");
    }
    for (std::size_t index = 0; index < k_stack_names.size(); ++index) {
        const auto name = k_stack_names[index];
        const auto* descriptor =
            aida::standalone::mcp::compat::find_contract(name);
        if (descriptor == nullptr) {
            throw std::runtime_error(
                "generated stack descriptor is missing for " + std::string(name));
        }
        validate_generated_descriptor(*descriptor, name);
        contracts_[index] = make_tool_contract(*descriptor);
        const auto validation = protocol::validate_tool_contract(contracts_[index], schemas_);
        if (!validation.valid) {
            throw std::runtime_error(
                "generated stack contract validation failed for " + std::string(name) +
                ": " + validation.reason);
        }
    }
}

std::size_t stack_handlers_t::size() const noexcept {
    return contracts_.size();
}

const protocol::tool_contract_t& stack_handlers_t::contract_at(std::size_t index) const {
    return contracts_.at(index);
}

const protocol::tool_contract_t* stack_handlers_t::find(std::string_view name) const noexcept {
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    return found == contracts_.end() ? nullptr : &*found;
}

const stack_handler_limits_t& stack_handlers_t::limits() const noexcept {
    return limits_;
}

protocol::mcp_result_t stack_handlers_t::invoke(
    std::string_view name, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const stack_invocation_options_t& options,
    const protocol::json& aida_metadata) const {
    if (!aida_metadata.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::internal_error,
            "Stack tool provenance metadata must be a JSON object.",
            protocol::json{{"field", "aida_metadata"}});
    }
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    if (found == contracts_.end()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "Stack tool is not registered in the pinned contract group.",
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

protocol::mcp_result_t stack_handlers_t::dispatch(
    std::size_t index, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const stack_invocation_options_t& options) const {
    const auto name = k_stack_names.at(index);
    const auto& contract = contracts_.at(index);
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Stack tool invocation was cancelled before adapter routing.",
            protocol::json{{"phase", "stack_pre_route"}});
    }

    std::string serialized_arguments;
    try {
        serialized_arguments = arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Stack tool arguments cannot be serialized.",
            protocol::json{{"phase", "stack_request_serialization"}});
    }
    if (serialized_arguments.size() > limits_.max_request_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Stack tool request exceeds the bounded adapter quota.",
            exceeded_value(
                "request_bytes",
                static_cast<std::uint64_t>(limits_.max_request_bytes),
                static_cast<std::uint64_t>(serialized_arguments.size())));
    }
    if (auto failure = validate_tool_bounds(name, arguments, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Stack tool arguments violate the bounded adapter policy.",
            *failure);
    }

    target_selector_t target;
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        const auto value = unsigned_integer(*pid);
        if (value) {
            target.pid = static_cast<std::uint32_t>(*value);
        }
    }
    if (const auto bin_name = arguments.find("bin_name"); bin_name != arguments.end()) {
        target.bin_name = bin_name->get<std::string>();
    }
    const auto deadline = options.deadline.value_or(
        std::chrono::steady_clock::now() +
        execution_timeout(contract, limits_.max_execution_time));
    if (deadline <= std::chrono::steady_clock::now()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Stack tool invocation deadline expired before adapter routing.",
            protocol::json{{"phase", "stack_deadline"}});
    }

    const auto invalid_output = [](std::string message, const json& details) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            std::move(message), details);
    };
    const auto cancelled = [](std::string_view phase) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Stack tool invocation was cancelled during compatibility translation.",
            protocol::json{{"phase", std::string(phase)}});
    };
    const auto finalize = [this](json structured, json metadata) {
        std::string text;
        try {
            text = structured.dump();
        } catch (const std::exception&) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Stack generated-compatible output cannot be serialized.",
                protocol::json{{"phase", "stack_output_serialization"}});
        }
        if (text.size() > limits_.max_response_bytes) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Stack generated-compatible output exceeds the bounded quota.",
                exceeded_value(
                    "response_bytes",
                    static_cast<std::uint64_t>(limits_.max_response_bytes),
                    static_cast<std::uint64_t>(text.size())));
        }
        std::size_t metadata_bytes = 0;
        try {
            metadata_bytes = metadata.dump().size();
        } catch (const std::exception&) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Stack trusted metadata cannot be serialized.",
                protocol::json{{"phase", "stack_metadata_serialization"}});
        }
        if (metadata_bytes > limits_.max_response_bytes - text.size()) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Stack generated output and typed metadata exceed the bounded quota.",
                exceeded_value(
                    "response_and_metadata_bytes",
                    static_cast<std::uint64_t>(limits_.max_response_bytes),
                    static_cast<std::uint64_t>(text.size()) +
                        static_cast<std::uint64_t>(metadata_bytes)));
        }
        return protocol::mcp_result_t::success(
            std::move(text), structured, metadata);
    };

    if (name == "stack_frame") {
        json generated_results = json::array();
        json typed_frames = json::array();
        std::size_t backend_response_bytes = 0;
        std::optional<std::uint64_t> analysis_revision;
        std::optional<std::uint64_t> overlay_revision;
        for (const auto& address_value : item_list(arguments.at("addrs"))) {
            const std::string address = address_value.get<std::string>();
            auto outcome = query_typed_frame(
                workspace_, target, options.expected_generation, deadline,
                cancellation, limits_, address);
            if (outcome.cancelled) {
                return cancelled("stack_frame_query");
            }
            if (outcome.output_failure) {
                return invalid_output(
                    "Stack read adapter returned an invalid typed frame.",
                    *outcome.output_failure);
            }
            if (outcome.adapter_error) {
                if (outcome.adapter_error->code != adapter_error_code_t::backend_rejected) {
                    return adapter_failure(*outcome.adapter_error);
                }
                const std::string error(outcome.adapter_error->stable_code);
                generated_results.push_back({
                    {"addr", address}, {"vars", nullptr}, {"error", error},
                });
                typed_frames.push_back({
                    {"requested_address", address},
                    {"status", "backend_rejected"},
                    {"error", error},
                });
                continue;
            }
            backend_response_bytes += outcome.response_bytes;
            if (backend_response_bytes > limits_.max_response_bytes) {
                return invalid_output(
                    "Stack typed-frame aggregate exceeds the bounded response quota.",
                    exceeded_value(
                        "aggregate_backend_response_bytes",
                        static_cast<std::uint64_t>(limits_.max_response_bytes),
                        static_cast<std::uint64_t>(backend_response_bytes)));
            }
            auto& frame = *outcome.frame;
            if ((analysis_revision && *analysis_revision != frame.analysis_revision) ||
                (overlay_revision && *overlay_revision != frame.overlay_revision)) {
                return invalid_output(
                    "Stack typed-frame snapshot changed during the generated batch.",
                    invalid_value(
                        "response._meta.aida", "snapshot_revision_changed",
                        json{{"analysis_revision", frame.analysis_revision},
                             {"overlay_revision", frame.overlay_revision}}));
            }
            analysis_revision = frame.analysis_revision;
            overlay_revision = frame.overlay_revision;
            generated_results.push_back(generated_frame_result(frame));
            typed_frames.push_back(typed_frame_metadata(frame));
        }
        return finalize(
            json{{"result", std::move(generated_results)}},
            json{
                {"adapter_truncated", false},
                {"adapter_response_bytes", backend_response_bytes},
                {"compatibility_path", "generated_schema_from_typed_stack_frame"},
                {"typed_frames", std::move(typed_frames)},
            });
    }

    const std::vector<json> items = item_list(arguments.at("items"));
    json generated_results = json::array();
    for (const auto& item : items) {
        generated_results.push_back({
            {"addr", item.at("addr")},
            {"name", item.at("name")},
        });
    }

    struct declaration_t final {
        std::size_t index = 0;
        std::string address;
        std::string name;
        std::string type;
        std::int64_t offset = 0;
        std::uint64_t size = 0;
    };
    struct deletion_t final {
        std::string address;
        std::int64_t offset = 0;
    };
    struct cached_frame_t final {
        std::optional<typed_stack_frame_t> frame;
        std::optional<std::string> error;
    };

    std::vector<declaration_t> declarations;
    std::vector<std::string> query_addresses;
    std::unordered_set<std::string> unique_addresses;
    declarations.reserve(items.size());
    query_addresses.reserve(items.size());
    for (std::size_t item_index = 0; item_index < items.size(); ++item_index) {
        const std::string address = items[item_index].at("addr").get<std::string>();
        if (name == "declare_stack") {
            const auto offset = parse_signed_offset(
                items[item_index].at("offset").get_ref<const std::string&>());
            if (!offset) {
                generated_results[item_index]["error"] = "invalid_offset";
                continue;
            }
            const std::string type = items[item_index].at("ty").get<std::string>();
            declarations.push_back({
                item_index,
                address,
                items[item_index].at("name").get<std::string>(),
                type,
                *offset,
                estimated_type_size(type),
            });
        }
        if (unique_addresses.insert(address).second) {
            query_addresses.push_back(address);
        }
    }

    std::unordered_map<std::string, cached_frame_t> frames;
    frames.reserve(query_addresses.size());
    json typed_frames = json::array();
    std::size_t backend_response_bytes = 0;
    std::optional<std::uint64_t> analysis_revision;
    std::optional<std::uint64_t> overlay_revision;
    for (const auto& address : query_addresses) {
        auto outcome = query_typed_frame(
            workspace_, target, options.expected_generation, deadline,
            cancellation, limits_, address);
        if (outcome.cancelled) {
            return cancelled("stack_mutation_preflight");
        }
        if (outcome.output_failure) {
            return invalid_output(
                "Stack mutation preflight returned an invalid typed frame.",
                *outcome.output_failure);
        }
        if (outcome.adapter_error) {
            if (outcome.adapter_error->code != adapter_error_code_t::backend_rejected) {
                return adapter_failure(*outcome.adapter_error);
            }
            const std::string error(outcome.adapter_error->stable_code);
            frames.emplace(address, cached_frame_t{std::nullopt, error});
            typed_frames.push_back({
                {"requested_address", address},
                {"status", "backend_rejected"},
                {"error", error},
            });
            continue;
        }
        backend_response_bytes += outcome.response_bytes;
        if (backend_response_bytes > limits_.max_response_bytes) {
            return invalid_output(
                "Stack mutation preflight aggregate exceeds the response quota.",
                exceeded_value(
                    "aggregate_backend_response_bytes",
                    static_cast<std::uint64_t>(limits_.max_response_bytes),
                    static_cast<std::uint64_t>(backend_response_bytes)));
        }
        auto frame = std::move(*outcome.frame);
        if ((analysis_revision && *analysis_revision != frame.analysis_revision) ||
            (overlay_revision && *overlay_revision != frame.overlay_revision)) {
            return invalid_output(
                "Stack mutation preflight snapshot changed during the request.",
                invalid_value(
                    "response._meta.aida", "snapshot_revision_changed",
                    json{{"analysis_revision", frame.analysis_revision},
                         {"overlay_revision", frame.overlay_revision}}));
        }
        analysis_revision = frame.analysis_revision;
        overlay_revision = frame.overlay_revision;
        typed_frames.push_back(typed_frame_metadata(frame));
        frames.emplace(address, cached_frame_t{std::move(frame), std::nullopt});
    }

    std::vector<declaration_t> accepted_declarations;
    std::vector<deletion_t> accepted_deletions;
    if (name == "declare_stack") {
        std::unordered_map<std::string, std::vector<typed_stack_slot_t>> pending;
        accepted_declarations.reserve(declarations.size());
        for (const auto& declaration : declarations) {
            const auto cached = frames.find(declaration.address);
            if (cached == frames.end() || !cached->second.frame) {
                generated_results[declaration.index]["error"] =
                    cached != frames.end() && cached->second.error
                        ? *cached->second.error
                        : "frame_not_found";
                continue;
            }
            const std::string& canonical_address = cached->second.frame->function;
            const auto candidate_interval = stack_interval(
                declaration.offset, declaration.size);
            if (!candidate_interval) {
                generated_results[declaration.index]["error"] = "type_extent_invalid";
                continue;
            }
            std::string conflict;
            const std::string normalized_type = normalized_type_name(declaration.type);
            const auto inspect_slot = [&](const typed_stack_slot_t& existing,
                                          bool request_slot) {
                if (!conflict.empty()) {
                    return;
                }
                if (existing.name && *existing.name == declaration.name) {
                    if (!existing.type ||
                        normalized_type_name(*existing.type) != normalized_type) {
                        conflict = "type_conflict";
                        return;
                    }
                    conflict = existing.slot.offset == declaration.offset
                        ? "duplicate_declaration"
                        : "name_conflict";
                    return;
                }
                const auto existing_interval = stack_interval(
                    existing.slot.offset, effective_slot_size(existing));
                if (!existing_interval) {
                    conflict = "existing_slot_extent_invalid";
                    return;
                }
                if (!intervals_overlap(*candidate_interval, *existing_interval)) {
                    return;
                }
                const bool attach_to_inferred =
                    !request_slot && existing.source == "inferred" &&
                    !existing.name && existing.slot.offset == declaration.offset &&
                    candidate_interval->end <= existing_interval->end;
                if (!attach_to_inferred) {
                    conflict = "offset_overlap_conflict";
                }
            };
            for (const auto& existing : cached->second.frame->slots) {
                inspect_slot(existing, false);
            }
            for (const auto& existing : pending[canonical_address]) {
                inspect_slot(existing, true);
            }
            if (!conflict.empty()) {
                generated_results[declaration.index]["error"] = conflict;
                continue;
            }
            typed_stack_slot_t pending_slot;
            pending_slot.slot.offset = declaration.offset;
            pending_slot.slot.size = declaration.size;
            pending_slot.slot.kind = analysis::stack_slot_kind_t::unknown;
            pending_slot.slot.provenance = analysis::fact_provenance_t::user_definition;
            pending_slot.slot.confidence = 100U;
            pending_slot.name = declaration.name;
            pending_slot.type = declaration.type;
            pending_slot.source = "declared";
            pending[canonical_address].push_back(std::move(pending_slot));
            declaration_t accepted = declaration;
            accepted.address = canonical_address;
            accepted_declarations.push_back(std::move(accepted));
        }
    } else {
        std::unordered_set<std::string> deleted_entities;
        accepted_deletions.reserve(items.size());
        for (std::size_t item_index = 0; item_index < items.size(); ++item_index) {
            const std::string address = items[item_index].at("addr").get<std::string>();
            const std::string variable = items[item_index].at("name").get<std::string>();
            const auto cached = frames.find(address);
            if (cached == frames.end() || !cached->second.frame) {
                generated_results[item_index]["error"] =
                    cached != frames.end() && cached->second.error
                        ? *cached->second.error
                        : "frame_not_found";
                continue;
            }
            std::vector<std::int64_t> matches;
            for (const auto& slot : cached->second.frame->slots) {
                if (slot.name && *slot.name == variable) {
                    matches.push_back(slot.slot.offset);
                }
            }
            if (matches.empty()) {
                generated_results[item_index]["error"] = "variable_not_found";
                continue;
            }
            if (matches.size() != 1U) {
                generated_results[item_index]["error"] = "ambiguous_variable_name";
                continue;
            }
            const std::string& canonical_address = cached->second.frame->function;
            const std::string entity =
                canonical_address + ":" + format_signed_offset(matches.front());
            if (!deleted_entities.insert(entity).second) {
                generated_results[item_index]["error"] = "duplicate_deletion";
                continue;
            }
            accepted_deletions.push_back({canonical_address, matches.front()});
        }
    }

    const std::size_t accepted_count = name == "declare_stack"
        ? accepted_declarations.size()
        : accepted_deletions.size();
    json result_metadata{
        {"adapter_truncated", false},
        {"adapter_response_bytes", backend_response_bytes},
        {"compatibility_path", "generated_stack_schema_to_typed_overlay"},
        {"typed_frames", std::move(typed_frames)},
        {"accepted_operations", accepted_count},
        {"rejected_operations", items.size() - accepted_count},
    };
    if (accepted_count == 0U) {
        result_metadata["preflight_only"] = true;
        return finalize(
            json{{"result", std::move(generated_results)}},
            std::move(result_metadata));
    }
    if (!overlay_revision) {
        return invalid_output(
            "Stack mutation preflight did not provide an overlay revision.",
            invalid_value(
                "response._meta.aida.overlay_revision",
                "required_for_transaction", nullptr));
    }

    json backend_items = json::array();
    if (name == "declare_stack") {
        for (const auto& declaration : accepted_declarations) {
            backend_items.push_back({
                {"address", declaration.address},
                {"offset", declaration.offset},
                {"name", declaration.name},
                {"type", declaration.type},
            });
        }
    } else {
        for (const auto& deletion : accepted_deletions) {
            backend_items.push_back({
                {"address", deletion.address},
                {"offset", deletion.offset},
            });
        }
    }
    json backend_arguments{
        {"items", std::move(backend_items)},
        {"aida_tx", json{{"expected_revision", *overlay_revision}}},
    };
    adapter_request_t request;
    request.target = target;
    request.expected_generation = options.expected_generation;
    request.deadline = deadline;
    try {
        request.payload = backend_arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Stack typed overlay request cannot be serialized.",
            protocol::json{{"phase", "stack_overlay_serialization"}});
    }
    if (request.payload.size() > limits_.max_request_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Stack typed overlay request exceeds the bounded adapter quota.",
            exceeded_value(
                "backend_request_bytes",
                static_cast<std::uint64_t>(limits_.max_request_bytes),
                static_cast<std::uint64_t>(request.payload.size())));
    }
    if (cancellation.cancelled()) {
        return cancelled("stack_overlay_pre_commit");
    }
    auto adapter_result = workspace_.overlay(name, request);
    if (!adapter_result) {
        return adapter_failure(adapter_result.error());
    }
    if (cancellation.cancelled()) {
        return cancelled("stack_overlay_commit");
    }
    auto response = std::move(adapter_result).take_value();
    backend_response_bytes += response.payload.size();
    if (response.truncated || response.payload.empty() ||
        response.payload.size() > limits_.max_response_bytes ||
        backend_response_bytes > limits_.max_response_bytes) {
        return invalid_output(
            "Stack overlay adapter returned an incomplete or oversized receipt.",
            invalid_value(
                "response_bytes", "complete_bounded_receipt_required",
                json{{"truncated", response.truncated},
                     {"response_bytes", response.payload.size()},
                     {"aggregate_response_bytes", backend_response_bytes}}));
    }
    const json receipt_json = json::parse(response.payload, nullptr, false);
    if (receipt_json.is_discarded()) {
        return invalid_output(
            "Stack overlay adapter returned malformed receipt JSON.",
            invalid_value("response", "valid_json_object_required", nullptr));
    }
    overlay_receipt_t receipt;
    if (auto failure = validate_overlay_receipt(
            name, receipt_json, accepted_count, *overlay_revision, receipt)) {
        return invalid_output(
            "Stack overlay adapter returned an invalid reversible transaction receipt.",
            *failure);
    }
    result_metadata["adapter_response_bytes"] = backend_response_bytes;
    result_metadata["overlay_receipt"] = overlay_receipt_metadata(name, receipt);
    return finalize(
        json{{"result", std::move(generated_results)}},
        std::move(result_metadata));
}

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t stack_frame(const handlers::stack_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const handlers::stack_invocation_options_t& options,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("stack_frame", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t declare_stack(const handlers::stack_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const handlers::stack_invocation_options_t& options,
                                    const protocol::json& aida_metadata) {
    return handlers.invoke("declare_stack", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t delete_stack(const handlers::stack_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const handlers::stack_invocation_options_t& options,
                                    const protocol::json& aida_metadata) {
    return handlers.invoke("delete_stack", arguments, cancellation, options, aida_metadata);
}

}
