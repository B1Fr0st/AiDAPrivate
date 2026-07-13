#include "memory.h"

#include "../ida_contracts_generated.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cmath>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

enum class integer_endian_t : std::uint8_t {
    little,
    big,
};

struct integer_type_t final {
    std::string requested;
    std::string canonical;
    std::size_t width = 0;
    bool signed_value = false;
    integer_endian_t endian = integer_endian_t::little;
};

struct normalized_range_t final {
    std::size_t index = 0;
    std::string address_text;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
};

struct normalized_overlay_operation_t final {
    std::size_t index = 0;
    std::string address_text;
    std::uint64_t address = 0;
    std::string kind;
    std::string requested_type;
    std::string value;
    std::vector<std::uint8_t> bytes;
};

struct normalized_request_t final {
    json backend_arguments = json::object();
    std::vector<normalized_range_t> ranges;
    std::vector<integer_type_t> integer_types;
    std::vector<normalized_overlay_operation_t> overlay_operations;
    std::uint64_t aggregate_bytes = 0;
    std::size_t item_count = 0;
};

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

std::string_view trim_ascii(std::string_view value) noexcept {
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.remove_prefix(1);
    }
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.remove_suffix(1);
    }
    return value;
}

std::optional<std::uint64_t> parse_address(std::string_view text) noexcept {
    text = trim_ascii(text);
    if (text.empty() || text.front() == '-') {
        return std::nullopt;
    }
    if (text.front() == '+') {
        text.remove_prefix(1);
    }
    int base = 10;
    if (text.size() > 2 && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(
        text.data(), text.data() + text.size(), result, base);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    return result;
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

bool parse_hex_bytes(std::string_view source, std::size_t maximum,
                     std::vector<std::uint8_t>& bytes, std::string& reason) {
    bytes.clear();
    int high_nibble = -1;
    for (std::size_t index = 0; index < source.size(); ++index) {
        const char value = source[index];
        if (is_hex_separator(value)) {
            if (high_nibble != -1) {
                reason = "incomplete_hex_byte";
                return false;
            }
            continue;
        }
        if (value == '0' && index + 1 < source.size() &&
            (source[index + 1] == 'x' || source[index + 1] == 'X') &&
            high_nibble == -1) {
            ++index;
            continue;
        }
        const int nibble = hex_nibble(value);
        if (nibble < 0) {
            reason = "hexadecimal_bytes_required";
            return false;
        }
        if (high_nibble == -1) {
            high_nibble = nibble;
            continue;
        }
        if (bytes.size() >= maximum) {
            reason = "maximum_exceeded";
            return false;
        }
        bytes.push_back(static_cast<std::uint8_t>((high_nibble << 4) | nibble));
        high_nibble = -1;
    }
    if (high_nibble != -1) {
        reason = "incomplete_hex_byte";
        return false;
    }
    if (bytes.empty()) {
        reason = "nonempty_hex_bytes_required";
        return false;
    }
    return true;
}

std::string format_hex_bytes(const std::vector<std::uint8_t>& bytes) {
    static constexpr char k_hex[] = "0123456789ABCDEF";
    std::string result;
    if (!bytes.empty()) {
        result.reserve(bytes.size() * 3U - 1U);
    }
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0) {
            result.push_back(' ');
        }
        result.push_back(k_hex[(bytes[index] >> 4U) & 0x0FU]);
        result.push_back(k_hex[bytes[index] & 0x0FU]);
    }
    return result;
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
validation_failure_t for_each_scalar_or_array(const json& value, std::string_view path,
                                               std::size_t maximum_items,
                                               validator_t&& validator) {
    if (!value.is_array()) {
        return validator(value, std::string(path), 0U);
    }
    if (value.empty()) {
        return invalid_value(std::string(path), "nonempty_value_required", value);
    }
    if (value.size() > maximum_items) {
        return exceeded_value(
            std::string(path), static_cast<std::uint64_t>(maximum_items),
            static_cast<std::uint64_t>(value.size()));
    }
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (auto failure = validator(
                value[index], std::string(path) + "[" + std::to_string(index) + "]",
                index)) {
            return failure;
        }
    }
    return std::nullopt;
}

validation_failure_t add_to_aggregate(std::uint64_t& aggregate, std::uint64_t amount,
                                      std::uint64_t maximum, std::string path) {
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

validation_failure_t normalize_address_member(
    const json& object, std::string_view field, const std::string& path,
    const memory_handler_limits_t& limits, std::string& text,
    std::uint64_t& address) {
    const auto found = object.find(std::string(field));
    if (found == object.end()) {
        return invalid_value(path + "." + std::string(field),
                             "field_required", json(nullptr));
    }
    if (auto failure = bounded_text(
            *found, path + "." + std::string(field),
            limits.maximum_address_bytes, false)) {
        return failure;
    }
    text = found->get<std::string>();
    const auto parsed = parse_address(text);
    if (!parsed) {
        return invalid_value(path + "." + std::string(field),
                             "hex_or_decimal_address_required", *found);
    }
    address = *parsed;
    return std::nullopt;
}

validation_failure_t normalize_integer_type(const json& value, std::string path,
                                            integer_type_t& type) {
    if (!value.is_string()) {
        return invalid_value(std::move(path), "string_required", value);
    }
    type.requested = value.get<std::string>();
    std::string normalized;
    normalized.reserve(type.requested.size());
    for (const char character : type.requested) {
        normalized.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(character))));
    }
    bool explicit_endian = false;
    if (normalized.size() > 2) {
        const std::string_view suffix(normalized.data() + normalized.size() - 2, 2);
        if (suffix == "le" || suffix == "be") {
            explicit_endian = true;
            type.endian = suffix == "be" ? integer_endian_t::big
                                         : integer_endian_t::little;
            normalized.resize(normalized.size() - 2);
        }
    }
    if (normalized.size() < 2 ||
        (normalized.front() != 'i' && normalized.front() != 'u')) {
        return invalid_value(std::move(path), "supported_integer_type_required", value);
    }
    type.signed_value = normalized.front() == 'i';
    const std::string_view width_text(normalized.data() + 1, normalized.size() - 1);
    unsigned int width_bits = 0;
    const auto parsed = std::from_chars(
        width_text.data(), width_text.data() + width_text.size(), width_bits, 10);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != width_text.data() + width_text.size() ||
        (width_bits != 8U && width_bits != 16U &&
         width_bits != 32U && width_bits != 64U)) {
        return invalid_value(std::move(path), "supported_integer_type_required", value);
    }
    type.width = width_bits / 8U;
    type.canonical = std::string(1, type.signed_value ? 'i' : 'u') +
        std::to_string(width_bits);
    if (explicit_endian) {
        type.canonical += type.endian == integer_endian_t::big ? "be" : "le";
    }
    return std::nullopt;
}

validation_failure_t parse_integer_value(std::string_view source,
                                         const integer_type_t& type,
                                         std::uint64_t& encoded) {
    source = trim_ascii(source);
    if (source.empty()) {
        return invalid_value("value", "integer_string_required", std::string(source));
    }
    bool negative = false;
    if (source.front() == '-' || source.front() == '+') {
        negative = source.front() == '-';
        source.remove_prefix(1);
    }
    if (source.empty() || (negative && !type.signed_value)) {
        return invalid_value("value", "integer_value_out_of_range", std::string(source));
    }
    int base = 10;
    if (source.size() > 2 && source[0] == '0' &&
        (source[1] == 'x' || source[1] == 'X')) {
        source.remove_prefix(2);
        base = 16;
    }
    if (source.empty()) {
        return invalid_value("value", "integer_string_required", std::string(source));
    }
    std::uint64_t magnitude = 0;
    const auto parsed = std::from_chars(
        source.data(), source.data() + source.size(), magnitude, base);
    if (parsed.ec != std::errc{} || parsed.ptr != source.data() + source.size()) {
        return invalid_value("value", "integer_string_required", std::string(source));
    }
    const unsigned int bits = static_cast<unsigned int>(type.width * 8U);
    const std::uint64_t mask = bits == 64U
        ? (std::numeric_limits<std::uint64_t>::max)()
        : (1ULL << bits) - 1ULL;
    if (!type.signed_value) {
        if (magnitude > mask) {
            return invalid_value("value", "integer_value_out_of_range", magnitude);
        }
        encoded = magnitude;
        return std::nullopt;
    }
    const std::uint64_t sign_limit = bits == 64U
        ? (1ULL << 63U)
        : (1ULL << (bits - 1U));
    const std::uint64_t positive_limit = sign_limit - 1ULL;
    if ((!negative && magnitude > positive_limit) ||
        (negative && magnitude > sign_limit)) {
        return invalid_value("value", "integer_value_out_of_range", magnitude);
    }
    encoded = negative ? ((~magnitude) + 1ULL) & mask : magnitude;
    return std::nullopt;
}

std::vector<std::uint8_t> encode_integer(std::uint64_t encoded,
                                         const integer_type_t& type) {
    std::vector<std::uint8_t> bytes(type.width);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const std::size_t source_index = type.endian == integer_endian_t::big
            ? bytes.size() - index - 1U
            : index;
        bytes[index] = static_cast<std::uint8_t>(
            (encoded >> (source_index * 8U)) & 0xFFU);
    }
    return bytes;
}

json decode_integer(const std::vector<std::uint8_t>& bytes,
                    const integer_type_t& type) {
    std::uint64_t encoded = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const std::size_t destination_index = type.endian == integer_endian_t::big
            ? bytes.size() - index - 1U
            : index;
        encoded |= static_cast<std::uint64_t>(bytes[index]) <<
            (destination_index * 8U);
    }
    if (!type.signed_value) {
        return encoded;
    }
    const unsigned int bits = static_cast<unsigned int>(type.width * 8U);
    const std::uint64_t sign_bit = bits == 64U
        ? (1ULL << 63U)
        : (1ULL << (bits - 1U));
    if ((encoded & sign_bit) == 0) {
        return static_cast<std::int64_t>(encoded);
    }
    const std::uint64_t magnitude = (~encoded) + 1ULL;
    if (bits == 64U && magnitude == sign_bit) {
        return (std::numeric_limits<std::int64_t>::min)();
    }
    const std::uint64_t mask = bits == 64U
        ? (std::numeric_limits<std::uint64_t>::max)()
        : (1ULL << bits) - 1ULL;
    return -static_cast<std::int64_t>(magnitude & mask);
}

validation_failure_t normalize_get_bytes(const json& arguments,
                                         const memory_handler_limits_t& limits,
                                         normalized_request_t& normalized) {
    const auto regions = arguments.find("regions");
    if (regions == arguments.end()) {
        return invalid_value("regions", "field_required", json(nullptr));
    }
    return for_each_scalar_or_array(*regions, "regions", limits.maximum_batch_items,
        [&limits, &normalized](const json& region, std::string path,
                               std::size_t index) -> validation_failure_t {
            if (!region.is_object()) {
                return invalid_value(std::move(path), "object_required", region);
            }
            normalized_range_t range;
            range.index = index;
            if (auto failure = normalize_address_member(
                    region, "addr", path, limits,
                    range.address_text, range.address)) {
                return failure;
            }
            const auto size = region.find("size");
            const auto parsed_size = size == region.end()
                ? std::optional<std::uint64_t>{}
                : unsigned_integer(*size);
            if (!parsed_size || *parsed_size == 0) {
                return invalid_value(path + ".size", "positive_integer_required",
                                     size == region.end() ? json(nullptr) : *size);
            }
            if (*parsed_size > limits.maximum_read_bytes_per_item) {
                return exceeded_value(path + ".size",
                                      limits.maximum_read_bytes_per_item,
                                      *parsed_size);
            }
            if (auto failure = add_to_aggregate(
                    normalized.aggregate_bytes, *parsed_size,
                    limits.maximum_read_bytes_per_call, "aggregate_read_bytes")) {
                return failure;
            }
            range.size = *parsed_size;
            normalized.ranges.push_back(std::move(range));
            ++normalized.item_count;
            return std::nullopt;
        });
}

validation_failure_t normalize_get_int(const json& arguments,
                                       const memory_handler_limits_t& limits,
                                       normalized_request_t& normalized) {
    const auto queries = arguments.find("queries");
    if (queries == arguments.end()) {
        return invalid_value("queries", "field_required", json(nullptr));
    }
    return for_each_scalar_or_array(*queries, "queries", limits.maximum_batch_items,
        [&limits, &normalized](const json& query, std::string path,
                               std::size_t index) -> validation_failure_t {
            if (!query.is_object()) {
                return invalid_value(std::move(path), "object_required", query);
            }
            normalized_range_t range;
            range.index = index;
            if (auto failure = normalize_address_member(
                    query, "addr", path, limits,
                    range.address_text, range.address)) {
                return failure;
            }
            if (auto failure = bounded_member_text(
                    query, "ty", path, limits.maximum_type_bytes, false)) {
                return failure;
            }
            const auto type_field = query.find("ty");
            integer_type_t type;
            if (type_field == query.end()) {
                return invalid_value(path + ".ty", "field_required", json(nullptr));
            }
            if (auto failure = normalize_integer_type(*type_field, path + ".ty", type)) {
                return failure;
            }
            range.size = static_cast<std::uint64_t>(type.width);
            if (auto failure = add_to_aggregate(
                    normalized.aggregate_bytes, range.size,
                    limits.maximum_read_bytes_per_call, "aggregate_read_bytes")) {
                return failure;
            }
            normalized.ranges.push_back(std::move(range));
            normalized.integer_types.push_back(std::move(type));
            ++normalized.item_count;
            return std::nullopt;
        });
}

validation_failure_t normalize_get_string(const json& arguments,
                                          const memory_handler_limits_t& limits,
                                          normalized_request_t& normalized) {
    const auto addrs = arguments.find("addrs");
    if (addrs == arguments.end()) {
        return invalid_value("addrs", "field_required", json(nullptr));
    }
    return for_each_scalar_or_array(*addrs, "addrs", limits.maximum_batch_items,
        [&limits, &normalized](const json& addr, std::string path,
                               std::size_t index) -> validation_failure_t {
            if (auto failure = bounded_text(
                    addr, path, limits.maximum_address_bytes, false)) {
                return failure;
            }
            normalized_range_t range;
            range.index = index;
            range.address_text = addr.get<std::string>();
            const auto parsed = parse_address(range.address_text);
            if (!parsed) {
                return invalid_value(std::move(path),
                                     "hex_or_decimal_address_required", addr);
            }
            range.address = *parsed;
            range.size = limits.maximum_string_bytes;
            if (auto failure = add_to_aggregate(
                    normalized.aggregate_bytes, range.size,
                    limits.maximum_read_bytes_per_call, "aggregate_string_bytes")) {
                return failure;
            }
            normalized.ranges.push_back(std::move(range));
            ++normalized.item_count;
            return std::nullopt;
        });
}

validation_failure_t normalize_get_global_value(const json& arguments,
                                                const memory_handler_limits_t& limits,
                                                normalized_request_t& normalized) {
    const auto queries = arguments.find("queries");
    if (queries == arguments.end()) {
        return invalid_value("queries", "field_required", json(nullptr));
    }
    return for_each_scalar_or_array(*queries, "queries", limits.maximum_batch_items,
        [&limits, &normalized](const json& item, std::string path,
                               std::size_t) -> validation_failure_t {
            if (auto failure = bounded_text(
                    item, std::move(path), limits.maximum_address_bytes, false)) {
                return failure;
            }
            ++normalized.item_count;
            return std::nullopt;
        });
}

validation_failure_t normalize_patch(const json& arguments,
                                     const memory_handler_limits_t& limits,
                                     normalized_request_t& normalized) {
    const auto patches = arguments.find("patches");
    if (patches == arguments.end()) {
        return invalid_value("patches", "field_required", json(nullptr));
    }
    return for_each_scalar_or_array(*patches, "patches", limits.maximum_batch_items,
        [&limits, &normalized](const json& patch, std::string path,
                               std::size_t index) -> validation_failure_t {
            if (!patch.is_object()) {
                return invalid_value(std::move(path), "object_required", patch);
            }
            normalized_overlay_operation_t operation;
            operation.index = index;
            operation.kind = "byte_patch";
            if (auto failure = normalize_address_member(
                    patch, "addr", path, limits,
                    operation.address_text, operation.address)) {
                return failure;
            }
            if (auto failure = bounded_member_text(
                    patch, "data", path, limits.maximum_request_bytes, false)) {
                return failure;
            }
            const auto data = patch.find("data");
            if (data == patch.end()) {
                return invalid_value(path + ".data", "field_required", json(nullptr));
            }
            std::string reason;
            if (!parse_hex_bytes(
                    data->get_ref<const std::string&>(),
                    static_cast<std::size_t>(limits.maximum_read_bytes_per_item),
                    operation.bytes, reason)) {
                return invalid_value(path + ".data", std::move(reason), *data);
            }
            if (auto failure = add_to_aggregate(
                    normalized.aggregate_bytes,
                    static_cast<std::uint64_t>(operation.bytes.size()),
                    limits.maximum_read_bytes_per_call, "aggregate_overlay_bytes")) {
                return failure;
            }
            normalized.overlay_operations.push_back(std::move(operation));
            ++normalized.item_count;
            return std::nullopt;
        });
}

validation_failure_t normalize_put_int(const json& arguments,
                                       const memory_handler_limits_t& limits,
                                       normalized_request_t& normalized) {
    const auto items = arguments.find("items");
    if (items == arguments.end()) {
        return invalid_value("items", "field_required", json(nullptr));
    }
    return for_each_scalar_or_array(*items, "items", limits.maximum_batch_items,
        [&limits, &normalized](const json& item, std::string path,
                               std::size_t index) -> validation_failure_t {
            if (!item.is_object()) {
                return invalid_value(std::move(path), "object_required", item);
            }
            normalized_overlay_operation_t operation;
            operation.index = index;
            operation.kind = "integer_patch";
            if (auto failure = normalize_address_member(
                    item, "addr", path, limits,
                    operation.address_text, operation.address)) {
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
            const auto type_field = item.find("ty");
            const auto value_field = item.find("value");
            if (type_field == item.end() || value_field == item.end()) {
                return invalid_value(path, "integer_patch_fields_required", item);
            }
            integer_type_t type;
            if (auto failure = normalize_integer_type(
                    *type_field, path + ".ty", type)) {
                return failure;
            }
            std::uint64_t encoded = 0;
            if (auto failure = parse_integer_value(
                    value_field->get_ref<const std::string&>(), type, encoded)) {
                (*failure)["field"] = path + ".value";
                (*failure)["actual"] = *value_field;
                return failure;
            }
            operation.requested_type = type.requested;
            operation.value = value_field->get<std::string>();
            operation.bytes = encode_integer(encoded, type);
            if (auto failure = add_to_aggregate(
                    normalized.aggregate_bytes,
                    static_cast<std::uint64_t>(operation.bytes.size()),
                    limits.maximum_read_bytes_per_call, "aggregate_overlay_bytes")) {
                return failure;
            }
            normalized.integer_types.push_back(std::move(type));
            normalized.overlay_operations.push_back(std::move(operation));
            ++normalized.item_count;
            return std::nullopt;
        });
}

json read_intent(std::string_view name, const normalized_request_t& normalized,
                 const memory_handler_limits_t& limits,
                 const memory_invocation_t& invocation) {
    json ranges = json::array();
    for (std::size_t index = 0; index < normalized.ranges.size(); ++index) {
        const auto& range = normalized.ranges[index];
        json entry{
            {"index", range.index},
            {"addr", range.address_text},
            {"address", range.address},
            {"size", range.size},
        };
        if (name == "get_int") {
            const auto& type = normalized.integer_types.at(index);
            entry["integer_type"] = type.canonical;
            entry["signed"] = type.signed_value;
            entry["endian"] = type.endian == integer_endian_t::big
                ? "big"
                : "little";
        }
        if (name == "get_string") {
            entry["null_terminated"] = true;
        }
        ranges.push_back(std::move(entry));
    }
    json intent{
        {"protocol", "aida.memory.v1"},
        {"operation", "read"},
        {"tool", std::string(name)},
        {"response_mode", name == "get_int" ? "raw_hex_bytes" : "public_result"},
        {"source_policy", "immutable_static_or_bounded_live"},
        {"aggregate_requested_bytes", normalized.aggregate_bytes},
        {"aggregate_limit_bytes", limits.maximum_read_bytes_per_call},
        {"item_count", normalized.item_count},
        {"ranges", std::move(ranges)},
        {"static_snapshot", json{
            {"required", true},
            {"immutable", true},
            {"generation_bound", true},
        }},
        {"live_snapshot", json{
            {"permitted", true},
            {"read_only", true},
            {"module_boundary_required", true},
            {"identity_revalidation_required", true},
            {"maximum_range_bytes", limits.maximum_read_bytes_per_item},
            {"maximum_aggregate_bytes", limits.maximum_read_bytes_per_call},
        }},
    };
    if (invocation.expected_generation) {
        intent["expected_generation"] = *invocation.expected_generation;
    }
    if (invocation.expected_live_identity) {
        const auto& identity = *invocation.expected_live_identity;
        intent["expected_live_identity"] = {
            {"target_id", identity.target_id},
            {"pid", identity.pid},
            {"process_creation_identity", identity.process_creation_identity},
            {"module_base", identity.module_base},
            {"module_size", identity.module_size},
            {"attach_generation", identity.attach_generation},
        };
    }
    return intent;
}

json overlay_intent(std::string_view name, const normalized_request_t& normalized,
                    const memory_invocation_t& invocation) {
    json operations = json::array();
    for (std::size_t index = 0; index < normalized.overlay_operations.size(); ++index) {
        const auto& operation = normalized.overlay_operations[index];
        json entry{
            {"index", operation.index},
            {"kind", operation.kind},
            {"addr", operation.address_text},
            {"address", operation.address},
            {"size", operation.bytes.size()},
            {"after", format_hex_bytes(operation.bytes)},
        };
        if (name == "put_int") {
            const auto& type = normalized.integer_types.at(index);
            entry["ty"] = operation.requested_type;
            entry["integer_type"] = type.canonical;
            entry["value"] = operation.value;
            entry["signed"] = type.signed_value;
            entry["endian"] = type.endian == integer_endian_t::big
                ? "big"
                : "little";
        }
        operations.push_back(std::move(entry));
    }
    json intent{
        {"protocol", "aida.memory.v1"},
        {"operation", "overlay_transaction"},
        {"tool", std::string(name)},
        {"static_target_only", true},
        {"live_write_permitted", false},
        {"atomic", true},
        {"reversible", true},
        {"aggregate_write_bytes", normalized.aggregate_bytes},
        {"item_count", normalized.item_count},
        {"operations", std::move(operations)},
    };
    if (invocation.expected_generation) {
        intent["expected_generation"] = *invocation.expected_generation;
    }
    return intent;
}

validation_failure_t normalize_tool_request(
    std::string_view name, const json& arguments,
    const memory_handler_limits_t& limits,
    const memory_invocation_t& invocation,
    normalized_request_t& normalized) {
    if (auto failure = validate_routing_bounds(arguments, limits)) {
        return failure;
    }
    normalized.backend_arguments = arguments;
    normalized.backend_arguments.erase("pid");
    normalized.backend_arguments.erase("bin_name");
    validation_failure_t failure;
    if (name == "get_bytes") {
        failure = normalize_get_bytes(arguments, limits, normalized);
    } else if (name == "get_int") {
        failure = normalize_get_int(arguments, limits, normalized);
    } else if (name == "get_string") {
        failure = normalize_get_string(arguments, limits, normalized);
    } else if (name == "get_global_value") {
        failure = normalize_get_global_value(arguments, limits, normalized);
    } else if (name == "patch") {
        failure = normalize_patch(arguments, limits, normalized);
    } else if (name == "put_int") {
        failure = normalize_put_int(arguments, limits, normalized);
    } else {
        return invalid_value("tool", "memory_tool_not_registered", std::string(name));
    }
    if (failure) {
        return failure;
    }
    normalized.backend_arguments["_aida_memory"] = is_overlay_tool(name)
        ? overlay_intent(name, normalized, invocation)
        : read_intent(name, normalized, limits, invocation);
    return std::nullopt;
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

struct normalized_response_t final {
    json structured = json::object();
    json metadata = json::object();
};

struct snapshot_receipt_t final {
    json value = json::object();
    std::uint64_t generation = 0;
    std::uint64_t bytes_read = 0;
};

bool member_is_true(const json& object, std::string_view name) {
    const auto found = object.find(std::string(name));
    return found != object.end() && found->is_boolean() && found->get<bool>();
}

bool member_is_false(const json& object, std::string_view name) {
    const auto found = object.find(std::string(name));
    return found != object.end() && found->is_boolean() && !found->get<bool>();
}

validation_failure_t require_unsigned_member(
    const json& object, std::string_view name, std::string path,
    std::uint64_t& value) {
    const auto found = object.find(std::string(name));
    if (found == object.end()) {
        return invalid_value(path + "." + std::string(name),
                             "field_required", json(nullptr));
    }
    const auto parsed = unsigned_integer(*found);
    if (!parsed) {
        return invalid_value(path + "." + std::string(name),
                             "nonnegative_integer_required", *found);
    }
    value = *parsed;
    return std::nullopt;
}

validation_failure_t require_string_member(
    const json& object, std::string_view name, std::string path,
    std::size_t maximum, std::string& value) {
    const auto found = object.find(std::string(name));
    if (found == object.end()) {
        return invalid_value(path + "." + std::string(name),
                             "field_required", json(nullptr));
    }
    if (auto failure = bounded_text(
            *found, path + "." + std::string(name), maximum, false)) {
        return failure;
    }
    value = found->get<std::string>();
    return std::nullopt;
}

validation_failure_t normalize_snapshot_receipt(
    const json& response, const normalized_request_t& request,
    const memory_handler_limits_t& limits,
    const memory_invocation_t& invocation,
    snapshot_receipt_t& receipt) {
    const auto memory = response.find("_aida_memory");
    if (memory == response.end() || !memory->is_object()) {
        return invalid_value("response._aida_memory", "object_required",
                             memory == response.end() ? json(nullptr) : *memory);
    }
    const auto snapshot = memory->find("snapshot");
    if (snapshot == memory->end() || !snapshot->is_object()) {
        return invalid_value("response._aida_memory.snapshot", "object_required",
                             snapshot == memory->end() ? json(nullptr) : *snapshot);
    }
    std::string source;
    if (auto failure = require_string_member(
            *snapshot, "source", "response._aida_memory.snapshot",
            limits.maximum_type_bytes, source)) {
        return failure;
    }
    if (auto failure = require_unsigned_member(
            *snapshot, "generation", "response._aida_memory.snapshot",
            receipt.generation)) {
        return failure;
    }
    if (receipt.generation == 0 ||
        (invocation.expected_generation &&
         receipt.generation != *invocation.expected_generation)) {
        return invalid_value("response._aida_memory.snapshot.generation",
                             "snapshot_generation_mismatch", receipt.generation);
    }
    if (auto failure = require_unsigned_member(
            *snapshot, "bytes_read", "response._aida_memory.snapshot",
            receipt.bytes_read)) {
        return failure;
    }
    const std::uint64_t receipt_limit = request.aggregate_bytes == 0
        ? limits.maximum_read_bytes_per_call
        : request.aggregate_bytes;
    if (receipt.bytes_read > receipt_limit) {
        return exceeded_value("response._aida_memory.snapshot.bytes_read",
                              receipt_limit, receipt.bytes_read);
    }
    if (!member_is_true(*snapshot, "read_only")) {
        return invalid_value("response._aida_memory.snapshot.read_only",
                             "true_required", snapshot->value("read_only", json(nullptr)));
    }
    if (source == "immutable_workspace_snapshot") {
        if (!member_is_true(*snapshot, "immutable")) {
            return invalid_value("response._aida_memory.snapshot.immutable",
                                 "true_required", snapshot->value("immutable", json(nullptr)));
        }
    } else if (source == "bounded_live_snapshot") {
        if (!member_is_true(*snapshot, "module_boundary_validated") ||
            !member_is_true(*snapshot, "identity_revalidated")) {
            return invalid_value("response._aida_memory.snapshot",
                                 "live_boundary_and_identity_evidence_required", *snapshot);
        }
        if (!invocation.expected_live_identity) {
            return invalid_value("response._aida_memory.snapshot",
                                 "live_identity_expectation_required", *snapshot);
        }
        std::uint64_t target_id = 0;
        std::uint64_t pid = 0;
        std::uint64_t process_creation_identity = 0;
        std::uint64_t module_base = 0;
        std::uint64_t module_size = 0;
        std::uint64_t attach_generation = 0;
        const std::string path = "response._aida_memory.snapshot";
        if (auto failure = require_unsigned_member(
                *snapshot, "target_id", path, target_id))
            return failure;
        if (auto failure = require_unsigned_member(*snapshot, "pid", path, pid))
            return failure;
        if (auto failure = require_unsigned_member(
                *snapshot, "process_creation_identity", path,
                process_creation_identity))
            return failure;
        if (auto failure = require_unsigned_member(
                *snapshot, "module_base", path, module_base))
            return failure;
        if (auto failure = require_unsigned_member(
                *snapshot, "module_size", path, module_size))
            return failure;
        if (auto failure = require_unsigned_member(
                *snapshot, "attach_generation", path, attach_generation))
            return failure;
        if (target_id == 0 || pid == 0 ||
            pid > (std::numeric_limits<std::uint32_t>::max)() ||
            process_creation_identity == 0 || module_base == 0 || module_size == 0 ||
            module_base > (std::numeric_limits<std::uint64_t>::max)() - module_size ||
            attach_generation == 0) {
            return invalid_value(path, "valid_live_identity_required", *snapshot);
        }
        const auto& expected = *invocation.expected_live_identity;
        if (target_id != expected.target_id ||
            pid != expected.pid ||
            process_creation_identity != expected.process_creation_identity ||
            module_base != expected.module_base || module_size != expected.module_size ||
            attach_generation != expected.attach_generation) {
            return invalid_value(path, "live_identity_mismatch", json{
                {"expected", json{
                    {"target_id", expected.target_id},
                    {"pid", expected.pid},
                    {"process_creation_identity", expected.process_creation_identity},
                    {"module_base", expected.module_base},
                    {"module_size", expected.module_size},
                    {"attach_generation", expected.attach_generation},
                }},
                {"actual", json{
                    {"target_id", target_id},
                    {"pid", pid},
                    {"process_creation_identity", process_creation_identity},
                    {"module_base", module_base},
                    {"module_size", module_size},
                    {"attach_generation", attach_generation},
                }},
            });
        }
    } else {
        return invalid_value("response._aida_memory.snapshot.source",
                             "supported_snapshot_source_required", source);
    }
    receipt.value = *snapshot;
    return std::nullopt;
}

validation_failure_t require_result_array(
    const json& response, std::size_t expected_count, const json*& result) {
    const auto found = response.find("result");
    if (found == response.end() || !found->is_array()) {
        return invalid_value("response.result", "array_required",
                             found == response.end() ? json(nullptr) : *found);
    }
    if (found->size() != expected_count) {
        return invalid_value("response.result", "item_count_mismatch",
                             json{{"expected", expected_count},
                                  {"actual", found->size()}});
    }
    result = &*found;
    return std::nullopt;
}

validation_failure_t normalize_get_bytes_response(
    const json& response, const normalized_request_t& request,
    const memory_handler_limits_t& limits, normalized_response_t& normalized,
    std::uint64_t& decoded_bytes) {
    const json* result = nullptr;
    if (auto failure = require_result_array(response, request.item_count, result)) {
        return failure;
    }
    json public_items = json::array();
    for (std::size_t index = 0; index < result->size(); ++index) {
        const auto& item = (*result)[index];
        if (!item.is_object()) {
            return invalid_value("response.result[" + std::to_string(index) + "]",
                                 "object_required", item);
        }
        const auto addr = item.find("addr");
        const auto data = item.find("data");
        if (addr == item.end() ||
            (!addr->is_string() && !addr->is_null()) ||
            data == item.end() ||
            (!data->is_string() && !data->is_null())) {
            return invalid_value("response.result[" + std::to_string(index) + "]",
                                 "address_and_data_required", item);
        }
        json output{{"addr", *addr}, {"data", *data}};
        bool has_error = false;
        if (const auto error = item.find("error"); error != item.end()) {
            if (!error->is_string()) {
                return invalid_value(
                    "response.result[" + std::to_string(index) + "].error",
                    "string_required", *error);
            }
            output["error"] = *error;
            has_error = !error->get_ref<const std::string&>().empty();
        }
        if (data->is_null()) {
            if (!has_error) {
                return invalid_value(
                    "response.result[" + std::to_string(index) + "].data",
                    "error_required_for_null_data", *data);
            }
        } else {
            std::vector<std::uint8_t> bytes;
            std::string reason;
            if (!parse_hex_bytes(
                    data->get_ref<const std::string&>(),
                    static_cast<std::size_t>(request.ranges[index].size),
                    bytes, reason)) {
                return invalid_value(
                    "response.result[" + std::to_string(index) + "].data",
                    std::move(reason), *data);
            }
            if (!has_error && bytes.size() != request.ranges[index].size) {
                return invalid_value(
                    "response.result[" + std::to_string(index) + "].data",
                    "complete_read_or_explicit_error_required", *data);
            }
            if (auto failure = add_to_aggregate(
                    decoded_bytes, static_cast<std::uint64_t>(bytes.size()),
                    limits.maximum_read_bytes_per_call,
                    "response.aggregate_read_bytes")) {
                return failure;
            }
            output["data"] = format_hex_bytes(bytes);
        }
        public_items.push_back(std::move(output));
    }
    normalized.structured = json{{"result", std::move(public_items)}};
    return std::nullopt;
}

validation_failure_t normalize_get_int_response(
    const json& response, const normalized_request_t& request,
    const memory_handler_limits_t& limits, normalized_response_t& normalized,
    std::uint64_t& decoded_bytes) {
    const json* result = nullptr;
    if (auto failure = require_result_array(response, request.item_count, result)) {
        return failure;
    }
    json public_items = json::array();
    for (std::size_t index = 0; index < result->size(); ++index) {
        const auto& item = (*result)[index];
        if (!item.is_object()) {
            return invalid_value("response.result[" + std::to_string(index) + "]",
                                 "object_required", item);
        }
        const auto addr = item.find("addr");
        if (addr == item.end() || !addr->is_string()) {
            return invalid_value(
                "response.result[" + std::to_string(index) + "].addr",
                "string_required", addr == item.end() ? json(nullptr) : *addr);
        }
        const auto& type = request.integer_types[index];
        json output{
            {"addr", *addr},
            {"ty", type.requested},
            {"value", nullptr},
        };
        bool has_error = false;
        if (const auto error = item.find("error"); error != item.end()) {
            if (!error->is_string()) {
                return invalid_value(
                    "response.result[" + std::to_string(index) + "].error",
                    "string_required", *error);
            }
            output["error"] = *error;
            has_error = !error->get_ref<const std::string&>().empty();
        }
        const auto data = item.find("data");
        if (has_error) {
            if (data != item.end() && !data->is_null()) {
                return invalid_value(
                    "response.result[" + std::to_string(index) + "].data",
                    "null_required_for_failed_integer_read", *data);
            }
        } else {
            if (data == item.end() || !data->is_string()) {
                return invalid_value(
                    "response.result[" + std::to_string(index) + "].data",
                    "raw_hex_bytes_required",
                    data == item.end() ? json(nullptr) : *data);
            }
            std::vector<std::uint8_t> bytes;
            std::string reason;
            if (!parse_hex_bytes(data->get_ref<const std::string&>(),
                                 type.width, bytes, reason) ||
                bytes.size() != type.width) {
                return invalid_value(
                    "response.result[" + std::to_string(index) + "].data",
                    bytes.size() == type.width ? std::move(reason)
                                               : "integer_width_mismatch",
                    *data);
            }
            if (auto failure = add_to_aggregate(
                    decoded_bytes, static_cast<std::uint64_t>(bytes.size()),
                    limits.maximum_read_bytes_per_call,
                    "response.aggregate_read_bytes")) {
                return failure;
            }
            output["value"] = decode_integer(bytes, type);
        }
        public_items.push_back(std::move(output));
    }
    normalized.structured = json{{"result", std::move(public_items)}};
    return std::nullopt;
}

validation_failure_t normalize_string_response(
    std::string_view name, const json& response,
    const normalized_request_t& request,
    const memory_handler_limits_t& limits,
    normalized_response_t& normalized) {
    const json* result = nullptr;
    if (auto failure = require_result_array(response, request.item_count, result)) {
        return failure;
    }
    const char* identity_field = name == "get_string" ? "addr" : "query";
    std::uint64_t aggregate_value_bytes = 0;
    json public_items = json::array();
    for (std::size_t index = 0; index < result->size(); ++index) {
        const auto& item = (*result)[index];
        if (!item.is_object()) {
            return invalid_value("response.result[" + std::to_string(index) + "]",
                                 "object_required", item);
        }
        const auto identity = item.find(identity_field);
        const auto value = item.find("value");
        if (identity == item.end() || !identity->is_string() ||
            value == item.end() || (!value->is_string() && !value->is_null())) {
            return invalid_value("response.result[" + std::to_string(index) + "]",
                                 "identity_and_value_required", item);
        }
        json output{{identity_field, *identity}, {"value", *value}};
        bool has_error = false;
        if (const auto error = item.find("error"); error != item.end()) {
            if (!error->is_string()) {
                return invalid_value(
                    "response.result[" + std::to_string(index) + "].error",
                    "string_required", *error);
            }
            output["error"] = *error;
            has_error = !error->get_ref<const std::string&>().empty();
        }
        if (value->is_null()) {
            if (!has_error) {
                return invalid_value(
                    "response.result[" + std::to_string(index) + "].value",
                    "error_required_for_null_value", *value);
            }
        } else {
            const auto value_size = static_cast<std::uint64_t>(
                value->get_ref<const std::string&>().size());
            if (value_size > limits.maximum_string_bytes) {
                return exceeded_value(
                    "response.result[" + std::to_string(index) + "].value",
                    limits.maximum_string_bytes, value_size);
            }
            if (auto failure = add_to_aggregate(
                    aggregate_value_bytes, value_size,
                    limits.maximum_read_bytes_per_call,
                    "response.aggregate_string_bytes")) {
                return failure;
            }
        }
        public_items.push_back(std::move(output));
    }
    normalized.structured = json{{"result", std::move(public_items)}};
    return std::nullopt;
}

validation_failure_t normalize_read_response(
    std::string_view name, const json& response,
    const normalized_request_t& request,
    const memory_handler_limits_t& limits,
    const memory_invocation_t& invocation,
    normalized_response_t& normalized) {
    snapshot_receipt_t receipt;
    if (auto failure = normalize_snapshot_receipt(
            response, request, limits, invocation, receipt)) {
        return failure;
    }
    std::uint64_t decoded_bytes = 0;
    validation_failure_t failure;
    if (name == "get_bytes") {
        failure = normalize_get_bytes_response(
            response, request, limits, normalized, decoded_bytes);
    } else if (name == "get_int") {
        failure = normalize_get_int_response(
            response, request, limits, normalized, decoded_bytes);
    } else if (name == "get_string" || name == "get_global_value") {
        failure = normalize_string_response(
            name, response, request, limits, normalized);
    } else {
        return invalid_value("response", "unsupported_memory_read_response",
                             std::string(name));
    }
    if (failure) {
        return failure;
    }
    if ((name == "get_bytes" || name == "get_int") &&
        decoded_bytes != receipt.bytes_read) {
        return invalid_value("response._aida_memory.snapshot.bytes_read",
                             "decoded_byte_count_mismatch",
                             json{{"receipt", receipt.bytes_read},
                                  {"decoded", decoded_bytes}});
    }
    normalized.metadata["memory_snapshot"] = receipt.value;
    normalized.metadata["generation"] = receipt.generation;
    return std::nullopt;
}

validation_failure_t normalize_overlay_response(
    std::string_view name, const json& response,
    const normalized_request_t& request,
    const memory_handler_limits_t& limits,
    const memory_invocation_t& invocation,
    normalized_response_t& normalized) {
    const auto memory = response.find("_aida_memory");
    if (memory == response.end() || !memory->is_object()) {
        return invalid_value("response._aida_memory", "object_required",
                             memory == response.end() ? json(nullptr) : *memory);
    }
    const auto transaction = memory->find("transaction");
    if (transaction == memory->end() || !transaction->is_object()) {
        return invalid_value("response._aida_memory.transaction", "object_required",
                             transaction == memory->end() ? json(nullptr) : *transaction);
    }
    if (!member_is_true(*transaction, "committed") ||
        !member_is_true(*transaction, "reversible") ||
        !member_is_true(*transaction, "undo_supported") ||
        !member_is_false(*transaction, "live_write_performed")) {
        return invalid_value("response._aida_memory.transaction",
                             "committed_reversible_static_transaction_required",
                             *transaction);
    }
    std::string transaction_id;
    std::string undo_token;
    if (auto failure = require_string_member(
            *transaction, "transaction_id", "response._aida_memory.transaction",
            limits.maximum_selector_bytes, transaction_id)) {
        return failure;
    }
    if (auto failure = require_string_member(
            *transaction, "undo_token", "response._aida_memory.transaction",
            limits.maximum_selector_bytes, undo_token)) {
        return failure;
    }
    std::uint64_t generation = 0;
    std::uint64_t revision_before = 0;
    std::uint64_t revision_after = 0;
    if (auto failure = require_unsigned_member(
            *transaction, "generation", "response._aida_memory.transaction",
            generation)) {
        return failure;
    }
    if (auto failure = require_unsigned_member(
            *transaction, "overlay_revision_before",
            "response._aida_memory.transaction", revision_before)) {
        return failure;
    }
    if (auto failure = require_unsigned_member(
            *transaction, "overlay_revision_after",
            "response._aida_memory.transaction", revision_after)) {
        return failure;
    }
    if (generation == 0 ||
        (invocation.expected_generation && generation != *invocation.expected_generation)) {
        return invalid_value("response._aida_memory.transaction.generation",
                             "transaction_generation_mismatch", generation);
    }
    if (revision_after <= revision_before) {
        return invalid_value(
            "response._aida_memory.transaction.overlay_revision_after",
            "revision_must_advance",
            json{{"before", revision_before}, {"after", revision_after}});
    }
    const auto operations = transaction->find("operations");
    if (operations == transaction->end() || !operations->is_array() ||
        operations->size() != request.overlay_operations.size()) {
        return invalid_value("response._aida_memory.transaction.operations",
                             "complete_operation_receipts_required",
                             operations == transaction->end() ? json(nullptr) : *operations);
    }
    std::vector<bool> seen(request.overlay_operations.size(), false);
    std::vector<json> normalized_operations(request.overlay_operations.size());
    for (std::size_t position = 0; position < operations->size(); ++position) {
        const auto& operation = (*operations)[position];
        if (!operation.is_object()) {
            return invalid_value(
                "response._aida_memory.transaction.operations[" +
                    std::to_string(position) + "]",
                "object_required", operation);
        }
        std::uint64_t operation_index = 0;
        std::uint64_t size = 0;
        if (auto failure = require_unsigned_member(
                operation, "index",
                "response._aida_memory.transaction.operations[" +
                    std::to_string(position) + "]",
                operation_index)) {
            return failure;
        }
        if (operation_index >= request.overlay_operations.size() ||
            seen[static_cast<std::size_t>(operation_index)]) {
            return invalid_value(
                "response._aida_memory.transaction.operations[" +
                    std::to_string(position) + "].index",
                "unique_request_index_required", operation_index);
        }
        seen[static_cast<std::size_t>(operation_index)] = true;
        const auto& expected =
            request.overlay_operations[static_cast<std::size_t>(operation_index)];
        std::string kind;
        std::string address_text;
        std::string before_text;
        std::string after_text;
        const std::string operation_path =
            "response._aida_memory.transaction.operations[" +
            std::to_string(position) + "]";
        if (auto failure = require_string_member(
                operation, "kind", operation_path,
                limits.maximum_type_bytes, kind)) {
            return failure;
        }
        if (auto failure = require_string_member(
                operation, "addr", operation_path,
                limits.maximum_address_bytes, address_text)) {
            return failure;
        }
        if (auto failure = require_string_member(
                operation, "before", operation_path,
                limits.maximum_response_bytes, before_text)) {
            return failure;
        }
        if (auto failure = require_string_member(
                operation, "after", operation_path,
                limits.maximum_response_bytes, after_text)) {
            return failure;
        }
        if (auto failure = require_unsigned_member(
                operation, "size", operation_path, size)) {
            return failure;
        }
        const auto receipt_address = parse_address(address_text);
        if (!receipt_address || *receipt_address != expected.address ||
            kind != expected.kind || size != expected.bytes.size()) {
            return invalid_value(operation_path,
                                 "operation_identity_mismatch", operation);
        }
        std::vector<std::uint8_t> before;
        std::vector<std::uint8_t> after;
        std::string reason;
        if (!parse_hex_bytes(before_text, expected.bytes.size(), before, reason) ||
            before.size() != expected.bytes.size()) {
            return invalid_value(operation_path + ".before",
                                 "before_width_mismatch", before_text);
        }
        reason.clear();
        if (!parse_hex_bytes(after_text, expected.bytes.size(), after, reason) ||
            after != expected.bytes) {
            return invalid_value(operation_path + ".after",
                                 "encoded_after_bytes_mismatch", after_text);
        }
        normalized_operations[static_cast<std::size_t>(operation_index)] = json{
            {"index", operation_index},
            {"kind", kind},
            {"addr", address_text},
            {"size", size},
            {"before", format_hex_bytes(before)},
            {"after", format_hex_bytes(after)},
        };
    }
    json public_items = json::array();
    for (const auto& operation : request.overlay_operations) {
        if (name == "patch") {
            public_items.push_back(json{
                {"addr", operation.address_text},
                {"size", operation.bytes.size()},
            });
        } else {
            public_items.push_back(json{
                {"addr", operation.address_text},
                {"ty", operation.requested_type},
                {"value", operation.value},
            });
        }
    }
    json transaction_metadata{
        {"transaction_id", transaction_id},
        {"committed", true},
        {"reversible", true},
        {"undo_supported", true},
        {"undo_token", undo_token},
        {"live_write_performed", false},
        {"generation", generation},
        {"overlay_revision_before", revision_before},
        {"overlay_revision_after", revision_after},
        {"operations", json::array()},
    };
    for (auto& operation : normalized_operations) {
        transaction_metadata["operations"].push_back(std::move(operation));
    }
    normalized.structured = json{{"result", std::move(public_items)}};
    normalized.metadata["overlay_transaction"] = std::move(transaction_metadata);
    normalized.metadata["generation"] = generation;
    normalized.metadata["overlay_revision"] = revision_after;
    normalized.metadata["reversible"] = true;
    normalized.metadata["undo_token"] = undo_token;
    return std::nullopt;
}

validation_failure_t normalize_backend_response(
    std::string_view name, const json& response,
    const normalized_request_t& request,
    const memory_handler_limits_t& limits,
    const memory_invocation_t& invocation,
    normalized_response_t& normalized) {
    if (is_overlay_tool(name)) {
        return normalize_overlay_response(
            name, response, request, limits, invocation, normalized);
    }
    return normalize_read_response(
        name, response, request, limits, invocation, normalized);
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
        normalized_request_t normalized_request;
        if (auto failure = normalize_tool_request(
                name, arguments, limits_, invocation, normalized_request)) {
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
        try {
            request.payload = normalized_request.backend_arguments.dump();
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
        normalized_response_t normalized_response;
        if (auto failure = normalize_backend_response(
                name, structured, normalized_request, limits_, invocation,
                normalized_response)) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Memory adapter response violates the C12 snapshot or overlay contract.",
                *failure);
        }
        const std::size_t response_bytes = response.payload.size();
        normalized_response.metadata["adapter_truncated"] = response.truncated;
        normalized_response.metadata["adapter_response_bytes"] = response_bytes;
        std::string normalized_text;
        try {
            normalized_text = normalized_response.structured.dump();
        } catch (const std::exception&) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_output,
                "Memory normalized response cannot be serialized.",
                protocol::json{{"phase", "memory_normalized_serialization"}});
        }
        return protocol::mcp_result_t::success(
            std::move(normalized_text),
            normalized_response.structured,
            normalized_response.metadata);
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
