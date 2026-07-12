#include "core.hpp"

#include "../ida_contracts_generated.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aida::standalone::mcp::compat::handlers {

namespace {

using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;

enum class core_lane_t : std::uint8_t {
    query,
    integer_conversion,
    checkpoint,
};

struct core_tool_spec_t final {
    std::string_view name;
    core_lane_t lane;
};

constexpr std::array<core_tool_spec_t, k_core_tool_count> k_core_specs{{
    {"server_health", core_lane_t::query},
    {"lookup_funcs", core_lane_t::query},
    {"int_convert", core_lane_t::integer_conversion},
    {"list_funcs", core_lane_t::query},
    {"func_query", core_lane_t::query},
    {"list_globals", core_lane_t::query},
    {"entity_query", core_lane_t::query},
    {"imports", core_lane_t::query},
    {"imports_query", core_lane_t::query},
    {"idb_save", core_lane_t::checkpoint},
    {"find_regex", core_lane_t::query},
    {"search_text", core_lane_t::query},
}};

constexpr std::array<std::string_view, k_core_tool_count> k_core_names{{
    "server_health",
    "lookup_funcs",
    "int_convert",
    "list_funcs",
    "func_query",
    "list_globals",
    "entity_query",
    "imports",
    "imports_query",
    "idb_save",
    "find_regex",
    "search_text",
}};

using validation_failure_t = std::optional<json>;

json parse_generated_json(std::string_view value, std::string_view field,
                          std::string_view tool_name) {
    try {
        return json::parse(value.begin(), value.end());
    } catch (const std::exception&) {
        throw std::runtime_error(
            "generated core contract JSON is invalid for " + std::string(tool_name) +
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
    throw std::runtime_error("generated core contract has an unknown effect");
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
    throw std::runtime_error("generated core contract has an unknown lock");
}

void validate_generated_descriptor(const contract_descriptor_t& descriptor,
                                   const core_tool_spec_t& spec) {
    const std::string expected_adapter =
        "aida::standalone::mcp::compat::adapters::" + std::string(spec.name);
    if (descriptor.name != spec.name || descriptor.adapter_symbol != expected_adapter ||
        !descriptor.archive_backed || descriptor.unsafe) {
        throw std::runtime_error(
            "generated core descriptor identity mismatch for " + std::string(spec.name));
    }

    const bool target_independent = spec.name == "int_convert";
    const bool checkpoint = spec.name == "idb_save";
    if (descriptor.target_dependent == target_independent ||
        descriptor.accepts_pid == target_independent ||
        descriptor.accepts_bin_name == target_independent) {
        throw std::runtime_error(
            "generated core descriptor routing mismatch for " + std::string(spec.name));
    }
    if (checkpoint) {
        if (descriptor.read_only || descriptor.effect != contract_effect_t::workspace_checkpoint ||
            descriptor.lock != contract_lock_t::workspace_checkpoint ||
            descriptor.description.find("workspace") == std::string_view::npos ||
            descriptor.description.find("checkpoint") == std::string_view::npos ||
            descriptor.description.find("IDB") != std::string_view::npos) {
            throw std::runtime_error("generated idb_save descriptor is not an AiDA checkpoint");
        }
        return;
    }
    if (!descriptor.read_only || descriptor.effect != contract_effect_t::workspace_read ||
        descriptor.lock != contract_lock_t::workspace_shared) {
        throw std::runtime_error(
            "generated core read descriptor policy mismatch for " + std::string(spec.name));
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
    contract.target_policy.requirement = descriptor.target_dependent
        ? protocol::target_requirement_t::optional
        : protocol::target_requirement_t::independent;
    contract.target_policy.accepts_pid = descriptor.accepts_pid;
    contract.target_policy.accepts_bin_name = descriptor.accepts_bin_name;
    contract.effect_policy.effect = protocol_effect(descriptor.effect);
    contract.effect_policy.lock = protocol_lock(descriptor.lock);
    contract.effect_policy.read_only = descriptor.read_only;
    contract.effect_policy.unsafe = descriptor.unsafe;
    return contract;
}

bool valid_limits(const core_handler_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 && limits.max_request_bytes <= 1024U * 1024U &&
        limits.max_response_bytes != 0 && limits.max_response_bytes <= 16U * 1024U * 1024U &&
        limits.max_selector_bytes != 0 && limits.max_selector_bytes <= 1024U &&
        limits.max_query_text_bytes != 0 && limits.max_query_text_bytes <= 16384U &&
        limits.max_batch_queries != 0 && limits.max_batch_queries <= 256U &&
        limits.max_lookup_queries != 0 && limits.max_lookup_queries <= 1000U &&
        limits.max_projection_fields != 0 && limits.max_projection_fields <= 256U &&
        limits.max_integer_bytes != 0 && limits.max_integer_bytes <= 4096U &&
        limits.max_offset != 0 && limits.max_offset <= 10000000ULL &&
        limits.max_page_items != 0 && limits.max_page_items <= 10000ULL &&
        limits.max_regex_matches != 0 && limits.max_regex_matches <= 500ULL &&
        limits.max_text_hits != 0 && limits.max_text_hits <= 500ULL &&
        limits.max_execution_time.count() > 0 &&
        limits.max_execution_time.count() <= 120000;
}

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_core_adapter"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_core_adapter"},
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
                                         const std::string& path_prefix,
                                         std::size_t maximum, bool allow_empty) {
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
                                             const core_handler_limits_t& limits) {
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

std::vector<std::pair<const json*, std::string>> query_objects(const json& value,
                                                               std::string_view path) {
    std::vector<std::pair<const json*, std::string>> result;
    if (value.is_array()) {
        result.reserve(value.size());
        for (std::size_t index = 0; index < value.size(); ++index) {
            result.emplace_back(&value[index], std::string(path) + "[" +
                std::to_string(index) + "]");
        }
    } else {
        result.emplace_back(&value, std::string(path));
    }
    return result;
}

validation_failure_t validate_page_query(const json& query, const std::string& path,
                                         const core_handler_limits_t& limits) {
    if (!query.is_object()) {
        return invalid_value(path, "object_required", query);
    }
    if (auto failure = bounded_integer(query, "offset", limits.max_offset, path)) {
        return failure;
    }
    return bounded_integer(query, "count", limits.max_page_items, path);
}

validation_failure_t validate_batch_page_queries(
    const json& arguments, const core_handler_limits_t& limits,
    std::initializer_list<std::string_view> text_fields) {
    const auto queries = query_objects(arguments.at("queries"), "queries");
    if (queries.size() > limits.max_batch_queries) {
        return exceeded_value(
            "queries", static_cast<std::uint64_t>(limits.max_batch_queries),
            static_cast<std::uint64_t>(queries.size()));
    }
    for (const auto& [query, path] : queries) {
        if (auto failure = validate_page_query(*query, path, limits)) {
            return failure;
        }
        for (const auto field : text_fields) {
            if (auto failure = bounded_member_text(
                    *query, field, path, limits.max_query_text_bytes, true)) {
                return failure;
            }
        }
    }
    return std::nullopt;
}

validation_failure_t validate_lookup(const json& arguments,
                                     const core_handler_limits_t& limits) {
    const auto& queries = arguments.at("queries");
    const std::size_t count = queries.is_array() ? queries.size() : 1U;
    if (count > limits.max_lookup_queries) {
        return exceeded_value(
            "queries", static_cast<std::uint64_t>(limits.max_lookup_queries),
            static_cast<std::uint64_t>(count));
    }
    if (queries.is_array()) {
        for (std::size_t index = 0; index < queries.size(); ++index) {
            if (auto failure = bounded_text(
                    queries[index], "queries[" + std::to_string(index) + "]",
                    limits.max_query_text_bytes, true)) {
                return failure;
            }
        }
        return std::nullopt;
    }
    return bounded_text(queries, "queries", limits.max_query_text_bytes, true);
}

validation_failure_t validate_integer_inputs(const json& arguments,
                                             const core_handler_limits_t& limits) {
    const auto inputs = query_objects(arguments.at("inputs"), "inputs");
    if (inputs.size() > limits.max_batch_queries) {
        return exceeded_value(
            "inputs", static_cast<std::uint64_t>(limits.max_batch_queries),
            static_cast<std::uint64_t>(inputs.size()));
    }
    for (const auto& [input, path] : inputs) {
        if (!input->is_object()) {
            return invalid_value(path, "object_required", *input);
        }
        if (auto failure = bounded_member_text(
                *input, "text", path, limits.max_query_text_bytes, true)) {
            return failure;
        }
        if (auto failure = bounded_integer(
                *input, "size", static_cast<std::uint64_t>(limits.max_integer_bytes), path)) {
            return failure;
        }
    }
    return std::nullopt;
}

validation_failure_t validate_func_query(const json& arguments,
                                         const core_handler_limits_t& limits) {
    if (auto failure = validate_batch_page_queries(
            arguments, limits, {"filter", "name_regex", "sort_by"})) {
        return failure;
    }
    const auto queries = query_objects(arguments.at("queries"), "queries");
    for (const auto& [query, path] : queries) {
        if (auto failure = bounded_integer(
                *query, "min_size", (std::numeric_limits<std::uint64_t>::max)(), path)) {
            return failure;
        }
        if (auto failure = bounded_integer(
                *query, "max_size", (std::numeric_limits<std::uint64_t>::max)(), path)) {
            return failure;
        }
        const auto min_size = query->find("min_size");
        const auto max_size = query->find("max_size");
        if (min_size != query->end() && max_size != query->end() &&
            *unsigned_integer(*min_size) > *unsigned_integer(*max_size)) {
            return invalid_value(path + ".min_size", "range_is_reversed", *min_size);
        }
    }
    return std::nullopt;
}

validation_failure_t validate_entity_query(const json& arguments,
                                           const core_handler_limits_t& limits) {
    if (auto failure = validate_batch_page_queries(
            arguments, limits,
            {"kind", "filter", "regex", "segment", "module", "min_addr", "max_addr", "sort_by"})) {
        return failure;
    }
    const auto queries = query_objects(arguments.at("queries"), "queries");
    for (const auto& [query, path] : queries) {
        const auto fields = query->find("fields");
        if (fields == query->end()) {
            continue;
        }
        if (!fields->is_array()) {
            return invalid_value(path + ".fields", "array_required", *fields);
        }
        if (fields->size() > limits.max_projection_fields) {
            return exceeded_value(
                path + ".fields",
                static_cast<std::uint64_t>(limits.max_projection_fields),
                static_cast<std::uint64_t>(fields->size()));
        }
        for (std::size_t index = 0; index < fields->size(); ++index) {
            if (auto failure = bounded_text(
                    (*fields)[index], path + ".fields[" + std::to_string(index) + "]",
                    limits.max_query_text_bytes, false)) {
                return failure;
            }
        }
    }
    return std::nullopt;
}

validation_failure_t validate_tool_bounds(std::string_view name, const json& arguments,
                                          const core_handler_limits_t& limits) {
    if (auto failure = validate_routing_bounds(arguments, limits)) {
        return failure;
    }
    if (name == "server_health") {
        return std::nullopt;
    }
    if (name == "lookup_funcs") {
        return validate_lookup(arguments, limits);
    }
    if (name == "int_convert") {
        return validate_integer_inputs(arguments, limits);
    }
    if (name == "list_funcs" || name == "list_globals") {
        return validate_batch_page_queries(arguments, limits, {"filter"});
    }
    if (name == "func_query") {
        return validate_func_query(arguments, limits);
    }
    if (name == "entity_query") {
        return validate_entity_query(arguments, limits);
    }
    if (name == "imports") {
        if (auto failure = bounded_integer(arguments, "offset", limits.max_offset)) {
            return failure;
        }
        return bounded_integer(arguments, "count", limits.max_page_items);
    }
    if (name == "imports_query") {
        return validate_batch_page_queries(arguments, limits, {"filter", "module"});
    }
    if (name == "idb_save") {
        const auto path = arguments.find("path");
        return path == arguments.end()
            ? validation_failure_t{}
            : bounded_text(*path, "path", limits.max_query_text_bytes, true);
    }
    if (name == "find_regex") {
        if (auto failure = bounded_text(
                arguments.at("pattern"), "pattern", limits.max_query_text_bytes, true)) {
            return failure;
        }
        if (auto failure = bounded_integer(
                arguments, "limit", (std::numeric_limits<std::uint64_t>::max)())) {
            return failure;
        }
        return bounded_integer(arguments, "offset", limits.max_offset);
    }
    if (name == "search_text") {
        if (auto failure = bounded_text(
                arguments.at("pattern"), "pattern", limits.max_query_text_bytes, true)) {
            return failure;
        }
        for (const auto field : {"start", "end", "include"}) {
            if (auto failure = bounded_member_text(
                    arguments, field, {}, limits.max_query_text_bytes, true)) {
                return failure;
            }
        }
        return bounded_integer(
            arguments, "limit", (std::numeric_limits<std::uint64_t>::max)());
    }
    return invalid_value("tool", "unsupported_core_tool", std::string(name));
}

json normalized_backend_arguments(std::string_view name, const json& arguments,
                                  const core_handler_limits_t& limits) {
    json normalized = arguments;
    normalized.erase("pid");
    normalized.erase("bin_name");
    if (name == "find_regex") {
        std::uint64_t limit = 30;
        if (const auto found = normalized.find("limit"); found != normalized.end()) {
            limit = *unsigned_integer(*found);
        }
        if (limit == 0) {
            limit = 30;
        }
        normalized["limit"] = (std::min)(limit, limits.max_regex_matches);
        if (!normalized.contains("offset")) {
            normalized["offset"] = 0;
        }
    } else if (name == "search_text") {
        std::uint64_t limit = 30;
        if (const auto found = normalized.find("limit"); found != normalized.end()) {
            limit = *unsigned_integer(*found);
        }
        if (limit == 0) {
            limit = 30;
        }
        normalized["limit"] = (std::min)(limit, limits.max_text_hits);
        if (!normalized.contains("start")) {
            normalized["start"] = "";
        }
        if (!normalized.contains("end")) {
            normalized["end"] = "";
        }
        if (!normalized.contains("regex")) {
            normalized["regex"] = false;
        }
        if (!normalized.contains("case_sensitive")) {
            normalized["case_sensitive"] = false;
        }
        if (!normalized.contains("include")) {
            normalized["include"] = "all";
        }
        if (!normalized.contains("code_only")) {
            normalized["code_only"] = true;
        }
    }
    return normalized;
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
        "Core workspace adapter rejected the request.",
        json{
            {"phase", "workspace_adapter"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

std::optional<std::chrono::steady_clock::time_point> invocation_deadline(
    const core_handler_limits_t& limits, const core_invocation_options_t& options) {
    const auto bounded = std::chrono::steady_clock::now() + limits.max_execution_time;
    if (!options.deadline) {
        return bounded;
    }
    return (std::min)(bounded, *options.deadline);
}

struct parsed_integer_t final {
    bool negative = false;
    std::vector<std::uint8_t> magnitude;
};

int digit_value(char value) noexcept {
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

void trim_magnitude(std::vector<std::uint8_t>& magnitude) {
    while (!magnitude.empty() && magnitude.back() == 0) {
        magnitude.pop_back();
    }
}

bool multiply_add(std::vector<std::uint8_t>& magnitude, std::uint32_t base,
                  std::uint32_t digit, std::size_t maximum_bytes) {
    std::uint32_t carry = digit;
    for (auto& byte : magnitude) {
        const std::uint32_t value = static_cast<std::uint32_t>(byte) * base + carry;
        byte = static_cast<std::uint8_t>(value & 0xffU);
        carry = value >> 8U;
    }
    while (carry != 0) {
        if (magnitude.size() >= maximum_bytes) {
            return false;
        }
        magnitude.push_back(static_cast<std::uint8_t>(carry & 0xffU));
        carry >>= 8U;
    }
    return true;
}

std::optional<parsed_integer_t> parse_integer_text(
    std::string_view input, std::size_t maximum_bytes, std::string& error) {
    std::size_t first = 0;
    while (first < input.size() &&
           std::isspace(static_cast<unsigned char>(input[first])) != 0) {
        ++first;
    }
    std::size_t last = input.size();
    while (last > first &&
           std::isspace(static_cast<unsigned char>(input[last - 1])) != 0) {
        --last;
    }
    if (first == last) {
        error = "Invalid number: " + std::string(input);
        return std::nullopt;
    }

    bool negative = false;
    if (input[first] == '+' || input[first] == '-') {
        negative = input[first] == '-';
        ++first;
    }
    if (first == last) {
        error = "Invalid number: " + std::string(input);
        return std::nullopt;
    }

    std::uint32_t base = 10;
    if (last - first >= 2 && input[first] == '0') {
        const char prefix = input[first + 1];
        if (prefix == 'x' || prefix == 'X') {
            base = 16;
            first += 2;
        } else if (prefix == 'b' || prefix == 'B') {
            base = 2;
            first += 2;
        } else if (prefix == 'o' || prefix == 'O') {
            base = 8;
            first += 2;
        }
    }
    if (first == last) {
        error = "Invalid number: " + std::string(input);
        return std::nullopt;
    }

    parsed_integer_t parsed;
    parsed.negative = negative;
    bool saw_digit = false;
    bool previous_separator = false;
    for (std::size_t index = first; index < last; ++index) {
        const char character = input[index];
        if (character == '_') {
            if (!saw_digit || previous_separator || index + 1 >= last ||
                digit_value(input[index + 1]) < 0 ||
                static_cast<std::uint32_t>(digit_value(input[index + 1])) >= base) {
                error = "Invalid number: " + std::string(input);
                return std::nullopt;
            }
            previous_separator = true;
            continue;
        }
        const int digit = digit_value(character);
        if (digit < 0 || static_cast<std::uint32_t>(digit) >= base ||
            !multiply_add(parsed.magnitude, base, static_cast<std::uint32_t>(digit),
                          maximum_bytes)) {
            error = parsed.magnitude.size() >= maximum_bytes
                ? "Number " + std::string(input) + " exceeds the AiDA conversion limit"
                : "Invalid number: " + std::string(input);
            return std::nullopt;
        }
        saw_digit = true;
        previous_separator = false;
    }
    if (!saw_digit || previous_separator) {
        error = "Invalid number: " + std::string(input);
        return std::nullopt;
    }
    trim_magnitude(parsed.magnitude);
    if (parsed.magnitude.empty()) {
        parsed.negative = false;
    }
    return parsed;
}

std::size_t magnitude_bit_length(const std::vector<std::uint8_t>& magnitude) noexcept {
    if (magnitude.empty()) {
        return 0;
    }
    std::uint8_t most_significant = magnitude.back();
    std::size_t bits = (magnitude.size() - 1U) * 8U;
    while (most_significant != 0) {
        ++bits;
        most_significant >>= 1U;
    }
    return bits;
}

std::string decimal_text(const parsed_integer_t& value) {
    if (value.magnitude.empty()) {
        return "0";
    }
    std::vector<std::uint8_t> work = value.magnitude;
    std::string digits;
    while (!work.empty()) {
        std::uint32_t remainder = 0;
        for (std::size_t index = work.size(); index-- > 0;) {
            const std::uint32_t current = (remainder << 8U) | work[index];
            work[index] = static_cast<std::uint8_t>(current / 10U);
            remainder = current % 10U;
        }
        digits.push_back(static_cast<char>('0' + remainder));
        trim_magnitude(work);
    }
    if (value.negative) {
        digits.push_back('-');
    }
    std::reverse(digits.begin(), digits.end());
    return digits;
}

std::string hexadecimal_text(const parsed_integer_t& value) {
    if (value.magnitude.empty()) {
        return "0x0";
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string result = value.negative ? "-0x" : "0x";
    bool emitted = false;
    for (std::size_t index = value.magnitude.size(); index-- > 0;) {
        const std::uint8_t byte = value.magnitude[index];
        const std::uint8_t high = static_cast<std::uint8_t>(byte >> 4U);
        const std::uint8_t low = static_cast<std::uint8_t>(byte & 0x0fU);
        if (high != 0 || emitted) {
            result.push_back(digits[high]);
            emitted = true;
        }
        result.push_back(digits[low]);
        emitted = true;
    }
    return result;
}

std::string binary_text(const parsed_integer_t& value) {
    if (value.magnitude.empty()) {
        return "0b0";
    }
    std::string result = value.negative ? "-0b" : "0b";
    bool emitted = false;
    for (std::size_t index = value.magnitude.size(); index-- > 0;) {
        for (int bit = 7; bit >= 0; --bit) {
            const bool set = (value.magnitude[index] & (1U << bit)) != 0;
            if (set || emitted) {
                result.push_back(set ? '1' : '0');
                emitted = true;
            }
        }
    }
    return result;
}

bool fits_signed_bytes(const parsed_integer_t& value, std::size_t size) noexcept {
    if (size == 0) {
        return value.magnitude.empty();
    }
    if (value.magnitude.size() < size) {
        return true;
    }
    if (value.magnitude.size() > size) {
        return false;
    }
    const std::uint8_t high = value.magnitude.back();
    if (!value.negative) {
        return (high & 0x80U) == 0;
    }
    if (high < 0x80U) {
        return true;
    }
    if (high > 0x80U) {
        return false;
    }
    return std::all_of(
        value.magnitude.begin(), value.magnitude.end() - 1,
        [](std::uint8_t byte) { return byte == 0; });
}

std::vector<std::uint8_t> signed_little_endian(const parsed_integer_t& value,
                                               std::size_t size) {
    std::vector<std::uint8_t> result(size, 0);
    std::copy(value.magnitude.begin(), value.magnitude.end(), result.begin());
    if (!value.negative) {
        return result;
    }
    for (auto& byte : result) {
        byte = static_cast<std::uint8_t>(~byte);
    }
    std::uint16_t carry = 1;
    for (auto& byte : result) {
        const std::uint16_t sum = static_cast<std::uint16_t>(byte) + carry;
        byte = static_cast<std::uint8_t>(sum & 0xffU);
        carry = static_cast<std::uint16_t>(sum >> 8U);
        if (carry == 0) {
            break;
        }
    }
    return result;
}

std::string bytes_text(const std::vector<std::uint8_t>& bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    if (!bytes.empty()) {
        result.reserve(bytes.size() * 3U - 1U);
    }
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0) {
            result.push_back(' ');
        }
        result.push_back(digits[bytes[index] >> 4U]);
        result.push_back(digits[bytes[index] & 0x0fU]);
    }
    return result;
}

json ascii_text(const std::vector<std::uint8_t>& bytes) {
    std::size_t size = bytes.size();
    while (size != 0 && bytes[size - 1] == 0) {
        --size;
    }
    std::string result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        const auto byte = bytes[index];
        if (byte < 32U || byte > 126U) {
            return nullptr;
        }
        result.push_back(static_cast<char>(byte));
    }
    return result;
}

mcp_result_t convert_integers(const json& arguments,
                              const protocol::cancellation_token_t& cancellation,
                              const core_handler_limits_t& limits) {
    const auto inputs = query_objects(arguments.at("inputs"), "inputs");
    json results = json::array();
    for (const auto& [input, path] : inputs) {
        if (cancellation.cancelled()) {
            return mcp_result_t::failure(
                result_error_code_t::cancelled,
                "Integer conversion was cancelled.",
                json{{"phase", "integer_conversion"}, {"field", path}});
        }
        const std::string text = input->value("text", std::string());
        std::string error;
        auto parsed = parse_integer_text(text, limits.max_integer_bytes, error);
        if (!parsed) {
            results.push_back({{"input", text}, {"result", nullptr}, {"error", error}});
            continue;
        }

        std::uint64_t requested_size = 0;
        if (const auto found = input->find("size"); found != input->end()) {
            requested_size = *unsigned_integer(*found);
        }
        const std::size_t size = requested_size == 0
            ? (magnitude_bit_length(parsed->magnitude) + 7U) / 8U
            : static_cast<std::size_t>(requested_size);
        if (!fits_signed_bytes(*parsed, size)) {
            results.push_back({
                {"input", text},
                {"result", nullptr},
                {"error", "Number " + text + " is too big for " +
                    std::to_string(size) + " bytes"},
            });
            continue;
        }

        const auto bytes = signed_little_endian(*parsed, size);
        results.push_back({
            {"input", text},
            {"result", {
                {"decimal", decimal_text(*parsed)},
                {"hexadecimal", hexadecimal_text(*parsed)},
                {"bytes", bytes_text(bytes)},
                {"ascii", ascii_text(bytes)},
                {"binary", binary_text(*parsed)},
            }},
            {"error", nullptr},
        });
    }
    json structured{{"result", std::move(results)}};
    const std::string text = structured.dump();
    if (text.size() > limits.max_response_bytes) {
        return mcp_result_t::failure(
            result_error_code_t::invalid_output,
            "Integer conversion output exceeds the bounded response quota.",
            exceeded_value(
                "response_bytes", static_cast<std::uint64_t>(limits.max_response_bytes),
                static_cast<std::uint64_t>(text.size())));
    }
    return mcp_result_t::success(
        text, structured,
        json{{"adapter", "local_integer_conversion"},
             {"adapter_response_bytes", text.size()}});
}

constexpr std::string_view k_unsupported_idb_i64 =
    "AiDA does not create IDB/I64 databases; idb_save only flushes the active AiDA workspace checkpoint and path must be empty.";

bool ends_with_case_insensitive(std::string_view value, std::string_view suffix) {
    if (value.size() < suffix.size()) {
        return false;
    }
    const std::size_t offset = value.size() - suffix.size();
    for (std::size_t index = 0; index < suffix.size(); ++index) {
        if (std::tolower(static_cast<unsigned char>(value[offset + index])) !=
            std::tolower(static_cast<unsigned char>(suffix[index]))) {
            return false;
        }
    }
    return true;
}

bool ida_database_reference(std::string_view value) {
    return ends_with_case_insensitive(value, ".idb") ||
        ends_with_case_insensitive(value, ".i64");
}

mcp_result_t checkpoint_result(json structured, bool adapter_truncated = false,
                               std::size_t adapter_bytes = 0) {
    const std::string text = structured.dump();
    return mcp_result_t::success(
        text, structured,
        json{{"adapter_truncated", adapter_truncated},
             {"adapter_response_bytes", adapter_bytes},
             {"idb_i64_supported", false},
             {"workspace_checkpoint", true}});
}

mcp_result_t checkpoint_failure(std::string error, std::size_t adapter_bytes = 0) {
    return checkpoint_result(
        json{{"ok", false}, {"path", nullptr}, {"error", std::move(error)}},
        false, adapter_bytes);
}

mcp_result_t normalize_checkpoint_response(adapter_response_t response,
                                           const core_handler_limits_t& limits) {
    if (response.payload.empty()) {
        return checkpoint_failure(
            "AiDA workspace checkpoint failed: checkpoint response was empty.");
    }
    if (response.payload.size() > limits.max_response_bytes) {
        return checkpoint_failure(
            "AiDA workspace checkpoint failed: checkpoint response exceeded the bounded quota.",
            response.payload.size());
    }
    json parsed = json::parse(response.payload, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        return checkpoint_failure(
            "AiDA workspace checkpoint failed: checkpoint response was malformed.",
            response.payload.size());
    }
    const auto ok = parsed.find("ok");
    if (ok == parsed.end() || !ok->is_boolean()) {
        return checkpoint_failure(
            "AiDA workspace checkpoint failed: checkpoint response omitted a valid status.",
            response.payload.size());
    }
    if (!ok->get<bool>()) {
        std::string error = "AiDA workspace checkpoint did not complete.";
        if (const auto detail = parsed.find("error");
            detail != parsed.end() && detail->is_string() && !detail->get_ref<const std::string&>().empty()) {
            error = detail->get<std::string>();
        }
        return checkpoint_failure(std::move(error), response.payload.size());
    }

    json path = nullptr;
    if (const auto found = parsed.find("path"); found != parsed.end()) {
        if (!found->is_null() && !found->is_string()) {
            return checkpoint_failure(
                "AiDA workspace checkpoint failed: checkpoint reference was invalid.",
                response.payload.size());
        }
        path = *found;
    }
    if (path.is_string() && ida_database_reference(path.get_ref<const std::string&>())) {
        return checkpoint_failure(std::string(k_unsupported_idb_i64), response.payload.size());
    }
    return checkpoint_result(
        json{{"ok", true}, {"path", std::move(path)}},
        response.truncated, response.payload.size());
}

}

const std::array<std::string_view, k_core_tool_count>& core_tool_names() noexcept {
    return k_core_names;
}

core_handlers_t::core_handlers_t(workspace_adapter_t& workspace,
                                 protocol::schema_runtime_t& schemas,
                                 core_handler_limits_t limits)
    : workspace_(workspace), schemas_(schemas), limits_(std::move(limits)) {
    if (!valid_limits(limits_)) {
        throw std::invalid_argument("core handler limits are invalid or weaken pinned maxima");
    }
    for (std::size_t index = 0; index < k_core_specs.size(); ++index) {
        const auto& spec = k_core_specs[index];
        const auto* descriptor =
            aida::standalone::mcp::compat::find_contract(spec.name);
        if (descriptor == nullptr) {
            throw std::runtime_error(
                "generated core descriptor is missing for " + std::string(spec.name));
        }
        validate_generated_descriptor(*descriptor, spec);
        contracts_[index] = make_tool_contract(*descriptor);
        const auto validation = protocol::validate_tool_contract(contracts_[index], schemas_);
        if (!validation.valid) {
            throw std::runtime_error(
                "generated core contract validation failed for " + std::string(spec.name) +
                ": " + validation.reason);
        }
    }
}

std::size_t core_handlers_t::size() const noexcept {
    return contracts_.size();
}

const protocol::tool_contract_t& core_handlers_t::contract_at(std::size_t index) const {
    return contracts_.at(index);
}

const protocol::tool_contract_t* core_handlers_t::find(std::string_view name) const noexcept {
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    return found == contracts_.end() ? nullptr : &*found;
}

const core_handler_limits_t& core_handlers_t::limits() const noexcept {
    return limits_;
}

protocol::mcp_result_t core_handlers_t::invoke(
    std::string_view name, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const core_invocation_options_t& options,
    const protocol::json& aida_metadata) const {
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    if (found == contracts_.end()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "Core tool is not registered in the pinned contract group.",
            protocol::json{{"tool", std::string(name)}},
            aida_metadata.is_object() ? aida_metadata : protocol::json::object());
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

protocol::mcp_result_t core_handlers_t::dispatch(
    std::size_t index, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const core_invocation_options_t& options) const {
    const auto& spec = k_core_specs.at(index);
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Core tool invocation was cancelled before adapter routing.",
            protocol::json{{"phase", "core_pre_route"}});
    }

    std::string serialized_arguments;
    try {
        serialized_arguments = arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Core tool arguments cannot be serialized.",
            protocol::json{{"phase", "core_request_serialization"}});
    }
    if (serialized_arguments.size() > limits_.max_request_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Core tool request exceeds the bounded adapter quota.",
            exceeded_value(
                "request_bytes", static_cast<std::uint64_t>(limits_.max_request_bytes),
                static_cast<std::uint64_t>(serialized_arguments.size())));
    }
    if (auto failure = validate_tool_bounds(spec.name, arguments, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Core tool arguments violate the bounded adapter policy.",
            *failure);
    }

    if (spec.lane == core_lane_t::integer_conversion) {
        return convert_integers(arguments, cancellation, limits_);
    }

    if (spec.lane == core_lane_t::checkpoint) {
        const auto path = arguments.find("path");
        if (path != arguments.end() && !path->get_ref<const std::string&>().empty()) {
            return checkpoint_failure(std::string(k_unsupported_idb_i64));
        }
    }

    adapter_request_t request;
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        request.target.pid = static_cast<std::uint32_t>(*unsigned_integer(*pid));
    }
    if (const auto bin_name = arguments.find("bin_name"); bin_name != arguments.end()) {
        request.target.bin_name = bin_name->get<std::string>();
    }
    request.expected_generation = options.expected_generation;
    request.deadline = invocation_deadline(limits_, options);
    if (request.deadline && *request.deadline <= std::chrono::steady_clock::now()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Core tool invocation deadline expired before adapter routing.",
            protocol::json{{"phase", "core_deadline"}});
    }
    try {
        request.payload = normalized_backend_arguments(spec.name, arguments, limits_).dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Core backend arguments cannot be serialized.",
            protocol::json{{"phase", "core_backend_serialization"}});
    }

    auto adapter_result = spec.lane == core_lane_t::checkpoint
        ? workspace_.checkpoint(spec.name, request)
        : workspace_.query(spec.name, request);
    if (!adapter_result) {
        if (spec.lane == core_lane_t::checkpoint) {
            return checkpoint_failure(
                "AiDA workspace checkpoint failed: " +
                std::string(adapter_result.error().stable_code) + ".");
        }
        return adapter_failure(adapter_result.error());
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Core tool invocation was cancelled during adapter execution.",
            protocol::json{{"phase", "core_post_adapter"}});
    }

    auto response = std::move(adapter_result).take_value();
    if (spec.lane == core_lane_t::checkpoint) {
        return normalize_checkpoint_response(std::move(response), limits_);
    }
    if (response.payload.empty() || response.payload.size() > limits_.max_response_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Core adapter response violates the output byte quota.",
            exceeded_value(
                "response_bytes", static_cast<std::uint64_t>(limits_.max_response_bytes),
                static_cast<std::uint64_t>(response.payload.size())));
    }
    protocol::json structured = protocol::json::parse(response.payload, nullptr, false);
    if (structured.is_discarded() || !structured.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Core adapter returned malformed structured output.",
            protocol::json{{"phase", "core_output_parse"},
                           {"response_bytes", response.payload.size()}});
    }
    if (spec.name == "server_health") {
        structured["idb_path"] = nullptr;
        structured["hexrays_ready"] = false;
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Core tool invocation was cancelled before output validation.",
            protocol::json{{"phase", "core_pre_output_validation"}});
    }
    const std::string text = structured.dump();
    return protocol::mcp_result_t::success(
        text,
        structured,
        protocol::json{
            {"adapter_truncated", response.truncated},
            {"adapter_response_bytes", response.payload.size()},
            {"idb_i64_supported", false},
        });
}

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t server_health(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("server_health", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t lookup_funcs(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("lookup_funcs", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t int_convert(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("int_convert", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t list_funcs(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("list_funcs", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t func_query(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("func_query", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t list_globals(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("list_globals", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t entity_query(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("entity_query", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t imports(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("imports", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t imports_query(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("imports_query", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t idb_save(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("idb_save", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t find_regex(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("find_regex", arguments, cancellation, options, aida_metadata);
}

protocol::mcp_result_t search_text(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options,
    const protocol::json& aida_metadata) {
    return handlers.invoke("search_text", arguments, cancellation, options, aida_metadata);
}

}
