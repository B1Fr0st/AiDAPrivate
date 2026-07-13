#include "types.hpp"

#include "../ida_contracts_generated.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace aida::standalone::mcp::compat::handlers {

namespace {

using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;

constexpr std::array<std::string_view, k_types_tool_count> k_types_names{{
    "declare_type",
    "enum_upsert",
    "read_struct",
    "search_structs",
    "type_query",
    "type_inspect",
    "set_type",
    "type_apply_batch",
    "infer_types",
}};

constexpr std::array<type_lane_t, k_types_tool_count> k_types_lanes{{
    type_lane_t::overlay,
    type_lane_t::overlay,
    type_lane_t::query,
    type_lane_t::query,
    type_lane_t::query,
    type_lane_t::query,
    type_lane_t::overlay,
    type_lane_t::overlay,
    type_lane_t::query,
}};

bool is_read_tool(std::string_view name) noexcept {
    return name == "read_struct" || name == "search_structs" ||
           name == "type_query" || name == "type_inspect" ||
           name == "infer_types";
}

json parse_generated_json(std::string_view value, std::string_view field,
                          std::string_view tool_name) {
    try {
        return json::parse(value.begin(), value.end());
    } catch (const std::exception&) {
        throw std::runtime_error(
            "generated types contract JSON is invalid for " + std::string(tool_name) +
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
    throw std::runtime_error("generated types contract has an unknown effect");
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
    throw std::runtime_error("generated types contract has an unknown lock");
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
            "generated types descriptor policy mismatch for " + std::string(name));
    }
    if (is_read_tool(name)) {
        if (descriptor.effect != contract_effect_t::workspace_read ||
            descriptor.lock != contract_lock_t::workspace_shared ||
            !descriptor.read_only) {
            throw std::runtime_error(
                "generated types read descriptor effect/lock mismatch for " + std::string(name));
        }
    } else {
        if (descriptor.effect != contract_effect_t::workspace_overlay_mutation ||
            descriptor.lock != contract_lock_t::workspace_overlay_transaction ||
            descriptor.read_only) {
            throw std::runtime_error(
                "generated types mutation descriptor effect/lock mismatch for " + std::string(name));
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

bool valid_limits(const types_handler_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 && limits.max_request_bytes <= 1024U * 1024U &&
        limits.max_response_bytes != 0 && limits.max_response_bytes <= 16U * 1024U * 1024U &&
        limits.max_selector_bytes != 0 && limits.max_selector_bytes <= 1024U &&
        limits.max_name_bytes != 0 && limits.max_name_bytes <= 4096U &&
        limits.max_type_bytes != 0 && limits.max_type_bytes <= 16384U &&
        limits.max_address_bytes != 0 && limits.max_address_bytes <= 1024U &&
        limits.max_decls_bytes != 0 && limits.max_decls_bytes <= 65536U &&
        limits.max_decls_count != 0 && limits.max_decls_count <= 256U &&
        limits.max_decl_string_bytes != 0 && limits.max_decl_string_bytes <= 16384U &&
        limits.max_queries_count != 0 && limits.max_queries_count <= 256U &&
        limits.max_filter_bytes != 0 && limits.max_filter_bytes <= 4096U &&
        limits.max_edits_count != 0 && limits.max_edits_count <= 256U &&
        limits.max_addrs_count != 0 && limits.max_addrs_count <= 256U &&
        limits.max_members_per_type != 0 && limits.max_members_per_type <= 1024U &&
        limits.max_enumerators_per_enum != 0 && limits.max_enumerators_per_enum <= 1024U &&
        limits.max_member_name_bytes != 0 && limits.max_member_name_bytes <= 4096U &&
        limits.max_member_type_bytes != 0 && limits.max_member_type_bytes <= 16384U &&
        limits.max_related_types != 0 && limits.max_related_types <= 256U &&
        limits.max_struct_size != 0 && limits.max_struct_size <= 1048576ULL &&
        limits.max_member_offset != 0 && limits.max_member_offset <= 1048576ULL &&
        limits.max_execution_time.count() > 0 && limits.max_execution_time.count() <= 120000;
}

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_types_adapter"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_types_adapter"},
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

using validation_failure_t = std::optional<json>;

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
                                             const types_handler_limits_t& limits) {
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

validation_failure_t validate_declare_type(const json& arguments,
                                           const types_handler_limits_t& limits) {
    const auto decls = arguments.find("decls");
    if (decls == arguments.end()) {
        return std::nullopt;
    }
    return scalar_or_array(*decls, "decls", limits.max_decls_count,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            return bounded_text(item, path, limits.max_decl_string_bytes, false);
        });
}

validation_failure_t validate_enum_upsert(const json& arguments,
                                          const types_handler_limits_t& limits) {
    const auto queries = arguments.find("queries");
    if (queries == arguments.end()) {
        return std::nullopt;
    }
    return scalar_or_array(*queries, "queries", limits.max_queries_count,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            if (!item.is_object()) {
                return invalid_value(path, "object_required", item);
            }
            if (auto f = bounded_member_text(item, "name", path, limits.max_name_bytes, false)) {
                return f;
            }
            const auto members = item.find("members");
            if (members != item.end()) {
                return scalar_or_array(*members, path + ".members",
                    limits.max_enumerators_per_enum,
                    [&limits, &path](const json& m, std::string mpath) -> validation_failure_t {
                        if (!m.is_object()) {
                            return invalid_value(mpath, "object_required", m);
                        }
                        if (auto f = bounded_member_text(m, "name", mpath, limits.max_member_name_bytes, false)) {
                            return f;
                        }
                        return std::nullopt;
                    });
            }
            return std::nullopt;
        });
}

validation_failure_t validate_read_struct(const json& arguments,
                                          const types_handler_limits_t& limits) {
    const auto queries = arguments.find("queries");
    if (queries == arguments.end()) {
        return std::nullopt;
    }
    return scalar_or_array(*queries, "queries", limits.max_queries_count,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            if (!item.is_object()) {
                return invalid_value(path, "object_required", item);
            }
            if (auto f = bounded_member_text(item, "addr", path, limits.max_address_bytes, false)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "struct", path, limits.max_name_bytes, true)) {
                return f;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_search_structs(const json& arguments,
                                             const types_handler_limits_t& limits) {
    return bounded_member_text(arguments, "filter", {}, limits.max_filter_bytes, false);
}

validation_failure_t validate_type_query(const json& arguments,
                                         const types_handler_limits_t& limits) {
    const auto queries = arguments.find("queries");
    if (queries == arguments.end()) {
        return std::nullopt;
    }
    return scalar_or_array(*queries, "queries", limits.max_queries_count,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            if (!item.is_object()) {
                return invalid_value(path, "object_required", item);
            }
            if (auto f = bounded_member_text(item, "filter", path, limits.max_filter_bytes, true)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "kind", path, limits.max_name_bytes, true)) {
                return f;
            }
            if (auto f = bounded_integer(item, "count", limits.max_queries_count, path)) {
                return f;
            }
            if (auto f = bounded_integer(item, "offset", limits.max_queries_count, path)) {
                return f;
            }
            if (auto f = bounded_integer(item, "max_members", limits.max_members_per_type, path)) {
                return f;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_type_inspect(const json& arguments,
                                           const types_handler_limits_t& limits) {
    const auto queries = arguments.find("queries");
    if (queries == arguments.end()) {
        return std::nullopt;
    }
    return scalar_or_array(*queries, "queries", limits.max_queries_count,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            if (!item.is_object()) {
                return invalid_value(path, "object_required", item);
            }
            if (auto f = bounded_member_text(item, "name", path, limits.max_name_bytes, false)) {
                return f;
            }
            if (auto f = bounded_integer(item, "max_members", limits.max_members_per_type, path)) {
                return f;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_set_type(const json& arguments,
                                       const types_handler_limits_t& limits) {
    const auto edits = arguments.find("edits");
    if (edits == arguments.end()) {
        return std::nullopt;
    }
    return scalar_or_array(*edits, "edits", limits.max_edits_count,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            if (!item.is_object()) {
                return invalid_value(path, "object_required", item);
            }
            if (auto f = bounded_member_text(item, "addr", path, limits.max_address_bytes, false)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "ty", path, limits.max_type_bytes, true)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "signature", path, limits.max_type_bytes, true)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "name", path, limits.max_name_bytes, true)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "variable", path, limits.max_name_bytes, true)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "kind", path, limits.max_name_bytes, true)) {
                return f;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_type_apply_batch(const json& arguments,
                                                const types_handler_limits_t& limits) {
    const auto batch = arguments.find("batch");
    if (batch == arguments.end() || !batch->is_object()) {
        return std::nullopt;
    }
    const auto edits = batch->find("edits");
    if (edits == batch->end()) {
        return std::nullopt;
    }
    return scalar_or_array(*edits, "batch.edits", limits.max_edits_count,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            if (!item.is_object()) {
                return invalid_value(path, "object_required", item);
            }
            if (auto f = bounded_member_text(item, "addr", path, limits.max_address_bytes, false)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "ty", path, limits.max_type_bytes, true)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "signature", path, limits.max_type_bytes, true)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "name", path, limits.max_name_bytes, true)) {
                return f;
            }
            if (auto f = bounded_member_text(item, "kind", path, limits.max_name_bytes, true)) {
                return f;
            }
            return std::nullopt;
        });
}

validation_failure_t validate_infer_types(const json& arguments,
                                          const types_handler_limits_t& limits) {
    const auto addrs = arguments.find("addrs");
    if (addrs == arguments.end()) {
        return std::nullopt;
    }
    return scalar_or_array(*addrs, "addrs", limits.max_addrs_count,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            return bounded_text(item, path, limits.max_address_bytes, false);
        });
}

validation_failure_t validate_tool_bounds(std::string_view name, const json& arguments,
                                          const types_handler_limits_t& limits) {
    if (auto failure = validate_routing_bounds(arguments, limits)) {
        return failure;
    }
    if (name == "declare_type") {
        return validate_declare_type(arguments, limits);
    }
    if (name == "enum_upsert") {
        return validate_enum_upsert(arguments, limits);
    }
    if (name == "read_struct") {
        return validate_read_struct(arguments, limits);
    }
    if (name == "search_structs") {
        return validate_search_structs(arguments, limits);
    }
    if (name == "type_query") {
        return validate_type_query(arguments, limits);
    }
    if (name == "type_inspect") {
        return validate_type_inspect(arguments, limits);
    }
    if (name == "set_type") {
        return validate_set_type(arguments, limits);
    }
    if (name == "type_apply_batch") {
        return validate_type_apply_batch(arguments, limits);
    }
    if (name == "infer_types") {
        return validate_infer_types(arguments, limits);
    }
    return invalid_value("tool", "types_tool_not_registered", std::string(name));
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
        "Types workspace adapter rejected the request.",
        json{
            {"phase", "workspace_adapter"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

std::string to_hex_string(std::uint64_t value) {
    std::ostringstream ss;
    ss << "0x" << std::hex << value;
    return ss.str();
}

std::string trim_ws(const std::string& s) {
    std::size_t first = 0;
    while (first < s.size() && std::isspace(static_cast<unsigned char>(s[first])) != 0) {
        ++first;
    }
    std::size_t last = s.size();
    while (last > first && std::isspace(static_cast<unsigned char>(s[last - 1])) != 0) {
        --last;
    }
    return s.substr(first, last - first);
}

std::string to_lower(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (char c : s) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) {
        return true;
    }
    const std::string h = to_lower(haystack);
    const std::string n = to_lower(needle);
    return h.find(n) != std::string::npos;
}

std::uint64_t builtin_type_size(const std::string& type_name) {
    static const std::unordered_map<std::string, std::uint64_t> sizes = {
        {"void", 0}, {"char", 1}, {"unsigned char", 1}, {"signed char", 1},
        {"short", 2}, {"unsigned short", 2}, {"short int", 2}, {"unsigned short int", 2},
        {"int", 4}, {"unsigned int", 4}, {"signed int", 4},
        {"long", 4}, {"unsigned long", 4}, {"long int", 4}, {"unsigned long int", 4},
        {"long long", 8}, {"unsigned long long", 8}, {"long long int", 8},
        {"float", 4}, {"double", 8}, {"long double", 16},
        {"bool", 1}, {"_Bool", 1},
        {"DWORD", 4}, {"DWORD32", 4}, {"DWORD64", 8},
        {"QWORD", 8}, {"WORD", 2}, {"BYTE", 1}, {"BOOL", 4},
        {"PVOID", 8}, {"PVOID32", 4}, {"PVOID64", 8},
        {"HANDLE", 8}, {"HMODULE", 8}, {"HWND", 8},
        {"LPVOID", 8}, {"LPCSTR", 8}, {"LPSTR", 8}, {"LPCWSTR", 8}, {"LPWSTR", 8},
        {"SIZE_T", 8}, {"SSIZE_T", 8}, {"ptrdiff_t", 8}, {"size_t", 8},
        {"uintptr_t", 8}, {"intptr_t", 8},
        {"uint8_t", 1}, {"uint16_t", 2}, {"uint32_t", 4}, {"uint64_t", 8},
        {"int8_t", 1}, {"int16_t", 2}, {"int32_t", 4}, {"int64_t", 8},
        {"ULONG", 4}, {"ULONG32", 4}, {"ULONG64", 8},
        {"ULONG_PTR", 8}, {"LONG", 4}, {"LONG_PTR", 8},
        {"USHORT", 2}, {"SHORT", 2}, {"UCHAR", 1}, {"CHAR", 1},
        {"PULONG", 8}, {"PULONG_PTR", 8}, {"PLONG", 8}, {"PLONG_PTR", 8},
        {"PUINT", 8}, {"PUINT32", 8}, {"PUINT64", 8}, {"PUINT_PTR", 8},
        {"UINT", 4}, {"UINT32", 4}, {"UINT64", 8}, {"UINT_PTR", 8},
        {"PWSTR", 8}, {"PCWSTR", 8}, {"PSTR", 8}, {"PCSTR", 8},
        {"NTSTATUS", 4}, {"LRESULT", 8}, {"WPARAM", 8}, {"LPARAM", 8},
        {"ATOM", 2}, {"HBRUSH", 8}, {"HFONT", 8}, {"HBITMAP", 8},
        {"HDC", 8}, {"HRGN", 8}, {"HPEN", 8}, {"HMENU", 8},
        {"HICON", 8}, {"HCURSOR", 8}, {"HINSTANCE", 8}, {"HKEY", 8},
        {"PHKEY", 8}, {"REGSAM", 4}, {"ACCESS_MASK", 4},
        {"KAPC_STATE", 0}, {"DISPATCHER_HEADER", 0},
        {"LIST_ENTRY", 16}, {"SINGLE_LIST_ENTRY", 8},
        {"PLIST_ENTRY", 8}, {"PSINGLE_LIST_ENTRY", 8},
        {"GUID", 16}, {"LUID", 8}, {"LARGE_INTEGER", 8}, {"ULARGE_INTEGER", 8},
        {"UNICODE_STRING", 16}, {"ANSI_STRING", 16},
        {"PUNICODE_STRING", 8}, {"PANSI_STRING", 8},
        {"RTL_BALANCED_NODE", 24}, {"MMVAD_SHORT", 0},
    };
    const auto it = sizes.find(type_name);
    if (it != sizes.end()) {
        return it->second;
    }
    return 0;
}

std::uint64_t builtin_type_alignment(const std::string& type_name) {
    if (type_name.find('*') != std::string::npos || type_name.find("PVOID") != std::string::npos) {
        return 8;
    }
    const std::uint64_t sz = builtin_type_size(type_name);
    if (sz == 0) {
        return 0;
    }
    if (sz > 8) {
        return 8;
    }
    return sz;
}

bool is_pointer_type(const std::string& type_name) {
    return type_name.find('*') != std::string::npos ||
           type_name.substr(0, 1) == "P" ||
           type_name.find("LP") == 0 ||
           type_name.find("PH") == 0;
}

}

types_overlay_store_t::types_overlay_store_t() {
    limits_ = {};
}

types_overlay_store_t::~types_overlay_store_t() = default;

std::string types_overlay_store_t::trim(const std::string& s) const {
    return trim_ws(s);
}

std::string types_overlay_store_t::to_hex(std::uint64_t value) const {
    return to_hex_string(value);
}

std::string types_overlay_store_t::normalize_type_name(const std::string& type_name) const {
    std::string result = trim_ws(type_name);
    while (!result.empty() && result.back() == ';') {
        result.pop_back();
    }
    return trim_ws(result);
}

std::uint64_t types_overlay_store_t::type_size_of(const std::string& type_name) const {
    const std::string normalized = normalize_type_name(type_name);
    if (normalized.find('*') != std::string::npos) {
        return 8;
    }
    const std::uint64_t builtin = builtin_type_size(normalized);
    if (builtin != 0) {
        return builtin;
    }
    const auto it = types_.find(normalized);
    if (it != types_.end()) {
        return it->second.size;
    }
    std::string stripped = normalized;
    if (stripped.size() > 2 && stripped.substr(0, 2) == "P_" ) {
        stripped = stripped.substr(2);
        const auto it2 = types_.find(stripped);
        if (it2 != types_.end()) {
            return 8;
        }
    }
    if (stripped.size() > 1 && stripped[0] == 'P') {
        stripped = stripped.substr(1);
        const auto it2 = types_.find(stripped);
        if (it2 != types_.end()) {
            return 8;
        }
    }
    return 0;
}

std::uint64_t types_overlay_store_t::type_alignment_of(const std::string& type_name) const {
    const std::string normalized = normalize_type_name(type_name);
    if (normalized.find('*') != std::string::npos) {
        return 8;
    }
    const std::uint64_t builtin = builtin_type_alignment(normalized);
    if (builtin != 0) {
        return builtin;
    }
    const auto it = types_.find(normalized);
    if (it != types_.end()) {
        if (it->second.is_union) {
            std::uint64_t max_align = 1;
            for (const auto& m : it->second.members) {
                max_align = std::max(max_align, type_alignment_of(m.type));
            }
            return max_align;
        }
        std::uint64_t max_align = 1;
        for (const auto& m : it->second.members) {
            max_align = std::max(max_align, type_alignment_of(m.type));
        }
        return max_align;
    }
    return 0;
}

std::uint64_t types_overlay_store_t::compute_member_offset(
    const std::vector<overlay_member_t>& members,
    std::uint64_t member_size) const {
    if (members.empty()) {
        return 0;
    }
    std::uint64_t current = members.back().offset + members.back().size;
    if (member_size == 0) {
        return current;
    }
    std::uint64_t alignment = member_size;
    if (alignment > 8) {
        alignment = 8;
    }
    if (alignment == 0) {
        alignment = 1;
    }
    const std::uint64_t remainder = current % alignment;
    if (remainder != 0) {
        current += alignment - remainder;
    }
    return current;
}

bool types_overlay_store_t::parse_struct_body(const std::string& body,
                                               const std::string& kind,
                                               const std::string& name,
                                               overlay_type_t& out) {
    out.name = name;
    out.kind = kind;
    out.is_union = (kind == "union");
    out.is_udt = true;
    out.declaration = kind + " " + name + " { " + body + " };";

    std::string trimmed = trim_ws(body);
    while (!trimmed.empty() && trimmed.back() == ';') {
        trimmed.pop_back();
        trimmed = trim_ws(trimmed);
    }
    if (trimmed.empty()) {
        out.size = 0;
        return true;
    }

    std::vector<std::string> fields;
    std::string current;
    int brace_depth = 0;
    for (char c : trimmed) {
        if (c == '{') {
            ++brace_depth;
            current.push_back(c);
        } else if (c == '}') {
            --brace_depth;
            current.push_back(c);
        } else if (c == ';' && brace_depth == 0) {
            std::string f = trim_ws(current);
            if (!f.empty()) {
                fields.push_back(f);
            }
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!trim_ws(current).empty()) {
        fields.push_back(trim_ws(current));
    }

    std::uint64_t struct_offset = 0;
    std::uint64_t union_max_size = 0;
    for (const auto& field : fields) {
        if (field.empty()) {
            continue;
        }
        std::string field_str = field;
        while (!field_str.empty() && field_str.back() == ';') {
            field_str.pop_back();
        }
        field_str = trim_ws(field_str);
        if (field_str.empty()) {
            continue;
        }
        std::size_t last_space = std::string::npos;
        int star_count = 0;
        for (int i = static_cast<int>(field_str.size()) - 1; i >= 0; --i) {
            if (field_str[i] == '*') {
                ++star_count;
                continue;
            }
            if (std::isspace(static_cast<unsigned char>(field_str[i])) != 0) {
                last_space = static_cast<std::size_t>(i);
                break;
            }
        }
        std::string member_type;
        std::string member_name;
        if (last_space != std::string::npos) {
            member_type = trim_ws(field_str.substr(0, last_space + 1));
            member_name = trim_ws(field_str.substr(last_space + 1));
        } else {
            member_name = field_str;
            member_type = "int";
        }
        if (star_count > 0) {
            member_type += std::string(star_count, '*');
            member_name = member_name.substr(0, member_name.size() - star_count);
            member_name = trim_ws(member_name);
        }
        std::string array_suffix;
        std::size_t bracket = member_name.find('[');
        if (bracket != std::string::npos) {
            array_suffix = member_name.substr(bracket);
            member_name = member_name.substr(0, bracket);
            member_name = trim_ws(member_name);
        }

        overlay_member_t member;
        member.name = member_name;
        member.type = member_type;
        const std::uint64_t base_size = type_size_of(member_type);
        std::uint64_t member_size = base_size;
        if (!array_suffix.empty()) {
            std::string num_str;
            for (char c : array_suffix) {
                if (std::isdigit(static_cast<unsigned char>(c)) != 0) {
                    num_str.push_back(c);
                }
            }
            if (!num_str.empty()) {
                try {
                    const std::uint64_t count = std::stoull(num_str);
                    member_size = base_size * count;
                } catch (...) {
                    member_size = base_size;
                }
            }
        }
        member.size = member_size;

        if (out.is_union) {
            member.offset = 0;
            union_max_size = std::max(union_max_size, member_size);
        } else {
            const std::uint64_t alignment = type_alignment_of(member_type);
            std::uint64_t aligned_offset = struct_offset;
            if (alignment > 0 && aligned_offset % alignment != 0) {
                aligned_offset += alignment - (aligned_offset % alignment);
            }
            member.offset = aligned_offset;
            struct_offset = aligned_offset + member_size;
        }
        out.members.push_back(std::move(member));
    }

    if (out.is_union) {
        out.size = union_max_size;
    } else {
        const std::uint64_t final_align = type_alignment_of(out.kind == "struct" ? out.name : "int");
        if (final_align > 0 && struct_offset % final_align != 0) {
            struct_offset += final_align - (struct_offset % final_align);
        }
        out.size = struct_offset;
    }
    return true;
}

bool types_overlay_store_t::parse_enum_body(const std::string& body,
                                             const std::string& name,
                                             overlay_type_t& out) {
    out.name = name;
    out.kind = "enum";
    out.is_enum = true;
    out.declaration = "enum " + name + " { " + body + " };";

    std::string trimmed = trim_ws(body);
    while (!trimmed.empty() && trimmed.back() == ';') {
        trimmed.pop_back();
        trimmed = trim_ws(trimmed);
    }

    std::vector<std::string> entries;
    std::string current;
    int depth = 0;
    for (char c : trimmed) {
        if (c == '{' || c == '(' || c == '[') {
            ++depth;
            current.push_back(c);
        } else if (c == '}' || c == ')' || c == ']') {
            --depth;
            current.push_back(c);
        } else if (c == ',' && depth == 0) {
            std::string e = trim_ws(current);
            if (!e.empty()) {
                entries.push_back(e);
            }
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!trim_ws(current).empty()) {
        entries.push_back(trim_ws(current));
    }

    std::int64_t next_value = 0;
    for (const auto& entry : entries) {
        std::string entry_str = trim_ws(entry);
        if (entry_str.empty()) {
            continue;
        }
        std::size_t eq_pos = entry_str.find('=');
        overlay_enumerator_t enumerator;
        if (eq_pos != std::string::npos) {
            enumerator.name = trim_ws(entry_str.substr(0, eq_pos));
            std::string val_str = trim_ws(entry_str.substr(eq_pos + 1));
            try {
                if (val_str.substr(0, 2) == "0x" || val_str.substr(0, 2) == "0X") {
                    enumerator.value = static_cast<std::int64_t>(
                        std::stoull(val_str.substr(2), nullptr, 16));
                } else {
                    enumerator.value = static_cast<std::int64_t>(std::stoll(val_str));
                }
                next_value = enumerator.value + 1;
            } catch (...) {
                enumerator.value = next_value++;
            }
        } else {
            enumerator.name = entry_str;
            enumerator.value = next_value++;
        }
        out.enumerators.push_back(std::move(enumerator));
    }
    out.size = 4;
    return true;
}

bool types_overlay_store_t::parse_typedef(const std::string& body,
                                           overlay_type_t& out) {
    std::string trimmed = trim_ws(body);
    if (trimmed.empty()) {
        return false;
    }
    std::string typedef_kw = "typedef";
    if (trimmed.size() > typedef_kw.size() &&
        trimmed.substr(0, typedef_kw.size()) == typedef_kw) {
        trimmed = trim_ws(trimmed.substr(typedef_kw.size()));
    }
    while (!trimmed.empty() && trimmed.back() == ';') {
        trimmed.pop_back();
        trimmed = trim_ws(trimmed);
    }
    std::size_t last_space = std::string::npos;
    int star_count = 0;
    for (int i = static_cast<int>(trimmed.size()) - 1; i >= 0; --i) {
        if (trimmed[i] == '*') {
            ++star_count;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(trimmed[i])) != 0) {
            last_space = static_cast<std::size_t>(i);
            break;
        }
    }
    std::string base_type;
    std::string alias;
    if (last_space != std::string::npos) {
        base_type = trim_ws(trimmed.substr(0, last_space + 1));
        alias = trim_ws(trimmed.substr(last_space + 1));
    } else {
        alias = trimmed;
        base_type = "int";
    }
    if (star_count > 0) {
        base_type += std::string(star_count, '*');
        alias = alias.substr(0, alias.size() - star_count);
        alias = trim_ws(alias);
    }

    out.name = alias;
    out.kind = "typedef";
    out.is_typedef = true;
    out.is_ptr = (base_type.find('*') != std::string::npos);
    out.declaration = "typedef " + base_type + " " + alias + ";";
    out.size = type_size_of(base_type);
    if (out.size == 0) {
        out.size = 8;
    }
    return true;
}

bool types_overlay_store_t::parse_declaration(const std::string& decl,
                                               overlay_type_t& out) {
    std::string trimmed = trim_ws(decl);
    if (trimmed.empty()) {
        return false;
    }
    while (!trimmed.empty() && trimmed.back() == ';') {
        trimmed.pop_back();
        trimmed = trim_ws(trimmed);
    }
    std::string lower = to_lower(trimmed);

    if (lower.substr(0, 7) == "typedef") {
        return parse_typedef(trimmed, out);
    }
    if (lower.substr(0, 6) == "struct" || lower.substr(0, 5) == "union") {
        std::string kind = lower.substr(0, 5) == "union" ? "union" : "struct";
        std::size_t kw_end = trimmed.find(' ', lower.substr(0, 5) == "union" ? 5 : 6);
        if (kw_end == std::string::npos) {
            return false;
        }
        std::string rest = trim_ws(trimmed.substr(kw_end));
        std::size_t brace_start = rest.find('{');
        if (brace_start == std::string::npos) {
            return false;
        }
        std::string name = trim_ws(rest.substr(0, brace_start));
        std::size_t brace_end = rest.rfind('}');
        if (brace_end == std::string::npos || brace_end <= brace_start) {
            return false;
        }
        std::string body = rest.substr(brace_start + 1, brace_end - brace_start - 1);
        return parse_struct_body(body, kind, name, out);
    }
    if (lower.substr(0, 4) == "enum") {
        std::size_t kw_end = trimmed.find(' ', 4);
        if (kw_end == std::string::npos) {
            return false;
        }
        std::string rest = trim_ws(trimmed.substr(kw_end));
        std::size_t brace_start = rest.find('{');
        if (brace_start == std::string::npos) {
            return false;
        }
        std::string name = trim_ws(rest.substr(0, brace_start));
        std::size_t brace_end = rest.rfind('}');
        if (brace_end == std::string::npos || brace_end <= brace_start) {
            return false;
        }
        std::string body = rest.substr(brace_start + 1, brace_end - brace_start - 1);
        return parse_enum_body(body, name, out);
    }
    return false;
}

std::string types_overlay_store_t::format_declaration(const overlay_type_t& type) const {
    return type.declaration;
}

protocol::json types_overlay_store_t::members_to_json(
    const std::vector<overlay_member_t>& members,
    bool include_value,
    const std::string& base_addr) const {
    json arr = json::array();
    for (const auto& m : members) {
        json obj = json::object();
        obj["name"] = m.name;
        obj["offset"] = to_hex(m.offset);
        obj["size"] = static_cast<std::int64_t>(m.size);
        obj["type"] = m.type;
        if (include_value) {
            obj["value"] = "0x0";
        }
        arr.push_back(std::move(obj));
    }
    return arr;
}

protocol::json types_overlay_store_t::enumerators_to_json(
    const std::vector<overlay_enumerator_t>& enumerators) const {
    json arr = json::array();
    for (const auto& e : enumerators) {
        json obj = json::object();
        obj["name"] = e.name;
        obj["value"] = static_cast<std::int64_t>(e.value);
        arr.push_back(std::move(obj));
    }
    return arr;
}

std::vector<type_relation_t> types_overlay_store_t::find_related_types(
    const std::string& name) const {
    std::vector<type_relation_t> relations;
    std::unordered_set<std::string> seen;
    seen.insert(name);
    for (const auto& [key, type] : types_) {
        if (key == name) {
            continue;
        }
        for (const auto& m : type.members) {
            const std::string normalized = normalize_type_name(m.type);
            if (normalized == name) {
                if (seen.insert(key).second) {
                    relations.push_back({key, type.kind});
                }
                break;
            }
            if (normalized.find(name + "*") != std::string::npos) {
                if (seen.insert(key).second) {
                    relations.push_back({key, type.kind});
                }
                break;
            }
        }
        if (type.is_typedef) {
            const std::string normalized = normalize_type_name(type.declaration);
            if (normalized.find(name) != std::string::npos && key != name) {
                if (seen.insert(key).second) {
                    relations.push_back({key, type.kind});
                }
            }
        }
    }
    if (relations.size() > limits_.max_related_types) {
        relations.resize(limits_.max_related_types);
    }
    return relations;
}

void types_overlay_store_t::record_undo(
    undo_entry_t::action_t action, const std::string& target,
    std::optional<overlay_type_t> old_type,
    std::optional<overlay_type_application_t> old_app) {
    undo_entry_t entry;
    entry.action = action;
    entry.target_name = target;
    entry.old_type = std::move(old_type);
    entry.old_application = std::move(old_app);
    entry.revision = revision_;
    undo_stack_.push_back(std::move(entry));
}

bool types_overlay_store_t::undo() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (undo_stack_.empty()) {
        return false;
    }
    undo_entry_t entry = std::move(undo_stack_.back());
    undo_stack_.pop_back();
    switch (entry.action) {
    case undo_entry_t::action_t::declare_type:
    case undo_entry_t::action_t::enum_upsert: {
        if (entry.old_type.has_value()) {
            types_[entry.target_name] = std::move(*entry.old_type);
        } else {
            types_.erase(entry.target_name);
        }
        break;
    }
    case undo_entry_t::action_t::set_type: {
        if (entry.old_application.has_value()) {
            applications_[entry.target_name] = std::move(*entry.old_application);
        } else {
            applications_.erase(entry.target_name);
        }
        break;
    }
    case undo_entry_t::action_t::delete_type: {
        if (entry.old_type.has_value()) {
            types_[entry.target_name] = std::move(*entry.old_type);
        }
        break;
    }
    case undo_entry_t::action_t::rename_type: {
        if (entry.old_type.has_value()) {
            types_[entry.target_name] = std::move(*entry.old_type);
            auto it = types_.find(entry.old_type->name);
            if (it != types_.end() && it->second.name != entry.target_name) {
                types_.erase(it);
            }
        }
        break;
    }
    default:
        break;
    }
    --revision_;
    return true;
}

void types_overlay_store_t::rollback_batch(std::vector<undo_entry_t>& batch_undo) {
    for (auto it = batch_undo.rbegin(); it != batch_undo.rend(); ++it) {
        switch (it->action) {
        case undo_entry_t::action_t::declare_type:
        case undo_entry_t::action_t::enum_upsert:
            if (it->old_type.has_value()) {
                types_[it->target_name] = std::move(*it->old_type);
            } else {
                types_.erase(it->target_name);
            }
            break;
        case undo_entry_t::action_t::set_type:
            if (it->old_application.has_value()) {
                applications_[it->target_name] = std::move(*it->old_application);
            } else {
                applications_.erase(it->target_name);
            }
            break;
        default:
            break;
        }
    }
    batch_undo.clear();
    --revision_;
}

bool types_overlay_store_t::apply_single_edit(const json& edit, json& result,
                                               std::vector<undo_entry_t>& batch_undo) {
    const std::string addr = edit.value("addr", std::string());
    if (addr.empty()) {
        result = json{{"edit", edit}, {"error", "address is required"}, {"kind", edit.value("kind", "data")}, {"ok", false}};
        return false;
    }
    const std::string ty = edit.value("ty", std::string());
    const std::string signature = edit.value("signature", std::string());
    const std::string name = edit.value("name", std::string());
    const std::string variable = edit.value("variable", std::string());
    if (ty.empty() && signature.empty() && name.empty() && variable.empty()) {
        result = json{{"edit", edit}, {"error", "no type information provided"}, {"kind", edit.value("kind", "data")}, {"ok", false}};
        return false;
    }
    const std::string kind = edit.value("kind", "data");

    overlay_type_application_t app;
    app.addr = addr;
    app.ty = ty;
    app.kind = kind;
    app.name = name;
    app.signature = signature;
    app.variable = variable;
    app.revision = revision_ + 1;

    std::optional<overlay_type_application_t> old_app;
    const auto existing = applications_.find(addr);
    if (existing != applications_.end()) {
        old_app = existing->second;
    }

    applications_[addr] = app;
    undo_entry_t entry;
    entry.action = undo_entry_t::action_t::set_type;
    entry.target_name = addr;
    entry.old_application = old_app;
    entry.revision = revision_;
    batch_undo.push_back(std::move(entry));

    result = json{{"edit", edit}, {"error", ""}, {"kind", kind}, {"ok", true}};
    return true;
}

json types_overlay_store_t::do_declare_type(const json& args) {
    std::vector<std::string> decls;
    const auto& decls_val = args.at("decls");
    if (decls_val.is_string()) {
        decls.push_back(decls_val.get<std::string>());
    } else if (decls_val.is_array()) {
        for (const auto& d : decls_val) {
            if (d.is_string()) {
                decls.push_back(d.get<std::string>());
            }
        }
    }

    json results = json::array();
    for (const auto& decl : decls) {
        json item = json::object();
        item["decl"] = decl;
        overlay_type_t type;
        if (parse_declaration(decl, type)) {
            const auto existing = types_.find(type.name);
            if (existing != types_.end()) {
                record_undo(undo_entry_t::action_t::declare_type, type.name, existing->second,
                            std::nullopt);
            } else {
                record_undo(undo_entry_t::action_t::declare_type, type.name, std::nullopt,
                            std::nullopt);
            }
            type.ordinal = next_ordinal_++;
            type.revision_added = revision_ + 1;
            type.revision_modified = revision_ + 1;
            types_[type.name] = std::move(type);
            ++revision_;
            item["error"] = "";
        } else {
            item["error"] = "failed to parse declaration";
        }
        results.push_back(std::move(item));
    }
    return json{{"result", results}};
}

json types_overlay_store_t::do_enum_upsert(const json& args) {
    std::vector<json> queries;
    const auto& q_val = args.at("queries");
    if (q_val.is_object()) {
        queries.push_back(q_val);
    } else if (q_val.is_array()) {
        for (const auto& q : q_val) {
            queries.push_back(q);
        }
    }

    json results = json::array();
    for (const auto& query : queries) {
        const std::string enum_name = query.value("name", std::string());
        const bool bitfield = query.value("bitfield", false);
        json item = json::object();
        item["name"] = enum_name;
        item["bitfield"] = bitfield;
        item["enum_id"] = enum_name.empty() ? "" : enum_name;

        if (enum_name.empty()) {
            item["created"] = false;
            item["error"] = "enum name is required";
            item["summary"] = json{{"created", 0}, {"skipped", 0}, {"conflicts", 0}};
            item["members"] = json::array();
            results.push_back(std::move(item));
            continue;
        }

        std::vector<std::pair<std::string, std::int64_t>> members_to_upsert;
        const auto& members_val = query.value("members", json::array());
        if (members_val.is_array()) {
            for (const auto& m : members_val) {
                const std::string m_name = m.value("name", std::string());
                std::int64_t m_value = 0;
                if (m.contains("value")) {
                    if (m["value"].is_number_integer()) {
                        m_value = m["value"].get<std::int64_t>();
                    } else if (m["value"].is_string()) {
                        try {
                            m_value = std::stoll(m["value"].get<std::string>());
                        } catch (...) {
                            m_value = 0;
                        }
                    }
                }
                if (!m_name.empty()) {
                    members_to_upsert.emplace_back(m_name, m_value);
                }
            }
        } else if (members_val.is_object()) {
            const std::string m_name = members_val.value("name", std::string());
            std::int64_t m_value = 0;
            if (members_val.contains("value")) {
                if (members_val["value"].is_number_integer()) {
                    m_value = members_val["value"].get<std::int64_t>();
                } else if (members_val["value"].is_string()) {
                    try {
                        m_value = std::stoll(members_val["value"].get<std::string>());
                    } catch (...) {
                        m_value = 0;
                    }
                }
            }
            if (!m_name.empty()) {
                members_to_upsert.emplace_back(m_name, m_value);
            }
        }

        bool created = false;
        std::unordered_map<std::string, std::int64_t> existing_enums;
        const auto existing = types_.find(enum_name);
        if (existing != types_.end() && existing->second.is_enum) {
            for (const auto& e : existing->second.enumerators) {
                existing_enums[e.name] = e.value;
            }
        } else if (existing == types_.end()) {
            created = true;
        }

        json members_result = json::array();
        int created_count = 0;
        int skipped_count = 0;
        int conflict_count = 0;

        overlay_type_t enum_type;
        if (existing != types_.end() && existing->second.is_enum) {
            enum_type = existing->second;
        } else {
            enum_type.name = enum_name;
            enum_type.kind = "enum";
            enum_type.is_enum = true;
            enum_type.size = 4;
            enum_type.declaration = "enum " + enum_name + " { };";
        }
        enum_type.bitfield = bitfield;

        for (const auto& [m_name, m_value] : members_to_upsert) {
            json m_result = json::object();
            m_result["name"] = m_name;
            m_result["value"] = static_cast<std::int64_t>(m_value);
            const auto ex_it = existing_enums.find(m_name);
            if (ex_it != existing_enums.end()) {
                if (ex_it->second == m_value) {
                    m_result["created"] = false;
                    m_result["skipped"] = true;
                    m_result["error"] = "";
                    ++skipped_count;
                } else {
                    m_result["created"] = false;
                    m_result["skipped"] = false;
                    m_result["error"] = "conflicting value";
                    ++conflict_count;
                    for (auto& e : enum_type.enumerators) {
                        if (e.name == m_name) {
                            e.value = m_value;
                            break;
                        }
                    }
                }
            } else {
                overlay_enumerator_t enumerator;
                enumerator.name = m_name;
                enumerator.value = m_value;
                enum_type.enumerators.push_back(std::move(enumerator));
                existing_enums[m_name] = m_value;
                m_result["created"] = true;
                m_result["skipped"] = false;
                m_result["error"] = "";
                ++created_count;
            }
            members_result.push_back(std::move(m_result));
        }

        enum_type.declaration = "enum " + enum_name + " { ";
        for (std::size_t i = 0; i < enum_type.enumerators.size(); ++i) {
            if (i > 0) {
                enum_type.declaration += ", ";
            }
            enum_type.declaration += enum_type.enumerators[i].name + " = " +
                std::to_string(enum_type.enumerators[i].value);
        }
        enum_type.declaration += " };";

        if (created) {
            enum_type.ordinal = next_ordinal_++;
            enum_type.revision_added = revision_ + 1;
            record_undo(undo_entry_t::action_t::enum_upsert, enum_name, std::nullopt, std::nullopt);
        } else {
            record_undo(undo_entry_t::action_t::enum_upsert, enum_name,
                        existing != types_.end() ? std::make_optional(existing->second) : std::nullopt,
                        std::nullopt);
        }
        enum_type.revision_modified = revision_ + 1;
        types_[enum_name] = std::move(enum_type);
        ++revision_;

        item["created"] = created;
        item["error"] = "";
        item["members"] = std::move(members_result);
        item["summary"] = json{
            {"created", created_count},
            {"skipped", skipped_count},
            {"conflicts", conflict_count},
        };
        results.push_back(std::move(item));
    }
    return json{{"result", results}};
}

json types_overlay_store_t::do_read_struct(const json& args) {
    std::vector<json> queries;
    const auto& q_val = args.at("queries");
    if (q_val.is_object()) {
        queries.push_back(q_val);
    } else if (q_val.is_array()) {
        for (const auto& q : q_val) {
            queries.push_back(q);
        }
    }

    json results = json::array();
    for (const auto& query : queries) {
        const std::string addr = query.value("addr", std::string());
        const std::string struct_name = query.value("struct", std::string());

        json item = json::object();
        item["addr"] = addr.empty() ? json(nullptr) : json(addr);
        item["error"] = "";
        item["struct"] = struct_name.empty() ? json(nullptr) : json(struct_name);
        item["members"] = nullptr;

        if (addr.empty()) {
            item["error"] = "address is required";
            results.push_back(std::move(item));
            continue;
        }

        std::string resolved_name = struct_name;
        if (resolved_name.empty()) {
            const auto app_it = applications_.find(addr);
            if (app_it != applications_.end()) {
                resolved_name = app_it->second.ty;
                if (!resolved_name.empty() && resolved_name.back() == '*') {
                    resolved_name.pop_back();
                    resolved_name = trim_ws(resolved_name);
                }
            }
        }

        if (resolved_name.empty()) {
            item["error"] = "no struct type specified and no type application found for address";
            results.push_back(std::move(item));
            continue;
        }

        const auto type_it = types_.find(resolved_name);
        if (type_it == types_.end()) {
            item["error"] = "type '" + resolved_name + "' is not declared";
            results.push_back(std::move(item));
            continue;
        }

        if (!type_it->second.is_udt) {
            item["error"] = "type '" + resolved_name + "' is not a struct/union";
            results.push_back(std::move(item));
            continue;
        }

        item["struct"] = resolved_name;
        item["members"] = members_to_json(type_it->second.members, true, addr);
        results.push_back(std::move(item));
    }
    return json{{"result", results}};
}

json types_overlay_store_t::do_search_structs(const json& args) {
    const std::string filter = args.value("filter", std::string());
    json results = json::array();
    std::vector<const overlay_type_t*> matches;
    for (const auto& [name, type] : types_) {
        if (type.is_udt && contains_ci(name, filter)) {
            matches.push_back(&type);
        }
    }
    std::sort(matches.begin(), matches.end(),
              [](const overlay_type_t* a, const overlay_type_t* b) {
                  return a->name < b->name;
              });
    for (const auto* type : matches) {
        results.push_back(json{
            {"name", type->name},
            {"size", static_cast<std::int64_t>(type->size)},
            {"cardinality", static_cast<std::int64_t>(type->members.size())},
            {"is_union", type->is_union},
            {"ordinal", static_cast<std::int64_t>(type->ordinal)},
        });
    }
    return json{{"result", results}};
}

json types_overlay_store_t::do_type_query(const json& args) {
    std::vector<json> queries;
    const auto& q_val = args.at("queries");
    if (q_val.is_object()) {
        queries.push_back(q_val);
    } else if (q_val.is_array()) {
        for (const auto& q : q_val) {
            queries.push_back(q);
        }
    }

    json results = json::array();
    for (const auto& query : queries) {
        const std::string filter = query.value("filter", std::string());
        const std::string kind = query.value("kind", "any");
        const std::string sort_by = query.value("sort_by", "name");
        const bool descending = query.value("descending", false);
        const int count = query.value("count", 0);
        const int offset = query.value("offset", 0);
        const bool include_decl = query.value("include_decl", false);
        const bool include_members = query.value("include_members", false);
        const bool include_relationships = query.value("include_relationships", false);
        const int max_members = query.value("max_members", 0);

        std::vector<const overlay_type_t*> matched;
        for (const auto& [name, type] : types_) {
            if (!filter.empty() && !contains_ci(name, filter)) {
                continue;
            }
            if (kind != "any") {
                bool kind_match = false;
                if (kind == "struct") {
                    kind_match = type.is_udt && !type.is_union;
                } else if (kind == "union") {
                    kind_match = type.is_union;
                } else if (kind == "enum") {
                    kind_match = type.is_enum;
                } else if (kind == "typedef") {
                    kind_match = type.is_typedef;
                } else if (kind == "ptr") {
                    kind_match = type.is_ptr;
                } else if (kind == "func") {
                    kind_match = type.is_func;
                } else if (kind == "udt") {
                    kind_match = type.is_udt;
                }
                if (!kind_match) {
                    continue;
                }
            }
            matched.push_back(&type);
        }

        std::sort(matched.begin(), matched.end(),
            [&sort_by, &descending](const overlay_type_t* a, const overlay_type_t* b) {
                int cmp = 0;
                if (sort_by == "size") {
                    cmp = (a->size < b->size) ? -1 : (a->size > b->size) ? 1 : 0;
                } else if (sort_by == "ordinal") {
                    cmp = (a->ordinal < b->ordinal) ? -1 : (a->ordinal > b->ordinal) ? 1 : 0;
                } else {
                    cmp = a->name.compare(b->name);
                }
                return descending ? cmp > 0 : cmp < 0;
            });

        const int total = static_cast<int>(matched.size());
        int start = std::max(0, offset);
        int end = total;
        if (count > 0) {
            end = std::min(end, start + count);
        }

        json data = json::array();
        for (int i = start; i < end; ++i) {
            const auto* type = matched[i];
            json entry = json::object();
            entry["name"] = type->name;
            entry["kind"] = type->kind;
            entry["size"] = static_cast<std::int64_t>(type->size);
            entry["ordinal"] = static_cast<std::int64_t>(type->ordinal);
            entry["member_count"] = static_cast<std::int64_t>(type->members.size());

            if (include_decl) {
                entry["declaration"] = format_declaration(*type);
            }

            bool members_truncated = false;
            if (include_members && type->is_udt) {
                int member_limit = max_members > 0 ? max_members : static_cast<int>(type->members.size());
                if (static_cast<int>(type->members.size()) > member_limit) {
                    members_truncated = true;
                }
                json members_arr = json::array();
                for (int mi = 0; mi < std::min(member_limit, static_cast<int>(type->members.size())); ++mi) {
                    const auto& m = type->members[mi];
                    members_arr.push_back(json{
                        {"name", m.name},
                        {"offset", to_hex(m.offset)},
                        {"size", static_cast<std::int64_t>(m.size)},
                        {"type", m.type},
                    });
                }
                entry["members"] = std::move(members_arr);
            }
            entry["members_truncated"] = members_truncated;

            bool related_truncated = false;
            int related_count = 0;
            if (include_relationships) {
                auto relations = find_related_types(type->name);
                related_count = static_cast<int>(relations.size());
                if (related_count > static_cast<int>(limits_.max_related_types)) {
                    related_truncated = true;
                }
                json related_arr = json::array();
                for (const auto& r : relations) {
                    related_arr.push_back(r.name);
                }
                entry["related_types"] = std::move(related_arr);
            } else {
                entry["related_types"] = json::array();
            }
            entry["related_count"] = related_count;
            entry["related_truncated"] = related_truncated;

            data.push_back(std::move(entry));
        }

        json::value_t next_offset_type = json(nullptr);
        if (count > 0 && end < total) {
            next_offset_type = json(end);
        }

        results.push_back(json{
            {"kind", kind},
            {"data", std::move(data)},
            {"next_offset", next_offset_type},
            {"total", total},
        });
    }
    return json{{"result", results}};
}

json types_overlay_store_t::do_type_inspect(const json& args) {
    std::vector<json> queries;
    const auto& q_val = args.at("queries");
    if (q_val.is_object()) {
        queries.push_back(q_val);
    } else if (q_val.is_array()) {
        for (const auto& q : q_val) {
            queries.push_back(q);
        }
    }

    json results = json::array();
    for (const auto& query : queries) {
        const std::string name = query.value("name", std::string());
        const bool include_members = query.value("include_members", true);
        const int max_members = query.value("max_members", 0);

        json item = json::object();
        item["name"] = name;
        item["exists"] = false;
        item["error"] = "";
        item["is_udt"] = false;
        item["is_enum"] = false;
        item["is_func"] = false;
        item["is_ptr"] = false;
        item["size"] = 0;
        item["member_count"] = 0;
        item["members"] = nullptr;
        item["declaration"] = "";

        if (name.empty()) {
            item["error"] = "type name is required";
            results.push_back(std::move(item));
            continue;
        }

        const auto it = types_.find(name);
        if (it == types_.end()) {
            item["error"] = "type '" + name + "' does not exist";
            results.push_back(std::move(item));
            continue;
        }

        const auto& type = it->second;
        item["exists"] = true;
        item["is_udt"] = type.is_udt;
        item["is_enum"] = type.is_enum;
        item["is_func"] = type.is_func;
        item["is_ptr"] = type.is_ptr;
        item["size"] = static_cast<std::int64_t>(type.size);
        item["member_count"] = static_cast<std::int64_t>(type.members.size());
        item["declaration"] = format_declaration(type);

        if (include_members && type.is_udt) {
            int member_limit = max_members > 0 ? max_members : static_cast<int>(type.members.size());
            json members_arr = json::array();
            for (int mi = 0; mi < std::min(member_limit, static_cast<int>(type.members.size())); ++mi) {
                const auto& m = type.members[mi];
                members_arr.push_back(json{
                    {"name", m.name},
                    {"offset", to_hex(m.offset)},
                    {"size", static_cast<std::int64_t>(m.size)},
                    {"type", m.type},
                });
            }
            item["members"] = std::move(members_arr);
        } else if (type.is_enum) {
            json members_arr = json::array();
            for (const auto& e : type.enumerators) {
                members_arr.push_back(json{
                    {"name", e.name},
                    {"offset", to_hex(static_cast<std::uint64_t>(e.value))},
                    {"size", 4},
                    {"type", "int"},
                });
            }
            item["members"] = std::move(members_arr);
        }
        results.push_back(std::move(item));
    }
    return json{{"result", results}};
}

json types_overlay_store_t::do_set_type(const json& args) {
    std::vector<json> edits;
    const auto& e_val = args.at("edits");
    if (e_val.is_object()) {
        edits.push_back(e_val);
    } else if (e_val.is_array()) {
        for (const auto& e : e_val) {
            edits.push_back(e);
        }
    }

    json results = json::array();
    for (const auto& edit : edits) {
        json result;
        std::vector<undo_entry_t> single_undo;
        apply_single_edit(edit, result, single_undo);
        for (auto& u : single_undo) {
            undo_stack_.push_back(std::move(u));
        }
        if (result.value("ok", false)) {
            ++revision_;
        }
        results.push_back(std::move(result));
    }
    return json{{"result", results}};
}

json types_overlay_store_t::do_type_apply_batch(const json& args) {
    const auto& batch = args.at("batch");
    const auto& edits_val = batch.at("edits");
    const bool stop_on_error = batch.value("stop_on_error", false);

    std::vector<json> edits;
    if (edits_val.is_object()) {
        edits.push_back(edits_val);
    } else if (edits_val.is_array()) {
        for (const auto& e : edits_val) {
            edits.push_back(e);
        }
    }

    ++revision_;
    json results = json::array();
    int applied = 0;
    int failed = 0;
    bool stopped = false;
    std::vector<undo_entry_t> batch_undo;

    for (std::size_t i = 0; i < edits.size(); ++i) {
        json result;
        if (apply_single_edit(edits[i], result, batch_undo)) {
            ++applied;
        } else {
            ++failed;
            if (stop_on_error) {
                stopped = true;
                results.push_back(std::move(result));
                for (++i; i < edits.size(); ++i) {
                    json skipped = json{
                        {"edit", edits[i]},
                        {"error", "skipped due to prior failure"},
                        {"kind", edits[i].value("kind", "data")},
                        {"ok", false},
                    };
                    results.push_back(std::move(skipped));
                }
                rollback_batch(batch_undo);
                applied = 0;
                failed = static_cast<int>(edits.size());
                for (auto& r : results) {
                    if (r.value("ok", false)) {
                        r["ok"] = false;
                        if (r.value("error", "") == "") {
                            r["error"] = "rolled back due to batch failure";
                        }
                    }
                }
                break;
            }
        }
        results.push_back(std::move(result));
    }

    if (!stopped) {
        for (auto& u : batch_undo) {
            undo_stack_.push_back(std::move(u));
        }
    }

    return json{
        {"ok", !stopped && failed == 0},
        {"applied", applied},
        {"failed", failed},
        {"stopped", stopped},
        {"results", std::move(results)},
    };
}

json types_overlay_store_t::do_infer_types(const json& args) {
    std::vector<std::string> addrs;
    const auto& a_val = args.at("addrs");
    if (a_val.is_string()) {
        addrs.push_back(a_val.get<std::string>());
    } else if (a_val.is_array()) {
        for (const auto& a : a_val) {
            if (a.is_string()) {
                addrs.push_back(a.get<std::string>());
            }
        }
    }

    json results = json::array();
    for (const auto& addr : addrs) {
        json item = json::object();
        item["addr"] = addr;
        item["error"] = "";

        const auto app_it = applications_.find(addr);
        if (app_it != applications_.end()) {
            item["inferred_type"] = app_it->second.ty;
            item["confidence"] = "high";
            item["method"] = "existing_type_application";
        } else {
            bool inferred = false;
            for (const auto& [name, type] : types_) {
                if (type.is_udt && type.size > 0 && type.size <= 256) {
                    for (const auto& m : type.members) {
                        if (m.type.find('*') != std::string::npos) {
                            const auto ptr_app = applications_.find(addr);
                            if (ptr_app != applications_.end() &&
                                contains_ci(ptr_app->second.ty, name)) {
                                item["inferred_type"] = name + "*";
                                item["confidence"] = "medium";
                                item["method"] = "xref_analysis";
                                inferred = true;
                                break;
                            }
                        }
                    }
                    if (inferred) {
                        break;
                    }
                }
            }

            if (!inferred) {
                for (const auto& [name, type] : types_) {
                    bool has_pointer_to = false;
                    for (const auto& m : type.members) {
                        if (m.type.find('*') != std::string::npos &&
                            contains_ci(m.type, name)) {
                            has_pointer_to = true;
                            break;
                        }
                    }
                    if (has_pointer_to) {
                        item["inferred_type"] = name + "*";
                        item["confidence"] = "low";
                        item["method"] = "size_heuristic";
                        inferred = true;
                        break;
                    }
                }
            }

            if (!inferred) {
                item["inferred_type"] = nullptr;
                item["confidence"] = "low";
                item["method"] = nullptr;
            }
        }
        results.push_back(std::move(item));
    }
    return json{{"result", results}};
}

adapter_result_t<adapter_response_t> types_overlay_store_t::handle_query(
    const adapter_call_context_t& context,
    const adapter_request_t& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (context.contract == nullptr) {
        return adapter_result_t<adapter_response_t>::failure(
            {adapter_error_code_t::backend_rejected, "types_query_no_contract", 0, 0});
    }
    const std::string name(context.contract->name);
    json args = json::parse(request.payload, nullptr, false);
    if (args.is_discarded() || !args.is_object()) {
        return adapter_result_t<adapter_response_t>::failure(
            {adapter_error_code_t::invalid_request, "types_query_invalid_payload", 0, 0});
    }
    json output;
    try {
        if (name == "read_struct") {
            output = do_read_struct(args);
        } else if (name == "search_structs") {
            output = do_search_structs(args);
        } else if (name == "type_query") {
            output = do_type_query(args);
        } else if (name == "type_inspect") {
            output = do_type_inspect(args);
        } else if (name == "infer_types") {
            output = do_infer_types(args);
        } else {
            return adapter_result_t<adapter_response_t>::failure(
                {adapter_error_code_t::operation_not_permitted, "types_query_unknown_tool", 0, 0});
        }
    } catch (const std::exception& e) {
        return adapter_result_t<adapter_response_t>::failure(
            {adapter_error_code_t::backend_rejected, "types_query_exception", 0, 0});
    }
    return adapter_result_t<adapter_response_t>::success({output.dump(), false});
}

adapter_result_t<adapter_response_t> types_overlay_store_t::handle_overlay(
    const adapter_call_context_t& context,
    const adapter_request_t& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (context.contract == nullptr) {
        return adapter_result_t<adapter_response_t>::failure(
            {adapter_error_code_t::backend_rejected, "types_overlay_no_contract", 0, 0});
    }
    const std::string name(context.contract->name);
    json args = json::parse(request.payload, nullptr, false);
    if (args.is_discarded() || !args.is_object()) {
        return adapter_result_t<adapter_response_t>::failure(
            {adapter_error_code_t::invalid_request, "types_overlay_invalid_payload", 0, 0});
    }
    json output;
    try {
        if (name == "declare_type") {
            output = do_declare_type(args);
        } else if (name == "enum_upsert") {
            output = do_enum_upsert(args);
        } else if (name == "set_type") {
            output = do_set_type(args);
        } else if (name == "type_apply_batch") {
            output = do_type_apply_batch(args);
        } else {
            return adapter_result_t<adapter_response_t>::failure(
                {adapter_error_code_t::operation_not_permitted, "types_overlay_unknown_tool", 0, 0});
        }
    } catch (const std::exception& e) {
        return adapter_result_t<adapter_response_t>::failure(
            {adapter_error_code_t::backend_rejected, "types_overlay_exception", 0, 0});
    }
    return adapter_result_t<adapter_response_t>::success({output.dump(), false});
}

std::uint64_t types_overlay_store_t::revision() const noexcept {
    return revision_;
}

std::size_t types_overlay_store_t::type_count() const noexcept {
    return types_.size();
}

std::size_t types_overlay_store_t::application_count() const noexcept {
    return applications_.size();
}

bool types_overlay_store_t::has_type(const std::string& name) const noexcept {
    return types_.find(name) != types_.end();
}

bool types_overlay_store_t::has_application(const std::string& addr) const noexcept {
    return applications_.find(addr) != applications_.end();
}

const overlay_type_t* types_overlay_store_t::find_type(const std::string& name) const noexcept {
    const auto it = types_.find(name);
    return it == types_.end() ? nullptr : &it->second;
}

const overlay_type_application_t* types_overlay_store_t::find_application(
    const std::string& addr) const noexcept {
    const auto it = applications_.find(addr);
    return it == applications_.end() ? nullptr : &it->second;
}

std::vector<std::string> types_overlay_store_t::all_type_names() const {
    std::vector<std::string> names;
    names.reserve(types_.size());
    for (const auto& [name, type] : types_) {
        names.push_back(name);
    }
    std::sort(names.begin(), names.end());
    return names;
}

void types_overlay_store_t::set_limits(const types_handler_limits_t& limits) {
    limits_ = limits;
}

void types_overlay_store_t::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    types_.clear();
    applications_.clear();
    undo_stack_.clear();
    revision_ = 0;
    next_ordinal_ = 0;
}

const std::array<std::string_view, k_types_tool_count>& types_tool_names() noexcept {
    return k_types_names;
}

types_handlers_t::types_handlers_t(workspace_adapter_t& workspace,
                                   protocol::schema_runtime_t& schemas,
                                   types_handler_limits_t limits)
    : workspace_(workspace), schemas_(schemas), limits_(std::move(limits)) {
    if (!valid_limits(limits_)) {
        throw std::invalid_argument("types handler limits are invalid or weaken pinned maxima");
    }
    for (std::size_t index = 0; index < k_types_names.size(); ++index) {
        const auto name = k_types_names[index];
        const auto* descriptor =
            aida::standalone::mcp::compat::find_contract(name);
        if (descriptor == nullptr) {
            throw std::runtime_error(
                "generated types descriptor is missing for " + std::string(name));
        }
        validate_generated_descriptor(*descriptor, name);
        contracts_[index] = make_tool_contract(*descriptor);
        const auto validation = protocol::validate_tool_contract(contracts_[index], schemas_);
        if (!validation.valid) {
            throw std::runtime_error(
                "generated types contract validation failed for " + std::string(name) +
                ": " + validation.reason);
        }
    }
}

std::size_t types_handlers_t::size() const noexcept {
    return contracts_.size();
}

const protocol::tool_contract_t& types_handlers_t::contract_at(std::size_t index) const {
    return contracts_.at(index);
}

const protocol::tool_contract_t* types_handlers_t::find(std::string_view name) const noexcept {
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    return found == contracts_.end() ? nullptr : &*found;
}

const types_handler_limits_t& types_handlers_t::limits() const noexcept {
    return limits_;
}

protocol::mcp_result_t types_handlers_t::invoke(
    std::string_view name, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata) const {
    if (!aida_metadata.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::internal_error,
            "Types tool provenance metadata must be a JSON object.",
            protocol::json{{"field", "aida_metadata"}});
    }
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    if (found == contracts_.end()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "Types tool is not registered in the pinned contract group.",
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

protocol::mcp_result_t types_handlers_t::dispatch(
    std::size_t index, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    const auto name = k_types_names.at(index);
    const auto lane = k_types_lanes.at(index);
    const auto& contract = contracts_.at(index);
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Types tool invocation was cancelled before adapter routing.",
            protocol::json{{"phase", "types_pre_route"}});
    }

    std::string serialized_arguments;
    try {
        serialized_arguments = arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Types tool arguments cannot be serialized.",
            protocol::json{{"phase", "types_request_serialization"}});
    }
    if (serialized_arguments.size() > limits_.max_request_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Types tool request exceeds the bounded adapter quota.",
            exceeded_value(
                "request_bytes",
                static_cast<std::uint64_t>(limits_.max_request_bytes),
                static_cast<std::uint64_t>(serialized_arguments.size())));
    }
    if (auto failure = validate_tool_bounds(name, arguments, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Types tool arguments violate the bounded adapter policy.",
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
            "Types backend arguments cannot be serialized.",
            protocol::json{{"phase", "types_backend_serialization"}});
    }
    request.deadline = std::chrono::steady_clock::now() +
        execution_timeout(contract, limits_.max_execution_time);

    auto adapter_result = [&]() -> adapter_result_t<adapter_response_t> {
        switch (lane) {
        case type_lane_t::query:
            return workspace_.query(name, request);
        case type_lane_t::overlay:
            return workspace_.overlay(name, request);
        }
        return adapter_result_t<adapter_response_t>::failure(
            adapter_error_t{adapter_error_code_t::operation_not_permitted,
                            "types_lane_invalid", 0, 0});
    }();
    if (!adapter_result) {
        return adapter_failure(adapter_result.error());
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Types tool invocation was cancelled during adapter execution.",
            protocol::json{{"phase", "types_post_adapter"}});
    }

    auto response = std::move(adapter_result).take_value();
    if (response.payload.empty()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Types adapter response is empty.",
            invalid_value("response_bytes", "nonempty_response_required", 0));
    }
    if (response.payload.size() > limits_.max_response_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Types adapter response violates the output byte quota.",
            exceeded_value(
                "response_bytes",
                static_cast<std::uint64_t>(limits_.max_response_bytes),
                static_cast<std::uint64_t>(response.payload.size())));
    }
    protocol::json structured = protocol::json::parse(response.payload, nullptr, false);
    if (structured.is_discarded() || !structured.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Types adapter returned malformed structured output.",
            protocol::json{{"phase", "types_output_parse"},
                           {"response_bytes", response.payload.size()}});
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Types tool invocation was cancelled before output validation.",
            protocol::json{{"phase", "types_pre_output_validation"}});
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

protocol::mcp_result_t declare_type(const handlers::types_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata) {
    return handlers.invoke("declare_type", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t enum_upsert(const handlers::types_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("enum_upsert", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t read_struct(const handlers::types_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("read_struct", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t search_structs(const handlers::types_handlers_t& handlers,
                                      const protocol::json& arguments,
                                      const protocol::cancellation_token_t& cancellation,
                                      const protocol::json& aida_metadata) {
    return handlers.invoke("search_structs", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t type_query(const handlers::types_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const protocol::json& aida_metadata) {
    return handlers.invoke("type_query", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t type_inspect(const handlers::types_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata) {
    return handlers.invoke("type_inspect", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t set_type(const handlers::types_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const protocol::json& aida_metadata) {
    return handlers.invoke("set_type", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t type_apply_batch(const handlers::types_handlers_t& handlers,
                                        const protocol::json& arguments,
                                        const protocol::cancellation_token_t& cancellation,
                                        const protocol::json& aida_metadata) {
    return handlers.invoke("type_apply_batch", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t infer_types(const handlers::types_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const protocol::json& aida_metadata) {
    return handlers.invoke("infer_types", arguments, cancellation, aida_metadata);
}

}
