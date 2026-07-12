#include "analysis.hpp"

#include "../ida_contracts_generated.hpp"

#include <algorithm>
#include <cmath>
#include <initializer_list>
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

enum class analysis_lane_t : std::uint8_t {
    query,
    analysis,
    decompilation,
};

constexpr std::array<std::string_view, k_analysis_tool_count> k_analysis_names{{
    "decompile",
    "disasm",
    "func_profile",
    "analyze_batch",
    "xrefs_to",
    "xref_query",
    "xrefs_to_field",
    "callees",
    "find_bytes",
    "basic_blocks",
    "find",
    "insn_query",
    "export_funcs",
    "callgraph",
}};

constexpr std::array<analysis_lane_t, k_analysis_tool_count> k_analysis_lanes{{
    analysis_lane_t::decompilation,
    analysis_lane_t::query,
    analysis_lane_t::query,
    analysis_lane_t::analysis,
    analysis_lane_t::query,
    analysis_lane_t::query,
    analysis_lane_t::query,
    analysis_lane_t::query,
    analysis_lane_t::query,
    analysis_lane_t::query,
    analysis_lane_t::query,
    analysis_lane_t::query,
    analysis_lane_t::query,
    analysis_lane_t::query,
}};

using validation_failure_t = std::optional<json>;

json parse_generated_json(std::string_view value, std::string_view field,
                          std::string_view tool_name) {
    try {
        return json::parse(value.begin(), value.end());
    } catch (const std::exception&) {
        throw std::runtime_error(
            "generated analysis contract JSON is invalid for " + std::string(tool_name) +
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
    throw std::runtime_error("generated analysis contract has an unknown effect");
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
    throw std::runtime_error("generated analysis contract has an unknown lock");
}

void validate_generated_descriptor(const contract_descriptor_t& descriptor,
                                   std::string_view name) {
    const std::string expected_adapter =
        "aida::standalone::mcp::compat::adapters::" + std::string(name);
    if (descriptor.name != name || descriptor.adapter_symbol != expected_adapter ||
        !descriptor.archive_backed || !descriptor.target_dependent ||
        !descriptor.accepts_pid || !descriptor.accepts_bin_name || !descriptor.read_only ||
        descriptor.unsafe || descriptor.effect != contract_effect_t::workspace_read ||
        descriptor.lock != contract_lock_t::workspace_shared) {
        throw std::runtime_error(
            "generated analysis descriptor policy mismatch for " + std::string(name));
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

bool valid_limits(const analysis_handler_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 && limits.max_request_bytes <= 1024U * 1024U &&
        limits.max_response_bytes != 0 && limits.max_response_bytes <= 16U * 1024U * 1024U &&
        limits.max_selector_bytes != 0 && limits.max_selector_bytes <= 1024U &&
        limits.max_address_bytes != 0 && limits.max_address_bytes <= 4096U &&
        limits.max_pattern_bytes != 0 && limits.max_pattern_bytes <= 16384U &&
        limits.max_filter_bytes != 0 && limits.max_filter_bytes <= 4096U &&
        limits.max_target_count != 0 && limits.max_target_count <= 256U &&
        limits.max_query_count != 0 && limits.max_query_count <= 256U &&
        limits.max_batch_query_count != 0 &&
        limits.max_batch_query_count <= 128U &&
        limits.max_batch_query_count <= limits.max_query_count &&
        limits.max_offset != 0 && limits.max_offset <= 10000000ULL &&
        limits.max_disasm_instructions != 0 && limits.max_disasm_instructions <= 50000ULL &&
        limits.max_profile_results != 0 && limits.max_profile_results <= 5000ULL &&
        limits.max_profile_list_items != 0 && limits.max_profile_list_items <= 5000ULL &&
        limits.max_batch_blocks != 0 && limits.max_batch_blocks <= 10000ULL &&
        limits.max_batch_relations != 0 && limits.max_batch_relations <= 5000ULL &&
        limits.max_batch_constants != 0 && limits.max_batch_constants <= 5000ULL &&
        limits.max_batch_disasm_instructions != 0 &&
        limits.max_batch_disasm_instructions <= 50000ULL &&
        limits.max_batch_strings != 0 && limits.max_batch_strings <= 5000ULL &&
        limits.max_xrefs_per_target != 0 && limits.max_xrefs_per_target <= 1000ULL &&
        limits.max_xref_query_results != 0 && limits.max_xref_query_results <= 5000ULL &&
        limits.max_callees_per_function != 0 &&
        limits.max_callees_per_function <= 500ULL &&
        limits.max_find_matches != 0 && limits.max_find_matches <= 10000ULL &&
        limits.max_basic_blocks != 0 && limits.max_basic_blocks <= 10000ULL &&
        limits.max_instruction_query_results != 0 &&
        limits.max_instruction_query_results <= 5000ULL &&
        limits.max_instruction_scan != 0 && limits.max_instruction_scan <= 5000000ULL &&
        limits.max_callgraph_depth != 0 && limits.max_callgraph_depth <= 64ULL &&
        limits.max_callgraph_nodes != 0 && limits.max_callgraph_nodes <= 100000ULL &&
        limits.max_callgraph_edges != 0 && limits.max_callgraph_edges <= 200000ULL &&
        limits.max_callgraph_edges_per_function != 0 &&
        limits.max_callgraph_edges_per_function <= 5000ULL &&
        limits.max_execution_time.count() > 0 && limits.max_execution_time.count() <= 120000;
}

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_analysis_adapter"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_analysis_adapter"},
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

validation_failure_t enum_member(const json& object, std::string_view field,
                                 std::string path_prefix,
                                 std::initializer_list<std::string_view> accepted) {
    const auto found = object.find(std::string(field));
    if (found == object.end()) {
        return std::nullopt;
    }
    const std::string path = path_prefix.empty()
        ? std::string(field)
        : path_prefix + "." + std::string(field);
    if (!found->is_string()) {
        return invalid_value(path, "string_required", *found);
    }
    const auto& value = found->get_ref<const std::string&>();
    const bool supported = std::any_of(
        accepted.begin(), accepted.end(),
        [&value](std::string_view candidate) { return candidate == value; });
    if (!supported) {
        return invalid_value(path, "unsupported_value", *found);
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

validation_failure_t validate_routing_bounds(const json& arguments,
                                             const analysis_handler_limits_t& limits) {
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

validation_failure_t validate_address_collection(const json& value, std::string_view path,
                                                 const analysis_handler_limits_t& limits) {
    return scalar_or_array(value, path, limits.max_target_count,
        [&limits](const json& item, std::string item_path) {
            return bounded_text(item, std::move(item_path), limits.max_address_bytes, false);
        });
}

validation_failure_t validate_func_profile(const json& arguments,
                                           const analysis_handler_limits_t& limits) {
    return scalar_or_array(arguments.at("queries"), "queries", limits.max_query_count,
        [&limits](const json& query, std::string path) -> validation_failure_t {
            if (!query.is_object()) {
                return invalid_value(std::move(path), "object_required", query);
            }
            if (auto failure = bounded_member_text(
                    query, "addr", path, limits.max_address_bytes, true)) {
                return failure;
            }
            if (auto failure = bounded_member_text(
                    query, "filter", path, limits.max_filter_bytes, true)) {
                return failure;
            }
            if (auto failure = bounded_integer(
                    query, "count", limits.max_profile_results, path)) {
                return failure;
            }
            if (auto failure = bounded_integer(
                    query, "max_items", limits.max_profile_list_items, path)) {
                return failure;
            }
            if (auto failure = bounded_integer(query, "offset", limits.max_offset, path)) {
                return failure;
            }
            return enum_member(query, "sort_by", path, {"addr", "name", "size"});
        });
}

validation_failure_t validate_analyze_batch(const json& arguments,
                                            const analysis_handler_limits_t& limits) {
    return scalar_or_array(arguments.at("queries"), "queries", limits.max_batch_query_count,
        [&limits](const json& query, std::string path) -> validation_failure_t {
            if (!query.is_object()) {
                return invalid_value(std::move(path), "object_required", query);
            }
            if (auto failure = bounded_member_text(
                    query, "addr", path, limits.max_address_bytes, false)) {
                return failure;
            }
            const std::pair<std::string_view, std::uint64_t> fields[] = {
                {"max_blocks", limits.max_batch_blocks},
                {"max_callees", limits.max_batch_relations},
                {"max_callers", limits.max_batch_relations},
                {"max_constants", limits.max_batch_constants},
                {"max_disasm_insns", limits.max_batch_disasm_instructions},
                {"max_strings", limits.max_batch_strings},
            };
            for (const auto& field : fields) {
                if (auto failure = bounded_integer(query, field.first, field.second, path)) {
                    return failure;
                }
            }
            return std::nullopt;
        });
}

validation_failure_t validate_xref_query(const json& arguments,
                                         const analysis_handler_limits_t& limits) {
    return scalar_or_array(arguments.at("queries"), "queries", limits.max_query_count,
        [&limits](const json& query, std::string path) -> validation_failure_t {
            if (!query.is_object()) {
                return invalid_value(std::move(path), "object_required", query);
            }
            if (auto failure = bounded_member_text(
                    query, "addr", path, limits.max_address_bytes, false)) {
                return failure;
            }
            if (auto failure = bounded_integer(
                    query, "count", limits.max_xref_query_results, path)) {
                return failure;
            }
            if (auto failure = bounded_integer(query, "offset", limits.max_offset, path)) {
                return failure;
            }
            if (auto failure = enum_member(
                    query, "direction", path, {"to", "from", "both"})) {
                return failure;
            }
            if (auto failure = enum_member(
                    query, "xref_type", path, {"any", "code", "data"})) {
                return failure;
            }
            return enum_member(query, "sort_by", path, {"addr", "type"});
        });
}

validation_failure_t validate_field_queries(const json& arguments,
                                            const analysis_handler_limits_t& limits) {
    return scalar_or_array(arguments.at("queries"), "queries", limits.max_query_count,
        [&limits](const json& query, std::string path) -> validation_failure_t {
            if (!query.is_object()) {
                return invalid_value(std::move(path), "object_required", query);
            }
            if (auto failure = bounded_member_text(
                    query, "struct", path, limits.max_address_bytes, false)) {
                return failure;
            }
            return bounded_member_text(
                query, "field", path, limits.max_address_bytes, false);
        });
}

validation_failure_t validate_find_targets(const json& value,
                                           const analysis_handler_limits_t& limits) {
    return scalar_or_array(value, "targets", limits.max_target_count,
        [&limits](const json& item, std::string path) -> validation_failure_t {
            if (item.is_string()) {
                return bounded_text(item, std::move(path), limits.max_pattern_bytes, false);
            }
            if (!item.is_number_integer() && !item.is_number_unsigned()) {
                return invalid_value(std::move(path), "string_or_integer_required", item);
            }
            return std::nullopt;
        });
}

validation_failure_t validate_instruction_queries(const json& arguments,
                                                  const analysis_handler_limits_t& limits) {
    return scalar_or_array(arguments.at("queries"), "queries", limits.max_query_count,
        [&limits](const json& query, std::string path) -> validation_failure_t {
            if (!query.is_object()) {
                return invalid_value(std::move(path), "object_required", query);
            }
            for (const char* field : {"start", "end", "func"}) {
                if (auto failure = bounded_member_text(
                        query, field, path, limits.max_address_bytes, false)) {
                    return failure;
                }
            }
            for (const char* field : {"segment", "mnem"}) {
                if (auto failure = bounded_member_text(
                        query, field, path, limits.max_filter_bytes, true)) {
                    return failure;
                }
            }
            if (auto failure = bounded_integer(
                    query, "count", limits.max_instruction_query_results, path)) {
                return failure;
            }
            if (auto failure = bounded_integer(
                    query, "max_scan_insns", limits.max_instruction_scan, path)) {
                return failure;
            }
            return bounded_integer(query, "offset", limits.max_offset, path);
        });
}

validation_failure_t validate_tool_bounds(std::string_view name, const json& arguments,
                                          const analysis_handler_limits_t& limits) {
    if (auto failure = validate_routing_bounds(arguments, limits)) {
        return failure;
    }
    if (name == "decompile") {
        return bounded_member_text(arguments, "addr", {}, limits.max_address_bytes, false);
    }
    if (name == "disasm") {
        if (auto failure = bounded_member_text(
                arguments, "addr", {}, limits.max_address_bytes, false)) {
            return failure;
        }
        if (auto failure = bounded_integer(
                arguments, "max_instructions", limits.max_disasm_instructions)) {
            return failure;
        }
        return bounded_integer(arguments, "offset", limits.max_offset);
    }
    if (name == "func_profile") {
        return validate_func_profile(arguments, limits);
    }
    if (name == "analyze_batch") {
        return validate_analyze_batch(arguments, limits);
    }
    if (name == "xrefs_to") {
        if (auto failure = validate_address_collection(arguments.at("addrs"), "addrs", limits)) {
            return failure;
        }
        return bounded_integer(arguments, "limit", limits.max_xrefs_per_target);
    }
    if (name == "xref_query") {
        return validate_xref_query(arguments, limits);
    }
    if (name == "xrefs_to_field") {
        return validate_field_queries(arguments, limits);
    }
    if (name == "callees") {
        if (auto failure = validate_address_collection(arguments.at("addrs"), "addrs", limits)) {
            return failure;
        }
        return bounded_integer(arguments, "limit", limits.max_callees_per_function);
    }
    if (name == "find_bytes") {
        if (auto failure = scalar_or_array(
                arguments.at("patterns"), "patterns", limits.max_target_count,
                [&limits](const json& item, std::string path) {
                    return bounded_text(
                        item, std::move(path), limits.max_pattern_bytes, false);
                })) {
            return failure;
        }
        if (auto failure = bounded_integer(arguments, "limit", limits.max_find_matches)) {
            return failure;
        }
        return bounded_integer(arguments, "offset", limits.max_offset);
    }
    if (name == "basic_blocks") {
        if (auto failure = validate_address_collection(arguments.at("addrs"), "addrs", limits)) {
            return failure;
        }
        if (auto failure = bounded_integer(
                arguments, "max_blocks", limits.max_basic_blocks)) {
            return failure;
        }
        return bounded_integer(arguments, "offset", limits.max_offset);
    }
    if (name == "find") {
        if (auto failure = validate_find_targets(arguments.at("targets"), limits)) {
            return failure;
        }
        if (auto failure = enum_member(
                arguments, "type", {}, {"string", "immediate", "data_ref", "code_ref"})) {
            return failure;
        }
        if (auto failure = bounded_integer(arguments, "limit", limits.max_find_matches)) {
            return failure;
        }
        return bounded_integer(arguments, "offset", limits.max_offset);
    }
    if (name == "insn_query") {
        return validate_instruction_queries(arguments, limits);
    }
    if (name == "export_funcs") {
        if (auto failure = validate_address_collection(arguments.at("addrs"), "addrs", limits)) {
            return failure;
        }
        return enum_member(arguments, "format", {}, {"json", "c_header", "prototypes"});
    }
    if (name == "callgraph") {
        if (auto failure = validate_address_collection(arguments.at("roots"), "roots", limits)) {
            return failure;
        }
        const std::pair<std::string_view, std::uint64_t> fields[] = {
            {"max_depth", limits.max_callgraph_depth},
            {"max_nodes", limits.max_callgraph_nodes},
            {"max_edges", limits.max_callgraph_edges},
            {"max_edges_per_func", limits.max_callgraph_edges_per_function},
        };
        for (const auto& field : fields) {
            if (auto failure = bounded_integer(arguments, field.first, field.second)) {
                return failure;
            }
        }
        return std::nullopt;
    }
    return invalid_value("tool", "analysis_tool_not_registered", std::string(name));
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
        "Analysis workspace adapter rejected the request.",
        json{
            {"phase", "workspace_adapter"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

}

const std::array<std::string_view, k_analysis_tool_count>& analysis_tool_names() noexcept {
    return k_analysis_names;
}

analysis_handlers_t::analysis_handlers_t(workspace_adapter_t& workspace,
                                         protocol::schema_runtime_t& schemas,
                                         analysis_handler_limits_t limits)
    : workspace_(workspace), schemas_(schemas), limits_(std::move(limits)) {
    if (!valid_limits(limits_)) {
        throw std::invalid_argument("analysis handler limits are invalid or weaken pinned maxima");
    }
    for (std::size_t index = 0; index < k_analysis_names.size(); ++index) {
        const auto name = k_analysis_names[index];
        const auto* descriptor =
            aida::standalone::mcp::compat::find_contract(name);
        if (descriptor == nullptr) {
            throw std::runtime_error(
                "generated analysis descriptor is missing for " + std::string(name));
        }
        validate_generated_descriptor(*descriptor, name);
        contracts_[index] = make_tool_contract(*descriptor);
        const auto validation = protocol::validate_tool_contract(contracts_[index], schemas_);
        if (!validation.valid) {
            throw std::runtime_error(
                "generated analysis contract validation failed for " + std::string(name) +
                ": " + validation.reason);
        }
    }
}

std::size_t analysis_handlers_t::size() const noexcept {
    return contracts_.size();
}

const protocol::tool_contract_t& analysis_handlers_t::contract_at(std::size_t index) const {
    return contracts_.at(index);
}

const protocol::tool_contract_t* analysis_handlers_t::find(std::string_view name) const noexcept {
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    return found == contracts_.end() ? nullptr : &*found;
}

const analysis_handler_limits_t& analysis_handlers_t::limits() const noexcept {
    return limits_;
}

protocol::mcp_result_t analysis_handlers_t::invoke(
    std::string_view name, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata) const {
    if (!aida_metadata.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::internal_error,
            "Analysis tool provenance metadata must be a JSON object.",
            protocol::json{{"field", "aida_metadata"}});
    }
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    if (found == contracts_.end()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "Analysis tool is not registered in the pinned contract group.",
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

protocol::mcp_result_t analysis_handlers_t::dispatch(
    std::size_t index, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    const auto name = k_analysis_names.at(index);
    const auto lane = k_analysis_lanes.at(index);
    const auto& contract = contracts_.at(index);
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Analysis tool invocation was cancelled before adapter routing.",
            protocol::json{{"phase", "analysis_pre_route"}});
    }

    std::string serialized_arguments;
    try {
        serialized_arguments = arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Analysis tool arguments cannot be serialized.",
            protocol::json{{"phase", "analysis_request_serialization"}});
    }
    if (serialized_arguments.size() > limits_.max_request_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Analysis tool request exceeds the bounded adapter quota.",
            exceeded_value(
                "request_bytes",
                static_cast<std::uint64_t>(limits_.max_request_bytes),
                static_cast<std::uint64_t>(serialized_arguments.size())));
    }
    if (auto failure = validate_tool_bounds(name, arguments, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Analysis tool arguments violate the bounded adapter policy.",
            *failure);
    }

    adapter_request_t request;
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        request.target.pid = static_cast<std::uint32_t>(*unsigned_integer(*pid));
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
            "Analysis backend arguments cannot be serialized.",
            protocol::json{{"phase", "analysis_backend_serialization"}});
    }
    request.deadline = std::chrono::steady_clock::now() +
        execution_timeout(contract, limits_.max_execution_time);

    auto adapter_result = [&]() -> adapter_result_t<adapter_response_t> {
        switch (lane) {
        case analysis_lane_t::query:
            return workspace_.query(name, request);
        case analysis_lane_t::analysis:
            return workspace_.analyze(name, request);
        case analysis_lane_t::decompilation:
            return workspace_.decompile(name, request);
        }
        return adapter_result_t<adapter_response_t>::failure(
            adapter_error_t{adapter_error_code_t::operation_not_permitted,
                            "analysis_lane_invalid", 0, 0});
    }();
    if (!adapter_result) {
        return adapter_failure(adapter_result.error());
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Analysis tool invocation was cancelled during adapter execution.",
            protocol::json{{"phase", "analysis_post_adapter"}});
    }

    auto response = std::move(adapter_result).take_value();
    if (response.payload.empty()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Analysis adapter response is empty.",
            invalid_value("response_bytes", "nonempty_response_required", 0));
    }
    if (response.payload.size() > limits_.max_response_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Analysis adapter response violates the output byte quota.",
            exceeded_value(
                "response_bytes",
                static_cast<std::uint64_t>(limits_.max_response_bytes),
                static_cast<std::uint64_t>(response.payload.size())));
    }
    protocol::json structured = protocol::json::parse(response.payload, nullptr, false);
    if (structured.is_discarded() || !structured.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Analysis adapter returned malformed structured output.",
            protocol::json{{"phase", "analysis_output_parse"},
                           {"response_bytes", response.payload.size()}});
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Analysis tool invocation was cancelled before output validation.",
            protocol::json{{"phase", "analysis_pre_output_validation"}});
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

protocol::mcp_result_t decompile(const handlers::analysis_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const protocol::json& aida_metadata) {
    return handlers.invoke("decompile", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t disasm(const handlers::analysis_handlers_t& handlers,
                              const protocol::json& arguments,
                              const protocol::cancellation_token_t& cancellation,
                              const protocol::json& aida_metadata) {
    return handlers.invoke("disasm", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t func_profile(const handlers::analysis_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata) {
    return handlers.invoke("func_profile", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t analyze_batch(const handlers::analysis_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const protocol::json& aida_metadata) {
    return handlers.invoke("analyze_batch", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t xrefs_to(const handlers::analysis_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const protocol::json& aida_metadata) {
    return handlers.invoke("xrefs_to", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t xref_query(const handlers::analysis_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const protocol::json& aida_metadata) {
    return handlers.invoke("xref_query", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t xrefs_to_field(const handlers::analysis_handlers_t& handlers,
                                      const protocol::json& arguments,
                                      const protocol::cancellation_token_t& cancellation,
                                      const protocol::json& aida_metadata) {
    return handlers.invoke("xrefs_to_field", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t callees(const handlers::analysis_handlers_t& handlers,
                               const protocol::json& arguments,
                               const protocol::cancellation_token_t& cancellation,
                               const protocol::json& aida_metadata) {
    return handlers.invoke("callees", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t find_bytes(const handlers::analysis_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const protocol::json& aida_metadata) {
    return handlers.invoke("find_bytes", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t basic_blocks(const handlers::analysis_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata) {
    return handlers.invoke("basic_blocks", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t find(const handlers::analysis_handlers_t& handlers,
                            const protocol::json& arguments,
                            const protocol::cancellation_token_t& cancellation,
                            const protocol::json& aida_metadata) {
    return handlers.invoke("find", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t insn_query(const handlers::analysis_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const protocol::json& aida_metadata) {
    return handlers.invoke("insn_query", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t export_funcs(const handlers::analysis_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata) {
    return handlers.invoke("export_funcs", arguments, cancellation, aida_metadata);
}

protocol::mcp_result_t callgraph(const handlers::analysis_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const protocol::json& aida_metadata) {
    return handlers.invoke("callgraph", arguments, cancellation, aida_metadata);
}

}
