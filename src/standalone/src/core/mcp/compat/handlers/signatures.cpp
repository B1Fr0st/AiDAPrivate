#include "signatures.h"

#include "../ida_contracts_generated.hpp"

#include <algorithm>
#include <cstdio>
#include <functional>
#include <initializer_list>
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

constexpr std::array<std::string_view, 4> k_signature_names{{
    "make_signature",
    "make_signature_for_function",
    "make_signature_for_range",
    "find_xref_signatures",
}};

using validation_failure_t = std::optional<json>;

json parse_generated_json(std::string_view value, std::string_view field,
                          std::string_view tool_name) {
    try {
        return json::parse(value.begin(), value.end());
    } catch (const std::exception&) {
        throw std::runtime_error(
            "generated signature contract JSON is invalid for " + std::string(tool_name) +
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
    throw std::runtime_error("generated signature contract has an unknown effect");
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
    throw std::runtime_error("generated signature contract has an unknown lock");
}

void validate_generated_descriptor(const contract_descriptor_t& descriptor,
                                   std::string_view name) {
    const std::string expected_adapter =
        "aida::standalone::mcp::compat::adapters::" + std::string(name);
    if (descriptor.name != name || descriptor.adapter_symbol != expected_adapter ||
        !descriptor.archive_backed || !descriptor.target_dependent ||
        !descriptor.accepts_pid || !descriptor.accepts_bin_name || !descriptor.read_only ||
        descriptor.unsafe ||
        descriptor.effect != contract_effect_t::workspace_read ||
        descriptor.lock != contract_lock_t::workspace_shared) {
        throw std::runtime_error(
            "generated signature descriptor policy mismatch for " + std::string(name));
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

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_signature_adapter"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_signature_adapter"},
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

validation_failure_t bounded_integer_field(const json& object, std::string_view field,
                                           std::uint64_t maximum,
                                           std::string path_prefix = {}) {
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

validation_failure_t validate_routing_bounds(const json& arguments) {
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        const auto value = unsigned_integer(*pid);
        if (!value || *value == 0 || *value > (std::numeric_limits<std::uint32_t>::max)()) {
            return invalid_value("pid", "valid_process_id_required", *pid);
        }
    }
    if (const auto bin_name = arguments.find("bin_name"); bin_name != arguments.end()) {
        if (auto failure = bounded_text(*bin_name, "bin_name", 1024U, false)) {
            return failure;
        }
    }
    return std::nullopt;
}

validation_failure_t validate_addrs(const json& arguments,
                                    const signature_limits_t& limits) {
    const auto addrs = arguments.find("addrs");
    if (addrs == arguments.end()) {
        return invalid_value("addrs", "required_field_missing", json(nullptr));
    }
    std::size_t total_bytes = 0;
    auto addr_validator = [&limits, &total_bytes](const json& item,
                                                   std::string path) -> validation_failure_t {
        if (auto failure = bounded_text(item, path, limits.maximum_query_bytes, false)) {
            return failure;
        }
        total_bytes += item.get_ref<const std::string&>().size();
        if (total_bytes > limits.maximum_query_bytes * limits.maximum_queries) {
            return exceeded_value("addrs", limits.maximum_query_bytes, total_bytes);
        }
        return std::nullopt;
    };
    auto failure = scalar_or_array(*addrs, "addrs", limits.maximum_queries, addr_validator);
    if (failure) return failure;
    return std::nullopt;
}

validation_failure_t validate_format(const json& arguments) {
    return enum_member(arguments, "format", "", {"ida", "x64dbg", "mask", "bitmask"});
}

validation_failure_t validate_max_length(const json& arguments,
                                         const signature_limits_t& limits) {
    return bounded_integer_field(arguments, "max_length",
                                 static_cast<std::uint64_t>(limits.maximum_signature_bytes));
}

validation_failure_t validate_top(const json& arguments,
                                  const signature_limits_t& limits) {
    return bounded_integer_field(arguments, "top",
                                 static_cast<std::uint64_t>(limits.maximum_top));
}

validation_failure_t validate_wildcard_operands(const json& arguments) {
    const auto found = arguments.find("wildcard_operands");
    if (found == arguments.end()) return std::nullopt;
    if (!found->is_boolean()) {
        return invalid_value("wildcard_operands", "boolean_required", *found);
    }
    return std::nullopt;
}

validation_failure_t validate_range_bounds(const json& arguments,
                                           const signature_limits_t& limits) {
    const auto start = arguments.find("start");
    if (start == arguments.end()) {
        return invalid_value("start", "required_field_missing", json(nullptr));
    }
    if (auto failure = bounded_text(*start, "start", limits.maximum_query_bytes, false)) {
        return failure;
    }
    const auto end = arguments.find("end");
    if (end == arguments.end()) {
        return invalid_value("end", "required_field_missing", json(nullptr));
    }
    if (auto failure = bounded_text(*end, "end", limits.maximum_query_bytes, false)) {
        return failure;
    }
    return std::nullopt;
}

std::string format_address(std::uint64_t addr) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX",
                  static_cast<unsigned long long>(addr));
    return std::string(buf);
}

std::uint8_t normalize_mask_byte(std::uint8_t mask) noexcept {
    return mask == 0xFF ? 0xFF : 0x00;
}

std::string format_signature(const std::vector<std::uint8_t>& bytes,
                             const std::vector<std::uint8_t>& mask,
                             std::string_view format) {
    if (bytes.empty()) return {};

    std::string result;

    if (format == "mask") {
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            result += (i < mask.size() && mask[i] == 0xFF) ? 'x' : '?';
        }
        return result;
    }

    if (format == "bitmask") {
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            result += (i < mask.size() && mask[i] == 0xFF) ? '1' : '0';
        }
        return result;
    }

    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) result += ' ';
        if (i < mask.size() && mask[i] == 0xFF) {
            char hex[4];
            std::snprintf(hex, sizeof(hex), "%02X", bytes[i]);
            result += hex;
        } else {
            result += "??";
        }
    }
    return result;
}

struct generation_result_t {
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> mask;
    bool unique = false;
    std::string error;
};

void append_instruction_bytes(generation_result_t& result,
                              const signature_instruction_t& insn,
                              std::size_t count, bool wildcard_operands) {
    for (std::size_t i = 0; i < count && i < insn.bytes.size(); ++i) {
        result.bytes.push_back(insn.bytes[i]);
        if (wildcard_operands) {
            result.mask.push_back(normalize_mask_byte(
                i < insn.stable_mask.size() ? insn.stable_mask[i] : 0x00));
        } else {
            result.mask.push_back(0xFF);
        }
    }
}

generation_result_t generate_signature_at(
    const signature_source_t& source,
    std::uint64_t address,
    std::size_t max_length,
    std::size_t maximum_instruction_bytes,
    bool wildcard_operands,
    const protocol::cancellation_token_t& cancellation) {

    generation_result_t result;
    std::uint64_t current = address;

    while (result.bytes.size() < max_length) {
        if (cancellation.cancelled()) {
            result.error = "cancelled";
            return result;
        }

        auto insn = source.instruction_at(current);
        if (!insn) {
            if (result.bytes.empty()) {
                result.error = "no_instruction_at_address";
            }
            break;
        }
        if (insn->bytes.empty() || insn->bytes.size() > maximum_instruction_bytes) {
            result.error = "instruction_size_out_of_bounds";
            break;
        }

        std::size_t remaining = max_length - result.bytes.size();
        std::size_t to_copy = (std::min)(insn->bytes.size(), remaining);
        append_instruction_bytes(result, *insn, to_copy, wildcard_operands);

        if (to_copy < insn->bytes.size()) {
            break;
        }

        auto match = source.find_matches(result.bytes, result.mask, 2, cancellation);
        if (!match.exhausted && match.error.empty() &&
            match.addresses.size() == 1 && match.addresses[0] == address) {
            result.unique = true;
            break;
        }

        current = insn->address + insn->bytes.size();
    }

    return result;
}

std::string get_format(const json& arguments) {
    const auto found = arguments.find("format");
    if (found != arguments.end() && found->is_string()) {
        return found->get<std::string>();
    }
    return "ida";
}

std::size_t get_max_length(const json& arguments, std::size_t default_value) {
    const auto found = arguments.find("max_length");
    if (found != arguments.end()) {
        auto value = unsigned_integer(*found);
        if (value && *value > 0) {
            return static_cast<std::size_t>(*value);
        }
    }
    return default_value;
}

bool get_wildcard_operands(const json& arguments) {
    const auto found = arguments.find("wildcard_operands");
    if (found != arguments.end() && found->is_boolean()) {
        return found->get<bool>();
    }
    return true;
}

std::size_t get_top(const json& arguments, std::size_t default_value) {
    const auto found = arguments.find("top");
    if (found != arguments.end()) {
        auto value = unsigned_integer(*found);
        if (value && *value > 0) {
            return static_cast<std::size_t>(*value);
        }
    }
    return default_value;
}

}

bool signature_limits_t::valid() const noexcept {
    return maximum_queries != 0 && maximum_queries <= 128 &&
           maximum_query_bytes != 0 && maximum_query_bytes <= 1024 &&
           maximum_signature_bytes != 0 && maximum_signature_bytes <= 4096 &&
           maximum_range_bytes != 0 && maximum_range_bytes <= 4096 &&
           maximum_xrefs_per_query != 0 && maximum_xrefs_per_query <= 4096 &&
           maximum_top != 0 && maximum_top <= 64 &&
           maximum_instruction_bytes != 0 && maximum_instruction_bytes <= 64;
}

bool is_signature_tool_name(std::string_view name) noexcept {
    return std::find(k_signature_names.begin(), k_signature_names.end(), name) !=
           k_signature_names.end();
}

protocol::tool_contract_t signature_tool_contract(std::string_view name) {
    if (!is_signature_tool_name(name)) {
        throw std::runtime_error("not a signature tool: " + std::string(name));
    }
    const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
    if (descriptor == nullptr) {
        throw std::runtime_error(
            "generated signature descriptor is missing for " + std::string(name));
    }
    validate_generated_descriptor(*descriptor, name);
    return make_tool_contract(*descriptor);
}

}

namespace aida::standalone::mcp::compat::adapters {

using namespace aida::standalone::mcp::compat::handlers;
using protocol::json;
using protocol::mcp_result_t;
using protocol::result_error_code_t;
using protocol::cancellation_token_t;

namespace {

mcp_result_t context_error(const char* field) {
    return mcp_result_t::failure(
        result_error_code_t::internal_error,
        "Signature handler context is not available.",
        protocol::json{{"field", field}});
}

}

mcp_result_t make_signature(
    const handlers::signature_handler_context_t& context,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) {

    if (context.source == nullptr) return context_error("source");
    if (context.schemas == nullptr) return context_error("schemas");

    const auto& limits = context.limits;
    const auto* source = context.source;

    auto contract = signature_tool_contract("make_signature");
    return protocol::invoke_tool_contract(
        contract, arguments,
        [source, &limits, &cancellation](const json& args,
                                          const cancellation_token_t& token) -> mcp_result_t {
            if (token.cancelled()) {
                return mcp_result_t::failure(
                    result_error_code_t::cancelled,
                    "Signature tool was cancelled before processing.",
                    json{{"phase", "make_signature_pre_process"}});
            }
            if (auto failure = validate_routing_bounds(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature routing arguments violate the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_addrs(args, limits)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature addrs violate the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_format(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature format is not supported.",
                    *failure);
            }
            if (auto failure = validate_max_length(args, limits)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature max_length violates the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_wildcard_operands(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature wildcard_operands is invalid.",
                    *failure);
            }

            const std::string format = get_format(args);
            const std::size_t max_length = get_max_length(args, 1000);
            const bool wildcard_operands = get_wildcard_operands(args);

            const auto& addrs = args.at("addrs");
            std::vector<json> queries;
            if (addrs.is_array()) {
                for (const auto& a : addrs) queries.push_back(a);
            } else {
                queries.push_back(addrs);
            }

            json result_array = json::array();
            std::size_t source_queries = 0;

            for (const auto& query : queries) {
                const std::string query_str = query.get<std::string>();
                json item;
                item["query"] = query_str;

                auto resolved = source->resolve_address(query_str);
                ++source_queries;

                if (!resolved) {
                    item["addr"] = nullptr;
                    item["signature"] = nullptr;
                    item["format"] = format;
                    item["error"] = "address_not_resolved";
                    result_array.push_back(std::move(item));
                    continue;
                }

                item["addr"] = format_address(*resolved);

                if (token.cancelled()) {
                    return mcp_result_t::failure(
                        result_error_code_t::cancelled,
                        "Signature tool was cancelled during address processing.",
                        json{{"phase", "make_signature_process"}});
                }

                auto gen = generate_signature_at(
                    *source, *resolved, max_length, limits.maximum_instruction_bytes,
                    wildcard_operands, token);
                ++source_queries;

                if (gen.error == "cancelled") {
                    return mcp_result_t::failure(
                        result_error_code_t::cancelled,
                        "Signature generation was cancelled.",
                        json{{"phase", "make_signature_generate"}});
                }

                if (gen.bytes.empty()) {
                    item["signature"] = nullptr;
                    item["format"] = format;
                    if (!gen.error.empty()) {
                        item["error"] = gen.error;
                    } else {
                        item["error"] = "no_bytes_generated";
                    }
                } else {
                    item["signature"] = format_signature(gen.bytes, gen.mask, format);
                    item["format"] = format;
                    item["unique"] = gen.unique;
                    if (!gen.error.empty()) {
                        item["error"] = gen.error;
                    }
                }

                result_array.push_back(std::move(item));
            }

            json structured{{"result", std::move(result_array)}};
            return mcp_result_t::success(
                structured.dump(),
                structured,
                json{
                    {"source_queries", source_queries},
                    {"signature_count", structured["result"].size()},
                });
        },
        *context.schemas, cancellation, context.aida_metadata);
}

mcp_result_t make_signature_for_function(
    const handlers::signature_handler_context_t& context,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) {

    if (context.source == nullptr) return context_error("source");
    if (context.schemas == nullptr) return context_error("schemas");

    const auto& limits = context.limits;
    const auto* source = context.source;

    auto contract = signature_tool_contract("make_signature_for_function");
    return protocol::invoke_tool_contract(
        contract, arguments,
        [source, &limits, &cancellation](const json& args,
                                          const cancellation_token_t& token) -> mcp_result_t {
            if (token.cancelled()) {
                return mcp_result_t::failure(
                    result_error_code_t::cancelled,
                    "Signature tool was cancelled before processing.",
                    json{{"phase", "make_sig_func_pre_process"}});
            }
            if (auto failure = validate_routing_bounds(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature routing arguments violate the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_addrs(args, limits)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature addrs violate the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_format(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature format is not supported.",
                    *failure);
            }
            if (auto failure = validate_max_length(args, limits)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature max_length violates the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_wildcard_operands(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature wildcard_operands is invalid.",
                    *failure);
            }

            const std::string format = get_format(args);
            const std::size_t max_length = get_max_length(args, 1000);
            const bool wildcard_operands = get_wildcard_operands(args);

            const auto& addrs = args.at("addrs");
            std::vector<json> queries;
            if (addrs.is_array()) {
                for (const auto& a : addrs) queries.push_back(a);
            } else {
                queries.push_back(addrs);
            }

            json result_array = json::array();
            std::size_t source_queries = 0;

            for (const auto& query : queries) {
                const std::string query_str = query.get<std::string>();
                json item;
                item["query"] = query_str;

                auto resolved = source->resolve_address(query_str);
                ++source_queries;

                if (!resolved) {
                    item["addr"] = nullptr;
                    item["name"] = nullptr;
                    item["signature"] = nullptr;
                    item["format"] = format;
                    item["error"] = "address_not_resolved";
                    result_array.push_back(std::move(item));
                    continue;
                }

                auto func = source->function_containing(*resolved);
                ++source_queries;

                if (!func) {
                    item["addr"] = format_address(*resolved);
                    item["name"] = nullptr;
                    item["signature"] = nullptr;
                    item["format"] = format;
                    item["error"] = "no_function_at_address";
                    result_array.push_back(std::move(item));
                    continue;
                }

                item["addr"] = format_address(func->start);
                item["name"] = func->name;

                if (token.cancelled()) {
                    return mcp_result_t::failure(
                        result_error_code_t::cancelled,
                        "Signature tool was cancelled during function processing.",
                        json{{"phase", "make_sig_func_process"}});
                }

                auto gen = generate_signature_at(
                    *source, func->start, max_length, limits.maximum_instruction_bytes,
                    wildcard_operands, token);
                ++source_queries;

                if (gen.error == "cancelled") {
                    return mcp_result_t::failure(
                        result_error_code_t::cancelled,
                        "Signature generation was cancelled.",
                        json{{"phase", "make_sig_func_generate"}});
                }

                if (gen.bytes.empty()) {
                    item["signature"] = nullptr;
                    item["format"] = format;
                    if (!gen.error.empty()) {
                        item["error"] = gen.error;
                    } else {
                        item["error"] = "no_bytes_generated";
                    }
                } else {
                    item["signature"] = format_signature(gen.bytes, gen.mask, format);
                    item["format"] = format;
                    if (!gen.error.empty()) {
                        item["error"] = gen.error;
                    }
                }

                result_array.push_back(std::move(item));
            }

            json structured{{"result", std::move(result_array)}};
            return mcp_result_t::success(
                structured.dump(),
                structured,
                json{
                    {"source_queries", source_queries},
                    {"signature_count", structured["result"].size()},
                });
        },
        *context.schemas, cancellation, context.aida_metadata);
}

mcp_result_t make_signature_for_range(
    const handlers::signature_handler_context_t& context,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) {

    if (context.source == nullptr) return context_error("source");
    if (context.schemas == nullptr) return context_error("schemas");

    const auto& limits = context.limits;
    const auto* source = context.source;

    auto contract = signature_tool_contract("make_signature_for_range");
    return protocol::invoke_tool_contract(
        contract, arguments,
        [source, &limits, &cancellation](const json& args,
                                          const cancellation_token_t& token) -> mcp_result_t {
            if (token.cancelled()) {
                return mcp_result_t::failure(
                    result_error_code_t::cancelled,
                    "Signature tool was cancelled before processing.",
                    json{{"phase", "make_sig_range_pre_process"}});
            }
            if (auto failure = validate_routing_bounds(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature routing arguments violate the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_range_bounds(args, limits)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature range arguments violate the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_format(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature format is not supported.",
                    *failure);
            }
            if (auto failure = validate_wildcard_operands(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature wildcard_operands is invalid.",
                    *failure);
            }

            const std::string format = get_format(args);
            const bool wildcard_operands = get_wildcard_operands(args);
            const std::string start_str = args.at("start").get<std::string>();
            const std::string end_str = args.at("end").get<std::string>();
            const std::string query_str = start_str + ":" + end_str;

            json result;
            result["query"] = query_str;

            auto start_resolved = source->resolve_address(start_str);
            auto end_resolved = source->resolve_address(end_str);

            if (!start_resolved) {
                result["addr"] = nullptr;
                result["signature"] = nullptr;
                result["format"] = format;
                result["error"] = "start_address_not_resolved";
                return mcp_result_t::success(
                    result.dump(), result,
                    json{{"source_queries", 2}});
            }

            if (!end_resolved) {
                result["addr"] = format_address(*start_resolved);
                result["signature"] = nullptr;
                result["format"] = format;
                result["error"] = "end_address_not_resolved";
                return mcp_result_t::success(
                    result.dump(), result,
                    json{{"source_queries", 2}});
            }

            if (*end_resolved <= *start_resolved) {
                result["addr"] = format_address(*start_resolved);
                result["signature"] = nullptr;
                result["format"] = format;
                result["error"] = "end_must_be_greater_than_start";
                return mcp_result_t::success(
                    result.dump(), result,
                    json{{"source_queries", 2}});
            }

            std::size_t range_size = static_cast<std::size_t>(*end_resolved - *start_resolved);
            if (range_size > limits.maximum_range_bytes) {
                result["addr"] = format_address(*start_resolved);
                result["signature"] = nullptr;
                result["format"] = format;
                result["error"] = "range_exceeds_maximum";
                return mcp_result_t::success(
                    result.dump(), result,
                    json{{"source_queries", 2},
                         {"range_bytes", range_size}});
            }

            if (token.cancelled()) {
                return mcp_result_t::failure(
                    result_error_code_t::cancelled,
                    "Signature tool was cancelled during range processing.",
                    json{{"phase", "make_sig_range_process"}});
            }

            std::vector<std::uint8_t> range_bytes;
            if (!source->read_bytes(*start_resolved, range_size, range_bytes)) {
                result["addr"] = format_address(*start_resolved);
                result["signature"] = nullptr;
                result["format"] = format;
                result["error"] = "failed_to_read_range_bytes";
                return mcp_result_t::success(
                    result.dump(), result,
                    json{{"source_queries", 3}});
            }

            std::vector<std::uint8_t> range_mask(range_bytes.size(), 0xFF);
            if (wildcard_operands) {
                std::uint64_t current = *start_resolved;
                while (current < *end_resolved) {
                    auto insn = source->instruction_at(current);
                    if (!insn) {
                        ++current;
                        continue;
                    }
                    if (insn->bytes.empty() ||
                        insn->bytes.size() > limits.maximum_instruction_bytes) {
                        result["addr"] = format_address(*start_resolved);
                        result["signature"] = nullptr;
                        result["format"] = format;
                        result["error"] = "instruction_size_out_of_bounds";
                        return mcp_result_t::success(
                            result.dump(), result,
                            json{{"source_queries", 3},
                                 {"range_bytes", range_size}});
                    }
                    for (std::size_t i = 0;
                         i < insn->bytes.size() && current < *end_resolved; ++i) {
                        std::size_t offset = static_cast<std::size_t>(current - *start_resolved);
                        range_mask[offset] = (i < insn->stable_mask.size())
                            ? normalize_mask_byte(insn->stable_mask[i])
                            : 0xFF;
                        ++current;
                    }
                }
            }

            result["addr"] = format_address(*start_resolved);
            result["signature"] = format_signature(range_bytes, range_mask, format);
            result["format"] = format;

            auto match_result = source->find_matches(
                range_bytes, range_mask, 2, token);
            result["unique"] = !match_result.exhausted &&
                               match_result.error.empty() &&
                               match_result.addresses.size() == 1 &&
                               match_result.addresses[0] == *start_resolved;

            return mcp_result_t::success(
                result.dump(), result,
                json{
                    {"source_queries", 4},
                    {"range_bytes", range_size},
                });
        },
        *context.schemas, cancellation, context.aida_metadata);
}

mcp_result_t find_xref_signatures(
    const handlers::signature_handler_context_t& context,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) {

    if (context.source == nullptr) return context_error("source");
    if (context.schemas == nullptr) return context_error("schemas");

    const auto& limits = context.limits;
    const auto* source = context.source;

    auto contract = signature_tool_contract("find_xref_signatures");
    return protocol::invoke_tool_contract(
        contract, arguments,
        [source, &limits, &cancellation](const json& args,
                                          const cancellation_token_t& token) -> mcp_result_t {
            if (token.cancelled()) {
                return mcp_result_t::failure(
                    result_error_code_t::cancelled,
                    "Signature tool was cancelled before processing.",
                    json{{"phase", "find_xref_pre_process"}});
            }
            if (auto failure = validate_routing_bounds(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature routing arguments violate the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_addrs(args, limits)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature addrs violate the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_format(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature format is not supported.",
                    *failure);
            }
            if (auto failure = validate_max_length(args, limits)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature max_length violates the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_top(args, limits)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature top violates the bounded policy.",
                    *failure);
            }
            if (auto failure = validate_wildcard_operands(args)) {
                return mcp_result_t::failure(
                    result_error_code_t::invalid_input,
                    "Signature wildcard_operands is invalid.",
                    *failure);
            }

            const std::string format = get_format(args);
            const std::size_t max_length = get_max_length(args, 250);
            const bool wildcard_operands = get_wildcard_operands(args);
            const std::size_t top = get_top(args, 5);

            const auto& addrs = args.at("addrs");
            std::vector<json> queries;
            if (addrs.is_array()) {
                for (const auto& a : addrs) queries.push_back(a);
            } else {
                queries.push_back(addrs);
            }

            json result_array = json::array();
            std::size_t source_queries = 0;

            for (const auto& query : queries) {
                const std::string query_str = query.get<std::string>();
                json item;
                item["query"] = query_str;

                auto resolved = source->resolve_address(query_str);
                ++source_queries;

                if (!resolved) {
                    item["addr"] = nullptr;
                    item["signatures"] = nullptr;
                    item["total_xrefs"] = 0;
                    item["error"] = "address_not_resolved";
                    result_array.push_back(std::move(item));
                    continue;
                }

                item["addr"] = format_address(*resolved);

                auto xrefs = source->xrefs_to(*resolved);
                ++source_queries;

                xrefs.erase(std::remove_if(xrefs.begin(), xrefs.end(),
                    [](const signature_xref_t& xref) { return !xref.code; }),
                    xrefs.end());
                std::sort(xrefs.begin(), xrefs.end(),
                          [](const signature_xref_t& a, const signature_xref_t& b) {
                              return a.from < b.from;
                          });
                std::size_t total_xrefs = xrefs.size();
                if (xrefs.size() > limits.maximum_xrefs_per_query) {
                    xrefs.resize(limits.maximum_xrefs_per_query);
                }

                struct sig_entry_t {
                    std::uint64_t addr;
                    std::vector<std::uint8_t> bytes;
                    std::vector<std::uint8_t> mask;
                    bool unique;
                    std::size_t length;
                };

                std::vector<sig_entry_t> sigs;
                for (const auto& xref : xrefs) {
                    if (token.cancelled()) {
                        return mcp_result_t::failure(
                            result_error_code_t::cancelled,
                            "Signature tool was cancelled during xref processing.",
                            json{{"phase", "find_xref_process"}});
                    }

                    auto gen = generate_signature_at(
                        *source, xref.from, max_length, limits.maximum_instruction_bytes,
                        wildcard_operands, token);
                    ++source_queries;

                    if (gen.error == "cancelled") {
                        return mcp_result_t::failure(
                            result_error_code_t::cancelled,
                            "Signature generation was cancelled.",
                            json{{"phase", "find_xref_generate"}});
                    }

                    if (gen.bytes.empty() || !gen.unique) continue;

                    sigs.push_back({xref.from, gen.bytes, gen.mask, gen.unique,
                                    gen.bytes.size()});
                }

                std::sort(sigs.begin(), sigs.end(),
                          [](const sig_entry_t& a, const sig_entry_t& b) {
                              if (a.length != b.length) return a.length < b.length;
                              return a.addr < b.addr;
                          });

                if (sigs.size() > top) {
                    sigs.resize(top);
                }

                json sig_array = json::array();
                for (const auto& s : sigs) {
                    sig_array.push_back(json{
                        {"addr", format_address(s.addr)},
                        {"signature", format_signature(s.bytes, s.mask, format)},
                        {"format", format},
                        {"unique", s.unique},
                    });
                }

                item["signatures"] = sig_array;
                item["total_xrefs"] = static_cast<std::int64_t>(total_xrefs);

                result_array.push_back(std::move(item));
            }

            json structured{{"result", std::move(result_array)}};
            return mcp_result_t::success(
                structured.dump(),
                structured,
                json{
                    {"source_queries", source_queries},
                    {"signature_count", structured["result"].size()},
                });
        },
        *context.schemas, cancellation, context.aida_metadata);
}

}
