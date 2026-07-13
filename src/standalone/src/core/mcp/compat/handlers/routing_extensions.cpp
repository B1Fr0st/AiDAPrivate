#include "routing_extensions.hpp"

#include "../ida_contracts_generated.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstring>
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
        meta.effect = protocol::tool_effect_t::workspace_read;
        meta.lock = protocol::effect_lock_t::workspace_shared;
        meta.read_only = true;
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
        meta.effect = protocol::tool_effect_t::unspecified;
        meta.lock = protocol::effect_lock_t::unspecified;
        meta.read_only = true;
        meta.lane = extension_lane_t::local_calculator;
    } else {
        meta.target_requirement = protocol::target_requirement_t::independent;
        meta.effect = protocol::tool_effect_t::registry_read;
        meta.lock = protocol::effect_lock_t::registry_read;
        meta.read_only = true;
        meta.lane = extension_lane_t::registry_read;
    }
    return meta;
}

bool valid_limits(const routing_extension_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 && limits.max_request_bytes <= 1024U * 1024U &&
        limits.max_response_bytes != 0 && limits.max_response_bytes <= 16U * 1024U * 1024U &&
        limits.max_selector_bytes != 0 && limits.max_selector_bytes <= 1024U &&
        limits.max_expression_bytes != 0 && limits.max_expression_bytes <= 16384U &&
        limits.max_function_addresses != 0 && limits.max_function_addresses <= 256U &&
        limits.max_instruction_results != 0 && limits.max_instruction_results <= 5000U &&
        limits.max_address_bytes != 0 && limits.max_address_bytes <= 4096U &&
        limits.max_mnemonic_bytes != 0 && limits.max_mnemonic_bytes <= 64U &&
        limits.max_operand_pattern_bytes != 0 && limits.max_operand_pattern_bytes <= 256U &&
        limits.max_offset != 0 && limits.max_offset <= 10000000ULL &&
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

validation_failure_t validate_analyze_funcs(const json& arguments,
                                           const routing_extension_limits_t& limits) {
    if (auto failure = validate_routing_bounds(arguments, limits)) {
        return failure;
    }
    const auto addrs = arguments.find("addrs");
    if (addrs == arguments.end()) {
        return invalid_value("addrs", "field_required", json(nullptr));
    }
    if (!addrs->is_array()) {
        return invalid_value("addrs", "array_required", *addrs);
    }
    if (addrs->size() > limits.max_function_addresses) {
        return exceeded_value(
            "addrs", static_cast<std::uint64_t>(limits.max_function_addresses),
            static_cast<std::uint64_t>(addrs->size()));
    }
    for (std::size_t index = 0; index < addrs->size(); ++index) {
        if (auto failure = bounded_text(
                (*addrs)[index], "addrs[" + std::to_string(index) + "]",
                limits.max_address_bytes, false)) {
            return failure;
        }
    }
    if (auto failure = bounded_integer(arguments, "max_depth", 64ULL)) {
        return failure;
    }
    return std::nullopt;
}

validation_failure_t validate_find_insns(const json& arguments,
                                        const routing_extension_limits_t& limits) {
    if (auto failure = validate_routing_bounds(arguments, limits)) {
        return failure;
    }
    if (auto failure = bounded_member_text(
            arguments, "mnem", {}, limits.max_mnemonic_bytes, false)) {
        return failure;
    }
    if (auto failure = bounded_member_text(
            arguments, "operand", {}, limits.max_operand_pattern_bytes, true)) {
        return failure;
    }
    if (auto failure = bounded_integer(
            arguments, "limit", limits.max_instruction_results)) {
        return failure;
    }
    if (auto failure = bounded_integer(arguments, "offset", limits.max_offset)) {
        return failure;
    }
    return std::nullopt;
}

validation_failure_t validate_calculator(const json& arguments,
                                        const routing_extension_limits_t& limits) {
    if (auto failure = bounded_member_text(
            arguments, "expression", {}, limits.max_expression_bytes, false)) {
        return failure;
    }
    return std::nullopt;
}

validation_failure_t validate_tool_bounds(std::string_view name, const json& arguments,
                                         const routing_extension_limits_t& limits) {
    if (name == "list_instances") {
        return validate_list_instances(arguments, limits);
    }
    if (name == "analyze_funcs") {
        return validate_analyze_funcs(arguments, limits);
    }
    if (name == "find_insns") {
        return validate_find_insns(arguments, limits);
    }
    if (name == "calculator" || name == "calculate") {
        return validate_calculator(arguments, limits);
    }
    return invalid_value("tool", "routing_extension_not_registered", std::string(name));
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
        "Routing extension workspace adapter rejected the request.",
        json{
            {"phase", "workspace_adapter"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

json list_instances_input_schema() {
    return json{
        {"type", "object"},
        {"properties", json{
            {"filter", json{{"type", "string"}}},
            {"include_retired", json{{"type", "boolean"}}},
        }},
        {"additionalProperties", false},
    };
}

json list_instances_output_schema() {
    return json{
        {"type", "object"},
        {"properties", json{
            {"instances", json{{"type", "array"}, {"items", json{{"type", "object"}}}}},
            {"count", json{{"type", "integer"}}},
        }},
        {"required", json::array({"instances", "count"})},
    };
}

json analyze_funcs_input_schema() {
    return json{
        {"type", "object"},
        {"properties", json{
            {"addrs", json{{"type", "array"}, {"items", json{{"type", "string"}}}}},
            {"pid", json{{"type", "integer"}}},
            {"bin_name", json{{"type", "string"}}},
            {"max_depth", json{{"type", "integer"}}},
        }},
        {"required", json::array({"addrs"})},
    };
}

json analyze_funcs_output_schema() {
    return json{
        {"type", "object"},
        {"properties", json{
            {"results", json{{"type", "array"}}},
        }},
        {"required", json::array({"results"})},
    };
}

json find_insns_input_schema() {
    return json{
        {"type", "object"},
        {"properties", json{
            {"mnem", json{{"type", "string"}}},
            {"operand", json{{"type", "string"}}},
            {"pid", json{{"type", "integer"}}},
            {"bin_name", json{{"type", "string"}}},
            {"limit", json{{"type", "integer"}}},
            {"offset", json{{"type", "integer"}}},
        }},
        {"required", json::array({"mnem"})},
    };
}

json find_insns_output_schema() {
    return json{
        {"type", "object"},
        {"properties", json{
            {"matches", json{{"type", "array"}}},
        }},
        {"required", json::array({"matches"})},
    };
}

json calculator_input_schema() {
    return json{
        {"type", "object"},
        {"properties", json{
            {"expression", json{{"type", "string"}}},
        }},
        {"required", json::array({"expression"})},
    };
}

json calculator_output_schema() {
    return json{
        {"type", "object"},
        {"properties", json{
            {"result", json{{"type", "string"}}},
            {"decimal", json{{"type", "string"}}},
            {"hex", json{{"type", "string"}}},
        }},
        {"required", json::array({"result"})},
    };
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
         "Analyze one or more functions by address with optional depth control.",
         analyze_funcs_input_schema, analyze_funcs_output_schema,
         protocol::target_requirement_t::optional, true, true,
         protocol::tool_effect_t::workspace_read, protocol::effect_lock_t::workspace_shared, true},
        {k_extension_tool_find_insns,
         "Find instructions matching a mnemonic and optional operand pattern.",
         find_insns_input_schema, find_insns_output_schema,
         protocol::target_requirement_t::optional, true, true,
         protocol::tool_effect_t::workspace_read, protocol::effect_lock_t::workspace_shared, true},
        {k_extension_tool_calculator,
         "Evaluate an arithmetic expression and return the result in multiple bases.",
         calculator_input_schema, calculator_output_schema,
         protocol::target_requirement_t::independent, false, false,
         protocol::tool_effect_t::unspecified, protocol::effect_lock_t::unspecified, true},
        {k_extension_tool_calculate,
         "Evaluate an arithmetic expression and return the result in multiple bases.",
         calculator_input_schema, calculator_output_schema,
         protocol::target_requirement_t::independent, false, false,
         protocol::tool_effect_t::unspecified, protocol::effect_lock_t::unspecified, true},
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

namespace calc {

enum class token_kind_t : std::uint8_t {
    number,
    plus,
    minus,
    star,
    slash,
    percent,
    amp,
    pipe,
    caret,
    tilde,
    shl,
    shr,
    lparen,
    rparen,
    end_of_input,
};

struct token_t {
    token_kind_t kind = token_kind_t::end_of_input;
    std::uint64_t value = 0;
};

class tokenizer_t final {
public:
    explicit tokenizer_t(std::string_view text) : text_(text) {}

    token_t next() {
        skip_whitespace();
        if (pos_ >= text_.size()) {
            return {token_kind_t::end_of_input, 0};
        }
        const char ch = text_[pos_];
        if (ch == '+') { ++pos_; return {token_kind_t::plus, 0}; }
        if (ch == '-') { ++pos_; return {token_kind_t::minus, 0}; }
        if (ch == '*') { ++pos_; return {token_kind_t::star, 0}; }
        if (ch == '/') { ++pos_; return {token_kind_t::slash, 0}; }
        if (ch == '%') { ++pos_; return {token_kind_t::percent, 0}; }
        if (ch == '&') { ++pos_; return {token_kind_t::amp, 0}; }
        if (ch == '|') { ++pos_; return {token_kind_t::pipe, 0}; }
        if (ch == '^') { ++pos_; return {token_kind_t::caret, 0}; }
        if (ch == '~') { ++pos_; return {token_kind_t::tilde, 0}; }
        if (ch == '(') { ++pos_; return {token_kind_t::lparen, 0}; }
        if (ch == ')') { ++pos_; return {token_kind_t::rparen, 0}; }
        if (ch == '<') {
            ++pos_;
            if (pos_ < text_.size() && text_[pos_] == '<') { ++pos_; return {token_kind_t::shl, 0}; }
            throw std::runtime_error("calculator: expected '<<'");
        }
        if (ch == '>') {
            ++pos_;
            if (pos_ < text_.size() && text_[pos_] == '>') { ++pos_; return {token_kind_t::shr, 0}; }
            throw std::runtime_error("calculator: expected '>>'");
        }
        if (ch == '0' && pos_ + 1 < text_.size() &&
            (text_[pos_ + 1] == 'x' || text_[pos_ + 1] == 'X')) {
            pos_ += 2;
            return parse_hex();
        }
        if (ch == '0' && pos_ + 1 < text_.size() &&
            (text_[pos_ + 1] == 'b' || text_[pos_ + 1] == 'B')) {
            pos_ += 2;
            return parse_binary();
        }
        if (std::isdigit(static_cast<unsigned char>(ch))) {
            return parse_decimal();
        }
        throw std::runtime_error("calculator: unexpected character");
    }

private:
    void skip_whitespace() {
        while (pos_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos_]))) {
            ++pos_;
        }
    }

    token_t parse_hex() {
        std::uint64_t value = 0;
        bool any = false;
        while (pos_ < text_.size()) {
            const char ch = text_[pos_];
            int digit = -1;
            if (ch >= '0' && ch <= '9') digit = ch - '0';
            else if (ch >= 'a' && ch <= 'f') digit = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') digit = ch - 'A' + 10;
            if (digit < 0) break;
            value = (value << 4) | static_cast<std::uint64_t>(digit);
            ++pos_;
            any = true;
        }
        if (!any) throw std::runtime_error("calculator: empty hex literal");
        return {token_kind_t::number, value};
    }

    token_t parse_binary() {
        std::uint64_t value = 0;
        bool any = false;
        while (pos_ < text_.size() && (text_[pos_] == '0' || text_[pos_] == '1')) {
            value = (value << 1) | static_cast<std::uint64_t>(text_[pos_] - '0');
            ++pos_;
            any = true;
        }
        if (!any) throw std::runtime_error("calculator: empty binary literal");
        return {token_kind_t::number, value};
    }

    token_t parse_decimal() {
        std::uint64_t value = 0;
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            value = value * 10 + static_cast<std::uint64_t>(text_[pos_] - '0');
            ++pos_;
        }
        return {token_kind_t::number, value};
    }

    std::string_view text_;
    std::size_t pos_ = 0;
};

class parser_t final {
public:
    explicit parser_t(std::string_view expression) : tokenizer_(expression) {
        current_ = tokenizer_.next();
    }

    std::uint64_t parse() {
        const std::uint64_t result = parse_expression();
        if (current_.kind != token_kind_t::end_of_input) {
            throw std::runtime_error("calculator: trailing tokens after expression");
        }
        return result;
    }

private:
    std::uint64_t parse_expression() {
        std::uint64_t left = parse_term();
        for (;;) {
            switch (current_.kind) {
            case token_kind_t::plus:
                current_ = tokenizer_.next();
                left = left + parse_term();
                break;
            case token_kind_t::minus:
                current_ = tokenizer_.next();
                left = left - parse_term();
                break;
            case token_kind_t::pipe:
                current_ = tokenizer_.next();
                left = left | parse_term();
                break;
            case token_kind_t::amp:
                current_ = tokenizer_.next();
                left = left & parse_term();
                break;
            case token_kind_t::caret:
                current_ = tokenizer_.next();
                left = left ^ parse_term();
                break;
            default:
                return left;
            }
        }
    }

    std::uint64_t parse_term() {
        std::uint64_t left = parse_factor();
        for (;;) {
            switch (current_.kind) {
            case token_kind_t::star:
                current_ = tokenizer_.next();
                left = left * parse_factor();
                break;
            case token_kind_t::slash:
                current_ = tokenizer_.next();
                {
                    const std::uint64_t divisor = parse_factor();
                    if (divisor == 0) throw std::runtime_error("calculator: division by zero");
                    left = left / divisor;
                }
                break;
            case token_kind_t::percent:
                current_ = tokenizer_.next();
                {
                    const std::uint64_t divisor = parse_factor();
                    if (divisor == 0) throw std::runtime_error("calculator: modulo by zero");
                    left = left % divisor;
                }
                break;
            case token_kind_t::shl:
                current_ = tokenizer_.next();
                left = left << parse_factor();
                break;
            case token_kind_t::shr:
                current_ = tokenizer_.next();
                left = left >> parse_factor();
                break;
            default:
                return left;
            }
        }
    }

    std::uint64_t parse_factor() {
        if (current_.kind == token_kind_t::tilde) {
            current_ = tokenizer_.next();
            return ~parse_factor();
        }
        if (current_.kind == token_kind_t::minus) {
            current_ = tokenizer_.next();
            return static_cast<std::uint64_t>(0) - parse_factor();
        }
        if (current_.kind == token_kind_t::plus) {
            current_ = tokenizer_.next();
            return parse_factor();
        }
        return parse_primary();
    }

    std::uint64_t parse_primary() {
        if (current_.kind == token_kind_t::number) {
            const std::uint64_t value = current_.value;
            current_ = tokenizer_.next();
            return value;
        }
        if (current_.kind == token_kind_t::lparen) {
            current_ = tokenizer_.next();
            const std::uint64_t value = parse_expression();
            if (current_.kind != token_kind_t::rparen) {
                throw std::runtime_error("calculator: expected closing parenthesis");
            }
            current_ = tokenizer_.next();
            return value;
        }
        throw std::runtime_error("calculator: unexpected token in primary");
    }

    tokenizer_t tokenizer_;
    token_t current_;
};

std::string decimal_string(std::uint64_t value) {
    if (value == 0) return "0";
    std::string digits;
    while (value > 0) {
        digits.push_back(static_cast<char>('0' + value % 10));
        value /= 10;
    }
    std::reverse(digits.begin(), digits.end());
    return digits;
}

std::string hex_string(std::uint64_t value) {
    constexpr char hex_digits[] = "0123456789abcdef";
    std::string result = "0x";
    bool emitted = false;
    for (int shift = 60; shift >= 0; shift -= 4) {
        const std::uint8_t nibble = static_cast<std::uint8_t>((value >> shift) & 0xf);
        if (nibble != 0 || emitted || shift == 0) {
            result.push_back(hex_digits[nibble]);
            emitted = true;
        }
    }
    return result;
}

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
        const auto* archive = aida::standalone::mcp::compat::contracts();
        const std::size_t archive_count = aida::standalone::mcp::compat::contract_count();
        for (std::size_t index = 0; index < archive_count; ++index) {
            result.push_back(metadata_from_descriptor(archive[index]));
        }
        for (const auto ext_name : k_aida_extension_names) {
            result.push_back(metadata_for_extension(ext_name));
        }
        return result;
    }();
    return inventory;
}

const routing_metadata_t* find_routing_metadata(std::string_view name) noexcept {
    const auto& inventory = routing_metadata_inventory();
    const auto found = std::find_if(
        inventory.begin(), inventory.end(),
        [name](const routing_metadata_t& meta) { return meta.name == name; });
    return found == inventory.end() ? nullptr : &*found;
}

std::size_t routing_metadata_count() noexcept {
    return routing_metadata_inventory().size();
}

routing_extensions_t::routing_extensions_t(target_resolver_t& resolver,
                                           workspace_adapter_t& workspace,
                                           protocol::schema_runtime_t& schemas,
                                           routing_extension_limits_t limits)
    : resolver_(resolver), workspace_(workspace), schemas_(schemas), limits_(std::move(limits)) {
    if (!valid_limits(limits_)) {
        throw std::invalid_argument(
            "routing extension limits are invalid or weaken pinned maxima");
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
    }
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

    json instances = json::array();
    std::string filter;
    bool include_retired = false;
    if (const auto filter_val = arguments.find("filter"); filter_val != arguments.end()) {
        filter = filter_val->get<std::string>();
    }
    if (const auto retired_val = arguments.find("include_retired");
        retired_val != arguments.end()) {
        include_retired = retired_val->get<bool>();
    }

    for (const auto& target : targets) {
        if (!filter.empty()) {
            if (target.bin_name.find(filter) == std::string::npos) {
                continue;
            }
        }
        instances.push_back(json{
            {"target_id", target.target_id},
            {"pid", target.pid},
            {"bin_name", target.bin_name},
            {"generation", target.generation},
            {"attach_generation", target.attach_generation},
            {"live", target.live},
            {"process_creation_identity", target.process_creation_identity},
            {"revision", target.revision},
        });
    }

    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "list_instances was cancelled after resolver snapshot.",
            protocol::json{{"phase", "list_instances_post_snapshot"}});
    }

    json output{
        {"instances", std::move(instances)},
        {"count", static_cast<std::uint64_t>(0)},
    };
    output["count"] = output["instances"].size();

    std::string payload = output.dump();
    return protocol::mcp_result_t::success(
        std::move(payload),
        std::move(output),
        protocol::json{
            {"resolver_target_count", targets.size()},
        });
}

protocol::mcp_result_t routing_extensions_t::handle_analyze_funcs(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const routing_extension_invocation_options_t& options) const {
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "analyze_funcs was cancelled before adapter routing.",
            protocol::json{{"phase", "analyze_funcs_pre_route"}});
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
            "analyze_funcs backend arguments cannot be serialized.",
            protocol::json{{"phase", "analyze_funcs_serialization"}});
    }
    request.expected_generation = options.expected_generation;
    request.deadline = options.deadline;
    if (!request.deadline.has_value()) {
        request.deadline = std::chrono::steady_clock::now() + limits_.max_execution_time;
    }

    auto adapter_result = workspace_.analyze("analyze_funcs", request);
    if (!adapter_result) {
        return adapter_failure(adapter_result.error());
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "analyze_funcs was cancelled during adapter execution.",
            protocol::json{{"phase", "analyze_funcs_post_adapter"}});
    }

    auto response = std::move(adapter_result).take_value();
    if (response.payload.empty()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "analyze_funcs adapter response is empty.",
            invalid_value("response_bytes", "nonempty_response_required", 0));
    }
    if (response.payload.size() > limits_.max_response_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "analyze_funcs adapter response violates the output byte quota.",
            exceeded_value(
                "response_bytes",
                static_cast<std::uint64_t>(limits_.max_response_bytes),
                static_cast<std::uint64_t>(response.payload.size())));
    }
    protocol::json structured = protocol::json::parse(response.payload, nullptr, false);
    if (structured.is_discarded() || !structured.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "analyze_funcs adapter returned malformed structured output.",
            protocol::json{{"phase", "analyze_funcs_output_parse"},
                           {"response_bytes", response.payload.size()}});
    }

    const std::size_t response_bytes = response.payload.size();
    return protocol::mcp_result_t::success(
        std::move(response.payload),
        std::move(structured),
        protocol::json{
            {"adapter_truncated", response.truncated},
            {"adapter_response_bytes", response_bytes},
        });
}

protocol::mcp_result_t routing_extensions_t::handle_find_insns(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const routing_extension_invocation_options_t& options) const {
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "find_insns was cancelled before adapter routing.",
            protocol::json{{"phase", "find_insns_pre_route"}});
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
            "find_insns backend arguments cannot be serialized.",
            protocol::json{{"phase", "find_insns_serialization"}});
    }
    request.expected_generation = options.expected_generation;
    request.deadline = options.deadline;
    if (!request.deadline.has_value()) {
        request.deadline = std::chrono::steady_clock::now() + limits_.max_execution_time;
    }

    auto adapter_result = workspace_.query("find_insns", request);
    if (!adapter_result) {
        return adapter_failure(adapter_result.error());
    }
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "find_insns was cancelled during adapter execution.",
            protocol::json{{"phase", "find_insns_post_adapter"}});
    }

    auto response = std::move(adapter_result).take_value();
    if (response.payload.empty()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "find_insns adapter response is empty.",
            invalid_value("response_bytes", "nonempty_response_required", 0));
    }
    if (response.payload.size() > limits_.max_response_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "find_insns adapter response violates the output byte quota.",
            exceeded_value(
                "response_bytes",
                static_cast<std::uint64_t>(limits_.max_response_bytes),
                static_cast<std::uint64_t>(response.payload.size())));
    }
    protocol::json structured = protocol::json::parse(response.payload, nullptr, false);
    if (structured.is_discarded() || !structured.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "find_insns adapter returned malformed structured output.",
            protocol::json{{"phase", "find_insns_output_parse"},
                           {"response_bytes", response.payload.size()}});
    }

    const std::size_t response_bytes = response.payload.size();
    return protocol::mcp_result_t::success(
        std::move(response.payload),
        std::move(structured),
        protocol::json{
            {"adapter_truncated", response.truncated},
            {"adapter_response_bytes", response_bytes},
        });
}

protocol::mcp_result_t routing_extensions_t::handle_calculator(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "calculator was cancelled before evaluation.",
            protocol::json{{"phase", "calculator_pre_eval"}});
    }

    const auto expression = arguments.at("expression").get_ref<const std::string&>();
    if (expression.empty()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "calculator expression must not be empty.",
            invalid_value("expression", "nonempty_string_required", expression));
    }

    std::uint64_t result_value = 0;
    try {
        calc::parser_t parser(expression);
        result_value = parser.parse();
    } catch (const std::exception& error) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "calculator expression evaluation failed.",
            json{
                {"phase", "calculator_eval"},
                {"reason", error.what()},
                {"expression", expression},
            });
    }

    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "calculator was cancelled after evaluation.",
            protocol::json{{"phase", "calculator_post_eval"}});
    }

    const std::string dec = calc::decimal_string(result_value);
    const std::string hex = calc::hex_string(result_value);
    json output{
        {"result", dec},
        {"decimal", dec},
        {"hex", hex},
    };

    std::string payload = output.dump();
    return protocol::mcp_result_t::success(
        std::move(payload),
        std::move(output),
        protocol::json{
            {"expression_bytes", expression.size()},
            {"local_computation", true},
        });
}

protocol::mcp_result_t routing_extensions_t::handle_calculate(
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "calculate was cancelled before evaluation.",
            protocol::json{{"phase", "calculate_pre_eval"}});
    }

    const auto expression = arguments.at("expression").get_ref<const std::string&>();
    if (expression.empty()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "calculate expression must not be empty.",
            invalid_value("expression", "nonempty_string_required", expression));
    }

    std::uint64_t result_value = 0;
    try {
        calc::parser_t parser(expression);
        result_value = parser.parse();
    } catch (const std::exception& error) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "calculate expression evaluation failed.",
            json{
                {"phase", "calculate_eval"},
                {"reason", error.what()},
                {"expression", expression},
            });
    }

    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "calculate was cancelled after evaluation.",
            protocol::json{{"phase", "calculate_post_eval"}});
    }

    const std::string dec = calc::decimal_string(result_value);
    const std::string hex = calc::hex_string(result_value);
    json output{
        {"result", dec},
        {"decimal", dec},
        {"hex", hex},
    };

    std::string payload = output.dump();
    return protocol::mcp_result_t::success(
        std::move(payload),
        std::move(output),
        protocol::json{
            {"expression_bytes", expression.size()},
            {"local_computation", true},
        });
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
