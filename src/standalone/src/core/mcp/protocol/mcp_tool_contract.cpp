#include "mcp_tool_contract.hpp"

#include <cctype>
#include <exception>
#include <optional>
#include <utility>

namespace aida::standalone::mcp::protocol {

namespace {

contract_validation_t rejected_contract(
    std::string reason,
    json details = json::object(),
    result_error_code_t error_code = result_error_code_t::invalid_contract) {
    contract_validation_t result;
    result.valid = false;
    result.error_code = error_code;
    result.reason = std::move(reason);
    result.details = std::move(details);
    return result;
}

bool is_valid_tool_name(const std::string& name) {
    if (name.empty() || name.size() > 128) {
        return false;
    }
    for (const unsigned char character : name) {
        if (!std::isalnum(character) && character != '_' && character != '-' && character != '.') {
            return false;
        }
    }
    return true;
}

bool has_object_type(const json& schema) {
    const auto type = schema.find("type");
    return type != schema.end() && type->is_string() && type->get_ref<const std::string&>() == "object";
}

bool schema_declares_property(const json& schema, const char* name) {
    const auto properties = schema.find("properties");
    return properties != schema.end() && properties->is_object() && properties->contains(name);
}

bool schema_requires_property(const json& schema, const char* name) {
    const auto required = schema.find("required");
    if (required == schema.end() || !required->is_array()) {
        return false;
    }
    for (const auto& value : *required) {
        if (value.is_string() && value.get_ref<const std::string&>() == name) {
            return true;
        }
    }
    return false;
}

bool effect_requires_read_only(tool_effect_t effect) {
    switch (effect) {
    case tool_effect_t::workspace_read:
    case tool_effect_t::debugger_read:
    case tool_effect_t::registry_read:
        return true;
    case tool_effect_t::workspace_checkpoint:
    case tool_effect_t::workspace_overlay_mutation:
    case tool_effect_t::debugger_control:
    case tool_effect_t::debugger_write:
    case tool_effect_t::isolated_python:
    case tool_effect_t::unspecified:
        return false;
    }
    return false;
}

effect_lock_t expected_lock(tool_effect_t effect) {
    switch (effect) {
    case tool_effect_t::workspace_read:
        return effect_lock_t::workspace_shared;
    case tool_effect_t::workspace_checkpoint:
        return effect_lock_t::workspace_checkpoint;
    case tool_effect_t::workspace_overlay_mutation:
        return effect_lock_t::workspace_overlay_transaction;
    case tool_effect_t::debugger_read:
    case tool_effect_t::debugger_control:
    case tool_effect_t::debugger_write:
        return effect_lock_t::debugger_lane;
    case tool_effect_t::isolated_python:
        return effect_lock_t::python_worker;
    case tool_effect_t::registry_read:
        return effect_lock_t::registry_read;
    case tool_effect_t::unspecified:
        return effect_lock_t::unspecified;
    }
    return effect_lock_t::unspecified;
}

contract_validation_t validate_annotation_fields(const tool_contract_t& contract) {
    const auto title = contract.annotations.find("title");
    if (title != contract.annotations.end() && !title->is_string()) {
        return rejected_contract("tool annotation title must be a string", json{{"field", "annotations.title"}});
    }

    const char* const boolean_annotations[] = {
        "readOnlyHint",
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
    };
    for (const char* name : boolean_annotations) {
        const auto value = contract.annotations.find(name);
        if (value != contract.annotations.end() && !value->is_boolean()) {
            return rejected_contract(
                "tool annotation hint must be a boolean",
                json{{"field", std::string("annotations.") + name}});
        }
    }

    const auto read_only_hint = contract.annotations.find("readOnlyHint");
    if (read_only_hint != contract.annotations.end() &&
        read_only_hint->get<bool>() != contract.effect_policy.read_only) {
        return rejected_contract(
            "readOnlyHint differs from the effect policy",
            json{{"annotation", read_only_hint->get<bool>()},
                 {"effect_policy", contract.effect_policy.read_only}},
            result_error_code_t::effect_policy_rejected);
    }
    return {};
}

json contract_provenance(const tool_contract_t& contract, const json& supplied_metadata) {
    json provenance = supplied_metadata;
    provenance["tool"] = contract.name;
    provenance["target_policy"] = std::string(target_requirement_name(contract.target_policy.requirement));
    provenance["effect"] = std::string(tool_effect_name(contract.effect_policy.effect));
    provenance["lock"] = std::string(effect_lock_name(contract.effect_policy.lock));
    provenance["read_only"] = contract.effect_policy.read_only;
    provenance["unsafe"] = contract.effect_policy.unsafe;
    return provenance;
}

mcp_result_t contract_rejection(
    result_error_code_t code,
    const char* text,
    const tool_contract_t& contract,
    const json& details,
    const json& supplied_metadata) {
    return mcp_result_t::failure(
        code,
        text,
        details,
        contract_provenance(contract, supplied_metadata));
}

}

std::string_view target_requirement_name(target_requirement_t requirement) noexcept {
    switch (requirement) {
    case target_requirement_t::independent:
        return "independent";
    case target_requirement_t::optional:
        return "optional";
    case target_requirement_t::required:
        return "required";
    }
    return "independent";
}

std::string_view tool_effect_name(tool_effect_t effect) noexcept {
    switch (effect) {
    case tool_effect_t::unspecified:
        return "unspecified";
    case tool_effect_t::workspace_read:
        return "workspace_read";
    case tool_effect_t::workspace_checkpoint:
        return "workspace_checkpoint";
    case tool_effect_t::workspace_overlay_mutation:
        return "workspace_overlay_mutation";
    case tool_effect_t::debugger_read:
        return "debugger_read";
    case tool_effect_t::debugger_control:
        return "debugger_control";
    case tool_effect_t::debugger_write:
        return "debugger_write";
    case tool_effect_t::isolated_python:
        return "isolated_python";
    case tool_effect_t::registry_read:
        return "registry_read";
    }
    return "unspecified";
}

std::string_view effect_lock_name(effect_lock_t lock) noexcept {
    switch (lock) {
    case effect_lock_t::unspecified:
        return "unspecified";
    case effect_lock_t::workspace_shared:
        return "workspace_shared";
    case effect_lock_t::workspace_checkpoint:
        return "workspace_checkpoint";
    case effect_lock_t::workspace_overlay_transaction:
        return "workspace_overlay_transaction";
    case effect_lock_t::debugger_lane:
        return "debugger_lane";
    case effect_lock_t::python_worker:
        return "python_worker";
    case effect_lock_t::registry_read:
        return "registry_read";
    }
    return "unspecified";
}

cancellation_token_t::cancellation_token_t()
    : state_(std::make_shared<std::atomic_bool>(false)) {
}

cancellation_token_t::cancellation_token_t(std::shared_ptr<std::atomic_bool> state)
    : state_(state ? std::move(state) : std::make_shared<std::atomic_bool>(false)) {
}

cancellation_token_t cancellation_token_t::create(bool cancelled) {
    return cancellation_token_t(std::make_shared<std::atomic_bool>(cancelled));
}

bool cancellation_token_t::cancelled() const noexcept {
    return state_ && state_->load(std::memory_order_acquire);
}

void cancellation_token_t::cancel() noexcept {
    if (state_) {
        state_->store(true, std::memory_order_release);
    }
}

std::shared_ptr<std::atomic_bool> cancellation_token_t::state() const noexcept {
    return state_;
}

json tool_contract_t::tool_list_entry() const {
    return json{
        {"name", name},
        {"description", description},
        {"inputSchema", input_schema},
        {"outputSchema", output_schema},
        {"annotations", annotations},
    };
}

json contract_validation_t::diagnostics() const {
    return json{
        {"valid", valid},
        {"error_code", std::string(canonical_error_code(error_code))},
        {"reason", reason},
        {"details", details},
    };
}

contract_validation_t validate_target_policy(
    const tool_contract_t& contract,
    const json& arguments) {
    if (!arguments.is_object()) {
        return rejected_contract(
            "arguments must be a JSON object",
            json{{"field", "arguments"}});
    }

    const bool has_pid = arguments.contains("pid");
    const bool has_bin_name = arguments.contains("bin_name");
    const bool has_selector = has_pid || has_bin_name;
    const auto& policy = contract.target_policy;

    if (policy.requirement == target_requirement_t::independent) {
        if (has_selector) {
            return rejected_contract(
                "target-independent tools do not accept target selectors",
                json{{"pid", has_pid}, {"bin_name", has_bin_name}});
        }
        return {};
    }

    if (!policy.accepts_pid && has_pid) {
        return rejected_contract("the pid selector is not permitted", json{{"selector", "pid"}});
    }
    if (!policy.accepts_bin_name && has_bin_name) {
        return rejected_contract("the bin_name selector is not permitted", json{{"selector", "bin_name"}});
    }
    if (policy.requirement == target_requirement_t::required && !has_selector) {
        return rejected_contract(
            "a target selector is required",
            json{{"accepted", json{{"pid", policy.accepts_pid}, {"bin_name", policy.accepts_bin_name}}}});
    }
    return {};
}

contract_validation_t validate_effect_policy(const tool_contract_t& contract) {
    const auto& policy = contract.effect_policy;
    if (policy.effect == tool_effect_t::unspecified) {
        return rejected_contract(
            "tool effect must be explicit",
            json{{"field", "effect"}},
            result_error_code_t::effect_policy_rejected);
    }
    const effect_lock_t expected = expected_lock(policy.effect);
    if (policy.lock != expected) {
        return rejected_contract(
            "tool effect requires a different lock policy",
            json{{"effect", std::string(tool_effect_name(policy.effect))},
                 {"expected_lock", std::string(effect_lock_name(expected))},
                 {"actual_lock", std::string(effect_lock_name(policy.lock))}},
            result_error_code_t::effect_policy_rejected);
    }
    const bool expected_read_only = effect_requires_read_only(policy.effect);
    if (policy.read_only != expected_read_only) {
        return rejected_contract(
            "tool effect has an inconsistent read-only policy",
            json{{"effect", std::string(tool_effect_name(policy.effect))},
                 {"expected_read_only", expected_read_only},
                 {"actual_read_only", policy.read_only}},
            result_error_code_t::effect_policy_rejected);
    }
    return {};
}

contract_validation_t validate_tool_contract(
    const tool_contract_t& contract,
    schema_runtime_t& schemas) {
    if (!is_valid_tool_name(contract.name)) {
        return rejected_contract("tool name is invalid", json{{"field", "name"}});
    }
    if (contract.description.empty() || contract.description.size() > 4096) {
        return rejected_contract("tool description is invalid", json{{"field", "description"}});
    }
    if (!contract.input_schema.is_object() || !has_object_type(contract.input_schema)) {
        return rejected_contract("input schema must explicitly describe an object", json{{"field", "inputSchema"}});
    }
    if (!contract.output_schema.is_object() || !has_object_type(contract.output_schema)) {
        return rejected_contract("output schema must explicitly describe an object", json{{"field", "outputSchema"}});
    }
    if (!contract.annotations.is_object()) {
        return rejected_contract("tool annotations must be a JSON object", json{{"field", "annotations"}});
    }

    const auto effect_validation = validate_effect_policy(contract);
    if (!effect_validation.valid) {
        return effect_validation;
    }
    const auto annotation_validation = validate_annotation_fields(contract);
    if (!annotation_validation.valid) {
        return annotation_validation;
    }

    const auto& target = contract.target_policy;
    const bool schema_pid = schema_declares_property(contract.input_schema, "pid");
    const bool schema_bin_name = schema_declares_property(contract.input_schema, "bin_name");
    if (target.requirement == target_requirement_t::independent) {
        if (target.accepts_pid || target.accepts_bin_name || schema_pid || schema_bin_name) {
            return rejected_contract(
                "target-independent tool declares target selectors",
                json{{"accepts_pid", target.accepts_pid},
                     {"accepts_bin_name", target.accepts_bin_name},
                     {"schema_pid", schema_pid},
                     {"schema_bin_name", schema_bin_name}});
        }
    } else {
        if (!target.accepts_pid && !target.accepts_bin_name) {
            return rejected_contract("target-dependent tool accepts no target selector");
        }
        if (schema_pid != target.accepts_pid || schema_bin_name != target.accepts_bin_name) {
            return rejected_contract(
                "target selector policy differs from the input schema",
                json{{"accepts_pid", target.accepts_pid},
                     {"accepts_bin_name", target.accepts_bin_name},
                     {"schema_pid", schema_pid},
                     {"schema_bin_name", schema_bin_name}});
        }
        if (target.requirement == target_requirement_t::optional &&
            (schema_requires_property(contract.input_schema, "pid") ||
             schema_requires_property(contract.input_schema, "bin_name"))) {
            return rejected_contract(
                "optional target policy cannot require a target selector",
                json{{"field", "required"}});
        }
        if (target.requirement == target_requirement_t::required &&
            schema_requires_property(contract.input_schema, "pid") &&
            schema_requires_property(contract.input_schema, "bin_name")) {
            return rejected_contract(
                "required target policy cannot require both target selectors",
                json{{"field", "required"}});
        }
    }

    const auto input_validation = schemas.compile(contract.input_schema);
    if (!input_validation.valid) {
        return rejected_contract(
            "input schema is invalid",
            json{{"field", "inputSchema"}, {"schema", input_validation.diagnostics()}});
    }
    const auto output_validation = schemas.compile(contract.output_schema);
    if (!output_validation.valid) {
        return rejected_contract(
            "output schema is invalid",
            json{{"field", "outputSchema"}, {"schema", output_validation.diagnostics()}});
    }
    return {};
}

mcp_result_t invoke_tool_contract(
    const tool_contract_t& contract,
    const json& arguments,
    const tool_handler_t& handler,
    schema_runtime_t& schemas,
    const cancellation_token_t& cancellation,
    const json& aida_metadata) {
    if (!aida_metadata.is_object()) {
        return mcp_result_t::failure(
            result_error_code_t::internal_error,
            "MCP provenance metadata must be a JSON object.",
            json{{"field", "aida_metadata"}});
    }
    if (cancellation.cancelled()) {
        return contract_rejection(
            result_error_code_t::cancelled,
            "Tool invocation was cancelled before validation.",
            contract,
            json{{"phase", "pre_validation"}},
            aida_metadata);
    }

    const auto definition = validate_tool_contract(contract, schemas);
    if (!definition.valid) {
        return contract_rejection(
            definition.error_code,
            "Tool contract validation failed.",
            contract,
            definition.diagnostics(),
            aida_metadata);
    }

    const auto target_validation = validate_target_policy(contract, arguments);
    if (!target_validation.valid) {
        const result_error_code_t code = arguments.is_object()
            ? result_error_code_t::target_policy_rejected
            : result_error_code_t::invalid_input;
        return contract_rejection(
            code,
            arguments.is_object() ? "Tool target policy rejected the arguments." : "Tool arguments must be a JSON object.",
            contract,
            target_validation.diagnostics(),
            aida_metadata);
    }

    const auto input_validation = schemas.validate(contract.input_schema, arguments);
    if (!input_validation.valid) {
        return contract_rejection(
            result_error_code_t::invalid_input,
            "Tool arguments do not satisfy the input schema.",
            contract,
            json{{"schema", input_validation.diagnostics()}},
            aida_metadata);
    }
    if (cancellation.cancelled()) {
        return contract_rejection(
            result_error_code_t::cancelled,
            "Tool invocation was cancelled before dispatch.",
            contract,
            json{{"phase", "pre_dispatch"}},
            aida_metadata);
    }
    if (!handler) {
        return contract_rejection(
            result_error_code_t::handler_failed,
            "Tool handler is unavailable.",
            contract,
            json{{"phase", "dispatch"}},
            aida_metadata);
    }

    std::optional<mcp_result_t> result;
    try {
        result.emplace(handler(arguments, cancellation));
    } catch (const std::exception&) {
        return contract_rejection(
            result_error_code_t::handler_failed,
            "Tool handler failed.",
            contract,
            json{{"phase", "handler"}},
            aida_metadata);
    } catch (...) {
        return contract_rejection(
            result_error_code_t::handler_failed,
            "Tool handler failed.",
            contract,
            json{{"phase", "handler"}},
            aida_metadata);
    }

    if (cancellation.cancelled()) {
        return contract_rejection(
            result_error_code_t::cancelled,
            "Tool invocation was cancelled before result delivery.",
            contract,
            json{{"phase", "post_dispatch"}},
            aida_metadata);
    }

    if (!result->is_error()) {
        const auto output_validation = schemas.validate(contract.output_schema, result->structured_content());
        if (!output_validation.valid) {
            return contract_rejection(
                result_error_code_t::invalid_output,
                "Tool result does not satisfy the output schema.",
                contract,
                json{{"schema", output_validation.diagnostics()}},
                aida_metadata);
        }
    }

    return result->with_aida_metadata(contract_provenance(contract, aida_metadata));
}

mcp_result_t invoke_tool_contract(
    const tool_contract_t& contract,
    const json& arguments,
    const tool_handler_t& handler,
    schema_runtime_t& schemas,
    const json& aida_metadata) {
    return invoke_tool_contract(
        contract,
        arguments,
        handler,
        schemas,
        cancellation_token_t::create(),
        aida_metadata);
}

}
