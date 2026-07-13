#include "survey_handler_harness.hpp"

#include "../../src/core/mcp/compat/handlers/survey.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::standalone::tests::mcp_compat {

namespace {

using namespace aida::standalone::mcp::compat;
using namespace aida::standalone::mcp::compat::handlers;
using protocol::cancellation_token_t;
using protocol::json;

json schema_instance(const json& schema) {
    if (!schema.is_object()) {
        return nullptr;
    }
    if (const auto constant = schema.find("const"); constant != schema.end()) {
        return *constant;
    }
    if (const auto enumeration = schema.find("enum");
        enumeration != schema.end() && enumeration->is_array() && !enumeration->empty()) {
        return (*enumeration)[0];
    }
    for (const char* keyword : {"anyOf", "oneOf"}) {
        const auto alternatives = schema.find(keyword);
        if (alternatives != schema.end() && alternatives->is_array() && !alternatives->empty()) {
            return schema_instance((*alternatives)[0]);
        }
    }
    const auto all_of = schema.find("allOf");
    if (all_of != schema.end() && all_of->is_array() && !all_of->empty()) {
        json merged = json::object();
        for (const auto& component : *all_of) {
            json instance = schema_instance(component);
            if (!instance.is_object()) {
                return instance;
            }
            merged.update(instance);
        }
        return merged;
    }

    std::string type;
    const auto type_field = schema.find("type");
    if (type_field != schema.end() && type_field->is_string()) {
        type = type_field->get<std::string>();
    } else if (type_field != schema.end() && type_field->is_array()) {
        for (const auto& candidate : *type_field) {
            if (candidate.is_string() && candidate.get_ref<const std::string&>() != "null") {
                type = candidate.get<std::string>();
                break;
            }
        }
    } else if (schema.contains("properties")) {
        type = "object";
    }

    if (type == "object") {
        json result = json::object();
        const auto required = schema.find("required");
        const auto properties = schema.find("properties");
        if (required != schema.end() && required->is_array()) {
            for (const auto& name : *required) {
                if (!name.is_string() || properties == schema.end() || !properties->is_object()) {
                    throw std::runtime_error("generated output schema has an unresolved required property");
                }
                const auto property = properties->find(name.get_ref<const std::string&>());
                if (property == properties->end()) {
                    throw std::runtime_error("generated output schema required property is absent");
                }
                result[name.get_ref<const std::string&>()] = schema_instance(*property);
            }
        }
        return result;
    }
    if (type == "array") {
        json result = json::array();
        std::size_t count = 0;
        if (const auto minimum = schema.find("minItems");
            minimum != schema.end() && minimum->is_number_unsigned()) {
            count = minimum->get<std::size_t>();
        }
        const auto items = schema.find("items");
        for (std::size_t index = 0; index < count; ++index) {
            result.push_back(items == schema.end() ? json(nullptr) : schema_instance(*items));
        }
        return result;
    }
    if (type == "string") {
        std::size_t length = 1;
        if (const auto minimum = schema.find("minLength");
            minimum != schema.end() && minimum->is_number_unsigned()) {
            length = (std::max)(length, minimum->get<std::size_t>());
        }
        return std::string(length, 'x');
    }
    if (type == "integer") {
        if (const auto minimum = schema.find("minimum");
            minimum != schema.end() && minimum->is_number_integer()) {
            return *minimum;
        }
        return 0;
    }
    if (type == "number") {
        return 0.0;
    }
    if (type == "boolean") {
        return false;
    }
    return nullptr;
}

struct backend_state_t final {
    std::size_t calls = 0;
    bool invalid_output = false;
    bool empty_output = false;
    bool oversized_output = false;
    std::size_t oversized_size = 0;
    std::string last_contract;
    json last_arguments = json::object();
    std::uint32_t last_pid = 0;
    std::string last_bin_name;
    bool saw_deadline = false;
    std::uint64_t last_generation = 0;
    std::shared_ptr<std::atomic_bool> cancel_during_dispatch;
    json custom_output;

    adapter_result_t<adapter_response_t> respond(
        const adapter_call_context_t& context,
        const adapter_request_t& request) {
        ++calls;
        last_contract = context.contract == nullptr ? std::string() : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0;
        last_bin_name = context.target ? context.target->target().bin_name : std::string();
        last_generation = context.target ? context.target->target().generation : 0;
        saw_deadline = request.deadline.has_value() &&
            *request.deadline > std::chrono::steady_clock::now();
        last_arguments = json::parse(request.payload, nullptr, false);
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
        }

        if (empty_output) {
            return adapter_result_t<adapter_response_t>::success({{}, false});
        }

        if (oversized_output) {
            std::string huge(oversized_size > 0 ? oversized_size : 17 * 1024 * 1024, 'Z');
            return adapter_result_t<adapter_response_t>::success({std::move(huge), false});
        }

        if (!custom_output.is_null()) {
            return adapter_result_t<adapter_response_t>::success({custom_output.dump(), false});
        }

        json output{{"__schema_violation", true}};
        if (!invalid_output) {
            if (context.contract == nullptr) {
                return adapter_result_t<adapter_response_t>::failure(
                    {adapter_error_code_t::backend_rejected, "fixture_contract_missing", 0, 0});
            }
            const json schema = json::parse(
                context.contract->output_schema_json.begin(),
                context.contract->output_schema_json.end());
            output = schema_instance(schema);
        }
        return adapter_result_t<adapter_response_t>::success({output.dump(), false});
    }
};

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view category, std::string_view detail) {
    if (!condition) {
        throw std::runtime_error(
            "survey_binary " + std::string(category) + " fixture: " + std::string(detail));
    }
}

target_record_t make_target(std::uint64_t target_id, std::uint32_t pid,
                            std::uint64_t creation_identity, std::string name,
                            std::uint64_t generation = 9) {
    target_record_t target;
    target.target_id = target_id;
    target.pid = pid;
    target.process_creation_identity = creation_identity;
    target.bin_name = std::move(name);
    target.generation = generation;
    target.attach_generation = 0x109ULL;
    target.revision = 1;
    return target;
}

target_record_t make_live_target(std::uint64_t target_id, std::uint32_t pid,
                                 std::uint64_t creation_identity, std::string name) {
    target_record_t target = make_target(target_id, pid, creation_identity, std::move(name), 11);
    target.live = true;
    target.live_capture_base = 0x140000000ULL;
    target.live_capture_size = 0x100000ULL;
    target.live_snapshot_permitted = true;
    target.live_snapshot_maximum_bytes = 4096;
    return target;
}

json routed(json arguments) {
    arguments["pid"] = 4101;
    return arguments;
}

void verify_contracts(const survey_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas) {
    require(handlers.size() == k_survey_tool_count,
            "survey handler contract count is not exactly one");
    require(survey_tool_names().size() == k_survey_tool_count,
            "survey name ledger count is not exactly one");
    for (std::size_t index = 0; index < k_survey_tool_count; ++index) {
        const auto name = survey_tool_names()[index];
        const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
        const auto& contract = handlers.contract_at(index);
        require(descriptor != nullptr, "survey generated descriptor is missing");
        require(contract.name == name && handlers.find(name) == &contract,
                "survey handler lookup differs from the exact name ledger");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "survey generated adapter symbol differs from the linked function name");
        require(contract.description == descriptor->description,
                "survey generated description was not preserved");
        require(contract.input_schema == json::parse(
                    descriptor->input_schema_json.begin(), descriptor->input_schema_json.end()) &&
                    contract.output_schema == json::parse(
                    descriptor->output_schema_json.begin(), descriptor->output_schema_json.end()) &&
                    contract.annotations == json::parse(
                    descriptor->annotations_json.begin(), descriptor->annotations_json.end()),
                "survey generated schema or annotations were not preserved");
        require(contract.target_policy.requirement == protocol::target_requirement_t::optional &&
                    contract.target_policy.accepts_pid &&
                    contract.target_policy.accepts_bin_name,
                "survey target routing policy is not the generated optional selector policy");
        require(contract.effect_policy.effect == protocol::tool_effect_t::workspace_read &&
                    contract.effect_policy.lock == protocol::effect_lock_t::workspace_shared &&
                    contract.effect_policy.read_only && !contract.effect_policy.unsafe,
                "survey effect policy is not generated shared workspace read");
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "survey generated contract does not validate through the schema runtime");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "survey tool list entry altered schema or embedded provenance");
    }
}

void verify_valid_standard(survey_handlers_t& handlers, backend_state_t& backend,
                           std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    const json args = routed({{"detail_level", "standard"}});

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "valid_standard", result.text());
    require_fixture(backend.calls == before + 1, "valid_standard",
                    "backend was not invoked exactly once");
    require_fixture(backend.last_contract == "survey_binary",
                    "valid_standard", "request reached the wrong contract");
    require_fixture(backend.last_pid == 4101 && backend.saw_deadline,
                    "valid_standard", "target binding or deadline was not propagated");
    require_fixture(backend.last_arguments == json{{"detail_level", "standard"}},
                    "valid_standard", "routing selectors leaked into backend arguments or detail_level was altered");
    require_fixture(result.structured_content().is_object() &&
                        !result.structured_content().contains("_meta"),
                    "valid_standard", "structured output or metadata separation changed");
    require_fixture(result.aida_metadata().value("tool", std::string()) == "survey_binary" &&
                        result.aida_metadata().value("fixture_tool", std::string()) == "survey_binary" &&
                        result.aida_metadata().value("effect", std::string()) == "workspace_read" &&
                        result.aida_metadata().value("lock", std::string()) == "workspace_shared",
                    "valid_standard", "top-level provenance metadata is incomplete");
    require_fixture(result.aida_metadata().value("adapter_truncated", false) == false,
                    "valid_standard", "adapter_truncated should be false for a bounded response");
    require_fixture(result.aida_metadata().value("adapter_response_bytes", std::uint64_t(0)) > 0,
                    "valid_standard", "adapter_response_bytes should be positive");
    ++completed;
}

void verify_valid_minimal(survey_handlers_t& handlers, backend_state_t& backend,
                          std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    const json args = routed({{"detail_level", "minimal"}});

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "valid_minimal", result.text());
    require_fixture(backend.calls == before + 1, "valid_minimal",
                    "backend was not invoked exactly once");
    require_fixture(backend.last_arguments == json{{"detail_level", "minimal"}},
                    "valid_minimal", "detail_level minimal was not propagated to backend");
    ++completed;
}

void verify_default_detail_level(survey_handlers_t& handlers, backend_state_t& backend,
                                 std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    const json args = routed(json::object());

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "default_detail_level", result.text());
    require_fixture(backend.calls == before + 1, "default_detail_level",
                    "backend was not invoked exactly once");
    require_fixture(backend.last_arguments == json{{"detail_level", "standard"}},
                    "default_detail_level", "detail_level was not defaulted to standard");
    ++completed;
}

void verify_boundary_bin_name(survey_handlers_t& handlers, backend_state_t& backend,
                              const survey_handler_limits_t& limits,
                              std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    json args = json::object();
    args["bin_name"] = std::string(limits.max_selector_bytes, 'A');

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "boundary_bin_name", result.text());
    require_fixture(backend.calls == before + 1, "boundary_bin_name",
                    "pinned maximum bin_name was not admitted by the backend");
    require_fixture(backend.last_arguments == json{{"detail_level", "standard"}},
                    "boundary_bin_name", "routing selectors leaked into backend arguments");
    ++completed;
}

void verify_invalid_detail_level(survey_handlers_t& handlers, backend_state_t& backend,
                                 std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    const json args = routed({{"detail_level", "verbose"}});

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "invalid_detail_level", "out-of-policy detail_level was not rejected canonically");
    require_fixture(backend.calls == before, "invalid_detail_level",
                    "invalid detail_level reached the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "policy", std::string()) == "bounded_survey_adapter",
        "invalid_detail_level", "bounded policy diagnostics are absent");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "reason", std::string()) == "unsupported_value",
        "invalid_detail_level", "unsupported_value reason is absent");
    ++completed;
}

void verify_invalid_pid(survey_handlers_t& handlers, backend_state_t& backend,
                        std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    json args = json::object();
    args["pid"] = 0;

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "invalid_pid", "zero pid was not rejected canonically");
    require_fixture(backend.calls == before, "invalid_pid",
                    "zero pid reached the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "field", std::string()) == "pid",
        "invalid_pid", "pid field is absent from diagnostics");
    ++completed;
}

void verify_oversized_bin_name(survey_handlers_t& handlers, backend_state_t& backend,
                               const survey_handler_limits_t& limits,
                               std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    json args = json::object();
    args["bin_name"] = std::string(limits.max_selector_bytes + 1, 'B');

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "oversized_bin_name", "oversized bin_name was not rejected canonically");
    require_fixture(backend.calls == before, "oversized_bin_name",
                    "oversized bin_name reached the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "reason", std::string()) == "maximum_exceeded",
        "oversized_bin_name", "maximum_exceeded reason is absent");
    ++completed;
}

void verify_ambiguous_target(survey_handlers_t& handlers, backend_state_t& backend,
                             std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    json args = json::object();
    args["bin_name"] = "fixture";

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED",
                    "ambiguous_target", "ambiguous binary selector was not rejected canonically");
    require_fixture(backend.calls == before, "ambiguous_target",
                    "ambiguous target reached the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "adapter_code", std::string()) == "target_ambiguous",
        "ambiguous_target", "resolver ambiguity evidence is absent");
    ++completed;
}

void verify_cancellation_before_dispatch(survey_handlers_t& handlers, backend_state_t& backend,
                                         std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    auto cancellation = cancellation_token_t::create();
    cancellation.cancel();

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, routed({{"detail_level", "standard"}}),
                                          cancellation, metadata);
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    "cancellation_before", "pre-dispatch cancellation was not observed canonically");
    require_fixture(backend.calls == before, "cancellation_before",
                    "pre-dispatch cancellation reached the backend");
    ++completed;
}

void verify_cancellation_during_dispatch(survey_handlers_t& handlers, backend_state_t& backend,
                                         std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    auto cancellation = cancellation_token_t::create();
    backend.cancel_during_dispatch = cancellation.state();

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, routed({{"detail_level", "standard"}}),
                                          cancellation, metadata);
    backend.cancel_during_dispatch.reset();
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    "cancellation_during", "in-flight cancellation was not observed canonically");
    require_fixture(backend.calls == before + 1, "cancellation_during",
                    "in-flight cancellation fixture did not enter the backend");
    ++completed;
}

void verify_invalid_output(survey_handlers_t& handlers, backend_state_t& backend,
                           std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    backend.invalid_output = true;

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, routed({{"detail_level", "standard"}}),
                                          cancellation_token_t::create(), metadata);
    backend.invalid_output = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "invalid_output", "schema-invalid structured output was not rejected canonically");
    require_fixture(backend.calls == before + 1, "invalid_output",
                    "output validation fixture did not enter the backend");
    ++completed;
}

void verify_empty_output(survey_handlers_t& handlers, backend_state_t& backend,
                         std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    backend.empty_output = true;

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, routed({{"detail_level", "standard"}}),
                                          cancellation_token_t::create(), metadata);
    backend.empty_output = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "empty_output", "empty response was not rejected canonically");
    require_fixture(backend.calls == before + 1, "empty_output",
                    "empty output fixture did not enter the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "reason", std::string()) == "nonempty_response_required",
        "empty_output", "nonempty_response_required reason is absent");
    ++completed;
}

void verify_oversized_output(survey_handlers_t& handlers, backend_state_t& backend,
                             const survey_handler_limits_t& limits,
                             std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    backend.oversized_output = true;
    backend.oversized_size = limits.max_response_bytes + 1;

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, routed({{"detail_level", "standard"}}),
                                          cancellation_token_t::create(), metadata);
    backend.oversized_output = false;
    backend.oversized_size = 0;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "oversized_output", "oversized response was not rejected canonically");
    require_fixture(backend.calls == before + 1, "oversized_output",
                    "oversized output fixture did not enter the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "reason", std::string()) == "maximum_exceeded",
        "oversized_output", "maximum_exceeded reason is absent for oversized output");
    ++completed;
}

void verify_backend_rejection(std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};

    target_resolver_t reject_resolver;
    effect_lock_manager_t reject_locks;
    workspace_adapter_handlers_t reject_workspace_handlers;
    reject_workspace_handlers.query = [](const adapter_call_context_t&,
                                         const adapter_request_t&) {
        return adapter_result_t<adapter_response_t>::failure(
            {adapter_error_code_t::backend_rejected, "fixture_backend_rejected", 0, 0});
    };
    workspace_adapter_t reject_workspace(reject_resolver, reject_locks,
                                         std::move(reject_workspace_handlers));
    reject_resolver.publish(make_target(1, 4101, 0xA101ULL, "fixture-survey.exe"));
    protocol::schema_runtime_t reject_schemas(64);
    survey_handlers_t reject_survey_handlers(reject_workspace, reject_schemas);

    auto result = adapters::survey_binary(reject_survey_handlers,
                                          routed({{"detail_level", "standard"}}),
                                          cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_HANDLER_FAILED",
                    "backend_rejection", "backend rejection was not surfaced as handler_failed");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "adapter_code", std::string()) == "fixture_backend_rejected",
        "backend_rejection", "adapter_code evidence is absent");
    ++completed;
}

void verify_collection_routing(survey_handlers_t& handlers, backend_state_t& backend,
                               std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    json args = json::object();
    args["pid"] = 4102;

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "collection_routing", result.text());
    require_fixture(backend.calls == before + 1, "collection_routing",
                    "backend was not invoked exactly once");
    require_fixture(backend.last_pid == 4102,
                    "collection_routing", "pid 4102 was not routed to the second target");
    require_fixture(backend.last_bin_name == "fixture-beta.exe",
                    "collection_routing", "routed target bin_name was not the second target");
    require_fixture(backend.last_generation == 9,
                    "collection_routing", "routed target generation was not propagated");
    ++completed;
}

void verify_live_bounded_target(survey_handlers_t& handlers, backend_state_t& backend,
                                std::size_t& completed) {
    const json metadata{{"fixture_tool", "survey_binary"}};
    json args = json::object();
    args["pid"] = 4103;

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "live_bounded", result.text());
    require_fixture(backend.calls == before + 1, "live_bounded",
                    "backend was not invoked exactly once for live target");
    require_fixture(backend.last_pid == 4103,
                    "live_bounded", "pid 4103 was not routed to the live target");
    require_fixture(backend.last_generation == 11,
                    "live_bounded", "live target generation was not propagated");
    require_fixture(backend.last_arguments == json{{"detail_level", "standard"}},
                    "live_bounded", "detail_level was not defaulted for live target");
    ++completed;
}

void verify_partial_state_metadata(survey_handlers_t& handlers, backend_state_t& backend,
                                   std::size_t& completed) {
    const json metadata{
        {"fixture_tool", "survey_binary"},
        {"partial_state_probe", true},
    };
    const json args = routed({{"detail_level", "minimal"}});

    const std::size_t before = backend.calls;
    auto result = adapters::survey_binary(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "partial_state_metadata", result.text());
    require_fixture(backend.calls == before + 1, "partial_state_metadata",
                    "backend was not invoked exactly once");
    require_fixture(backend.last_generation == 9,
                    "partial_state_metadata",
                    "workspace generation was not pinned to the current immutable generation");
    require_fixture(result.aida_metadata().value("adapter_response_bytes", std::uint64_t(0)) > 0,
                    "partial_state_metadata",
                    "adapter_response_bytes metadata is absent");
    require_fixture(result.aida_metadata().contains("adapter_truncated"),
                    "partial_state_metadata",
                    "adapter_truncated metadata is absent");
    ++completed;
}

void verify_survey_handler() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1, 4101, 0xA101ULL, "fixture-survey.exe"))),
            "first survey handler target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(2, 4102, 0xA102ULL, "fixture-beta.exe"))),
            "second survey handler target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_live_target(3, 4103, 0xA103ULL, "fixture-live.exe"))),
            "live survey handler target publication failed");

    backend_state_t backend;
    workspace_adapter_handlers_t workspace_handlers;
    workspace_handlers.query = [&backend](const adapter_call_context_t& context,
                                          const adapter_request_t& request) {
        return backend.respond(context, request);
    };
    workspace_adapter_t workspace(resolver, locks, std::move(workspace_handlers));
    protocol::schema_runtime_t schemas(64);
    survey_handlers_t handlers(workspace, schemas);

    verify_contracts(handlers, schemas);

    const auto& limits = handlers.limits();
    std::size_t completed = 0;

    verify_valid_standard(handlers, backend, completed);
    verify_valid_minimal(handlers, backend, completed);
    verify_default_detail_level(handlers, backend, completed);
    verify_boundary_bin_name(handlers, backend, limits, completed);
    verify_invalid_detail_level(handlers, backend, completed);
    verify_invalid_pid(handlers, backend, completed);
    verify_oversized_bin_name(handlers, backend, limits, completed);
    verify_ambiguous_target(handlers, backend, completed);
    verify_cancellation_before_dispatch(handlers, backend, completed);
    verify_cancellation_during_dispatch(handlers, backend, completed);
    verify_invalid_output(handlers, backend, completed);
    verify_empty_output(handlers, backend, completed);
    verify_oversized_output(handlers, backend, limits, completed);
    verify_backend_rejection(completed);
    verify_collection_routing(handlers, backend, completed);
    verify_live_bounded_target(handlers, backend, completed);
    verify_partial_state_metadata(handlers, backend, completed);

    require(completed == 17,
            "survey handler harness did not execute all seventeen fixture families");
}

}

bool run_survey_handler_harness(std::string& failure) {
    try {
        verify_survey_handler();
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
