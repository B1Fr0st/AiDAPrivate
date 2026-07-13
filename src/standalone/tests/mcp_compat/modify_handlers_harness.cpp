#include "modify_handlers_harness.hpp"

#include "../../src/core/mcp/compat/handlers/modify.hpp"
#include "../../src/core/mcp/compat/workspace_adapter.hpp"
#include "../../src/core/mcp/compat/target_resolver.hpp"
#include "../../src/core/mcp/compat/effect_policy.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../../src/core/mcp/protocol/mcp_tool_contract.hpp"

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

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view tool, std::string_view category,
                     std::string_view detail) {
    if (!condition) {
        throw std::runtime_error(
            std::string(tool) + " " + std::string(category) + " fixture: " +
            std::string(detail));
    }
}

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

const adapters::modify_adapter_t k_modify_adapters[k_modify_tool_count] = {
    &adapters::set_comments,
    &adapters::append_comments,
    &adapters::rename,
    &adapters::define_code,
    &adapters::define_func,
    &adapters::undefine,
    &adapters::make_data,
    &adapters::patch_asm,
    &adapters::force_recompile,
    &adapters::set_op_type,
    &adapters::set_type,
};

struct backend_state_t final {
    std::size_t calls = 0;
    bool invalid_output = false;
    std::string last_contract;
    std::string last_lane;
    json last_arguments = json::object();
    std::uint32_t last_pid = 0;
    bool saw_deadline = false;
    std::shared_ptr<std::atomic_bool> cancel_during_dispatch;

    adapter_result_t<adapter_response_t> respond(
        const char* lane_name, const adapter_call_context_t& context,
        const adapter_request_t& request) {
        ++calls;
        last_lane = lane_name;
        last_contract = context.contract == nullptr ? std::string() : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0;
        saw_deadline = request.deadline.has_value() &&
            *request.deadline > std::chrono::steady_clock::now();
        last_arguments = json::parse(request.payload, nullptr, false);
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
        }
        json output;
        if (!invalid_output) {
            if (context.contract == nullptr) {
                return adapter_result_t<adapter_response_t>::failure(
                    {adapter_error_code_t::backend_rejected, "fixture_contract_missing", 0, 0});
            }
            const json schema = json::parse(
                context.contract->output_schema_json.begin(),
                context.contract->output_schema_json.end());
            output = schema_instance(schema);
        } else {
            output = json{{"__schema_violation", true}};
        }
        return adapter_result_t<adapter_response_t>::success({output.dump(), false});
    }
};

target_record_t make_target(std::uint64_t target_id, std::uint32_t pid,
                            std::uint64_t creation_identity, std::string name) {
    target_record_t target;
    target.target_id = target_id;
    target.pid = pid;
    target.process_creation_identity = creation_identity;
    target.bin_name = std::move(name);
    target.generation = 9;
    target.attach_generation = 0x109ULL;
    target.revision = 1;
    return target;
}

json routed(json arguments) {
    arguments["pid"] = 4101;
    return arguments;
}

json make_valid_args(std::string_view tool) {
    if (tool == "set_comments") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"comment", "test comment"}}}});
    }
    if (tool == "append_comments") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"comment", "appended"}}}});
    }
    if (tool == "rename") {
        return routed({{"batch", json{{"func", json{{"addr", "0x140001000"}, {"name", "my_func"}}}}}});
    }
    if (tool == "define_code") {
        return routed({{"items", json{{"addr", "0x140001000"}}}});
    }
    if (tool == "define_func") {
        return routed({{"items", json{{"addr", "0x140001000"}}}});
    }
    if (tool == "undefine") {
        return routed({{"items", json{{"addr", "0x140001000"}}}});
    }
    if (tool == "make_data") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"type", "int"}, {"name", "g_var"}}}});
    }
    if (tool == "patch_asm") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"asm", "nop"}}}});
    }
    if (tool == "force_recompile") {
        return routed({{"items", json{{"addr", "0x140001000"}}}});
    }
    if (tool == "set_op_type") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"kind", "offset"}, {"op_n", 0}}}});
    }
    if (tool == "set_type") {
        return routed({{"edits", json{{"addr", "0x140001000"}, {"ty", "int"}}}});
    }
    return routed(json::object());
}

json make_boundary_args(std::string_view tool, const modify_handler_limits_t& limits) {
    if (tool == "set_comments" || tool == "append_comments") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"comment", std::string(limits.max_comment_bytes, 'c')}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "define_code" || tool == "define_func") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", "0x140001000"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "undefine") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"size", limits.max_data_bytes}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "make_data") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"type", std::string(limits.max_type_bytes, 't')}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "patch_asm") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"asm", std::string(limits.max_asm_bytes, 'n')}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "force_recompile") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", "0x140001000"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "set_op_type") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"kind", "offset"}, {"op_n", 0}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "set_type") {
        json edits = json::array();
        for (std::size_t i = 0; i < limits.max_type_batch_items; ++i) {
            edits.push_back({{"addr", "0x140001000"}, {"ty", std::string(limits.max_type_bytes, 't')}});
        }
        return routed({{"edits", std::move(edits)}});
    }
    if (tool == "rename") {
        json funcs = json::array();
        for (std::size_t i = 0; i < limits.max_rename_batch_items; ++i) {
            funcs.push_back({{"addr", "0x140001000"}, {"name", std::string(limits.max_name_bytes, 'n')}});
        }
        return routed({{"batch", json{{"func", std::move(funcs)}}}});
    }
    return routed(json::object());
}

json make_invalid_args(std::string_view tool, const modify_handler_limits_t& limits) {
    if (tool == "set_comments" || tool == "append_comments") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items + 1; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"comment", "x"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "define_code" || tool == "define_func") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items + 1; ++i) {
            items.push_back({{"addr", "0x140001000"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "undefine") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"size", limits.max_data_bytes + 1}}}});
    }
    if (tool == "make_data") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"type", std::string(limits.max_type_bytes + 1, 't')}}}});
    }
    if (tool == "patch_asm") {
        return routed({{"items", json{{"addr", "0x140001000"}, {"asm", std::string(limits.max_asm_bytes + 1, 'n')}}}});
    }
    if (tool == "set_op_type") {
        json items = json::array();
        for (std::size_t i = 0; i < limits.max_batch_items + 1; ++i) {
            items.push_back({{"addr", "0x140001000"}, {"kind", "offset"}});
        }
        return routed({{"items", std::move(items)}});
    }
    if (tool == "set_type") {
        json edits = json::array();
        for (std::size_t i = 0; i < limits.max_type_batch_items + 1; ++i) {
            edits.push_back({{"addr", "0x140001000"}, {"ty", "int"}});
        }
        return routed({{"edits", std::move(edits)}});
    }
    if (tool == "rename") {
        return routed({{"batch", json::object()}});
    }
    if (tool == "force_recompile") {
        return routed({{"items", 123}});
    }
    return routed(json::object());
}

void verify_contracts(const modify_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas) {
    require(handlers.size() == k_modify_tool_count,
            "modify handler contract count is not exactly eleven");
    require(modify_tool_names().size() == k_modify_tool_count,
            "modify name ledger count is not exactly eleven");
    std::unordered_set<std::string> unique_names;
    for (std::size_t index = 0; index < k_modify_tool_count; ++index) {
        const auto name = modify_tool_names()[index];
        const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
        const auto& contract = handlers.contract_at(index);
        require(descriptor != nullptr, "modify generated descriptor is missing");
        require(contract.name == name && handlers.find(name) == &contract,
                "modify handler lookup differs from the exact name ledger");
        require(unique_names.emplace(contract.name).second,
                "modify handler name ledger contains a duplicate");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "modify generated adapter symbol differs from the linked function name");
        require(contract.description == descriptor->description,
                "modify generated description was not preserved");
        require(contract.input_schema == json::parse(
                    descriptor->input_schema_json.begin(), descriptor->input_schema_json.end()) &&
                    contract.output_schema == json::parse(
                    descriptor->output_schema_json.begin(), descriptor->output_schema_json.end()) &&
                    contract.annotations == json::parse(
                    descriptor->annotations_json.begin(), descriptor->annotations_json.end()),
                "modify generated schema or annotations were not preserved");
        require(contract.target_policy.requirement == protocol::target_requirement_t::optional &&
                    contract.target_policy.accepts_pid &&
                    contract.target_policy.accepts_bin_name,
                "modify target routing policy is not the generated optional selector policy");
        require(contract.effect_policy.effect == protocol::tool_effect_t::workspace_overlay_mutation &&
                    contract.effect_policy.lock == protocol::effect_lock_t::workspace_overlay_transaction &&
                    !contract.effect_policy.read_only && !contract.effect_policy.unsafe,
                "modify effect policy is not generated overlay mutation transaction");
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "modify generated contract does not validate through the schema runtime");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "modify tool list entry altered schema or embedded provenance");
    }
}

void verify_fixture(std::string_view tool_name,
                    adapters::modify_adapter_t adapter,
                    const modify_handlers_t& handlers,
                    backend_state_t& backend,
                    std::size_t& completed) {
    const json metadata{{"fixture_tool", std::string(tool_name)}};

    json valid = make_valid_args(tool_name);
    std::size_t before = backend.calls;
    auto result = adapter(handlers, valid, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), tool_name, "valid", result.text());
    require_fixture(backend.calls == before + 1, tool_name, "valid",
                    "backend was not invoked exactly once");
    require_fixture(backend.last_contract == tool_name, tool_name, "valid",
                    "request reached the wrong tool in backend");
    require_fixture(backend.last_pid == 4101 && backend.saw_deadline, tool_name, "valid",
                    "target binding or deadline was not propagated");
    json expected_args = valid;
    expected_args.erase("pid");
    expected_args.erase("bin_name");
    require_fixture(backend.last_arguments == expected_args, tool_name, "valid",
                    "routing selectors leaked into backend arguments");
    require_fixture(result.structured_content().is_object() &&
                        !result.structured_content().contains("_meta"),
                    tool_name, "valid", "structured output or metadata separation changed");
    require_fixture(result.aida_metadata().value("tool", std::string()) == tool_name,
                    tool_name, "valid", "provenance metadata is incomplete");
    ++completed;

    json boundary = make_boundary_args(tool_name, handlers.limits());
    if (boundary.size() > 1 || (boundary.is_object() && boundary.contains("pid"))) {
        before = backend.calls;
        result = adapter(handlers, boundary, cancellation_token_t::create(), metadata);
        require_fixture(!result.is_error(), tool_name, "boundary", result.text());
        require_fixture(backend.calls == before + 1, tool_name, "boundary",
                        "pinned maximum was not admitted by the backend lane");
        ++completed;
    }

    json invalid = make_invalid_args(tool_name, handlers.limits());
    before = backend.calls;
    result = adapter(handlers, invalid, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    tool_name, "invalid", "out-of-policy input was not rejected canonically");
    require_fixture(backend.calls == before, tool_name, "invalid",
                    "invalid input reached the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "policy", std::string()) == "bounded_modify_adapter",
        tool_name, "invalid", "bounded policy diagnostics are absent");
    ++completed;

    json ambiguous = valid;
    ambiguous.erase("pid");
    ambiguous["bin_name"] = "fixture";
    before = backend.calls;
    result = adapter(handlers, ambiguous, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED",
                    tool_name, "ambiguous_target",
                    "ambiguous binary selector was not rejected canonically");
    require_fixture(backend.calls == before, tool_name, "ambiguous_target",
                    "ambiguous target reached the backend");
    ++completed;

    auto cancellation = cancellation_token_t::create();
    backend.cancel_during_dispatch = cancellation.state();
    before = backend.calls;
    result = adapter(handlers, valid, cancellation, metadata);
    backend.cancel_during_dispatch.reset();
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    tool_name, "cancellation",
                    "in-flight cancellation was not observed canonically");
    ++completed;

    backend.invalid_output = true;
    before = backend.calls;
    result = adapter(handlers, valid, cancellation_token_t::create(), metadata);
    backend.invalid_output = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    tool_name, "output_validation",
                    "schema-invalid structured output was not rejected canonically");
    ++completed;
}

void verify_modify_handlers() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1, 4101, 0xA101ULL, "fixture-alpha.exe"))),
            "first modify handler target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(2, 4102, 0xA102ULL, "fixture-beta.exe"))),
            "second modify handler target publication failed");

    backend_state_t backend;
    workspace_adapter_handlers_t workspace_handlers;
    workspace_handlers.overlay = [&backend](const adapter_call_context_t& context,
                                            const adapter_request_t& request) {
        return backend.respond("overlay", context, request);
    };
    workspace_adapter_t workspace(resolver, locks, std::move(workspace_handlers));
    protocol::schema_runtime_t schemas(64);
    modify_handlers_t handlers(workspace, schemas);

    verify_contracts(handlers, schemas);

    std::size_t completed = 0;
    for (std::size_t index = 0; index < k_modify_tool_count; ++index) {
        const auto name = modify_tool_names()[index];
        require(k_modify_adapters[index] != nullptr,
                "modify adapter function is not linked");
        verify_fixture(name, k_modify_adapters[index], handlers, backend, completed);
    }

    require(completed >= k_modify_tool_count * 5U,
            "modify handler harness did not execute all fixture families");
}

}

bool run_modify_handlers_harness(std::string& failure) {
    try {
        verify_modify_handlers();
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
