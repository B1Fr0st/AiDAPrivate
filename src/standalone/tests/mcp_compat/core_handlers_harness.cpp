#include "core_handlers_harness.hpp"

#include "../../src/core/mcp/compat/handlers/core.hpp"

#include <algorithm>
#include <array>
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

struct core_tool_fixture_t final {
    std::string_view name;
    adapters::core_adapter_t adapter;
    json valid;
    json invalid;
    bool target_independent = false;
    bool checkpoint = false;
};

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

struct core_backend_state_t final {
    std::size_t query_calls = 0;
    std::size_t checkpoint_calls = 0;
    bool invalid_output = false;
    std::shared_ptr<std::atomic_bool> cancel_during_dispatch;
    std::string last_contract;
    std::uint32_t last_pid = 0;
    bool saw_deadline = false;

    adapter_result_t<adapter_response_t> respond_query(
        const adapter_call_context_t& context,
        const adapter_request_t& request) {
        ++query_calls;
        last_contract = context.contract == nullptr
            ? std::string()
            : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0;
        saw_deadline = request.deadline.has_value() &&
            *request.deadline > std::chrono::steady_clock::now();
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
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

    adapter_result_t<adapter_response_t> respond_checkpoint(
        const adapter_call_context_t& context,
        const adapter_request_t& request) {
        ++checkpoint_calls;
        last_contract = context.contract == nullptr
            ? std::string()
            : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0;
        saw_deadline = request.deadline.has_value() &&
            *request.deadline > std::chrono::steady_clock::now();
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
        }
        json checkpoint_output{{"ok", true}, {"path", nullptr}};
        return adapter_result_t<adapter_response_t>::success(
            {checkpoint_output.dump(), false});
    }
};

std::vector<core_tool_fixture_t> make_fixtures(const core_handler_limits_t& limits) {
    std::vector<core_tool_fixture_t> fixtures;
    fixtures.reserve(k_core_tool_count);

    fixtures.push_back({
        "server_health", &adapters::server_health,
        routed({}),
        routed({{"pid", 0}}),
        false, false});

    fixtures.push_back({
        "lookup_funcs", &adapters::lookup_funcs,
        routed({{"queries", json::array({"main"})}}),
        routed({{"queries", json::array({std::string(limits.max_query_text_bytes + 1, 'x')})}}),
        false, false});

    fixtures.push_back({
        "int_convert", &adapters::int_convert,
        json{{"inputs", json::array({json{{"text", "42"}}})}},
        json{{"inputs", json::array({json{{"text", "42"}, {"size", limits.max_integer_bytes + 1}}})}},
        true, false});

    fixtures.push_back({
        "list_funcs", &adapters::list_funcs,
        routed({{"queries", json::array({json{{"offset", 0}, {"count", 10}}})}}),
        routed({{"queries", json::array({json{{"count", limits.max_page_items + 1}}})}}),
        false, false});

    fixtures.push_back({
        "func_query", &adapters::func_query,
        routed({{"queries", json::array({json{{"filter", "main"}}})}}),
        routed({{"queries", json::array({json{{"count", limits.max_page_items + 1}}})}}),
        false, false});

    fixtures.push_back({
        "list_globals", &adapters::list_globals,
        routed({{"queries", json::array({json{{"offset", 0}, {"count", 10}}})}}),
        routed({{"queries", json::array({json{{"count", limits.max_page_items + 1}}})}}),
        false, false});

    fixtures.push_back({
        "entity_query", &adapters::entity_query,
        routed({{"queries", json::array({json{{"kind", "function"}}})}}),
        routed({{"queries", json::array({json{{"count", limits.max_page_items + 1}}})}}),
        false, false});

    fixtures.push_back({
        "imports", &adapters::imports,
        routed({{"offset", 0}, {"count", 10}}),
        routed({{"count", limits.max_page_items + 1}}),
        false, false});

    fixtures.push_back({
        "imports_query", &adapters::imports_query,
        routed({{"queries", json::array({json{{"filter", "kernel32"}}})}}),
        routed({{"queries", json::array({json{{"count", limits.max_page_items + 1}}})}}),
        false, false});

    fixtures.push_back({
        "idb_save", &adapters::idb_save,
        routed({}),
        routed({{"path", std::string(limits.max_query_text_bytes + 1, 'x')}}),
        false, true});

    fixtures.push_back({
        "find_regex", &adapters::find_regex,
        routed({{"pattern", "main"}}),
        routed({{"pattern", std::string(limits.max_query_text_bytes + 1, 'x')}}),
        false, false});

    fixtures.push_back({
        "search_text", &adapters::search_text,
        routed({{"pattern", "password"}}),
        routed({{"pattern", std::string(limits.max_query_text_bytes + 1, 'x')}}),
        false, false});

    return fixtures;
}

void verify_contracts(const core_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas) {
    require(handlers.size() == k_core_tool_count,
            "core handler contract count is not exactly twelve");
    require(core_tool_names().size() == k_core_tool_count,
            "core name ledger count is not exactly twelve");
    std::unordered_set<std::string> unique_names;
    for (std::size_t index = 0; index < k_core_tool_count; ++index) {
        const auto name = core_tool_names()[index];
        const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
        const auto& contract = handlers.contract_at(index);
        require(descriptor != nullptr, "core generated descriptor is missing");
        require(contract.name == name && handlers.find(name) == &contract,
                "core handler lookup differs from the exact name ledger");
        require(unique_names.emplace(contract.name).second,
                "core handler name ledger contains a duplicate");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "core generated adapter symbol differs from the linked function name");
        require(contract.description == descriptor->description,
                "core generated description was not preserved");
        require(contract.input_schema == json::parse(
                    descriptor->input_schema_json.begin(),
                    descriptor->input_schema_json.end()) &&
                    contract.output_schema == json::parse(
                    descriptor->output_schema_json.begin(),
                    descriptor->output_schema_json.end()) &&
                    contract.annotations == json::parse(
                    descriptor->annotations_json.begin(),
                    descriptor->annotations_json.end()),
                "core generated schema or annotations were not preserved");
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "core generated contract does not validate through the schema runtime");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "core tool list entry altered schema or embedded provenance");

        if (name == "int_convert") {
            require(contract.target_policy.requirement ==
                        protocol::target_requirement_t::independent &&
                        !contract.target_policy.accepts_pid &&
                        !contract.target_policy.accepts_bin_name,
                    "int_convert target policy is not independent");
            require(!descriptor->target_dependent && !descriptor->accepts_pid &&
                        !descriptor->accepts_bin_name,
                    "int_convert descriptor routing is not target-independent");
        } else {
            require(contract.target_policy.requirement ==
                        protocol::target_requirement_t::optional &&
                        contract.target_policy.accepts_pid &&
                        contract.target_policy.accepts_bin_name,
                    "core target routing policy is not the generated optional selector policy");
            require(descriptor->target_dependent && descriptor->accepts_pid &&
                        descriptor->accepts_bin_name,
                    "core descriptor routing is not target-dependent optional selector");
        }

        if (name == "idb_save") {
            require(!contract.effect_policy.read_only,
                        "idb_save effect policy should not be read-only");
            require(contract.effect_policy.effect ==
                        protocol::tool_effect_t::workspace_checkpoint,
                        "idb_save effect policy is not workspace checkpoint");
            require(contract.effect_policy.lock ==
                        protocol::effect_lock_t::workspace_checkpoint,
                        "idb_save effect lock is not workspace checkpoint");
            require(descriptor->description.find("workspace") != std::string_view::npos,
                        "idb_save descriptor does not mention workspace");
            require(descriptor->description.find("checkpoint") != std::string_view::npos,
                        "idb_save descriptor does not mention checkpoint");
            require(descriptor->description.find("IDB") == std::string_view::npos,
                        "idb_save descriptor should not mention IDB");
        } else {
            require(contract.effect_policy.read_only &&
                        contract.effect_policy.effect ==
                        protocol::tool_effect_t::workspace_read &&
                        contract.effect_policy.lock ==
                        protocol::effect_lock_t::workspace_shared &&
                        !contract.effect_policy.unsafe,
                        "core effect policy is not generated shared workspace read");
        }
    }
}

void verify_fixture(const core_tool_fixture_t& fixture,
                    const core_handlers_t& handlers,
                    core_backend_state_t& backend,
                    std::size_t& completed_fixtures) {
    const json metadata{{"fixture_tool", std::string(fixture.name)}};

    auto result = fixture.adapter(
        handlers, fixture.valid, cancellation_token_t::create(), {}, metadata);
    require_fixture(!result.is_error(), fixture.name, "valid", result.text());
    if (fixture.target_independent) {
        require_fixture(backend.query_calls == 0 && backend.checkpoint_calls == 0,
                        fixture.name, "valid",
                        "target-independent tool should not call the workspace adapter");
        require_fixture(result.aida_metadata().value("adapter", std::string()) ==
                            "local_integer_conversion",
                        fixture.name, "valid",
                        "int_convert should use the local integer conversion adapter");
    } else if (fixture.checkpoint) {
        require_fixture(backend.checkpoint_calls > 0 && backend.query_calls == 0,
                        fixture.name, "valid",
                        "checkpoint tool should route to checkpoint handler not query");
        require_fixture(result.structured_content().value("ok", false) == true,
                        fixture.name, "valid",
                        "checkpoint should report ok=true on success");
        require_fixture(result.aida_metadata().value("workspace_checkpoint", false) == true,
                        fixture.name, "valid",
                        "checkpoint metadata should include workspace_checkpoint=true");
        require_fixture(result.aida_metadata().value("idb_i64_supported", true) == false,
                        fixture.name, "valid",
                        "checkpoint metadata should include idb_i64_supported=false");
    } else {
        require_fixture(backend.query_calls > 0, fixture.name, "valid",
                        "workspace adapter query handler was not invoked");
        require_fixture(backend.last_pid == 4101 && backend.saw_deadline,
                        fixture.name, "valid",
                        "target binding or deadline was not propagated");
    }
    require_fixture(result.structured_content().is_object(),
                    fixture.name, "valid", "structured output is not an object");
    require_fixture(result.aida_metadata().value("tool", std::string()) == fixture.name,
                    fixture.name, "valid", "tool provenance metadata is absent");
    ++completed_fixtures;

    const std::size_t before_query = backend.query_calls;
    const std::size_t before_checkpoint = backend.checkpoint_calls;
    result = fixture.adapter(
        handlers, fixture.invalid, cancellation_token_t::create(), {}, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    fixture.name, "invalid", "invalid input was not rejected canonically");
    require_fixture(backend.query_calls == before_query &&
                        backend.checkpoint_calls == before_checkpoint,
                    fixture.name, "invalid", "invalid input reached the backend");
    ++completed_fixtures;

    if (fixture.target_independent) {
        auto cancellation = cancellation_token_t::create(true);
        result = fixture.adapter(handlers, fixture.valid, cancellation, {}, metadata);
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_CANCELLED",
                        fixture.name, "cancellation",
                        "pre-cancelled invocation was not observed canonically");
    } else {
        auto cancellation = cancellation_token_t::create();
        backend.cancel_during_dispatch = cancellation.state();
        result = fixture.adapter(handlers, fixture.valid, cancellation, {}, metadata);
        backend.cancel_during_dispatch.reset();
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_CANCELLED",
                        fixture.name, "cancellation",
                        "in-flight cancellation was not observed canonically");
    }
    ++completed_fixtures;
}

void verify_idb_save_idb_path_rejection(const core_handlers_t& handlers,
                                        core_backend_state_t& backend) {
    const json idb_args{{"path", "output.idb"}, {"pid", 4101}};
    const std::size_t before_checkpoint = backend.checkpoint_calls;
    auto result = adapters::idb_save(
        handlers, idb_args, cancellation_token_t::create(), {},
        json{{"fixture_tool", "idb_save"}, {"scenario", "idb_path_rejection"}});
    require_fixture(!result.is_error(), "idb_save", "idb path rejection",
                    "idb path rejection should return a success with ok=false, not an error");
    require_fixture(result.structured_content().value("ok", true) == false,
                    "idb_save", "idb path rejection",
                    "idb path rejection should set ok to false");
    const auto error_text = result.structured_content().value("error", std::string());
    require_fixture(error_text.find("IDB") != std::string::npos ||
                        error_text.find("idb") != std::string::npos ||
                        error_text.find("I64") != std::string::npos ||
                        error_text.find("i64") != std::string::npos,
                    "idb_save", "idb path rejection",
                    "idb path rejection error message does not mention IDB or I64");
    require_fixture(result.aida_metadata().value("workspace_checkpoint", false) == true,
                    "idb_save", "idb path rejection",
                    "idb path rejection metadata should still include workspace_checkpoint");
    require_fixture(result.aida_metadata().value("idb_i64_supported", true) == false,
                    "idb_save", "idb path rejection",
                    "idb path rejection metadata should still include idb_i64_supported=false");
    require_fixture(backend.checkpoint_calls == before_checkpoint,
                    "idb_save", "idb path rejection",
                    "idb path rejection should not reach the checkpoint handler");
}

void verify_int_convert_target_independence(const core_handlers_t& handlers) {
    const auto* contract = handlers.find("int_convert");
    require(contract != nullptr,
            "int_convert contract is not registered in the core handler group");
    require(contract->target_policy.requirement ==
                protocol::target_requirement_t::independent,
            "int_convert target requirement is not independent");
    require(!contract->target_policy.accepts_pid,
            "int_convert should not accept pid selector");
    require(!contract->target_policy.accepts_bin_name,
            "int_convert should not accept bin_name selector");

    json with_pid{{"inputs", json::array({json{{"text", "42"}}})}, {"pid", 4101}};
    auto result = adapters::int_convert(
        handlers, with_pid, cancellation_token_t::create(), {},
        json{{"fixture_tool", "int_convert"}, {"scenario", "target_independence"}});
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "int_convert", "target independence",
                    "int_convert should reject pid selector as invalid input");

    json with_bin{{"inputs", json::array({json{{"text", "42"}}})}, {"bin_name", "target.exe"}};
    result = adapters::int_convert(
        handlers, with_bin, cancellation_token_t::create(), {},
        json{{"fixture_tool", "int_convert"}, {"scenario", "target_independence"}});
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "int_convert", "target independence",
                    "int_convert should reject bin_name selector as invalid input");
}

void verify_core_handlers() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1, 4101, 0xA101ULL, "fixture-alpha.exe"))),
            "first core handler target publication failed");

    core_backend_state_t backend;
    workspace_adapter_handlers_t workspace_handlers;
    workspace_handlers.query = [&backend](
        const adapter_call_context_t& context,
        const adapter_request_t& request) {
        return backend.respond_query(context, request);
    };
    workspace_handlers.checkpoint = [&backend](
        const adapter_call_context_t& context,
        const adapter_request_t& request) {
        return backend.respond_checkpoint(context, request);
    };

    workspace_adapter_t workspace(resolver, locks, std::move(workspace_handlers));
    protocol::schema_runtime_t schemas(64);
    core_handlers_t handlers(workspace, schemas);

    verify_contracts(handlers, schemas);
    const auto fixtures = make_fixtures(handlers.limits());
    require(fixtures.size() == k_core_tool_count,
            "core fixture table does not cover exactly twelve tools");
    std::size_t completed_fixtures = 0;
    for (const auto& fixture : fixtures) {
        require(fixture.adapter != nullptr,
                "core adapter function is not linked");
        verify_fixture(fixture, handlers, backend, completed_fixtures);
    }
    require(completed_fixtures == k_core_tool_count * 3U,
            "core handler harness did not execute all thirty-six fixture families");

    verify_idb_save_idb_path_rejection(handlers, backend);
    verify_int_convert_target_independence(handlers);
}

}

bool run_core_handlers_harness(std::string& failure) {
    try {
        verify_core_handlers();
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
