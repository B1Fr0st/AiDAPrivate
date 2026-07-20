#include "core_handlers_harness.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/compat/handlers/core.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
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
namespace protocol = aida::standalone::mcp::protocol;
using protocol::cancellation_token_t;
using protocol::json;

constexpr std::size_t k_per_tool_fixture_count = 5;
constexpr std::size_t k_forwarded_payload_fixture_count = 9;
constexpr std::size_t k_special_fixture_count = 6;

struct core_tool_fixture_t final {
    std::string_view name;
    adapters::core_adapter_t adapter;
    json valid;
    json invalid;
    bool target_independent = false;
    bool checkpoint = false;
};

enum class checkpoint_backend_mode_t : std::uint8_t {
    success,
    adapter_failure,
    malformed_output,
    i64_output,
};

void require(bool condition, std::string_view message) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view tool, std::string_view category,
                     std::string_view detail) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, detail, __FILE__, __LINE__);
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
    json last_arguments = json::object();
    std::uint32_t last_pid = 0;
    bool saw_deadline = false;
    std::optional<json> query_output;
    checkpoint_backend_mode_t checkpoint_mode = checkpoint_backend_mode_t::success;

    void reset_controls() {
        invalid_output = false;
        cancel_during_dispatch.reset();
        query_output.reset();
        checkpoint_mode = checkpoint_backend_mode_t::success;
    }

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
        last_arguments = json::parse(request.payload, nullptr, false);
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
        }
        json output{{"__schema_violation", true}};
        if (!invalid_output) {
            if (query_output) {
                output = *query_output;
            } else if (context.contract == nullptr) {
                return adapter_result_t<adapter_response_t>::failure(
                    {adapter_error_code_t::backend_rejected, "fixture_contract_missing", 0, 0});
            } else {
                const json schema = json::parse(
                    context.contract->output_schema_json.begin(),
                    context.contract->output_schema_json.end());
                output = schema_instance(schema);
            }
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
        last_arguments = json::parse(request.payload, nullptr, false);
        if (cancel_during_dispatch) {
            cancel_during_dispatch->store(true, std::memory_order_release);
        }
        if (checkpoint_mode == checkpoint_backend_mode_t::adapter_failure) {
            return adapter_result_t<adapter_response_t>::failure(
                {adapter_error_code_t::backend_rejected,
                 "fixture_checkpoint_backend_failed", 0, 0});
        }
        json checkpoint_output;
        if (checkpoint_mode == checkpoint_backend_mode_t::malformed_output) {
            checkpoint_output = json{{"ok", true}, {"path", 7}};
        } else if (checkpoint_mode == checkpoint_backend_mode_t::i64_output) {
            checkpoint_output = json{{"ok", true}, {"path", "fixture.i64"}};
        } else {
            checkpoint_output = json{{"ok", true}, {"path", nullptr}};
        }
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
        json{{"pid", 0}},
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
        require(!schemas.validate(
                     contract.output_schema, json{{"__schema_violation", true}}).valid,
                "core generated output schema admitted a malformed fixture payload");
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
                    protocol::schema_runtime_t& schemas,
                    std::size_t& completed_fixtures) {
    const json metadata{{"fixture_tool", std::string(fixture.name)}};
    backend.reset_controls();

    const std::size_t before_valid_query = backend.query_calls;
    const std::size_t before_valid_checkpoint = backend.checkpoint_calls;
    auto result = fixture.adapter(
        handlers, fixture.valid, cancellation_token_t::create(), {}, metadata);
    require_fixture(!result.is_error(), fixture.name, "valid", result.text());
    if (fixture.target_independent) {
        require_fixture(backend.query_calls == before_valid_query &&
                            backend.checkpoint_calls == before_valid_checkpoint,
                        fixture.name, "valid",
                        "target-independent tool should not call the workspace adapter");
        require_fixture(result.aida_metadata().value("adapter", std::string()) ==
                            "local_integer_conversion",
                        fixture.name, "valid",
                        "int_convert should use the local integer conversion adapter");
    } else if (fixture.checkpoint) {
        require_fixture(backend.checkpoint_calls == before_valid_checkpoint + 1 &&
                            backend.query_calls == before_valid_query,
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
        require_fixture(backend.query_calls == before_valid_query + 1 &&
                            backend.checkpoint_calls == before_valid_checkpoint,
                        fixture.name, "valid",
                        "workspace adapter query handler was not invoked");
        require_fixture(backend.last_pid == 4101 && backend.saw_deadline,
                        fixture.name, "valid",
                        "target binding or deadline was not propagated");
    }
    require_fixture(result.structured_content().is_object(),
                    fixture.name, "valid", "structured output is not an object");
    require_fixture(result.aida_metadata().value("tool", std::string()) == fixture.name,
                    fixture.name, "valid", "tool provenance metadata is absent");
    const auto* contract = handlers.find(fixture.name);
    require_fixture(contract != nullptr &&
                        schemas.validate(
                            contract->output_schema, result.structured_content()).valid,
                    fixture.name, "valid",
                    "handler result does not satisfy the exact generated output schema");
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

    const std::size_t before_routing_query = backend.query_calls;
    const std::size_t before_routing_checkpoint = backend.checkpoint_calls;
    if (fixture.target_independent) {
        json with_pid = fixture.valid;
        with_pid["pid"] = 4101;
        json with_bin_name = fixture.valid;
        with_bin_name["bin_name"] = "fixture-alpha.exe";
        for (const auto& rejected : {with_pid, with_bin_name}) {
            result = fixture.adapter(
                handlers, rejected, cancellation_token_t::create(), {}, metadata);
            require_fixture(result.is_error() &&
                                result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED",
                            fixture.name, "target independence",
                            "target-independent handler admitted a routing selector");
        }
    } else {
        json ambiguous = fixture.valid;
        ambiguous.erase("pid");
        ambiguous["bin_name"] = "fixture";
        result = fixture.adapter(
            handlers, ambiguous, cancellation_token_t::create(), {}, metadata);
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED",
                        fixture.name, "ambiguous target",
                        "ambiguous binary selector was not rejected canonically");
        require_fixture(
            result.structured_content().at("error").at("details").value(
                "adapter_code", std::string()) == "target_ambiguous",
            fixture.name, "ambiguous target", "resolver ambiguity evidence is absent");
    }
    require_fixture(backend.query_calls == before_routing_query &&
                        backend.checkpoint_calls == before_routing_checkpoint,
                    fixture.name, "routing",
                    "rejected routing selectors reached the workspace backend");
    ++completed_fixtures;

    backend.reset_controls();
    const std::size_t before_cancel_query = backend.query_calls;
    const std::size_t before_cancel_checkpoint = backend.checkpoint_calls;
    if (fixture.target_independent) {
        result = fixture.adapter(
            handlers, fixture.valid, cancellation_token_t::create(true), {}, metadata);
        require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                        fixture.name, "cancellation",
                        "pre-cancelled invocation was not observed canonically");
    } else {
        auto cancellation = cancellation_token_t::create();
        backend.cancel_during_dispatch = cancellation.state();
        result = fixture.adapter(handlers, fixture.valid, cancellation, {}, metadata);
        backend.cancel_during_dispatch.reset();
        require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                        fixture.name, "cancellation",
                        "in-flight cancellation was not observed canonically");
        const std::size_t adapter_calls = fixture.checkpoint
            ? backend.checkpoint_calls - before_cancel_checkpoint
            : backend.query_calls - before_cancel_query;
        require_fixture(adapter_calls == 1, fixture.name, "cancellation",
                        "in-flight cancellation did not execute exactly one backend call");
    }
    ++completed_fixtures;

    backend.reset_controls();
    const std::size_t before_output_query = backend.query_calls;
    const std::size_t before_output_checkpoint = backend.checkpoint_calls;
    if (fixture.target_independent) {
        result = fixture.adapter(
            handlers, fixture.valid, cancellation_token_t::create(), {}, metadata);
        require_fixture(!result.is_error() && contract != nullptr &&
                            schemas.validate(
                                contract->output_schema, result.structured_content()).valid &&
                            !schemas.validate(
                                contract->output_schema,
                                json{{"__schema_violation", true}}).valid &&
                            backend.query_calls == before_output_query &&
                            backend.checkpoint_calls == before_output_checkpoint,
                        fixture.name, "output validation",
                        "local handler output schema validation is not exact");
    } else if (fixture.checkpoint) {
        backend.checkpoint_mode = checkpoint_backend_mode_t::malformed_output;
        result = fixture.adapter(
            handlers, fixture.valid, cancellation_token_t::create(), {}, metadata);
        require_fixture(!result.is_error() &&
                            !result.structured_content().value("ok", true) &&
                            result.structured_content().at("path").is_null() &&
                            contract != nullptr &&
                            schemas.validate(
                                contract->output_schema, result.structured_content()).valid,
                        fixture.name, "output validation",
                        "malformed checkpoint output was not normalized to a schema-valid failure");
        require_fixture(backend.checkpoint_calls == before_output_checkpoint + 1 &&
                            backend.query_calls == before_output_query,
                        fixture.name, "output validation",
                        "checkpoint output normalization did not execute exactly one backend call");
    } else {
        backend.invalid_output = true;
        result = fixture.adapter(
            handlers, fixture.valid, cancellation_token_t::create(), {}, metadata);
        backend.invalid_output = false;
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                        fixture.name, "output validation",
                        "schema-invalid structured output was not rejected canonically");
        require_fixture(backend.query_calls == before_output_query + 1 &&
                            backend.checkpoint_calls == before_output_checkpoint,
                        fixture.name, "output validation",
                        "output validation fixture did not execute exactly one query backend call");
    }
    backend.reset_controls();
    ++completed_fixtures;
}

struct forwarded_payload_fixture_t final {
    std::string_view name;
    adapters::core_adapter_t adapter;
    json arguments;
    json expected_payload;
};

void verify_forwarded_payloads(const core_handlers_t& handlers,
                               core_backend_state_t& backend,
                               std::size_t& completed_fixtures) {
    const auto& limits = handlers.limits();
    const json list_funcs_payload{{"queries", json::array({
        json{{"offset", 17}, {"count", 23}, {"filter", "main*"}}
    })}};
    const json func_query_payload{{"queries", json::array({
        json{{"offset", 3}, {"count", 7}, {"filter", "sub_*"},
             {"name_regex", "^sub_"}, {"min_size", 16}, {"max_size", 4096},
             {"sort_by", "size"}, {"descending", true}, {"has_type", true}}
    })}};
    const json list_globals_payload{{"queries", json::array({
        json{{"offset", 5}, {"count", 11}, {"filter", "g_*"}}
    })}};
    const json entity_query_payload{{"queries", json::array({
        json{{"kind", "functions"}, {"offset", 2}, {"count", 13},
             {"filter", "main*"}, {"regex", "^main"}, {"segment", ".text"},
             {"min_addr", "0x140001000"}, {"max_addr", "0x140010000"},
             {"sort_by", "name"}, {"descending", false},
             {"fields", json::array({"addr", "name"})}}
    })}};
    const json imports_payload{{"offset", 19}, {"count", 29}};
    const json imports_query_payload{{"queries", json::array({
        json{{"offset", 4}, {"count", 31}, {"filter", "Create*"},
             {"module", "kernel32*"}}
    })}};
    const json find_regex_arguments{
        {"pattern", "password|secret"}, {"offset", 41},
        {"limit", limits.max_regex_matches + 100ULL}};
    json find_regex_payload = find_regex_arguments;
    find_regex_payload["limit"] = limits.max_regex_matches;
    const json search_arguments{
        {"pattern", "CreateFile"}, {"limit", limits.max_text_hits + 100ULL},
        {"start", "0x140001000"}, {"end", "0x140020000"}, {"regex", true},
        {"case_sensitive", true}, {"include", "comments"}, {"code_only", false}};
    json search_payload = search_arguments;
    search_payload["limit"] = limits.max_text_hits;
    const json search_default_arguments{{"pattern", "CreateProcess"}};
    json search_default_payload = search_default_arguments;
    search_default_payload["limit"] = 30;
    search_default_payload["start"] = "";
    search_default_payload["end"] = "";
    search_default_payload["regex"] = false;
    search_default_payload["case_sensitive"] = false;
    search_default_payload["include"] = "all";
    search_default_payload["code_only"] = true;

    std::vector<forwarded_payload_fixture_t> fixtures;
    fixtures.reserve(k_forwarded_payload_fixture_count);
    fixtures.push_back({"list_funcs", &adapters::list_funcs,
                        routed(list_funcs_payload), list_funcs_payload});
    fixtures.push_back({"func_query", &adapters::func_query,
                        routed(func_query_payload), func_query_payload});
    fixtures.push_back({"list_globals", &adapters::list_globals,
                        routed(list_globals_payload), list_globals_payload});
    fixtures.push_back({"entity_query", &adapters::entity_query,
                        routed(entity_query_payload), entity_query_payload});
    fixtures.push_back({"imports", &adapters::imports,
                        routed(imports_payload), imports_payload});
    fixtures.push_back({"imports_query", &adapters::imports_query,
                        routed(imports_query_payload), imports_query_payload});
    fixtures.push_back({"find_regex", &adapters::find_regex,
                        routed(find_regex_arguments), find_regex_payload});
    fixtures.push_back({"search_text", &adapters::search_text,
                        routed(search_arguments), search_payload});
    fixtures.push_back({"search_text", &adapters::search_text,
                        routed(search_default_arguments), search_default_payload});
    require(fixtures.size() == k_forwarded_payload_fixture_count,
            "core forwarded payload table does not contain exactly nine fixtures");

    for (const auto& fixture : fixtures) {
        backend.reset_controls();
        const std::size_t before = backend.query_calls;
        const auto result = fixture.adapter(
            handlers, fixture.arguments, cancellation_token_t::create(), {},
            json{{"fixture_tool", std::string(fixture.name)},
                 {"fixture_family", "forwarded_payload"}});
        require_fixture(!result.is_error(), fixture.name, "forwarded payload", result.text());
        require_fixture(backend.query_calls == before + 1 &&
                            backend.last_contract == fixture.name &&
                            backend.last_pid == 4101 && backend.saw_deadline &&
                            backend.last_arguments == fixture.expected_payload,
                        fixture.name, "forwarded payload",
                        "pagination or search payload was not forwarded and normalized exactly");
        ++completed_fixtures;
    }
}

void verify_health_normalization(const core_handlers_t& handlers,
                                 core_backend_state_t& backend,
                                 protocol::schema_runtime_t& schemas,
                                 std::size_t& completed_fixtures) {
    backend.reset_controls();
    backend.query_output = json{
        {"status", "ready"}, {"uptime_sec", 12.5},
        {"idb_path", "fixture.idb"}, {"module", "fixture.exe"},
        {"input_path", "C:\\fixture.exe"}, {"imagebase", "0x140000000"},
        {"auto_analysis_ready", true}, {"hexrays_ready", true},
        {"strings_cache_ready", true}, {"strings_cache_size", 17},
    };
    const std::size_t before = backend.query_calls;
    const auto result = adapters::server_health(
        handlers, routed({}), cancellation_token_t::create(), {},
        json{{"fixture_tool", "server_health"}, {"fixture_family", "normalization"}});
    backend.query_output.reset();
    require_fixture(!result.is_error() && backend.query_calls == before + 1,
                    "server_health", "normalization", result.text());
    const auto& output = result.structured_content();
    require_fixture(output.at("idb_path").is_null() &&
                        !output.value("hexrays_ready", true) &&
                        output.value("status", std::string()) == "ready" &&
                        output.value("auto_analysis_ready", false) &&
                        output.value("strings_cache_size", 0) == 17 &&
                        !result.aida_metadata().value("idb_i64_supported", true) &&
                        backend.last_arguments == json::object(),
                    "server_health", "normalization",
                    "standalone health fields or stripped payload are incorrect");
    const auto* contract = handlers.find("server_health");
    require_fixture(contract != nullptr &&
                        schemas.validate(contract->output_schema, output).valid &&
                        json::parse(result.text()) == output,
                    "server_health", "normalization",
                    "normalized health result is not exact generated-schema output");
    ++completed_fixtures;
}

void verify_integer_conversion(const core_handlers_t& handlers,
                               core_backend_state_t& backend,
                               protocol::schema_runtime_t& schemas,
                               std::size_t& completed_fixtures) {
    backend.reset_controls();
    const std::size_t before_query = backend.query_calls;
    const std::size_t before_checkpoint = backend.checkpoint_calls;
    const json arguments{{"inputs", json::array({
        json{{"text", "42"}, {"size", 1}},
        json{{"text", "0x4142"}, {"size", 2}},
        json{{"text", "-1"}, {"size", 1}},
        json{{"text", "not-a-number"}},
    })}};
    const auto result = adapters::int_convert(
        handlers, arguments, cancellation_token_t::create(), {},
        json{{"fixture_tool", "int_convert"}, {"fixture_family", "values"}});
    require_fixture(!result.is_error() && backend.query_calls == before_query &&
                        backend.checkpoint_calls == before_checkpoint,
                    "int_convert", "values", result.text());
    const auto& rows = result.structured_content().at("result");
    require_fixture(rows.is_array() && rows.size() == 4,
                    "int_convert", "values", "conversion row count is incorrect");
    const auto& decimal = rows[0].at("result");
    require_fixture(decimal.value("decimal", std::string()) == "42" &&
                        decimal.value("hexadecimal", std::string()) == "0x2a" &&
                        decimal.value("bytes", std::string()) == "2a" &&
                        decimal.value("ascii", std::string()) == "*" &&
                        decimal.value("binary", std::string()) == "0b101010",
                    "int_convert", "values", "decimal conversion values are incorrect");
    const auto& hexadecimal = rows[1].at("result");
    require_fixture(hexadecimal.value("decimal", std::string()) == "16706" &&
                        hexadecimal.value("hexadecimal", std::string()) == "0x4142" &&
                        hexadecimal.value("bytes", std::string()) == "42 41" &&
                        hexadecimal.value("ascii", std::string()) == "BA",
                    "int_convert", "values", "hexadecimal conversion values are incorrect");
    const auto& negative = rows[2].at("result");
    require_fixture(negative.value("decimal", std::string()) == "-1" &&
                        negative.value("hexadecimal", std::string()) == "-0x1" &&
                        negative.value("bytes", std::string()) == "ff" &&
                        negative.at("ascii").is_null() &&
                        negative.value("binary", std::string()) == "-0b1",
                    "int_convert", "values", "negative conversion values are incorrect");
    require_fixture(rows[3].at("result").is_null() &&
                        rows[3].at("error").is_string() &&
                        !rows[3].at("error").get_ref<const std::string&>().empty(),
                    "int_convert", "values", "invalid conversion did not return row-local error");
    const auto* contract = handlers.find("int_convert");
    require_fixture(contract != nullptr &&
                        schemas.validate(
                            contract->output_schema, result.structured_content()).valid,
                    "int_convert", "values",
                    "integer conversion result violates the exact generated output schema");
    ++completed_fixtures;
}

void verify_checkpoint_failures(const core_handlers_t& handlers,
                                core_backend_state_t& backend,
                                protocol::schema_runtime_t& schemas,
                                std::size_t& completed_fixtures) {
    const auto* contract = handlers.find("idb_save");
    require(contract != nullptr, "idb_save contract is not registered in the core handler group");
    const json metadata{{"fixture_tool", "idb_save"}, {"fixture_family", "failure"}};

    backend.reset_controls();
    backend.checkpoint_mode = checkpoint_backend_mode_t::adapter_failure;
    std::size_t before = backend.checkpoint_calls;
    auto result = adapters::idb_save(
        handlers, routed({}), cancellation_token_t::create(), {}, metadata);
    require_fixture(!result.is_error() && backend.checkpoint_calls == before + 1 &&
                        !result.structured_content().value("ok", true) &&
                        result.structured_content().at("path").is_null() &&
                        result.structured_content().value("error", std::string()) ==
                            "AiDA workspace checkpoint failed: fixture_checkpoint_backend_failed." &&
                        result.aida_metadata().value("workspace_checkpoint", false) &&
                        !result.aida_metadata().value("idb_i64_supported", true) &&
                        schemas.validate(
                            contract->output_schema, result.structured_content()).valid,
                    "idb_save", "backend failure",
                    "checkpoint backend failure was not normalized to the stable schema shape");
    ++completed_fixtures;

    backend.reset_controls();
    for (const auto path : {"output.idb", "output.i64"}) {
        before = backend.checkpoint_calls;
        result = adapters::idb_save(
            handlers, json{{"path", path}, {"pid", 4101}},
            cancellation_token_t::create(), {}, metadata);
        require_fixture(!result.is_error() && backend.checkpoint_calls == before &&
                            !result.structured_content().value("ok", true) &&
                            result.structured_content().at("path").is_null() &&
                            result.structured_content().value("error", std::string()).find(
                                "IDB/I64") != std::string::npos &&
                            result.aida_metadata().value("workspace_checkpoint", false) &&
                            !result.aida_metadata().value("idb_i64_supported", true) &&
                            schemas.validate(
                                contract->output_schema, result.structured_content()).valid,
                        "idb_save", path,
                        "caller-selected IDB/I64 path was not rejected before checkpoint routing");
        ++completed_fixtures;
    }

    backend.reset_controls();
    backend.checkpoint_mode = checkpoint_backend_mode_t::i64_output;
    before = backend.checkpoint_calls;
    result = adapters::idb_save(
        handlers, routed({}), cancellation_token_t::create(), {}, metadata);
    require_fixture(!result.is_error() && backend.checkpoint_calls == before + 1 &&
                        !result.structured_content().value("ok", true) &&
                        result.structured_content().at("path").is_null() &&
                        result.structured_content().value("error", std::string()).find(
                            "IDB/I64") != std::string::npos &&
                        result.aida_metadata().value("workspace_checkpoint", false) &&
                        !result.aida_metadata().value("idb_i64_supported", true) &&
                        schemas.validate(
                            contract->output_schema, result.structured_content()).valid,
                    "idb_save", "backend I64 rejection",
                    "backend-provided I64 reference was not rejected and normalized");
    backend.reset_controls();
    ++completed_fixtures;
}

void verify_core_handlers() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1, 4101, 0xA101ULL, "fixture-alpha.exe"))),
            "first core handler target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(2, 4102, 0xA102ULL, "fixture-beta.exe"))),
            "second core handler target publication failed");

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
        verify_fixture(fixture, handlers, backend, schemas, completed_fixtures);
    }
    verify_forwarded_payloads(handlers, backend, completed_fixtures);
    verify_health_normalization(handlers, backend, schemas, completed_fixtures);
    verify_integer_conversion(handlers, backend, schemas, completed_fixtures);
    verify_checkpoint_failures(handlers, backend, schemas, completed_fixtures);
    require(completed_fixtures ==
                k_core_tool_count * k_per_tool_fixture_count +
                    k_forwarded_payload_fixture_count + k_special_fixture_count,
            "core handler harness did not execute all seventy-five fixture families");
}

}

bool run_core_handlers_harness(std::string& failure) {
    try {
        verify_core_handlers();
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
