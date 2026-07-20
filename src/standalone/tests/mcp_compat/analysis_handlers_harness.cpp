#include "analysis_handlers_harness.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/compat/handlers/analysis.hpp"

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
namespace protocol = aida::standalone::mcp::protocol;
using protocol::cancellation_token_t;
using protocol::json;

enum class observed_lane_t : std::uint8_t {
    none,
    query,
    analysis,
    decompilation,
};

struct tool_fixture_t final {
    std::string_view name;
    adapters::analysis_adapter_t adapter = nullptr;
    json valid;
    json boundary;
    json invalid;
    observed_lane_t expected_lane = observed_lane_t::none;
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

struct backend_state_t final {
    std::size_t calls = 0;
    bool invalid_output = false;
    observed_lane_t last_lane = observed_lane_t::none;
    std::string last_contract;
    json last_arguments = json::object();
    std::uint32_t last_pid = 0;
    bool saw_deadline = false;
    std::shared_ptr<std::atomic_bool> cancel_during_dispatch;

    adapter_result_t<adapter_response_t> respond(
        observed_lane_t lane, const adapter_call_context_t& context,
        const adapter_request_t& request) {
        ++calls;
        last_lane = lane;
        last_contract = context.contract == nullptr ? std::string() : std::string(context.contract->name);
        last_pid = context.target ? context.target->target().pid : 0;
        saw_deadline = request.deadline.has_value() &&
            *request.deadline > std::chrono::steady_clock::now();
        last_arguments = json::parse(request.payload, nullptr, false);
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

json repeated_strings(std::size_t count, std::string_view prefix) {
    json values = json::array();
    for (std::size_t index = 0; index < count; ++index) {
        values.push_back(std::string(prefix) + std::to_string(index));
    }
    return values;
}

json repeated_value(std::size_t count, std::string_view value) {
    json values = json::array();
    for (std::size_t index = 0; index < count; ++index) {
        values.push_back(value);
    }
    return values;
}

json routed(json arguments) {
    arguments["pid"] = 4101;
    return arguments;
}

std::vector<tool_fixture_t> make_fixtures(const analysis_handler_limits_t& limits) {
    std::vector<tool_fixture_t> fixtures;
    fixtures.reserve(k_analysis_tool_count);

    fixtures.push_back({
        "decompile", &adapters::decompile,
        routed({{"addr", "main"}}),
        routed({{"addr", std::string(limits.max_address_bytes, 'A')}}),
        routed({{"addr", ""}}),
        observed_lane_t::decompilation});

    fixtures.push_back({
        "disasm", &adapters::disasm,
        routed({{"addr", "0x140001000"}}),
        routed({{"addr", "main"},
                {"max_instructions", limits.max_disasm_instructions},
                {"offset", limits.max_offset}}),
        routed({{"addr", "main"},
                {"max_instructions", limits.max_disasm_instructions + 1ULL}}),
        observed_lane_t::query});

    fixtures.push_back({
        "func_profile", &adapters::func_profile,
        routed({{"queries", json{{"addr", "main"}}}}),
        routed({{"queries", json{{"addr", "*"},
                                   {"count", limits.max_profile_results},
                                   {"max_items", limits.max_profile_list_items},
                                   {"offset", limits.max_offset},
                                   {"sort_by", "size"},
                                   {"filter", std::string(limits.max_filter_bytes, 'f')}}}}),
        routed({{"queries", json{{"count", limits.max_profile_results + 1ULL}}}}),
        observed_lane_t::query});

    fixtures.push_back({
        "analyze_batch", &adapters::analyze_batch,
        routed({{"queries", json{{"addr", "main"}}}}),
        routed({{"queries", json{{"addr", "main"},
                                   {"max_blocks", limits.max_batch_blocks},
                                   {"max_callees", limits.max_batch_relations},
                                   {"max_callers", limits.max_batch_relations},
                                   {"max_constants", limits.max_batch_constants},
                                   {"max_disasm_insns", limits.max_batch_disasm_instructions},
                                   {"max_strings", limits.max_batch_strings}}}}),
        routed({{"queries", json{{"addr", "main"},
                                   {"max_disasm_insns",
                                    limits.max_batch_disasm_instructions + 1ULL}}}}),
        observed_lane_t::analysis});

    fixtures.push_back({
        "xrefs_to", &adapters::xrefs_to,
        routed({{"addrs", "main"}}),
        routed({{"addrs", repeated_strings(limits.max_target_count, "xref_")},
                {"limit", limits.max_xrefs_per_target}}),
        routed({{"addrs", "main"}, {"limit", limits.max_xrefs_per_target + 1ULL}}),
        observed_lane_t::query});

    fixtures.push_back({
        "xref_query", &adapters::xref_query,
        routed({{"queries", json{{"addr", "main"}}}}),
        routed({{"queries", json{{"addr", "main"},
                                   {"count", limits.max_xref_query_results},
                                   {"offset", limits.max_offset},
                                   {"direction", "both"},
                                   {"xref_type", "data"},
                                   {"sort_by", "type"}}}}),
        routed({{"queries", json{{"addr", "main"},
                                   {"count", limits.max_xref_query_results + 1ULL}}}}),
        observed_lane_t::query});

    fixtures.push_back({
        "xrefs_to_field", &adapters::xrefs_to_field,
        routed({{"queries", json{{"struct", "IMAGE_DOS_HEADER"}, {"field", "e_lfanew"}}}}),
        routed({{"queries", json{{"struct", std::string(limits.max_address_bytes, 'S')},
                                   {"field", std::string(limits.max_address_bytes, 'F')}}}}),
        routed({{"queries", json{{"struct", "IMAGE_DOS_HEADER"}, {"field", ""}}}}),
        observed_lane_t::query});

    fixtures.push_back({
        "callees", &adapters::callees,
        routed({{"addrs", "main"}}),
        routed({{"addrs", repeated_strings(limits.max_target_count, "callee_")},
                {"limit", limits.max_callees_per_function}}),
        routed({{"addrs", "main"},
                {"limit", limits.max_callees_per_function + 1ULL}}),
        observed_lane_t::query});

    fixtures.push_back({
        "find_bytes", &adapters::find_bytes,
        routed({{"patterns", "48 8B ?? ??"}}),
        routed({{"patterns", repeated_value(limits.max_target_count, "48 8B ?? ??")},
                {"limit", limits.max_find_matches},
                {"offset", limits.max_offset}}),
        routed({{"patterns", "48 8B"}, {"limit", limits.max_find_matches + 1ULL}}),
        observed_lane_t::query});

    fixtures.push_back({
        "basic_blocks", &adapters::basic_blocks,
        routed({{"addrs", "main"}}),
        routed({{"addrs", repeated_strings(limits.max_target_count, "block_")},
                {"max_blocks", limits.max_basic_blocks},
                {"offset", limits.max_offset}}),
        routed({{"addrs", "main"}, {"max_blocks", limits.max_basic_blocks + 1ULL}}),
        observed_lane_t::query});

    fixtures.push_back({
        "find", &adapters::find,
        routed({{"type", "string"}, {"targets", "password"}}),
        routed({{"type", "code_ref"},
                {"targets", repeated_strings(limits.max_target_count, "target_")},
                {"limit", limits.max_find_matches},
                {"offset", limits.max_offset}}),
        routed({{"type", "unsupported"}, {"targets", "main"}}),
        observed_lane_t::query});

    fixtures.push_back({
        "insn_query", &adapters::insn_query,
        routed({{"queries", json{{"func", "main"}, {"mnem", "call"}}}}),
        routed({{"queries", json{{"allow_broad", true},
                                   {"count", limits.max_instruction_query_results},
                                   {"max_scan_insns", limits.max_instruction_scan},
                                   {"offset", limits.max_offset}}}}),
        routed({{"queries", json{{"allow_broad", true},
                                   {"max_scan_insns", limits.max_instruction_scan + 1ULL}}}}),
        observed_lane_t::query});

    fixtures.push_back({
        "export_funcs", &adapters::export_funcs,
        routed({{"addrs", "main"}}),
        routed({{"addrs", repeated_strings(limits.max_target_count, "export_")},
                {"format", "prototypes"}}),
        routed({{"addrs", "main"}, {"format", "binary"}}),
        observed_lane_t::query});

    fixtures.push_back({
        "callgraph", &adapters::callgraph,
        routed({{"roots", "main"}}),
        routed({{"roots", repeated_strings(limits.max_target_count, "root_")},
                {"max_depth", limits.max_callgraph_depth},
                {"max_nodes", limits.max_callgraph_nodes},
                {"max_edges", limits.max_callgraph_edges},
                {"max_edges_per_func", limits.max_callgraph_edges_per_function}}),
        routed({{"roots", "main"},
                {"max_edges", limits.max_callgraph_edges + 1ULL}}),
        observed_lane_t::query});

    return fixtures;
}

void verify_contracts(const analysis_handlers_t& handlers,
                      protocol::schema_runtime_t& schemas) {
    require(handlers.size() == k_analysis_tool_count,
            "analysis handler contract count is not exactly fourteen");
    require(analysis_tool_names().size() == k_analysis_tool_count,
            "analysis name ledger count is not exactly fourteen");
    std::unordered_set<std::string> unique_names;
    for (std::size_t index = 0; index < k_analysis_tool_count; ++index) {
        const auto name = analysis_tool_names()[index];
        const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
        const auto& contract = handlers.contract_at(index);
        require(descriptor != nullptr, "analysis generated descriptor is missing");
        require(contract.name == name && handlers.find(name) == &contract,
                "analysis handler lookup differs from the exact name ledger");
        require(unique_names.emplace(contract.name).second,
                "analysis handler name ledger contains a duplicate");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "analysis generated adapter symbol differs from the linked function name");
        require(contract.description == descriptor->description,
                "analysis generated description was not preserved");
        require(contract.input_schema == json::parse(
                    descriptor->input_schema_json.begin(), descriptor->input_schema_json.end()) &&
                    contract.output_schema == json::parse(
                    descriptor->output_schema_json.begin(), descriptor->output_schema_json.end()) &&
                    contract.annotations == json::parse(
                    descriptor->annotations_json.begin(), descriptor->annotations_json.end()),
                "analysis generated schema or annotations were not preserved");
        require(contract.target_policy.requirement == protocol::target_requirement_t::optional &&
                    contract.target_policy.accepts_pid &&
                    contract.target_policy.accepts_bin_name,
                "analysis target routing policy is not the generated optional selector policy");
        require(contract.effect_policy.effect == protocol::tool_effect_t::workspace_read &&
                    contract.effect_policy.lock == protocol::effect_lock_t::workspace_shared &&
                    contract.effect_policy.read_only && !contract.effect_policy.unsafe,
                "analysis effect policy is not generated shared workspace read");
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "analysis generated contract does not validate through the schema runtime");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "analysis tool list entry altered schema or embedded provenance");
    }
}

void verify_fixture(const tool_fixture_t& fixture, analysis_handlers_t& handlers,
                    backend_state_t& backend, std::size_t& completed_fixtures) {
    const json metadata{{"fixture_tool", std::string(fixture.name)}};

    std::size_t before = backend.calls;
    auto result = fixture.adapter(
        handlers, fixture.valid, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), fixture.name, "valid", result.text());
    require_fixture(backend.calls == before + 1, fixture.name, "valid",
                    "backend was not invoked exactly once");
    require_fixture(backend.last_contract == fixture.name &&
                        backend.last_lane == fixture.expected_lane,
                    fixture.name, "valid", "request reached the wrong adapter lane");
    require_fixture(backend.last_pid == 4101 && backend.saw_deadline,
                    fixture.name, "valid", "target binding or deadline was not propagated");
    json expected_arguments = fixture.valid;
    expected_arguments.erase("pid");
    expected_arguments.erase("bin_name");
    require_fixture(backend.last_arguments == expected_arguments,
                    fixture.name, "valid", "routing selectors leaked into backend arguments");
    require_fixture(result.structured_content().is_object() &&
                        !result.structured_content().contains("_meta"),
                    fixture.name, "valid", "structured output or metadata separation changed");
    require_fixture(result.aida_metadata().value("tool", std::string()) == fixture.name &&
                        result.aida_metadata().value("fixture_tool", std::string()) == fixture.name &&
                        result.aida_metadata().value("effect", std::string()) == "workspace_read" &&
                        result.aida_metadata().value("lock", std::string()) == "workspace_shared",
                    fixture.name, "valid", "top-level provenance metadata is incomplete");
    ++completed_fixtures;

    before = backend.calls;
    result = fixture.adapter(
        handlers, fixture.boundary, cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), fixture.name, "boundary", result.text());
    require_fixture(backend.calls == before + 1, fixture.name, "boundary",
                    "pinned maximum was not admitted by the backend lane");
    ++completed_fixtures;

    before = backend.calls;
    result = fixture.adapter(
        handlers, fixture.invalid, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    fixture.name, "invalid", "out-of-policy input was not rejected canonically");
    require_fixture(backend.calls == before, fixture.name, "invalid",
                    "invalid input reached the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "policy", std::string()) == "bounded_analysis_adapter",
        fixture.name, "invalid", "bounded policy diagnostics are absent");
    ++completed_fixtures;

    json ambiguous = fixture.valid;
    ambiguous.erase("pid");
    ambiguous["bin_name"] = "fixture";
    before = backend.calls;
    result = fixture.adapter(
        handlers, ambiguous, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED",
                    fixture.name, "ambiguous target",
                    "ambiguous binary selector was not rejected canonically");
    require_fixture(backend.calls == before, fixture.name, "ambiguous target",
                    "ambiguous target reached the backend");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "adapter_code", std::string()) == "target_ambiguous",
        fixture.name, "ambiguous target", "resolver ambiguity evidence is absent");
    ++completed_fixtures;

    auto cancellation = cancellation_token_t::create();
    backend.cancel_during_dispatch = cancellation.state();
    before = backend.calls;
    result = fixture.adapter(handlers, fixture.valid, cancellation, metadata);
    backend.cancel_during_dispatch.reset();
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    fixture.name, "cancellation",
                    "in-flight cancellation was not observed canonically");
    require_fixture(backend.calls == before + 1, fixture.name, "cancellation",
                    "in-flight cancellation fixture did not enter the backend");
    ++completed_fixtures;

    backend.invalid_output = true;
    before = backend.calls;
    result = fixture.adapter(
        handlers, fixture.valid, cancellation_token_t::create(), metadata);
    backend.invalid_output = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    fixture.name, "output validation",
                    "schema-invalid structured output was not rejected canonically");
    require_fixture(backend.calls == before + 1, fixture.name, "output validation",
                    "output validation fixture did not enter the backend");
    ++completed_fixtures;
}

void verify_analysis_handlers() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1, 4101, 0xA101ULL, "fixture-alpha.exe"))),
            "first analysis handler target publication failed");
    require(static_cast<bool>(resolver.publish(
                make_target(2, 4102, 0xA102ULL, "fixture-beta.exe"))),
            "second analysis handler target publication failed");

    backend_state_t backend;
    workspace_adapter_handlers_t workspace_handlers;
    workspace_handlers.query = [&backend](const adapter_call_context_t& context,
                                          const adapter_request_t& request) {
        return backend.respond(observed_lane_t::query, context, request);
    };
    workspace_handlers.analysis = [&backend](const adapter_call_context_t& context,
                                             const adapter_request_t& request) {
        return backend.respond(observed_lane_t::analysis, context, request);
    };
    workspace_handlers.decompilation = [&backend](const adapter_call_context_t& context,
                                                  const adapter_request_t& request) {
        return backend.respond(observed_lane_t::decompilation, context, request);
    };
    workspace_adapter_t workspace(resolver, locks, std::move(workspace_handlers));
    protocol::schema_runtime_t schemas(64);
    analysis_handlers_t handlers(workspace, schemas);

    verify_contracts(handlers, schemas);
    const auto fixtures = make_fixtures(handlers.limits());
    require(fixtures.size() == k_analysis_tool_count,
            "analysis fixture table does not cover exactly fourteen tools");
    std::size_t completed_fixtures = 0;
    for (const auto& fixture : fixtures) {
        require(fixture.adapter != nullptr, "analysis adapter function is not linked");
        verify_fixture(fixture, handlers, backend, completed_fixtures);
    }
    require(completed_fixtures == k_analysis_tool_count * 6U,
            "analysis handler harness did not execute all eighty-four fixture families");
}

}

bool run_analysis_handlers_harness(std::string& failure) {
    try {
        verify_analysis_handlers();
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
