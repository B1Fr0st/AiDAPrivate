#include "composite_handlers_harness.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/compat/handlers/composite.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::standalone::tests::mcp_compat {

namespace {

using namespace aida::standalone::mcp::compat;
using namespace aida::standalone::mcp::compat::handlers;
namespace protocol = aida::standalone::mcp::protocol;
using protocol::cancellation_token_t;
using protocol::json;

constexpr std::size_t k_per_composite_tool_fixture_count = 4;
constexpr std::size_t k_composite_edge_fixture_count = 6;

using composite_adapter_fn_t = protocol::mcp_result_t (*)(
    handlers::composite_handlers_t&,
    workspace_adapter_t&,
    protocol::schema_runtime_t&,
    const protocol::json&,
    const protocol::cancellation_token_t&,
    const handlers::composite_invocation_options_t&,
    const protocol::json&);

struct composite_tool_fixture_t final {
    std::string_view name;
    composite_adapter_fn_t adapter;
    json valid;
    json invalid;
    bool mutation = false;
};

enum class composite_backend_scenario_t : std::uint8_t {
    normal,
    partial,
    stale_overlay,
    baseline_started,
    deep_work_started,
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

struct composite_backend_state_t final {
    std::size_t bound_calls = 0;
    std::size_t calls = 0;
    bool invalid_bound_output = false;
    std::shared_ptr<std::atomic_bool> cancel_during_step;
    composite_backend_scenario_t scenario = composite_backend_scenario_t::normal;
    std::size_t scenario_calls = 0;
    bool saw_baseline_permission = false;
    bool saw_deep_work_permission = false;

    void begin(composite_backend_scenario_t next) {
        scenario = next;
        scenario_calls = 0;
        saw_baseline_permission = false;
        saw_deep_work_permission = false;
    }

    composite_step_response_t respond(
        const adapter_call_context_t& context,
        const composite_step_request_t& request,
        const cancellation_token_t&) {
        ++calls;
        ++scenario_calls;
        saw_baseline_permission = saw_baseline_permission || request.permit_baseline_start;
        saw_deep_work_permission =
            saw_deep_work_permission || request.permit_unrequested_deep_work;
        if (cancel_during_step) {
            cancel_during_step->store(true, std::memory_order_release);
        }
        composite_step_response_t response;
        response.status = composite_step_status_t::complete;
        response.workspace_generation =
            context.target ? context.target->target().generation : 0;
        std::uint64_t observed = request.expected_overlay_generation.value_or(1);
        if (scenario == composite_backend_scenario_t::stale_overlay && scenario_calls == 1) {
            ++observed;
        }
        response.observed_overlay_generation = observed;

        switch (request.kind) {
        case composite_step_kind_t::function_snapshot: {
            composite_function_snapshot_t snapshot;
            snapshot.addr = request.subject;
            snapshot.name = "func_" + request.subject;
            snapshot.size = 128;
            snapshot.prototype = "int func_" + request.subject + "(void)";
            snapshot.strings = {"hello", "world"};
            snapshot.constants = {json{{"type", "int"}, {"value", 42}}};
            snapshot.callers = {"caller_a", "caller_b"};
            snapshot.callees = {"callee_a", "callee_b"};
            snapshot.xrefs = json{{"read", json::array({"0x1000"})}};
            snapshot.basic_block_count = 4;
            snapshot.cyclomatic_complexity = 3;
            snapshot.globals = {{"0x2000", "g_global"}};
            response.payload = std::move(snapshot);
            break;
        }
        case composite_step_kind_t::decompile_function: {
            composite_text_snapshot_t text;
            if (observed <= 1) {
                text.text = "int func_" + request.subject + "(void) { return 0; }";
            } else {
                text.text = "int renamed_" + request.subject + "(void) { return 1; }";
            }
            response.payload = std::move(text);
            break;
        }
        case composite_step_kind_t::disassemble_function: {
            composite_text_snapshot_t text;
            text.text = "mov rax, 0\nret\n";
            response.payload = std::move(text);
            break;
        }
        case composite_step_kind_t::xref_neighbors: {
            composite_xref_batch_t batch;
            batch.neighbors = {{"0x3000", "data"}, {"0x4000", "code"}};
            response.payload = std::move(batch);
            break;
        }
        case composite_step_kind_t::address_snapshot: {
            composite_address_snapshot_t snapshot;
            snapshot.addr = request.subject;
            snapshot.function = "func_" + request.subject;
            snapshot.instruction = "mov rax, 0";
            snapshot.type = "code";
            snapshot.name = "func_" + request.subject;
            response.payload = std::move(snapshot);
            break;
        }
        case composite_step_kind_t::apply_overlay_action: {
            composite_overlay_result_t result;
            result.applied = true;
            result.action_applied = request.action;
            response.payload = std::move(result);
            response.committed_overlay_generation = observed + 1;
            break;
        }
        }
        if (scenario_calls == 1) {
            if (scenario == composite_backend_scenario_t::partial) {
                response.status = composite_step_status_t::partial;
                response.diagnostic_code = "FIXTURE_PARTIAL";
                response.diagnostic_message = "fixture returned a deterministic bounded partial";
            } else if (scenario == composite_backend_scenario_t::baseline_started) {
                response.baseline_started = true;
            } else if (scenario == composite_backend_scenario_t::deep_work_started) {
                response.unrequested_deep_work_started = true;
            }
        }
        return response;
    }
};

std::vector<composite_tool_fixture_t> make_fixtures() {
    std::vector<composite_tool_fixture_t> fixtures;
    fixtures.reserve(k_composite_tool_count);

    fixtures.push_back({
        "analyze_function",
        &adapters::analyze_function,
        routed({{"addr", "main"}}),
        routed({{"addr", ""}}),
        false});

    fixtures.push_back({
        "analyze_component",
        &adapters::analyze_component,
        routed({{"addrs", json::array({"main", "helper"})}}),
        routed({{"addrs", json::array()}}),
        false});

    fixtures.push_back({
        "diff_before_after",
        &adapters::diff_before_after,
        routed({{"addr", "main"},
                {"action", "rename_func"},
                {"action_args", json{{"name", "renamed_func"}}}}),
        routed({{"addr", "main"},
                {"action", "invalid_action"},
                {"action_args", json{{"name", "x"}}}}),
        true});

    fixtures.push_back({
        "trace_data_flow",
        &adapters::trace_data_flow,
        routed({{"addr", "main"}, {"direction", "forward"}}),
        routed({{"addr", "main"}, {"direction", "sideways"}}),
        false});

    return fixtures;
}

void verify_contracts(protocol::schema_runtime_t& schemas) {
    const std::array<std::string_view, k_composite_tool_count> names = {
        "analyze_function",
        "analyze_component",
        "diff_before_after",
        "trace_data_flow",
    };
    for (const auto name : names) {
        const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
        require(descriptor != nullptr, "composite generated descriptor is missing");
        require(descriptor->name == name && descriptor->archive_backed &&
                    descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "composite generated identity differs from the linked archive-backed adapter");
        const bool mutation = name == "diff_before_after";
        if (mutation) {
            require(descriptor->effect == contract_effect_t::workspace_overlay_mutation &&
                        descriptor->lock == contract_lock_t::workspace_overlay_transaction &&
                        !descriptor->read_only && descriptor->unsafe,
                    "composite mutation descriptor effect policy is invalid");
        } else {
            require(descriptor->effect == contract_effect_t::workspace_read &&
                        descriptor->lock == contract_lock_t::workspace_shared &&
                        descriptor->read_only && !descriptor->unsafe,
                    "composite read descriptor effect policy is invalid");
        }
        require(descriptor->target_dependent && descriptor->accepts_pid &&
                    descriptor->accepts_bin_name,
                "composite descriptor routing policy is not target-dependent optional selector");

        protocol::tool_contract_t contract;
        contract.name.assign(descriptor->name.data(), descriptor->name.size());
        contract.description.assign(descriptor->description.data(), descriptor->description.size());
        contract.input_schema = json::parse(
            descriptor->input_schema_json.begin(), descriptor->input_schema_json.end());
        contract.output_schema = json::parse(
            descriptor->output_schema_json.begin(), descriptor->output_schema_json.end());
        contract.annotations = json::parse(
            descriptor->annotations_json.begin(), descriptor->annotations_json.end());
        contract.target_policy.requirement = protocol::target_requirement_t::optional;
        contract.target_policy.accepts_pid = descriptor->accepts_pid;
        contract.target_policy.accepts_bin_name = descriptor->accepts_bin_name;
        contract.effect_policy.effect = mutation
            ? protocol::tool_effect_t::workspace_overlay_mutation
            : protocol::tool_effect_t::workspace_read;
        contract.effect_policy.lock = mutation
            ? protocol::effect_lock_t::workspace_overlay_transaction
            : protocol::effect_lock_t::workspace_shared;
        contract.effect_policy.read_only = descriptor->read_only;
        contract.effect_policy.unsafe = descriptor->unsafe;
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "composite generated contract does not validate through the schema runtime");
        const json list_entry = contract.tool_list_entry();
        require(list_entry.at("inputSchema") == contract.input_schema &&
                    list_entry.at("outputSchema") == contract.output_schema &&
                    !list_entry.contains("_meta"),
                "composite tool list entry altered a generated schema or embedded provenance");
        require(!schemas.validate(
                     contract.output_schema, json{{"__schema_violation", true}}).valid,
                "composite generated output schema admitted a malformed fixture payload");
    }
}

void verify_fixture(const composite_tool_fixture_t& fixture,
                    composite_handlers_t& handlers,
                    workspace_adapter_t& workspace,
                    protocol::schema_runtime_t& schemas,
                    composite_backend_state_t& backend,
                    std::size_t& completed_fixtures) {
    const json metadata{{"fixture_tool", std::string(fixture.name)}};
    backend.begin(composite_backend_scenario_t::normal);

    const std::size_t before_bound = backend.bound_calls;
    const std::size_t before_valid = backend.calls;
    auto result = fixture.adapter(
        handlers, workspace, schemas, fixture.valid,
        cancellation_token_t::create(), {}, metadata);
    require_fixture(!result.is_error(), fixture.name, "valid", result.text());
    require_fixture(backend.bound_calls == before_bound + 1 && backend.calls > before_valid,
                    fixture.name, "valid",
                    "backend was not invoked during valid composition");
    require_fixture(result.structured_content().is_object(),
                    fixture.name, "valid", "structured output is not an object");
    require_fixture(result.aida_metadata().value("tool", std::string()) == fixture.name,
                    fixture.name, "valid", "tool provenance metadata is absent");
    require_fixture(result.aida_metadata().contains("composite"),
                    fixture.name, "valid", "composite metadata section is absent");
    require_fixture(result.aida_metadata().at("composite").contains("quota"),
                    fixture.name, "valid", "composite quota metadata is absent");
    require_fixture(result.aida_metadata().at("composite").contains("diagnostics"),
                    fixture.name, "valid", "composite diagnostics metadata is absent");
    ++completed_fixtures;

    const std::size_t before_invalid_bound = backend.bound_calls;
    const std::size_t before_invalid = backend.calls;
    result = fixture.adapter(
        handlers, workspace, schemas, fixture.invalid,
        cancellation_token_t::create(), {}, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    fixture.name, "invalid", "invalid input was not rejected canonically");
    require_fixture(backend.bound_calls == before_invalid_bound && backend.calls == before_invalid,
                    fixture.name, "invalid", "invalid input reached the backend");
    ++completed_fixtures;

    auto cancellation = cancellation_token_t::create();
    backend.cancel_during_step = cancellation.state();
    const std::size_t before_cancel_bound = backend.bound_calls;
    const std::size_t before_cancel = backend.calls;
    result = fixture.adapter(
        handlers, workspace, schemas, fixture.valid,
        cancellation, {}, metadata);
    backend.cancel_during_step.reset();
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    fixture.name, "cancellation",
                    "in-flight cancellation was not observed canonically");
    require_fixture(backend.bound_calls == before_cancel_bound + 1 &&
                        backend.calls > before_cancel,
                    fixture.name, "cancellation",
                    "cancellation fixture did not enter the backend");
    ++completed_fixtures;

    backend.invalid_bound_output = true;
    const std::size_t before_output_bound = backend.bound_calls;
    const std::size_t before_output = backend.calls;
    result = fixture.adapter(
        handlers, workspace, schemas, fixture.valid,
        cancellation_token_t::create(), {}, metadata);
    backend.invalid_bound_output = false;
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    fixture.name, "output validation",
                    "schema-invalid structured output was not rejected canonically");
    require_fixture(backend.bound_calls == before_output_bound + 1 &&
                        backend.calls == before_output,
                    fixture.name, "output validation",
                    "malformed bound output did not stop before composite step execution");
    ++completed_fixtures;
}

bool has_diagnostic(const protocol::mcp_result_t& result, std::string_view code) {
    const auto& metadata = result.aida_metadata();
    const auto composite = metadata.find("composite");
    if (composite == metadata.end() || !composite->is_object()) {
        return false;
    }
    const auto diagnostics = composite->find("diagnostics");
    if (diagnostics == composite->end() || !diagnostics->is_array()) {
        return false;
    }
    return std::any_of(
        diagnostics->begin(), diagnostics->end(),
        [code](const json& diagnostic) {
            return diagnostic.is_object() &&
                diagnostic.value("code", std::string()) == std::string(code);
        });
}

void verify_edge_fixtures(composite_handlers_t& handlers,
                          workspace_adapter_t& workspace,
                          protocol::schema_runtime_t& schemas,
                          composite_backend_state_t& backend,
                          std::size_t& completed_fixtures) {
    const json metadata{{"fixture_tool", "analyze_function"}, {"fixture_family", "edge"}};
    const json function_args = routed({{"addr", "main"}});

    composite_invocation_options_t options;
    auto quota = handlers.limits().hard_quota;
    quota.max_steps = 1;
    options.quota = quota;
    backend.begin(composite_backend_scenario_t::normal);
    auto result = adapters::analyze_function(
        handlers, workspace, schemas, function_args,
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error() && has_diagnostic(result, "COMPOSITE_QUOTA_EXHAUSTED"),
                    "analyze_function", "quota exhaustion",
                    "bounded step exhaustion did not produce a deterministic partial diagnostic");
    const auto& quota_metadata = result.aida_metadata().at("composite").at("quota");
    require_fixture(quota_metadata.value("steps_used", 0ULL) == 1 &&
                        quota_metadata.value("steps_limit", 0ULL) == 1 &&
                        backend.scenario_calls == 1 &&
                        result.aida_metadata().at("composite").value("partial", false) &&
                        result.structured_content().value("name", std::string()) == "func_main" &&
                        result.structured_content().at("decompiled").is_null(),
                    "analyze_function", "quota exhaustion",
                    "quota accounting or partial status is incorrect");
    ++completed_fixtures;

    options = {};
    options.expected_overlay_generation = 7;
    backend.begin(composite_backend_scenario_t::stale_overlay);
    result = adapters::analyze_function(
        handlers, workspace, schemas, function_args,
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error() &&
                        has_diagnostic(result, "COMPOSITE_OVERLAY_GENERATION_STALE") &&
                        result.structured_content().value("name", std::string()) == "main",
                    "analyze_function", "stale overlay",
                    "stale read generation was not retained as a partial diagnostic");
    ++completed_fixtures;

    const json mutation_args = routed({
        {"addr", "main"},
        {"action", "rename_func"},
        {"action_args", json{{"name", "renamed_func"}}},
    });
    backend.begin(composite_backend_scenario_t::stale_overlay);
    result = adapters::diff_before_after(
        handlers, workspace, schemas, mutation_args,
        cancellation_token_t::create(), options,
        json{{"fixture_tool", "diff_before_after"}, {"fixture_family", "stale_overlay"}});
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_HANDLER_FAILED",
                    "diff_before_after", "stale overlay",
                    "stale mutation generation did not fail closed");
    const auto& generation_details =
        result.structured_content().at("error").at("details");
    require_fixture(generation_details.value("expected_overlay_generation", 0ULL) == 7 &&
                        generation_details.value("actual_overlay_generation", 0ULL) == 8,
                    "diff_before_after", "stale overlay",
                    "stale mutation failure omitted expected and actual generations");
    ++completed_fixtures;

    options = {};
    backend.begin(composite_backend_scenario_t::partial);
    const auto first_partial = adapters::analyze_function(
        handlers, workspace, schemas, function_args,
        cancellation_token_t::create(), options, metadata);
    backend.begin(composite_backend_scenario_t::partial);
    const auto second_partial = adapters::analyze_function(
        handlers, workspace, schemas, function_args,
        cancellation_token_t::create(), options, metadata);
    require_fixture(!first_partial.is_error() && !second_partial.is_error() &&
                        has_diagnostic(first_partial, "FIXTURE_PARTIAL") &&
                        first_partial.structured_content().value(
                            "name", std::string()) == "func_main" &&
                        first_partial.aida_metadata().at("composite").at("diagnostics") ==
                            second_partial.aida_metadata().at("composite").at("diagnostics"),
                    "analyze_function", "partial diagnostics",
                    "partial backend diagnostics were absent or nondeterministic");
    ++completed_fixtures;

    backend.begin(composite_backend_scenario_t::baseline_started);
    result = adapters::analyze_function(
        handlers, workspace, schemas, function_args,
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error() &&
                        has_diagnostic(result, "COMPOSITE_HIDDEN_WORK_REJECTED") &&
                        !backend.saw_baseline_permission && !backend.saw_deep_work_permission &&
                        !result.aida_metadata().at("composite").value("baseline_started", true) &&
                        result.structured_content().value("name", std::string()) == "main",
                    "analyze_function", "hidden baseline rejection",
                    "backend baseline work was permitted or not rejected deterministically");
    ++completed_fixtures;

    backend.begin(composite_backend_scenario_t::deep_work_started);
    result = adapters::analyze_function(
        handlers, workspace, schemas, function_args,
        cancellation_token_t::create(), options, metadata);
    require_fixture(!result.is_error() &&
                        has_diagnostic(result, "COMPOSITE_HIDDEN_WORK_REJECTED") &&
                        !backend.saw_baseline_permission && !backend.saw_deep_work_permission &&
                        !result.aida_metadata().at("composite").value(
                            "unrequested_deep_work_started", true) &&
                        result.structured_content().value("name", std::string()) == "main",
                    "analyze_function", "hidden deep-work rejection",
                    "backend deep work was permitted or not rejected deterministically");
    ++completed_fixtures;

    backend.begin(composite_backend_scenario_t::normal);
}

void verify_composite_handlers() {
    target_resolver_t resolver;
    effect_lock_manager_t locks;
    require(static_cast<bool>(resolver.publish(
                make_target(1, 4101, 0xA101ULL, "fixture-alpha.exe"))),
            "composite handler target publication failed");

    composite_backend_state_t backend;
    composite_handlers_t handlers(
        [&backend](const adapter_call_context_t& context,
                   const composite_step_request_t& request,
                   const cancellation_token_t& cancellation) {
            return backend.respond(context, request, cancellation);
        },
        composite_limits_t{});

    workspace_adapter_handlers_t workspace_handlers;
    workspace_handlers.analysis = [&handlers, &backend](
        const adapter_call_context_t& context,
        const adapter_request_t& request) {
        ++backend.bound_calls;
        if (backend.invalid_bound_output) {
            adapter_response_t response;
            response.payload = json{
                {"status", "success"},
                {"text", "test"},
                {"structured_content", json{{"__schema_violation", true}}},
                {"aida_metadata", json::object()}
            }.dump();
            return adapter_result_t<adapter_response_t>::success(std::move(response));
        }
        return handlers.execute_bound(context, request);
    };
    workspace_handlers.overlay = [&handlers, &backend](
        const adapter_call_context_t& context,
        const adapter_request_t& request) {
        ++backend.bound_calls;
        if (backend.invalid_bound_output) {
            adapter_response_t response;
            response.payload = json{
                {"status", "success"},
                {"text", "test"},
                {"structured_content", json{{"__schema_violation", true}}},
                {"aida_metadata", json::object()}
            }.dump();
            return adapter_result_t<adapter_response_t>::success(std::move(response));
        }
        return handlers.execute_bound(context, request);
    };

    workspace_adapter_t workspace(resolver, locks, std::move(workspace_handlers));
    protocol::schema_runtime_t schemas(64);

    verify_contracts(schemas);
    const auto fixtures = make_fixtures();
    require(fixtures.size() == k_composite_tool_count,
            "composite fixture table does not cover exactly four tools");
    std::size_t completed_fixtures = 0;
    for (const auto& fixture : fixtures) {
        require(fixture.adapter != nullptr,
                "composite adapter function is not linked");
        verify_fixture(fixture, handlers, workspace, schemas, backend,
                        completed_fixtures);
    }
    verify_edge_fixtures(handlers, workspace, schemas, backend, completed_fixtures);
    require(completed_fixtures ==
                k_composite_tool_count * k_per_composite_tool_fixture_count +
                    k_composite_edge_fixture_count,
            "composite handler harness did not execute all twenty-two fixture families");
}

}

bool run_composite_handlers_harness(std::string& failure) {
    try {
        verify_composite_handlers();
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
