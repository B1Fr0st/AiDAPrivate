#include "python_handler_harness.hpp"

#include "../../src/core/mcp/compat/handlers/python.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
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
using namespace aida::standalone::mcp::compat::adapters;
using protocol::cancellation_token_t;
using protocol::json;

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view category, std::string_view detail) {
    if (!condition) {
        throw std::runtime_error(
            "py_exec_file " + std::string(category) + " fixture: " + std::string(detail));
    }
}

struct mock_executor_state_t final {
    std::size_t calls = 0;
    std::uint64_t last_job_id = 0;
    std::string last_script_path;
    json last_workspace_metadata = json::object();
    bool last_unsafe_approved = false;
    bool last_cancellation_present = false;
    bool last_deadline_present = false;
    python_worker_execution_result_t result;
    bool throw_exception = false;
    std::string exception_message;

    python_worker_execution_result_t execute(
        const python_worker_execution_request_t& request) {
        ++calls;
        last_job_id = request.job_id;
        last_script_path = request.script_path.string();
        last_workspace_metadata = request.workspace_metadata;
        last_unsafe_approved = request.unsafe_approved;
        last_cancellation_present = request.cancellation != nullptr;
        last_deadline_present = request.deadline.has_value();
        if (throw_exception) {
            throw std::runtime_error(exception_message);
        }
        return result;
    }
};

python_worker_execution_result_t make_completed_result() {
    python_worker_execution_result_t result;
    result.status = python_worker_status_t::completed;
    result.result = "{\"analysis\": \"ok\", \"functions\": 42}";
    result.stdout_text = "script started\nscript finished\n";
    result.stderr_text.clear();
    result.error_code.clear();
    result.worker_generation = 7;
    result.worker_process_id = 9999;
    result.worker_terminated = true;
    result.worker_replaced = false;
    return result;
}

python_worker_execution_result_t make_cancelled_result() {
    python_worker_execution_result_t result;
    result.status = python_worker_status_t::cancelled;
    result.error_code = "PYTHON_WORKER_CANCELLED";
    result.worker_terminated = true;
    result.worker_replaced = true;
    result.diagnostics.push_back({
        python_worker_error_code_t::cancelled,
        "python_worker.cancel",
        "worker cancellation requires replacement",
        0, true});
    return result;
}

python_worker_execution_result_t make_crashed_result() {
    python_worker_execution_result_t result;
    result.status = python_worker_status_t::worker_crashed;
    result.error_code = "PYTHON_WORKER_CRASHED";
    result.worker_terminated = true;
    result.worker_replaced = true;
    result.diagnostics.push_back({
        python_worker_error_code_t::worker_crashed,
        "python_worker.wait",
        "worker exited before terminal result",
        1, true});
    return result;
}

python_worker_execution_result_t make_host_stopped_result() {
    python_worker_execution_result_t result;
    result.status = python_worker_status_t::host_stopped;
    result.error_code = "PYTHON_WORKER_HOST_STOPPED";
    result.worker_terminated = false;
    result.worker_replaced = false;
    result.diagnostics.push_back({
        python_worker_error_code_t::invalid_request,
        "python_worker.execute",
        "worker host is stopped",
        0, false});
    return result;
}

python_worker_execution_result_t make_deadline_result() {
    python_worker_execution_result_t result;
    result.status = python_worker_status_t::deadline_exceeded;
    result.error_code = "PYTHON_WORKER_DEADLINE_EXCEEDED";
    result.worker_terminated = true;
    result.worker_replaced = true;
    result.diagnostics.push_back({
        python_worker_error_code_t::deadline_exceeded,
        "python_worker.cancel",
        "worker cancellation requires replacement",
        0, true});
    return result;
}

python_worker_execution_result_t make_protocol_failure_result() {
    python_worker_execution_result_t result;
    result.status = python_worker_status_t::protocol_failure;
    result.error_code = "PYTHON_WORKER_PROTOCOL_FAILURE";
    result.worker_terminated = true;
    result.worker_replaced = true;
    result.diagnostics.push_back({
        python_worker_error_code_t::protocol_malformed,
        "python_worker.response",
        "worker response is not a valid object",
        0, true});
    return result;
}

python_worker_execution_result_t make_worker_failed_result() {
    python_worker_execution_result_t result;
    result.status = python_worker_status_t::worker_failed;
    result.error_code = "PYTHON_WORKER_SCRIPT_FAILED";
    result.stderr_text = "Traceback (most recent call last):\n  ValueError: bad input\n";
    result.worker_terminated = true;
    result.worker_replaced = true;
    result.diagnostics.push_back({
        python_worker_error_code_t::worker_crashed,
        "python_worker.result",
        "worker reported a terminal failure",
        0, true});
    return result;
}

python_worker_execution_result_t make_unsafe_approval_rejected_result() {
    python_worker_execution_result_t result;
    result.status = python_worker_status_t::rejected;
    result.error_code = "PYTHON_WORKER_UNSAFE_APPROVAL_REQUIRED";
    result.worker_terminated = false;
    result.worker_replaced = false;
    result.diagnostics.push_back({
        python_worker_error_code_t::unsafe_approval_required,
        "python_worker.approval",
        "explicit unsafe approval is required",
        0, false});
    return result;
}

python_worker_execute_t bind_executor(mock_executor_state_t& state) {
    return [&state](const python_worker_execution_request_t& request) {
        return state.execute(request);
    };
}

json valid_arguments(std::string script_path = "scripts/analyze.py") {
    return json{
        {"script_path", std::move(script_path)},
        {"unsafe_approved", true},
    };
}

void verify_exact_schema(python_handlers_t& handlers,
                         protocol::schema_runtime_t& schemas,
                         std::size_t& completed) {
    require_fixture(handlers.size() == k_python_tool_count,
                    "exact_schema", "handler contract count is not exactly one");
    require_fixture(python_tool_names().size() == k_python_tool_count,
                    "exact_schema", "python name ledger count is not exactly one");
    const auto name = python_tool_names()[0];
    require_fixture(name == "py_exec_file",
                    "exact_schema", "tool name is not py_exec_file");
    const auto& contract = handlers.contract_at(0);
    require_fixture(contract.name == "py_exec_file",
                    "exact_schema", "contract name mismatch");
    require_fixture(handlers.find("py_exec_file") == &contract,
                    "exact_schema", "find lookup differs from contract_at");
    require_fixture(handlers.find("py_exec_file") != nullptr,
                    "exact_schema", "find returned null for registered tool");
    require_fixture(contract.input_schema.is_object(),
                    "exact_schema", "input schema is not an object");
    require_fixture(contract.output_schema.is_object(),
                    "exact_schema", "output schema is not an object");
    require_fixture(contract.annotations.is_object(),
                    "exact_schema", "annotations is not an object");
    require_fixture(
        contract.input_schema.at("properties").at("script_path").at("type") == "string",
        "exact_schema", "script_path property type is not string");
    require_fixture(
        contract.input_schema.at("properties").at("unsafe_approved").at("type") == "boolean",
        "exact_schema", "unsafe_approved property type is not boolean");
    require_fixture(
        contract.input_schema.at("properties").at("unsafe_approved").at("enum") == json::array({true}),
        "exact_schema", "unsafe_approved enum does not restrict to true");
    require_fixture(
        contract.input_schema.at("required") == json::array({"script_path", "unsafe_approved"}),
        "exact_schema", "required fields do not match");
    require_fixture(
        contract.input_schema.value("additionalProperties", true) == false,
        "exact_schema", "additionalProperties is not false");
    require_fixture(
        contract.output_schema.at("properties").at("status").at("type") == "string",
        "exact_schema", "output status type is not string");
    require_fixture(
        contract.output_schema.at("required") == json::array({"status", "worker_terminated", "worker_replaced"}),
        "exact_schema", "output required fields do not match");
    require_fixture(
        contract.output_schema.value("additionalProperties", true) == false,
        "exact_schema", "output additionalProperties is not false");
    require_fixture(
        contract.target_policy.requirement == protocol::target_requirement_t::independent,
        "exact_schema", "target policy is not independent");
    require_fixture(!contract.target_policy.accepts_pid,
                    "exact_schema", "target policy accepts_pid should be false");
    require_fixture(!contract.target_policy.accepts_bin_name,
                    "exact_schema", "target policy accepts_bin_name should be false");
    require_fixture(
        contract.effect_policy.effect == protocol::tool_effect_t::isolated_python,
        "exact_schema", "effect is not isolated_python");
    require_fixture(
        contract.effect_policy.lock == protocol::effect_lock_t::python_worker,
        "exact_schema", "lock is not python_worker");
    require_fixture(!contract.effect_policy.read_only,
                    "exact_schema", "effect read_only should be false");
    require_fixture(contract.effect_policy.unsafe,
                    "exact_schema", "effect unsafe should be true");
    require_fixture(
        protocol::validate_tool_contract(contract, schemas).valid,
        "exact_schema", "contract does not validate through the schema runtime");
    const json list_entry = contract.tool_list_entry();
    require_fixture(list_entry.at("inputSchema") == contract.input_schema &&
                        list_entry.at("outputSchema") == contract.output_schema &&
                        !list_entry.contains("_meta"),
                    "exact_schema", "tool list entry altered schema or embedded provenance");
    const auto annotations = contract.annotations;
    require_fixture(annotations.value("title", std::string()) == "Execute Python Script File",
                    "exact_schema", "annotation title mismatch");
    const auto decorators = annotations.find("decorators");
    require_fixture(decorators != annotations.end() && decorators->is_array() &&
                        !decorators->empty() &&
                        (*decorators)[0].value("name", std::string()) == "tool_timeout",
                    "exact_schema", "tool_timeout decorator is absent");
    ++completed;
}

void verify_py_eval_absence(python_handlers_t& handlers,
                            mock_executor_state_t& backend,
                            std::size_t& completed) {
    require_fixture(handlers.find("py_eval") == nullptr,
                    "py_eval_absence", "py_eval should not be registered");
    require_fixture(handlers.size() == 1,
                    "py_eval_absence", "handler count should be exactly one");
    const auto& names = python_tool_names();
    require_fixture(std::find(names.begin(), names.end(), "py_eval") == names.end(),
                    "py_eval_absence", "py_eval should not appear in the name ledger");
    require_fixture(find_contract("py_eval") == nullptr,
                    "py_eval_absence", "py_eval must not appear in the generated compatibility descriptor table");
    for (std::size_t i = 0; i < handlers.size(); ++i) {
        const auto& c = handlers.contract_at(i);
        require_fixture(c.name != "py_eval",
                        "py_eval_absence", "hidden contract named py_eval discovered at index");
        const auto ann_str = c.annotations.dump();
        require_fixture(ann_str.find("py_eval") == std::string::npos,
                        "py_eval_absence", "contract annotations reference py_eval");
        const auto aliases = c.annotations.find("aliases");
        if (aliases != c.annotations.end() && aliases->is_array()) {
            require_fixture(std::find(aliases->begin(), aliases->end(), "py_eval") == aliases->end(),
                            "py_eval_absence", "contract annotations expose py_eval as an alias");
        }
    }
    const auto entry = handlers.contract_at(0).tool_list_entry();
    require_fixture(!entry.contains("resources"),
                    "py_eval_absence", "tool list entry exposes a resources field");
    require_fixture(!entry.contains("resourceTemplates"),
                    "py_eval_absence", "tool list entry exposes a resourceTemplates field");
    require_fixture(!entry.contains("resource"),
                    "py_eval_absence", "tool list entry exposes a resource field");
    const json metadata{{"fixture_tool", "py_eval"}};
    const json args = valid_arguments();
    const std::size_t before = backend.calls;
    auto result = handlers.invoke("py_eval", args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error(),
                    "py_eval_absence", "invoking py_eval should return an error");
    require_fixture(result.error_code() == "MCP_TOOL_CONTRACT_INVALID",
                    "py_eval_absence", "py_eval should be rejected as invalid_contract");
    require_fixture(backend.calls == before,
                    "py_eval_absence", "py_eval invocation reached the executor");
    require_fixture(
        result.structured_content().at("error").at("details").value("tool", std::string()) == "py_eval",
        "py_eval_absence", "py_eval error details should name the rejected tool");
    ++completed;
}

void verify_missing_script_path(python_handlers_t& handlers,
                                mock_executor_state_t& backend,
                                std::size_t& completed) {
    const json metadata{{"fixture_tool", "py_exec_file"}};
    json args = json::object();
    args["unsafe_approved"] = true;
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "missing_script_path", "missing script_path was not rejected canonically");
    require_fixture(backend.calls == before,
                    "missing_script_path", "missing script_path reached the executor");
    ++completed;
}

void verify_missing_unsafe_approved(python_handlers_t& handlers,
                                    mock_executor_state_t& backend,
                                    std::size_t& completed) {
    const json metadata{{"fixture_tool", "py_exec_file"}};
    json args = json::object();
    args["script_path"] = "scripts/analyze.py";
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "missing_unsafe_approved", "missing unsafe_approved was not rejected canonically");
    require_fixture(backend.calls == before,
                    "missing_unsafe_approved", "missing unsafe_approved reached the executor");
    ++completed;
}

void verify_unsafe_approved_false(python_handlers_t& handlers,
                                  mock_executor_state_t& backend,
                                  std::size_t& completed) {
    const json metadata{{"fixture_tool", "py_exec_file"}};
    json args = json::object();
    args["script_path"] = "scripts/analyze.py";
    args["unsafe_approved"] = false;
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "unsafe_approved_false", "unsafe_approved=false was not rejected by schema");
    require_fixture(backend.calls == before,
                    "unsafe_approved_false", "unsafe_approved=false reached the executor");
    ++completed;
}

void verify_invalid_extension(python_handlers_t& handlers,
                              mock_executor_state_t& backend,
                              std::size_t& completed) {
    const json metadata{{"fixture_tool", "py_exec_file"}};
    json args = json::object();
    args["script_path"] = "scripts/analyze.txt";
    args["unsafe_approved"] = true;
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "invalid_extension", "non-.py script was not rejected canonically");
    require_fixture(backend.calls == before,
                    "invalid_extension", "non-.py script reached the executor");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "reason", std::string()) == "extension_required",
        "invalid_extension", "extension_required reason is absent");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "field", std::string()) == "script_path",
        "invalid_extension", "script_path field is absent from diagnostics");
    ++completed;
}

void verify_oversized_script_path(python_handlers_t& handlers,
                                  mock_executor_state_t& backend,
                                  const python_handler_limits_t& limits,
                                  std::size_t& completed) {
    const json metadata{{"fixture_tool", "py_exec_file"}};
    json args = json::object();
    args["script_path"] = std::string(limits.max_script_path_bytes + 1, 'A') + ".py";
    args["unsafe_approved"] = true;
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "oversized_script_path", "oversized script_path was not rejected canonically");
    require_fixture(backend.calls == before,
                    "oversized_script_path", "oversized script_path reached the executor");
    ++completed;
}

void verify_oversized_workspace_metadata(python_handlers_t& handlers,
                                         mock_executor_state_t& backend,
                                         const python_handler_limits_t& limits,
                                         std::size_t& completed) {
    const json metadata{{"fixture_tool", "py_exec_file"}};
    json args = json::object();
    args["script_path"] = "scripts/analyze.py";
    args["unsafe_approved"] = true;
    json large_meta = json::object();
    const std::size_t fill_count = 32;
    for (std::size_t i = 0; i < fill_count; ++i) {
        large_meta[std::string(60, 'k') + std::to_string(i)] =
            std::string(2048, 'v');
    }
    args["workspace_metadata"] = std::move(large_meta);
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "oversized_workspace_metadata",
                    "oversized workspace_metadata was not rejected canonically");
    require_fixture(backend.calls == before,
                    "oversized_workspace_metadata",
                    "oversized workspace_metadata reached the executor");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "reason", std::string()) == "maximum_exceeded",
        "oversized_workspace_metadata",
        "maximum_exceeded reason is absent for workspace_metadata");
    ++completed;
}

void verify_additional_property_rejected(python_handlers_t& handlers,
                                         mock_executor_state_t& backend,
                                         std::size_t& completed) {
    const json metadata{{"fixture_tool", "py_exec_file"}};
    json args = valid_arguments();
    args["extra_field"] = "not allowed";
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, args, cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "additional_property",
                    "additional property was not rejected by schema");
    require_fixture(backend.calls == before,
                    "additional_property", "additional property reached the executor");
    ++completed;
}

void verify_cancellation_before_dispatch(python_handlers_t& handlers,
                                         mock_executor_state_t& backend,
                                         std::size_t& completed) {
    const json metadata{{"fixture_tool", "py_exec_file"}};
    auto cancellation = cancellation_token_t::create();
    cancellation.cancel();
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation, metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_CANCELLED",
                    "cancellation_before",
                    "pre-dispatch cancellation was not observed canonically");
    require_fixture(backend.calls == before,
                    "cancellation_before",
                    "pre-dispatch cancellation reached the executor");
    require_fixture(
        result.structured_content().at("error").at("details").value(
            "phase", std::string()) == "python_pre_dispatch",
        "cancellation_before", "phase diagnostic is absent");
    ++completed;
}

void verify_completed_result(python_handlers_t& handlers,
                             mock_executor_state_t& backend,
                             std::size_t& completed) {
    backend.result = make_completed_result();
    const json metadata{{"fixture_tool", "py_exec_file"}};
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "completed_result", result.text());
    require_fixture(backend.calls == before + 1,
                    "completed_result", "executor was not invoked exactly once");
    require_fixture(backend.last_job_id != 0,
                    "completed_result", "job_id was not generated as non-zero");
    require_fixture(backend.last_script_path == "scripts/analyze.py",
                    "completed_result", "script_path was not propagated to executor");
    require_fixture(backend.last_unsafe_approved == true,
                    "completed_result", "unsafe_approved was not propagated as true");
    require_fixture(backend.last_workspace_metadata == json::object(),
                    "completed_result", "workspace_metadata was not defaulted to empty object");
    require_fixture(backend.last_cancellation_present,
                    "completed_result", "cancellation pointer was not propagated to executor");
    require_fixture(backend.last_deadline_present,
                    "completed_result", "deadline was not propagated to executor");
    const auto& structured = result.structured_content();
    require_fixture(structured.value("status", std::string()) == "completed",
                    "completed_result", "structured status is not completed");
    require_fixture(structured.value("result", std::string()) == "{\"analysis\": \"ok\", \"functions\": 42}",
                    "completed_result", "structured result text mismatch");
    require_fixture(structured.value("stdout", std::string()) == "script started\nscript finished\n",
                    "completed_result", "structured stdout mismatch");
    require_fixture(structured.value("worker_generation", 0ULL) == 7ULL,
                    "completed_result", "worker_generation was not mapped");
    require_fixture(structured.value("worker_process_id", 0U) == 9999U,
                    "completed_result", "worker_process_id was not mapped");
    require_fixture(structured.value("worker_terminated", false) == true,
                    "completed_result", "worker_terminated was not mapped");
    require_fixture(structured.value("worker_replaced", true) == false,
                    "completed_result", "worker_replaced was not mapped");
    require_fixture(result.aida_metadata().value("tool", std::string()) == "py_exec_file",
                    "completed_result", "aida_metadata tool field is not py_exec_file");
    require_fixture(result.aida_metadata().value("effect", std::string()) == "isolated_python",
                    "completed_result", "aida_metadata effect field is not isolated_python");
    require_fixture(result.aida_metadata().value("lock", std::string()) == "python_worker",
                    "completed_result", "aida_metadata lock field is not python_worker");
    require_fixture(result.aida_metadata().value("worker_status", std::string()) == "completed",
                    "completed_result", "aida_metadata worker_status is not completed");
    require_fixture(result.aida_metadata().value("job_id", 0ULL) != 0,
                    "completed_result", "aida_metadata job_id should be non-zero");
    require_fixture(!result.aida_metadata().contains("diagnostics"),
                    "completed_result", "aida_metadata should not contain diagnostics for success");
    ++completed;
}

void verify_cancelled_result_mapping(python_handlers_t& handlers,
                                     mock_executor_state_t& backend,
                                     std::size_t& completed) {
    backend.result = make_cancelled_result();
    const json metadata{{"fixture_tool", "py_exec_file"}};
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_CANCELLED",
                    "cancelled_mapping", "worker cancelled was not mapped to MCP_TOOL_CANCELLED");
    require_fixture(backend.calls == before + 1,
                    "cancelled_mapping", "executor was not invoked exactly once");
    const auto& details = result.structured_content().at("error").at("details");
    require_fixture(details.value("worker_status", std::string()) == "cancelled",
                    "cancelled_mapping", "worker_status in error details is not cancelled");
    require_fixture(details.value("worker_error_code", std::string()) == "PYTHON_WORKER_CANCELLED",
                    "cancelled_mapping", "worker_error_code in error details is not correct");
    require_fixture(details.contains("diagnostics"),
                    "cancelled_mapping", "diagnostics are absent from error details");
    require_fixture(result.aida_metadata().value("worker_status", std::string()) == "cancelled",
                    "cancelled_mapping", "aida_metadata worker_status is not cancelled");
    ++completed;
}

void verify_crashed_result_mapping(python_handlers_t& handlers,
                                   mock_executor_state_t& backend,
                                   std::size_t& completed) {
    backend.result = make_crashed_result();
    const json metadata{{"fixture_tool", "py_exec_file"}};
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_HANDLER_FAILED",
                    "crashed_mapping", "worker_crashed was not mapped to handler_failed");
    const auto& details = result.structured_content().at("error").at("details");
    require_fixture(details.value("worker_status", std::string()) == "worker_crashed",
                    "crashed_mapping", "worker_status in error details is not worker_crashed");
    require_fixture(details.value("worker_replaced", false) == true,
                    "crashed_mapping", "worker_replaced should be true for crash");
    require_fixture(details.contains("diagnostics"),
                    "crashed_mapping", "diagnostics are absent from crash error details");
    ++completed;
}

void verify_host_stopped_result_mapping(python_handlers_t& handlers,
                                        mock_executor_state_t& backend,
                                        std::size_t& completed) {
    backend.result = make_host_stopped_result();
    const json metadata{{"fixture_tool", "py_exec_file"}};
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INTERNAL_ERROR",
                    "host_stopped_mapping", "host_stopped was not mapped to internal_error");
    const auto& details = result.structured_content().at("error").at("details");
    require_fixture(details.value("worker_status", std::string()) == "host_stopped",
                    "host_stopped_mapping", "worker_status in error details is not host_stopped");
    require_fixture(details.value("worker_terminated", true) == false,
                    "host_stopped_mapping", "worker_terminated should be false for host_stopped");
    ++completed;
}

void verify_deadline_result_mapping(python_handlers_t& handlers,
                                    mock_executor_state_t& backend,
                                    std::size_t& completed) {
    backend.result = make_deadline_result();
    const json metadata{{"fixture_tool", "py_exec_file"}};
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_HANDLER_FAILED",
                    "deadline_mapping", "deadline_exceeded was not mapped to handler_failed");
    const auto& details = result.structured_content().at("error").at("details");
    require_fixture(details.value("worker_status", std::string()) == "deadline_exceeded",
                    "deadline_mapping", "worker_status in error details is not deadline_exceeded");
    require_fixture(details.value("worker_error_code", std::string()) == "PYTHON_WORKER_DEADLINE_EXCEEDED",
                    "deadline_mapping", "worker_error_code mismatch for deadline");
    ++completed;
}

void verify_protocol_failure_mapping(python_handlers_t& handlers,
                                     mock_executor_state_t& backend,
                                     std::size_t& completed) {
    backend.result = make_protocol_failure_result();
    const json metadata{{"fixture_tool", "py_exec_file"}};
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_HANDLER_FAILED",
                    "protocol_failure_mapping",
                    "protocol_failure was not mapped to handler_failed");
    const auto& details = result.structured_content().at("error").at("details");
    require_fixture(details.value("worker_status", std::string()) == "protocol_failure",
                    "protocol_failure_mapping",
                    "worker_status in error details is not protocol_failure");
    ++completed;
}

void verify_worker_failed_mapping(python_handlers_t& handlers,
                                  mock_executor_state_t& backend,
                                  std::size_t& completed) {
    backend.result = make_worker_failed_result();
    const json metadata{{"fixture_tool", "py_exec_file"}};
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_HANDLER_FAILED",
                    "worker_failed_mapping",
                    "worker_failed was not mapped to handler_failed");
    const auto& details = result.structured_content().at("error").at("details");
    require_fixture(details.value("worker_status", std::string()) == "worker_failed",
                    "worker_failed_mapping",
                    "worker_status in error details is not worker_failed");
    require_fixture(details.value("worker_error_code", std::string()) == "PYTHON_WORKER_SCRIPT_FAILED",
                    "worker_failed_mapping", "worker_error_code mismatch for script failure");
    ++completed;
}

void verify_unsafe_approval_rejected_mapping(python_handlers_t& handlers,
                                             mock_executor_state_t& backend,
                                             std::size_t& completed) {
    backend.result = make_unsafe_approval_rejected_result();
    const json metadata{{"fixture_tool", "py_exec_file"}};
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_EFFECT_POLICY_REJECTED",
                    "unsafe_rejected_mapping",
                    "unsafe_approval_required was not mapped to effect_policy_rejected");
    const auto& details = result.structured_content().at("error").at("details");
    require_fixture(details.value("worker_status", std::string()) == "rejected",
                    "unsafe_rejected_mapping", "worker_status in error details is not rejected");
    require_fixture(details.value("worker_error_code", std::string()) ==
                        "PYTHON_WORKER_UNSAFE_APPROVAL_REQUIRED",
                    "unsafe_rejected_mapping", "worker_error_code mismatch for approval rejection");
    ++completed;
}

void verify_executor_exception(python_handlers_t& handlers,
                               mock_executor_state_t& backend,
                               std::size_t& completed) {
    backend.throw_exception = true;
    backend.exception_message = "simulated worker host failure";
    const json metadata{{"fixture_tool", "py_exec_file"}};
    const std::size_t before = backend.calls;
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), metadata);
    backend.throw_exception = false;
    backend.exception_message.clear();
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_HANDLER_FAILED",
                    "executor_exception",
                    "executor exception was not mapped to handler_failed");
    require_fixture(backend.calls == before + 1,
                    "executor_exception", "executor was not invoked despite exception");
    const auto& details = result.structured_content().at("error").at("details");
    require_fixture(details.value("phase", std::string()) == "python_executor_exception",
                    "executor_exception", "phase is not python_executor_exception");
    require_fixture(details.value("exception", std::string()) == "simulated worker host failure",
                    "executor_exception", "exception message was not captured in details");
    require_fixture(details.value("job_id", 0ULL) != 0,
                    "executor_exception", "job_id should be non-zero in exception details");
    ++completed;
}

void verify_workspace_metadata_propagation(python_handlers_t& handlers,
                                           mock_executor_state_t& backend,
                                           std::size_t& completed) {
    backend.result = make_completed_result();
    const json metadata{{"fixture_tool", "py_exec_file"}};
    json args = valid_arguments();
    json meta = json::object();
    meta["target_pid"] = 4101;
    meta["analysis_mode"] = "vulnerability";
    args["workspace_metadata"] = std::move(meta);
    auto result = adapters::py_exec_file(handlers, args,
                                         cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "workspace_metadata_propagation", result.text());
    require_fixture(backend.last_workspace_metadata.value("target_pid", 0U) == 4101U,
                    "workspace_metadata_propagation",
                    "target_pid was not propagated to executor workspace_metadata");
    require_fixture(backend.last_workspace_metadata.value("analysis_mode", std::string()) == "vulnerability",
                    "workspace_metadata_propagation",
                    "analysis_mode was not propagated to executor workspace_metadata");
    ++completed;
}

void verify_non_object_aida_metadata(python_handlers_t& handlers,
                                      std::size_t& completed) {
    const json bad_metadata = json::array({"not_an_object"});
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), bad_metadata);
    require_fixture(result.is_error() &&
                        result.error_code() == "MCP_TOOL_INTERNAL_ERROR",
                    "non_object_metadata",
                    "non-object aida_metadata was not rejected as internal_error");
    ++completed;
}

void verify_output_schema_validation(python_handlers_t& handlers,
                                     protocol::schema_runtime_t& schemas,
                                     mock_executor_state_t& backend,
                                     std::size_t& completed) {
    backend.result = make_completed_result();
    const json metadata{{"fixture_tool", "py_exec_file"}};
    auto result = adapters::py_exec_file(handlers, valid_arguments(),
                                         cancellation_token_t::create(), metadata);
    require_fixture(!result.is_error(), "output_schema_validation", result.text());
    const auto& structured = result.structured_content();
    const auto& output_schema = handlers.contract_at(0).output_schema;
    const auto validation = schemas.validate(output_schema, structured);
    require_fixture(validation.valid,
                    "output_schema_validation",
                    "completed structured result does not satisfy the output schema");
    json bad_structured = json{
        {"status", "completed"},
        {"result", "ok"},
        {"stdout", "out"},
        {"stderr", ""},
        {"error_code", ""},
        {"worker_generation", 0},
        {"worker_process_id", 0},
        {"worker_terminated", true},
        {"worker_replaced", false},
        {"unexpected_extra", "should_not_be_here"},
    };
    const auto bad_validation = schemas.validate(output_schema, bad_structured);
    require_fixture(!bad_validation.valid,
                    "output_schema_validation",
                    "output schema accepted additionalProperties which should be rejected");
    json missing_required = json{
        {"status", "completed"},
        {"result", "ok"},
    };
    const auto missing_validation = schemas.validate(output_schema, missing_required);
    require_fixture(!missing_validation.valid,
                    "output_schema_validation",
                    "output schema accepted missing required fields");
    json invalid_status = json{
        {"status", 42},
        {"worker_terminated", true},
        {"worker_replaced", false},
    };
    const auto status_validation = schemas.validate(output_schema, invalid_status);
    require_fixture(!status_validation.valid,
                    "output_schema_validation",
                    "output schema accepted non-string status");
    json invalid_enum = json{
        {"status", "bogus_status"},
        {"worker_terminated", true},
        {"worker_replaced", false},
    };
    const auto enum_validation = schemas.validate(output_schema, invalid_enum);
    require_fixture(!enum_validation.valid,
                    "output_schema_validation",
                    "output schema accepted status outside the enum");
    ++completed;
}

void verify_python_handler() {
    protocol::schema_runtime_t schemas(64);
    mock_executor_state_t backend;
    auto executor = bind_executor(backend);
    python_handlers_t handlers(std::move(executor), schemas);
    const auto& limits = handlers.limits();
    std::size_t completed = 0;

    verify_exact_schema(handlers, schemas, completed);
    verify_py_eval_absence(handlers, backend, completed);
    verify_missing_script_path(handlers, backend, completed);
    verify_missing_unsafe_approved(handlers, backend, completed);
    verify_unsafe_approved_false(handlers, backend, completed);
    verify_invalid_extension(handlers, backend, completed);
    verify_oversized_script_path(handlers, backend, limits, completed);
    verify_oversized_workspace_metadata(handlers, backend, limits, completed);
    verify_additional_property_rejected(handlers, backend, completed);
    verify_cancellation_before_dispatch(handlers, backend, completed);
    verify_completed_result(handlers, backend, completed);
    verify_cancelled_result_mapping(handlers, backend, completed);
    verify_crashed_result_mapping(handlers, backend, completed);
    verify_host_stopped_result_mapping(handlers, backend, completed);
    verify_deadline_result_mapping(handlers, backend, completed);
    verify_protocol_failure_mapping(handlers, backend, completed);
    verify_worker_failed_mapping(handlers, backend, completed);
    verify_unsafe_approval_rejected_mapping(handlers, backend, completed);
    verify_executor_exception(handlers, backend, completed);
    verify_workspace_metadata_propagation(handlers, backend, completed);
    verify_non_object_aida_metadata(handlers, completed);
    verify_output_schema_validation(handlers, schemas, backend, completed);

    require(completed == 22,
            "python handler harness did not execute all twenty-two fixture families");
}

}

bool run_python_handler_harness(std::string& failure) {
    try {
        verify_python_handler();
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
