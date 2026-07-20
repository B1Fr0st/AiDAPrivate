#include "python_handler_harness.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/compat/handlers/python.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"

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
namespace protocol = aida::standalone::mcp::protocol;
using protocol::cancellation_token_t;
using protocol::json;

void require(bool condition, std::string_view message) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view category, std::string_view detail) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(condition, detail, __FILE__, __LINE__);
    if (!condition) {
        throw std::runtime_error(
            "py_exec_file " + std::string(category) + " fixture: " + std::string(detail));
    }
}

python_workspace_response_t workspace_response(
    const python_workspace_query_t& query,
    const std::atomic<bool>*) {
    python_workspace_response_t response;
    response.success = true;
    response.data = json{{"operation", query.operation}, {"arguments", query.arguments}};
    return response;
}

python_target_lease_t make_target(std::uint32_t pid,
                                  std::string workspace_id,
                                  std::string bin_name,
                                  std::string source_path,
                                  std::uint64_t generation,
                                  bool live = false) {
    python_target_lease_t target;
    target.owner = std::make_shared<std::uint64_t>(generation);
    target.workspace_id = std::move(workspace_id);
    target.pid = pid;
    target.bin_name = std::move(bin_name);
    target.normalized_source_path = std::move(source_path);
    target.generation = generation;
    target.analysis_revision = generation + 10;
    target.overlay_revision = generation + 20;
    target.live = live;
    target.workspace_metadata = json{{"architecture", "x86_64"}};
    target.workspace_api = workspace_response;
    return target;
}

struct target_state_t final {
    std::vector<python_target_lease_t> targets;
    std::size_t calls = 0;
    target_selector_t last_selector;
    bool reject = false;
    adapter_error_t rejection{
        adapter_error_code_t::target_resolution_failed,
        "fixture_target_not_found", 0, 0};

    adapter_result_t<python_target_lease_t> acquire(
        const target_selector_t& selector,
        std::optional<std::chrono::steady_clock::time_point> deadline) {
        ++calls;
        last_selector = selector;
        if (reject || !deadline || *deadline <= std::chrono::steady_clock::now()) {
            return adapter_result_t<python_target_lease_t>::failure(rejection);
        }
        const python_target_lease_t* match = nullptr;
        for (const auto& target : targets) {
            const bool pid_match = !selector.pid || target.pid == selector.pid;
            const bool name_match = !selector.bin_name || target.bin_name == *selector.bin_name;
            if (pid_match && name_match) {
                if (match != nullptr) {
                    return adapter_result_t<python_target_lease_t>::failure({
                        adapter_error_code_t::target_resolution_failed,
                        "target_ambiguous", 1, 2});
                }
                match = &target;
            }
        }
        if (match == nullptr) {
            return adapter_result_t<python_target_lease_t>::failure(rejection);
        }
        return adapter_result_t<python_target_lease_t>::success(*match);
    }
};

python_worker_execution_result_t completed_result() {
    python_worker_execution_result_t result;
    result.status = python_worker_status_t::completed;
    result.result = "analysis complete";
    result.stdout_text = "worker stdout";
    result.stderr_text.clear();
    result.worker_generation = 7;
    result.worker_process_id = 9911;
    result.worker_terminated = true;
    result.worker_replaced = false;
    return result;
}

struct executor_state_t final {
    std::size_t calls = 0;
    std::filesystem::path last_root;
    python_worker_execution_request_t last_request;
    python_worker_execution_result_t result = completed_result();
    bool throw_exception = false;

    python_worker_execution_result_t execute(
        const std::filesystem::path& root,
        const python_worker_execution_request_t& request) {
        ++calls;
        last_root = root;
        last_request = request;
        if (throw_exception) {
            throw std::runtime_error("fixture executor failure");
        }
        return result;
    }
};

json valid_arguments(std::uint32_t pid = 4101) {
    return json{
        {"file_path", "scripts/analyze.py"},
        {"approve_unsafe", true},
        {"pid", pid},
    };
}

void verify_generated_contract(const python_handlers_t& handlers,
                               protocol::schema_runtime_t& schemas,
                               std::size_t& completed) {
    require_fixture(handlers.size() == 1 && python_tool_names().size() == 1,
                    "generated_contract", "tool inventory is not an exact singleton");
    require_fixture(python_tool_names()[0] == "py_exec_file" &&
                        handlers.find("py_exec_file") == &handlers.contract_at(0),
                    "generated_contract", "py_exec_file lookup is inconsistent");
    require_fixture(handlers.find("py_eval") == nullptr && find_contract("py_eval") == nullptr,
                    "generated_contract", "py_eval is present in the compatibility surface");
    const auto* descriptor = find_contract("py_exec_file");
    require_fixture(descriptor != nullptr,
                    "generated_contract", "generated descriptor is absent");
    require_fixture(descriptor->adapter_symbol ==
                        "aida::standalone::mcp::compat::adapters::py_exec_file" &&
                        descriptor->target_dependent && descriptor->accepts_pid &&
                        descriptor->accepts_bin_name && descriptor->unsafe,
                    "generated_contract", "generated worker adapter policy is incorrect");
    const auto& contract = handlers.contract_at(0);
    require_fixture(
        contract.input_schema == json::parse(
            descriptor->input_schema_json.begin(), descriptor->input_schema_json.end()) &&
            contract.output_schema == json::parse(
                descriptor->output_schema_json.begin(), descriptor->output_schema_json.end()) &&
            contract.annotations == json::parse(
                descriptor->annotations_json.begin(), descriptor->annotations_json.end()),
        "generated_contract", "handler contract differs from generated JSON");
    const auto& properties = contract.input_schema.at("properties");
    require_fixture(properties.contains("file_path") && properties.contains("approve_unsafe") &&
                        properties.contains("pid") && properties.contains("bin_name") &&
                        !properties.contains("script_path") &&
                        !properties.contains("unsafe_approved"),
                    "generated_contract", "generated input field contract is not exact");
    require_fixture(
        contract.target_policy.requirement == protocol::target_requirement_t::optional &&
            contract.target_policy.accepts_pid && contract.target_policy.accepts_bin_name,
        "generated_contract", "target routing policy is not generated-target compatible");
    require_fixture(
        contract.effect_policy.effect == protocol::tool_effect_t::isolated_python &&
            contract.effect_policy.lock == protocol::effect_lock_t::python_worker &&
            !contract.effect_policy.read_only && contract.effect_policy.unsafe,
        "generated_contract", "isolated worker effect policy is incorrect");
    require_fixture(protocol::validate_tool_contract(contract, schemas).valid,
                    "generated_contract", "generated contract fails schema compilation");
    const auto required = contract.output_schema.at("required");
    require_fixture(required == json::array({
                        "result", "stdout", "stderr", "worker_generation",
                        "worker_process_id", "diagnostics"}),
                    "generated_contract", "generated output requirements are not exact");
    ++completed;
}

void verify_old_and_unsafe_inputs(python_handlers_t& handlers,
                                  target_state_t& targets,
                                  executor_state_t& executor,
                                  std::size_t& completed) {
    const std::size_t target_calls = targets.calls;
    const std::size_t worker_calls = executor.calls;
    auto old_result = adapters::py_exec_file(
        handlers,
        json{{"script_path", "scripts/analyze.py"}, {"unsafe_approved", true}, {"pid", 4101}},
        cancellation_token_t::create());
    require_fixture(old_result.is_error() &&
                        old_result.error_code() == "MCP_TOOL_INPUT_INVALID",
                    "old_inputs", "retired Python input fields were accepted");
    auto denied = adapters::py_exec_file(
        handlers,
        json{{"file_path", "scripts/analyze.py"}, {"approve_unsafe", false}, {"pid", 4101}},
        cancellation_token_t::create());
    require_fixture(denied.is_error() &&
                        denied.error_code() == "MCP_TOOL_EFFECT_POLICY_REJECTED",
                    "old_inputs", "false unsafe approval was not rejected by effect policy");
    require_fixture(targets.calls == target_calls && executor.calls == worker_calls,
                    "old_inputs", "invalid or unapproved input reached target or worker code");
    ++completed;
}

void verify_target_derived_roots(python_handlers_t& handlers,
                                 target_state_t& targets,
                                 executor_state_t& executor,
                                 protocol::schema_runtime_t& schemas,
                                 std::size_t& completed) {
    executor.result = completed_result();
    auto alpha = adapters::py_exec_file(
        handlers, valid_arguments(4101), cancellation_token_t::create(),
        json{{"fixture", "alpha"}});
    require_fixture(!alpha.is_error(), "target_root", alpha.text());
    require_fixture(executor.last_root.lexically_normal() ==
                        std::filesystem::path(L"C:\\fixtures\\alpha").lexically_normal(),
                    "target_root", "alpha script root was not derived from target source parent");
    require_fixture(executor.last_request.script_path.lexically_normal() ==
                        std::filesystem::path(L"C:\\fixtures\\alpha\\scripts\\analyze.py").lexically_normal(),
                    "target_root", "alpha script path was not rooted under its target");
    require_fixture(executor.last_request.workspace_metadata.at("workspace_id") == "workspace-alpha" &&
                        executor.last_request.workspace_metadata.at("generation") == 11 &&
                        executor.last_request.workspace_metadata.at("bin_name") == "alpha.exe" &&
                        executor.last_request.unsafe_approved &&
                        executor.last_request.workspace_api != nullptr,
                    "target_root", "target generation metadata was not bound to the worker request");
    const auto api_result = executor.last_request.workspace_api(
        python_workspace_query_t{"metadata", json::object()}, nullptr);
    require_fixture(api_result.success && api_result.data.at("operation") == "metadata",
                    "target_root", "leased workspace API was not propagated");
    require_fixture(
        schemas.validate(handlers.contract_at(0).output_schema, alpha.structured_content()).valid,
        "target_root", "completed output fails the generated schema");
    require_fixture(alpha.structured_content().size() == 6 &&
                        alpha.structured_content().at("diagnostics").is_array(),
                    "target_root", "completed output contains non-generated fields");
    require_fixture(alpha.aida_metadata().at("workspace_id") == "workspace-alpha" &&
                        alpha.aida_metadata().at("generation_lease") == "local_immutable" &&
                        alpha.aida_metadata().at("script_root_source") == "target_source_parent" &&
                        alpha.aida_metadata().at("output_schema_validation") == "passed",
                    "target_root", "target and output-validation metadata hooks are absent");

    auto beta_args = json{
        {"file_path", "tools/beta.py"},
        {"approve_unsafe", true},
        {"bin_name", "beta.exe"},
    };
    auto beta = adapters::py_exec_file(
        handlers, beta_args, cancellation_token_t::create());
    require_fixture(!beta.is_error(), "target_root", beta.text());
    require_fixture(executor.last_root.lexically_normal() ==
                        std::filesystem::path(L"D:\\workspaces\\beta").lexically_normal() &&
                        targets.last_selector.bin_name == std::optional<std::string>("beta.exe"),
                    "target_root", "bin_name routing did not select the beta target root");
    ++completed;
}

void verify_path_containment(python_handlers_t& handlers,
                             target_state_t& targets,
                             executor_state_t& executor,
                             std::size_t& completed) {
    const std::size_t target_calls = targets.calls;
    const std::size_t worker_calls = executor.calls;
    for (const std::string& path : {
            "../escape.py", "scripts/../escape.py", "C:\\escape.py",
            "scripts/not_python.txt", "scripts/UPPER.PY"}) {
        json arguments = valid_arguments();
        arguments["file_path"] = path;
        auto result = adapters::py_exec_file(
            handlers, arguments, cancellation_token_t::create());
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_INPUT_INVALID",
                        "containment", "uncontained or non-.py path was accepted");
    }
    require_fixture(targets.calls == target_calls && executor.calls == worker_calls,
                    "containment", "rejected path reached target or worker code");
    ++completed;
}

void verify_target_failures(python_handlers_t& handlers,
                            target_state_t& targets,
                            executor_state_t& executor,
                            std::size_t& completed) {
    targets.reject = true;
    const std::size_t before = executor.calls;
    auto rejected = adapters::py_exec_file(
        handlers, valid_arguments(), cancellation_token_t::create());
    targets.reject = false;
    require_fixture(rejected.is_error() &&
                        rejected.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED" &&
                        rejected.structured_content().at("error").at("details").at("adapter_code") ==
                            "fixture_target_not_found",
                    "target_failure", "target resolution failure was not canonical");

    auto live_args = valid_arguments(4103);
    auto live = adapters::py_exec_file(
        handlers, live_args, cancellation_token_t::create());
    require_fixture(live.is_error() &&
                        live.error_code() == "MCP_TOOL_EFFECT_POLICY_REJECTED",
                    "target_failure", "live target was not denied");
    require_fixture(executor.calls == before,
                    "target_failure", "failed or live target reached the worker");
    ++completed;
}

void verify_cancellation(python_handlers_t& handlers,
                         target_state_t& targets,
                         executor_state_t& executor,
                         std::size_t& completed) {
    auto cancellation = cancellation_token_t::create(true);
    const std::size_t target_calls = targets.calls;
    const std::size_t worker_calls = executor.calls;
    auto result = adapters::py_exec_file(handlers, valid_arguments(), cancellation);
    require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                    "cancellation", "pre-dispatch cancellation was not canonical");
    require_fixture(targets.calls == target_calls && executor.calls == worker_calls,
                    "cancellation", "cancelled request reached target or worker code");
    ++completed;
}

void verify_worker_failures(python_handlers_t& handlers,
                            executor_state_t& executor,
                            std::size_t& completed) {
    struct failure_case_t final {
        python_worker_status_t status;
        std::string error_code;
        std::string expected_result;
        std::string expected_status;
    };
    const std::vector<failure_case_t> cases{
        {python_worker_status_t::cancelled, "FIXTURE_WORKER_FAILURE",
         "MCP_TOOL_CANCELLED", "cancelled"},
        {python_worker_status_t::rejected, "PYTHON_WORKER_UNSAFE_APPROVAL_REQUIRED",
         "MCP_TOOL_EFFECT_POLICY_REJECTED", "rejected"},
        {python_worker_status_t::rejected, "PYTHON_WORKER_INVALID_REQUEST",
         "MCP_TOOL_INPUT_INVALID", "rejected"},
        {python_worker_status_t::rejected, "PYTHON_WORKER_SCRIPT_REJECTED",
         "MCP_TOOL_INPUT_INVALID", "rejected"},
        {python_worker_status_t::rejected, "FIXTURE_WORKER_FAILURE",
         "MCP_TOOL_HANDLER_FAILED", "rejected"},
        {python_worker_status_t::deadline_exceeded, "FIXTURE_WORKER_FAILURE",
         "MCP_TOOL_HANDLER_FAILED", "deadline_exceeded"},
        {python_worker_status_t::worker_crashed, "FIXTURE_WORKER_FAILURE",
         "MCP_TOOL_HANDLER_FAILED", "worker_crashed"},
        {python_worker_status_t::protocol_failure, "FIXTURE_WORKER_FAILURE",
         "MCP_TOOL_HANDLER_FAILED", "protocol_failure"},
        {python_worker_status_t::worker_failed, "FIXTURE_WORKER_FAILURE",
         "MCP_TOOL_HANDLER_FAILED", "worker_failed"},
        {python_worker_status_t::host_stopped, "FIXTURE_WORKER_FAILURE",
         "MCP_TOOL_HANDLER_FAILED", "host_stopped"},
    };
    for (const auto& item : cases) {
        executor.result = {};
        executor.result.status = item.status;
        executor.result.error_code = item.error_code;
        executor.result.worker_generation = 8;
        executor.result.worker_process_id = 9912;
        executor.result.worker_terminated =
            item.status != python_worker_status_t::host_stopped;
        executor.result.worker_replaced =
            item.status != python_worker_status_t::host_stopped;
        executor.result.diagnostics.push_back({
            python_worker_error_code_t::worker_replaced,
            "fixture.worker", "terminal fixture failure", 0, true});
        auto result = adapters::py_exec_file(
            handlers, valid_arguments(), cancellation_token_t::create());
        require_fixture(result.is_error() && result.error_code() == item.expected_result,
                        "worker_failure", "worker status mapping is not canonical");
        require_fixture(result.aida_metadata().at("worker_status") ==
                            item.expected_status,
                        "worker_failure", "worker status metadata is absent");
    }
    executor.result = completed_result();
    ++completed;
}

void verify_output_bounds(python_handlers_t& handlers,
                          executor_state_t& executor,
                          const python_handler_limits_t& limits,
                          protocol::schema_runtime_t& schemas,
                          std::size_t& completed) {
    executor.result = completed_result();
    executor.result.stdout_text.assign(limits.max_result_bytes, 'X');
    auto oversized = adapters::py_exec_file(
        handlers, valid_arguments(), cancellation_token_t::create());
    require_fixture(oversized.is_error() &&
                        oversized.error_code() == "MCP_TOOL_OUTPUT_INVALID",
                    "output_bounds", "oversized completed output was accepted");
    const json missing_diagnostics{
        {"result", "ok"},
        {"stdout", ""},
        {"stderr", ""},
        {"worker_generation", 1},
        {"worker_process_id", 2},
    };
    require_fixture(
        !schemas.validate(handlers.contract_at(0).output_schema, missing_diagnostics).valid,
        "output_bounds", "generated output schema accepted missing diagnostics");
    executor.result = completed_result();
    ++completed;
}

void verify_executor_exception_and_metadata(python_handlers_t& handlers,
                                            executor_state_t& executor,
                                            std::size_t& completed) {
    executor.throw_exception = true;
    auto failure = adapters::py_exec_file(
        handlers, valid_arguments(), cancellation_token_t::create());
    executor.throw_exception = false;
    require_fixture(failure.is_error() &&
                        failure.error_code() == "MCP_TOOL_HANDLER_FAILED",
                    "executor_exception", "executor exception was not contained");
    auto invalid_metadata = adapters::py_exec_file(
        handlers, valid_arguments(), cancellation_token_t::create(), json::array());
    require_fixture(invalid_metadata.is_error() &&
                        invalid_metadata.error_code() == "MCP_TOOL_INTERNAL_ERROR",
                    "executor_exception", "non-object provenance metadata was accepted");
    ++completed;
}

void verify_invalid_lease(protocol::schema_runtime_t& schemas,
                          std::size_t& completed) {
    target_state_t invalid_targets;
    auto missing_owner = make_target(
        5001, "workspace-invalid", "invalid.exe", "relative\\invalid.exe", 4);
    missing_owner.owner.reset();
    invalid_targets.targets.push_back(std::move(missing_owner));
    invalid_targets.targets.push_back(make_target(
        5002, "workspace-relative", "relative.exe", "relative\\relative.exe", 5));
    invalid_targets.targets.push_back(make_target(
        5003, "workspace-normalization", "normalization.exe",
        "C:\\fixtures\\normalization\\..\\normalization.exe", 6));
    auto oversized_identity = make_target(
        5004, "workspace-oversized", "oversized.exe",
        "C:\\fixtures\\oversized\\oversized.exe", 7);
    oversized_identity.workspace_id.assign(4097, 'W');
    invalid_targets.targets.push_back(std::move(oversized_identity));
    executor_state_t executor;
    python_handlers_t handlers(
        [&invalid_targets](const target_selector_t& selector,
                           std::optional<std::chrono::steady_clock::time_point> deadline) {
            return invalid_targets.acquire(selector, deadline);
        },
        [&executor](const std::filesystem::path& root,
                    const python_worker_execution_request_t& request) {
            return executor.execute(root, request);
        },
        schemas);
    for (const std::uint32_t pid : {5001U, 5002U, 5003U, 5004U}) {
        auto result = adapters::py_exec_file(
            handlers, valid_arguments(pid), cancellation_token_t::create());
        require_fixture(result.is_error() &&
                            result.error_code() == "MCP_TOOL_TARGET_POLICY_REJECTED",
                        "invalid_lease", "invalid local target lease was accepted");
    }
    require_fixture(executor.calls == 0,
                    "invalid_lease", "invalid local target lease reached the worker");
    ++completed;
}

void verify_python_handler() {
    protocol::schema_runtime_t schemas(64);
    target_state_t targets;
    targets.targets.push_back(make_target(
        4101, "workspace-alpha", "alpha.exe",
        "C:\\fixtures\\alpha\\alpha.exe", 11));
    targets.targets.push_back(make_target(
        4102, "workspace-beta", "beta.exe",
        "D:\\workspaces\\beta\\beta.exe", 19));
    targets.targets.push_back(make_target(
        4103, "workspace-live", "live.exe",
        "C:\\captures\\live.exe", 23, true));
    executor_state_t executor;
    python_handlers_t handlers(
        [&targets](const target_selector_t& selector,
                   std::optional<std::chrono::steady_clock::time_point> deadline) {
            return targets.acquire(selector, deadline);
        },
        [&executor](const std::filesystem::path& root,
                    const python_worker_execution_request_t& request) {
            return executor.execute(root, request);
        },
        schemas);

    std::size_t completed = 0;
    verify_generated_contract(handlers, schemas, completed);
    verify_old_and_unsafe_inputs(handlers, targets, executor, completed);
    verify_target_derived_roots(handlers, targets, executor, schemas, completed);
    verify_path_containment(handlers, targets, executor, completed);
    verify_target_failures(handlers, targets, executor, completed);
    verify_cancellation(handlers, targets, executor, completed);
    verify_worker_failures(handlers, executor, completed);
    verify_output_bounds(handlers, executor, handlers.limits(), schemas, completed);
    verify_executor_exception_and_metadata(handlers, executor, completed);
    verify_invalid_lease(schemas, completed);
    require(completed == 10,
            "python handler harness did not execute all ten fixture families");
}

}

bool run_python_handler_harness(std::string& failure) {
    try {
        verify_python_handler();
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
