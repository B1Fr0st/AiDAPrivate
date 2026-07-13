#include "python.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <exception>
#include <filesystem>
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

constexpr std::array<std::string_view, k_python_tool_count> k_python_names{{
    "py_exec_file",
}};

bool valid_limits(const python_handler_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 &&
        limits.max_request_bytes <= 1024U * 1024U &&
        limits.max_script_path_bytes != 0 &&
        limits.max_script_path_bytes <= 4096U &&
        limits.max_workspace_metadata_bytes != 0 &&
        limits.max_workspace_metadata_bytes <= 64U * 1024U &&
        limits.max_result_bytes != 0 &&
        limits.max_result_bytes <= 256U * 1024U &&
        limits.max_execution_time.count() > 0 &&
        limits.max_execution_time.count() <= 30000;
}

std::string_view status_name(python_worker_status_t status) noexcept {
    switch (status) {
    case python_worker_status_t::completed:
        return "completed";
    case python_worker_status_t::rejected:
        return "rejected";
    case python_worker_status_t::cancelled:
        return "cancelled";
    case python_worker_status_t::deadline_exceeded:
        return "deadline_exceeded";
    case python_worker_status_t::worker_crashed:
        return "worker_crashed";
    case python_worker_status_t::protocol_failure:
        return "protocol_failure";
    case python_worker_status_t::worker_failed:
        return "worker_failed";
    case python_worker_status_t::host_stopped:
        return "host_stopped";
    }
    return "unknown";
}

std::string_view diagnostic_code_name(python_worker_error_code_t code) noexcept {
    switch (code) {
    case python_worker_error_code_t::none:
        return "none";
    case python_worker_error_code_t::invalid_request:
        return "invalid_request";
    case python_worker_error_code_t::unsafe_approval_required:
        return "unsafe_approval_required";
    case python_worker_error_code_t::manifest_unavailable:
        return "manifest_unavailable";
    case python_worker_error_code_t::manifest_hash_mismatch:
        return "manifest_hash_mismatch";
    case python_worker_error_code_t::manifest_malformed:
        return "manifest_malformed";
    case python_worker_error_code_t::worker_path_rejected:
        return "worker_path_rejected";
    case python_worker_error_code_t::worker_hash_mismatch:
        return "worker_hash_mismatch";
    case python_worker_error_code_t::script_path_rejected:
        return "script_path_rejected";
    case python_worker_error_code_t::script_too_large:
        return "script_too_large";
    case python_worker_error_code_t::script_encoding_invalid:
        return "script_encoding_invalid";
    case python_worker_error_code_t::launch_policy_rejected:
        return "launch_policy_rejected";
    case python_worker_error_code_t::launch_failed:
        return "launch_failed";
    case python_worker_error_code_t::bootstrap_failed:
        return "bootstrap_failed";
    case python_worker_error_code_t::hello_failed:
        return "hello_failed";
    case python_worker_error_code_t::protocol_malformed:
        return "protocol_malformed";
    case python_worker_error_code_t::workspace_api_denied:
        return "workspace_api_denied";
    case python_worker_error_code_t::workspace_api_failed:
        return "workspace_api_failed";
    case python_worker_error_code_t::output_limit_exceeded:
        return "output_limit_exceeded";
    case python_worker_error_code_t::deadline_exceeded:
        return "deadline_exceeded";
    case python_worker_error_code_t::cancelled:
        return "cancelled";
    case python_worker_error_code_t::worker_crashed:
        return "worker_crashed";
    case python_worker_error_code_t::worker_replaced:
        return "worker_replaced";
    }
    return "unknown";
}

result_error_code_t map_status_to_error_code(
    python_worker_status_t status,
    const std::string& worker_error_code) noexcept {
    switch (status) {
    case python_worker_status_t::cancelled:
        return result_error_code_t::cancelled;
    case python_worker_status_t::host_stopped:
        return result_error_code_t::internal_error;
    case python_worker_status_t::rejected:
        if (worker_error_code == "PYTHON_WORKER_UNSAFE_APPROVAL_REQUIRED")
            return result_error_code_t::effect_policy_rejected;
        if (worker_error_code == "PYTHON_WORKER_INVALID_REQUEST" ||
            worker_error_code == "PYTHON_WORKER_SCRIPT_REJECTED" ||
            worker_error_code == "PYTHON_WORKER_SCRIPT_ENCODING_INVALID" ||
            worker_error_code == "PYTHON_WORKER_SCRIPT_TOO_LARGE")
            return result_error_code_t::invalid_input;
        return result_error_code_t::handler_failed;
    case python_worker_status_t::deadline_exceeded:
    case python_worker_status_t::worker_crashed:
    case python_worker_status_t::protocol_failure:
    case python_worker_status_t::worker_failed:
        return result_error_code_t::handler_failed;
    case python_worker_status_t::completed:
        return result_error_code_t::handler_failed;
    }
    return result_error_code_t::handler_failed;
}

std::string map_status_to_text(
    python_worker_status_t status,
    const std::string& worker_error_code) {
    switch (status) {
    case python_worker_status_t::cancelled:
        return "Python worker execution was cancelled.";
    case python_worker_status_t::host_stopped:
        return "Python worker host is stopped and cannot accept execution requests.";
    case python_worker_status_t::rejected:
        if (worker_error_code == "PYTHON_WORKER_UNSAFE_APPROVAL_REQUIRED")
            return "Python worker requires explicit unsafe approval.";
        if (worker_error_code == "PYTHON_WORKER_INVALID_REQUEST")
            return "Python worker request is invalid.";
        if (worker_error_code == "PYTHON_WORKER_SCRIPT_REJECTED")
            return "Python script was rejected by the worker path policy.";
        if (worker_error_code == "PYTHON_WORKER_MANIFEST_REJECTED")
            return "Python worker manifest verification failed.";
        if (worker_error_code == "PYTHON_WORKER_LAUNCH_FAILED")
            return "Python worker process launch failed.";
        return "Python worker rejected the execution request.";
    case python_worker_status_t::deadline_exceeded:
        return "Python worker execution exceeded the configured deadline.";
    case python_worker_status_t::worker_crashed:
        return "Python worker process crashed before producing a terminal result.";
    case python_worker_status_t::protocol_failure:
        return "Python worker violated the authenticated frame protocol.";
    case python_worker_status_t::worker_failed:
        return "Python worker reported a terminal script failure.";
    case python_worker_status_t::completed:
        return "Python worker completed successfully.";
    }
    return "Python worker returned an unrecognized status.";
}

json diagnostics_array(const std::vector<python_worker_diagnostic_t>& diagnostics) {
    json array = json::array();
    for (const auto& diag : diagnostics) {
        array.push_back(json{
            {"code", std::string(diagnostic_code_name(diag.code))},
            {"phase", diag.phase},
            {"detail", diag.detail},
            {"win32_error", diag.win32_error},
            {"replacement", diag.replacement},
        });
    }
    return array;
}

json worker_metadata(
    const python_worker_execution_result_t& result,
    std::uint64_t job_id) {
    json metadata = json{
        {"worker_status", std::string(status_name(result.status))},
        {"worker_error_code", result.error_code.empty() ? "PYTHON_WORKER_OK" : result.error_code},
        {"worker_generation", result.worker_generation},
        {"worker_process_id", result.worker_process_id},
        {"worker_terminated", result.worker_terminated},
        {"worker_replaced", result.worker_replaced},
        {"job_id", job_id},
    };
    if (!result.diagnostics.empty()) {
        metadata["diagnostics"] = diagnostics_array(result.diagnostics);
    }
    return metadata;
}

json worker_structured(const python_worker_execution_result_t& result) {
    return json{
        {"status", std::string(status_name(result.status))},
        {"result", result.result},
        {"stdout", result.stdout_text},
        {"stderr", result.stderr_text},
        {"error_code", result.error_code},
        {"worker_generation", result.worker_generation},
        {"worker_process_id", result.worker_process_id},
        {"worker_terminated", result.worker_terminated},
        {"worker_replaced", result.worker_replaced},
    };
}

json worker_error_details(
    const python_worker_execution_result_t& result,
    std::uint64_t job_id) {
    json details = json{
        {"phase", "python_worker_result"},
        {"worker_status", std::string(status_name(result.status))},
        {"worker_error_code", result.error_code},
        {"worker_generation", result.worker_generation},
        {"worker_process_id", result.worker_process_id},
        {"worker_terminated", result.worker_terminated},
        {"worker_replaced", result.worker_replaced},
        {"job_id", job_id},
    };
    if (!result.diagnostics.empty()) {
        details["diagnostics"] = diagnostics_array(result.diagnostics);
    }
    return details;
}

mcp_result_t map_worker_result(
    const python_worker_execution_result_t& result,
    std::uint64_t job_id) {
    const auto metadata = worker_metadata(result, job_id);
    if (result.completed()) {
        const std::size_t total_output =
            result.result.size() + result.stdout_text.size() + result.stderr_text.size();
        if (total_output > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
            return mcp_result_t::failure(
                result_error_code_t::invalid_output,
                "Python worker output exceeds the representable byte range.",
                json{{"phase", "python_output_bounds"}, {"total_bytes", total_output}},
                metadata);
        }
        return mcp_result_t::success(
            result.result.empty() ? "Python script completed." : result.result,
            worker_structured(result),
            metadata);
    }
    const auto error_code = map_status_to_error_code(result.status, result.error_code);
    const auto error_text = map_status_to_text(result.status, result.error_code);
    return mcp_result_t::failure(
        error_code,
        error_text,
        worker_error_details(result, job_id),
        metadata);
}

std::chrono::milliseconds execution_timeout(
    const protocol::tool_contract_t& contract,
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
        const auto args = decorator.find("args");
        if (args == decorator.end() || !args->is_array() || args->empty() ||
            !(*args)[0].is_number()) {
            continue;
        }
        try {
            const double seconds = (*args)[0].get<double>();
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

protocol::tool_contract_t make_py_exec_file_contract() {
    protocol::tool_contract_t contract;
    contract.name = "py_exec_file";
    contract.description =
        "Execute a Python script file in an isolated, sandboxed worker "
        "process with explicit unsafe approval and bounded output.";
    contract.input_schema = json::parse(R"({
        "type": "object",
        "properties": {
            "script_path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "description": "Path to a .py script within the approved script root."
            },
            "unsafe_approved": {
                "type": "boolean",
                "enum": [true],
                "description": "Must be true to authorize isolated Python execution."
            },
            "workspace_metadata": {
                "type": "object",
                "maxProperties": 64,
                "description": "Optional metadata object passed to the worker."
            }
        },
        "required": ["script_path", "unsafe_approved"],
        "additionalProperties": false
    })", nullptr, false);
    contract.output_schema = json::parse(R"({
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["completed", "rejected", "cancelled", "deadline_exceeded", "worker_crashed", "protocol_failure", "worker_failed", "host_stopped"]
            },
            "result": {"type": "string"},
            "stdout": {"type": "string"},
            "stderr": {"type": "string"},
            "error_code": {"type": "string"},
            "worker_generation": {"type": "integer", "minimum": 0},
            "worker_process_id": {"type": "integer", "minimum": 0},
            "worker_terminated": {"type": "boolean"},
            "worker_replaced": {"type": "boolean"}
        },
        "required": ["status", "worker_terminated", "worker_replaced"],
        "additionalProperties": false
    })", nullptr, false);
    contract.annotations = json::parse(R"({
        "title": "Execute Python Script File",
        "decorators": [
            {"name": "tool_timeout", "args": [30]}
        ]
    })", nullptr, false);
    contract.target_policy.requirement = protocol::target_requirement_t::independent;
    contract.target_policy.accepts_pid = false;
    contract.target_policy.accepts_bin_name = false;
    contract.effect_policy.effect = protocol::tool_effect_t::isolated_python;
    contract.effect_policy.lock = protocol::effect_lock_t::python_worker;
    contract.effect_policy.read_only = false;
    contract.effect_policy.unsafe = true;
    return contract;
}

json invalid_value(std::string path, std::string reason, const json& actual) {
    return json{
        {"policy", "bounded_python_handler"},
        {"field", std::move(path)},
        {"reason", std::move(reason)},
        {"actual", actual},
    };
}

json exceeded_value(std::string path, std::uint64_t maximum, std::uint64_t actual) {
    return json{
        {"policy", "bounded_python_handler"},
        {"field", std::move(path)},
        {"reason", "maximum_exceeded"},
        {"maximum", maximum},
        {"actual", actual},
    };
}

}

const std::array<std::string_view, k_python_tool_count>& python_tool_names() noexcept {
    return k_python_names;
}

python_handlers_t::python_handlers_t(python_worker_execute_t executor,
                                     protocol::schema_runtime_t& schemas,
                                     python_handler_limits_t limits)
    : executor_(std::move(executor)), schemas_(schemas), limits_(std::move(limits)) {
    if (!executor_) {
        throw std::invalid_argument("python handler executor must not be null");
    }
    if (!valid_limits(limits_)) {
        throw std::invalid_argument("python handler limits are invalid or weaken pinned maxima");
    }
    contracts_[0] = make_py_exec_file_contract();
    const auto validation = protocol::validate_tool_contract(contracts_[0], schemas_);
    if (!validation.valid) {
        throw std::runtime_error(
            "python handler contract validation failed for py_exec_file: " +
            validation.reason);
    }
}

std::size_t python_handlers_t::size() const noexcept {
    return contracts_.size();
}

const protocol::tool_contract_t& python_handlers_t::contract_at(std::size_t index) const {
    return contracts_.at(index);
}

const protocol::tool_contract_t* python_handlers_t::find(std::string_view name) const noexcept {
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    return found == contracts_.end() ? nullptr : &*found;
}

const python_handler_limits_t& python_handlers_t::limits() const noexcept {
    return limits_;
}

protocol::mcp_result_t python_handlers_t::invoke(
    std::string_view name, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata) const {
    if (!aida_metadata.is_object()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::internal_error,
            "Python tool provenance metadata must be a JSON object.",
            protocol::json{{"field", "aida_metadata"}});
    }
    const auto found = std::find_if(
        contracts_.begin(), contracts_.end(),
        [name](const protocol::tool_contract_t& contract) { return contract.name == name; });
    if (found == contracts_.end()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_contract,
            "Python tool is not registered in the pinned contract group.",
            protocol::json{{"tool", std::string(name)}},
            aida_metadata);
    }
    const std::size_t index = static_cast<std::size_t>(std::distance(contracts_.begin(), found));
    return protocol::invoke_tool_contract(
        *found,
        arguments,
        [this, index](const protocol::json& validated_arguments,
                       const protocol::cancellation_token_t& token) {
            return dispatch(index, validated_arguments, token);
        },
        schemas_,
        cancellation,
        aida_metadata);
}

protocol::mcp_result_t python_handlers_t::dispatch(
    std::size_t index, const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation) const {
    const auto name = k_python_names.at(index);
    const auto& contract = contracts_.at(index);

    if (cancellation.cancelled()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Python tool invocation was cancelled before worker dispatch.",
            protocol::json{{"phase", "python_pre_dispatch"}, {"tool", std::string(name)}});
    }

    const auto script_path_it = arguments.find("script_path");
    if (script_path_it == arguments.end() || !script_path_it->is_string()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python tool requires a string script_path argument.",
            invalid_value("script_path", "string_required",
                          script_path_it == arguments.end() ? json(nullptr) : *script_path_it));
    }
    const auto& script_path = script_path_it->get_ref<const std::string&>();
    if (script_path.empty()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python tool script_path must not be empty.",
            invalid_value("script_path", "nonempty_string_required", *script_path_it));
    }
    if (script_path.size() > limits_.max_script_path_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python tool script_path exceeds the bounded handler quota.",
            exceeded_value("script_path",
                           static_cast<std::uint64_t>(limits_.max_script_path_bytes),
                           static_cast<std::uint64_t>(script_path.size())));
    }
    if (script_path.size() < 3 ||
        script_path.compare(script_path.size() - 3, 3, ".py") != 0) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python tool script_path must use the .py extension.",
            invalid_value("script_path", "extension_required", *script_path_it));
    }

    const auto approval_it = arguments.find("unsafe_approved");
    if (approval_it == arguments.end() || !approval_it->is_boolean()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python tool requires a boolean unsafe_approved argument.",
            invalid_value("unsafe_approved", "boolean_required",
                          approval_it == arguments.end() ? json(nullptr) : *approval_it));
    }
    if (!approval_it->get<bool>()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::effect_policy_rejected,
            "Python tool requires explicit unsafe approval set to true.",
            invalid_value("unsafe_approved", "explicit_approval_required", *approval_it));
    }

    json workspace_metadata = json::object();
    if (const auto metadata_it = arguments.find("workspace_metadata");
        metadata_it != arguments.end()) {
        if (!metadata_it->is_object()) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_input,
                "Python tool workspace_metadata must be a JSON object.",
                invalid_value("workspace_metadata", "object_required", *metadata_it));
        }
        workspace_metadata = *metadata_it;
        std::string metadata_serialized;
        try {
            metadata_serialized = workspace_metadata.dump();
        } catch (const std::exception&) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_input,
                "Python tool workspace_metadata cannot be serialized.",
                invalid_value("workspace_metadata", "serialization_failed", *metadata_it));
        }
        if (metadata_serialized.size() > limits_.max_workspace_metadata_bytes) {
            return protocol::mcp_result_t::failure(
                protocol::result_error_code_t::invalid_input,
                "Python tool workspace_metadata exceeds the bounded handler quota.",
                exceeded_value("workspace_metadata",
                               static_cast<std::uint64_t>(limits_.max_workspace_metadata_bytes),
                               static_cast<std::uint64_t>(metadata_serialized.size())));
        }
    }

    std::string serialized_arguments;
    try {
        serialized_arguments = arguments.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python tool arguments cannot be serialized.",
            protocol::json{{"phase", "python_request_serialization"}});
    }
    if (serialized_arguments.size() > limits_.max_request_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python tool request exceeds the bounded handler quota.",
            exceeded_value("request_bytes",
                           static_cast<std::uint64_t>(limits_.max_request_bytes),
                           static_cast<std::uint64_t>(serialized_arguments.size())));
    }

    static std::atomic<std::uint64_t> job_counter{1};
    python_worker_execution_request_t exec_request;
    exec_request.job_id = job_counter.fetch_add(1, std::memory_order_relaxed);
    exec_request.script_path = std::filesystem::path(script_path);
    exec_request.workspace_metadata = std::move(workspace_metadata);
    exec_request.unsafe_approved = true;
    exec_request.cancellation = cancellation.state().get();
    exec_request.deadline = std::chrono::steady_clock::now() +
        execution_timeout(contract, limits_.max_execution_time);

    python_worker_execution_result_t exec_result;
    try {
        exec_result = executor_(exec_request);
    } catch (const std::exception& error) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::handler_failed,
            "Python worker executor threw an exception.",
            protocol::json{
                {"phase", "python_executor_exception"},
                {"exception", error.what()},
                {"job_id", exec_request.job_id},
            });
    }

    if (cancellation.cancelled() &&
        exec_result.status != python_worker_status_t::cancelled) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Python tool invocation was cancelled during worker execution.",
            protocol::json{
                {"phase", "python_post_execute"},
                {"job_id", exec_request.job_id},
                {"worker_status", std::string(status_name(exec_result.status))},
            });
    }

    return map_worker_result(exec_result, exec_request.job_id);
}

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t py_exec_file(const handlers::python_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata) {
    return handlers.invoke("py_exec_file", arguments, cancellation, aida_metadata);
}

}
