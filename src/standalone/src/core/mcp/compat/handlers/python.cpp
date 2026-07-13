#include "python.hpp"

#include "../ida_contracts_generated.hpp"

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

using validation_failure_t = std::optional<json>;

json parse_generated_json(std::string_view value, std::string_view field,
                          std::string_view tool_name) {
    try {
        return json::parse(value.begin(), value.end());
    } catch (const std::exception&) {
        throw std::runtime_error(
            "generated Python contract JSON is invalid for " + std::string(tool_name) +
            " field " + std::string(field));
    }
}

protocol::tool_effect_t protocol_effect(contract_effect_t effect) {
    switch (effect) {
    case contract_effect_t::workspace_read:
        return protocol::tool_effect_t::workspace_read;
    case contract_effect_t::workspace_checkpoint:
        return protocol::tool_effect_t::workspace_checkpoint;
    case contract_effect_t::workspace_overlay_mutation:
        return protocol::tool_effect_t::workspace_overlay_mutation;
    case contract_effect_t::debugger_read:
        return protocol::tool_effect_t::debugger_read;
    case contract_effect_t::debugger_control:
        return protocol::tool_effect_t::debugger_control;
    case contract_effect_t::debugger_write:
        return protocol::tool_effect_t::debugger_write;
    case contract_effect_t::isolated_python:
        return protocol::tool_effect_t::isolated_python;
    case contract_effect_t::registry_read:
        return protocol::tool_effect_t::registry_read;
    }
    throw std::runtime_error("generated Python contract has an unknown effect");
}

protocol::effect_lock_t protocol_lock(contract_lock_t lock) {
    switch (lock) {
    case contract_lock_t::workspace_shared:
        return protocol::effect_lock_t::workspace_shared;
    case contract_lock_t::workspace_checkpoint:
        return protocol::effect_lock_t::workspace_checkpoint;
    case contract_lock_t::workspace_overlay_transaction:
        return protocol::effect_lock_t::workspace_overlay_transaction;
    case contract_lock_t::debugger_lane:
        return protocol::effect_lock_t::debugger_lane;
    case contract_lock_t::python_worker:
        return protocol::effect_lock_t::python_worker;
    case contract_lock_t::registry_read:
        return protocol::effect_lock_t::registry_read;
    }
    throw std::runtime_error("generated Python contract has an unknown lock");
}

void validate_generated_descriptor(const contract_descriptor_t& descriptor) {
    constexpr std::string_view expected_adapter =
        "aida::standalone::mcp::compat::python_worker_host_t::execute";
    if (descriptor.name != "py_exec_file" ||
        descriptor.adapter_symbol != expected_adapter ||
        !descriptor.archive_backed || !descriptor.target_dependent ||
        !descriptor.accepts_pid || !descriptor.accepts_bin_name ||
        descriptor.read_only || !descriptor.unsafe ||
        descriptor.effect != contract_effect_t::isolated_python ||
        descriptor.lock != contract_lock_t::python_worker) {
        throw std::runtime_error("generated py_exec_file descriptor policy mismatch");
    }
}

protocol::tool_contract_t make_tool_contract(const contract_descriptor_t& descriptor) {
    protocol::tool_contract_t contract;
    contract.name.assign(descriptor.name.data(), descriptor.name.size());
    contract.description.assign(descriptor.description.data(), descriptor.description.size());
    contract.input_schema = parse_generated_json(
        descriptor.input_schema_json, "input_schema", descriptor.name);
    contract.output_schema = parse_generated_json(
        descriptor.output_schema_json, "output_schema", descriptor.name);
    contract.annotations = parse_generated_json(
        descriptor.annotations_json, "annotations", descriptor.name);
    contract.target_policy.requirement = protocol::target_requirement_t::optional;
    contract.target_policy.accepts_pid = descriptor.accepts_pid;
    contract.target_policy.accepts_bin_name = descriptor.accepts_bin_name;
    contract.effect_policy.effect = protocol_effect(descriptor.effect);
    contract.effect_policy.lock = protocol_lock(descriptor.lock);
    contract.effect_policy.read_only = descriptor.read_only;
    contract.effect_policy.unsafe = descriptor.unsafe;
    return contract;
}

bool valid_limits(const python_handler_limits_t& limits) noexcept {
    return limits.max_request_bytes != 0 &&
        limits.max_request_bytes <= 1024U * 1024U &&
        limits.max_script_path_bytes != 0 &&
        limits.max_script_path_bytes <= 4096U &&
        limits.max_target_source_path_bytes != 0 &&
        limits.max_target_source_path_bytes <= 32U * 1024U &&
        limits.max_selector_bytes != 0 &&
        limits.max_selector_bytes <= 1024U &&
        limits.max_workspace_id_bytes != 0 &&
        limits.max_workspace_id_bytes <= 4096U &&
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

json diagnostics_array(const std::vector<python_worker_diagnostic_t>& diagnostics) {
    json array = json::array();
    for (const auto& diagnostic : diagnostics) {
        array.push_back(json{
            {"code", std::string(diagnostic_code_name(diagnostic.code))},
            {"phase", diagnostic.phase},
            {"detail", diagnostic.detail},
            {"win32_error", diagnostic.win32_error},
            {"worker_replaced", diagnostic.replacement},
        });
    }
    return array;
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

std::optional<std::uint64_t> unsigned_integer(const json& value) noexcept {
    try {
        if (value.is_number_unsigned()) {
            return value.get<std::uint64_t>();
        }
        if (value.is_number_integer()) {
            const auto signed_value = value.get<std::int64_t>();
            if (signed_value >= 0) {
                return static_cast<std::uint64_t>(signed_value);
            }
        }
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

validation_failure_t bounded_text(const json& value, std::string path,
                                  std::size_t maximum, bool allow_empty) {
    if (!value.is_string()) {
        return invalid_value(std::move(path), "string_required", value);
    }
    const auto& text = value.get_ref<const std::string&>();
    if (!allow_empty && text.empty()) {
        return invalid_value(std::move(path), "nonempty_string_required", value);
    }
    if (text.find('\0') != std::string::npos) {
        return invalid_value(std::move(path), "nul_forbidden", value);
    }
    if (text.size() > maximum) {
        return exceeded_value(
            std::move(path), static_cast<std::uint64_t>(maximum),
            static_cast<std::uint64_t>(text.size()));
    }
    return std::nullopt;
}

validation_failure_t validate_routing_bounds(const json& arguments,
                                             const python_handler_limits_t& limits) {
    const bool has_pid = arguments.contains("pid");
    const bool has_bin_name = arguments.contains("bin_name");
    if (has_pid && has_bin_name) {
        return invalid_value("target", "single_selector_required", json{
            {"pid", arguments.at("pid")},
            {"bin_name", arguments.at("bin_name")},
        });
    }
    if (has_pid) {
        const auto value = unsigned_integer(arguments.at("pid"));
        if (!value || *value == 0 ||
            *value > (std::numeric_limits<std::uint32_t>::max)()) {
            return invalid_value("pid", "valid_process_id_required", arguments.at("pid"));
        }
    }
    if (has_bin_name) {
        return bounded_text(
            arguments.at("bin_name"), "bin_name", limits.max_selector_bytes, false);
    }
    return std::nullopt;
}

target_selector_t target_selector(const json& arguments) {
    target_selector_t selector;
    if (const auto pid = arguments.find("pid"); pid != arguments.end()) {
        selector.pid = static_cast<std::uint32_t>(*unsigned_integer(*pid));
    }
    if (const auto bin_name = arguments.find("bin_name"); bin_name != arguments.end()) {
        selector.bin_name = bin_name->get<std::string>();
    }
    return selector;
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
            if (!std::isfinite(seconds) || seconds <= 0.0 || seconds > 86400.0) {
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

result_error_code_t adapter_error_code(adapter_error_code_t code) noexcept {
    switch (code) {
    case adapter_error_code_t::invalid_request:
        return result_error_code_t::invalid_input;
    case adapter_error_code_t::target_resolution_failed:
        return result_error_code_t::target_policy_rejected;
    case adapter_error_code_t::operation_not_permitted:
    case adapter_error_code_t::effect_policy_failed:
        return result_error_code_t::effect_policy_rejected;
    case adapter_error_code_t::none:
    case adapter_error_code_t::contract_not_found:
    case adapter_error_code_t::effect_lock_busy:
    case adapter_error_code_t::backend_unavailable:
    case adapter_error_code_t::backend_rejected:
    case adapter_error_code_t::live_snapshot_denied:
    case adapter_error_code_t::live_snapshot_bounds:
    case adapter_error_code_t::live_snapshot_invalid:
        return result_error_code_t::handler_failed;
    }
    return result_error_code_t::handler_failed;
}

mcp_result_t target_failure(const adapter_error_t& error) {
    return mcp_result_t::failure(
        adapter_error_code(error.code),
        "Python target lease acquisition failed.",
        json{
            {"phase", "python_target_lease"},
            {"adapter_code", std::string(error.stable_code)},
            {"expected", error.expected},
            {"actual", error.actual},
        });
}

validation_failure_t validate_target_lease(
    const python_target_lease_t& lease,
    const python_handler_limits_t& limits) {
    if (!lease.owner) {
        return invalid_value("target.owner", "local_lease_required", nullptr);
    }
    const auto validate_identity_text = [](const std::string& value,
                                           std::string path,
                                           std::size_t maximum) -> validation_failure_t {
        if (value.empty()) {
            return invalid_value(std::move(path), "nonempty_string_required", value);
        }
        if (value.find('\0') != std::string::npos) {
            return invalid_value(std::move(path), "nul_forbidden", value);
        }
        if (value.size() > maximum) {
            return exceeded_value(
                std::move(path), static_cast<std::uint64_t>(maximum),
                static_cast<std::uint64_t>(value.size()));
        }
        return std::nullopt;
    };
    if (auto failure = validate_identity_text(
            lease.workspace_id, "target.workspace_id",
            limits.max_workspace_id_bytes)) {
        return failure;
    }
    if (auto failure = validate_identity_text(
            lease.bin_name, "target.bin_name", limits.max_selector_bytes)) {
        return failure;
    }
    if (lease.generation == 0) {
        return invalid_value("target.generation", "immutable_generation_required", 0);
    }
    if (lease.pid && *lease.pid == 0) {
        return invalid_value("target.pid", "valid_process_id_required", 0);
    }
    if (lease.normalized_source_path.empty() ||
        lease.normalized_source_path.find('\0') != std::string::npos) {
        return invalid_value(
            "target.normalized_source_path", "normalized_source_path_required",
            lease.normalized_source_path);
    }
    if (lease.normalized_source_path.size() > limits.max_target_source_path_bytes) {
        return exceeded_value(
            "target.normalized_source_path",
            static_cast<std::uint64_t>(limits.max_target_source_path_bytes),
            static_cast<std::uint64_t>(lease.normalized_source_path.size()));
    }
    if (!lease.workspace_metadata.is_object()) {
        return invalid_value("target.workspace_metadata", "object_required", lease.workspace_metadata);
    }
    if (!lease.workspace_api) {
        return invalid_value("target.workspace_api", "workspace_api_required", nullptr);
    }
    return std::nullopt;
}

std::optional<std::filesystem::path> target_script_root(
    const python_target_lease_t& lease) noexcept {
    try {
        const auto supplied = std::filesystem::u8path(lease.normalized_source_path);
        const auto source = supplied.lexically_normal();
        if (source != supplied) {
            return std::nullopt;
        }
        for (const auto& component : supplied) {
            if (component == std::filesystem::path(".") ||
                component == std::filesystem::path("..")) {
                return std::nullopt;
            }
        }
        if (source.empty() || !source.is_absolute() || source.has_root_directory() == false ||
            source.filename().empty()) {
            return std::nullopt;
        }
        const auto root = source.parent_path().lexically_normal();
        if (root.empty() || !root.is_absolute() || root == root.root_path()) {
            return std::nullopt;
        }
        return root;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<std::filesystem::path> relative_script_path(
    std::string_view file_path) noexcept {
    try {
        const auto supplied = std::filesystem::u8path(file_path);
        if (supplied.empty() || supplied.is_absolute() || supplied.has_root_name() ||
            supplied.has_root_directory()) {
            return std::nullopt;
        }
        for (const auto& component : supplied) {
            if (component == std::filesystem::path(".") ||
                component == std::filesystem::path("..")) {
                return std::nullopt;
            }
        }
        const auto relative = supplied.lexically_normal();
        if (relative.empty() ||
            relative.extension() != std::filesystem::path(".py")) {
            return std::nullopt;
        }
        return relative;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

json target_metadata(const python_target_lease_t& lease) {
    return json{
        {"workspace_id", lease.workspace_id},
        {"pid", lease.pid ? json(*lease.pid) : json(nullptr)},
        {"bin_name", lease.bin_name},
        {"generation", lease.generation},
        {"analysis_revision", lease.analysis_revision},
        {"overlay_revision", lease.overlay_revision},
        {"target_kind", lease.live ? "live_snapshot" : "static_file"},
        {"generation_lease", "local_immutable"},
        {"script_root_source", "target_source_parent"},
    };
}

json worker_metadata(const python_worker_execution_result_t& result,
                     const python_target_lease_t& lease,
                     std::uint64_t job_id) {
    json metadata = target_metadata(lease);
    metadata["worker_status"] = std::string(status_name(result.status));
    metadata["worker_error_code"] =
        result.error_code.empty() ? "PYTHON_WORKER_OK" : result.error_code;
    metadata["worker_generation"] = result.worker_generation;
    metadata["worker_process_id"] = result.worker_process_id;
    metadata["worker_terminated"] = result.worker_terminated;
    metadata["worker_replaced"] = result.worker_replaced;
    metadata["job_id"] = job_id;
    if (!result.diagnostics.empty()) {
        metadata["diagnostics"] = diagnostics_array(result.diagnostics);
    }
    return metadata;
}

result_error_code_t worker_error_code(
    python_worker_status_t status,
    const std::string& stable_code) noexcept {
    switch (status) {
    case python_worker_status_t::cancelled:
        return result_error_code_t::cancelled;
    case python_worker_status_t::rejected:
        if (stable_code == "PYTHON_WORKER_UNSAFE_APPROVAL_REQUIRED") {
            return result_error_code_t::effect_policy_rejected;
        }
        if (stable_code == "PYTHON_WORKER_INVALID_REQUEST" ||
            stable_code == "PYTHON_WORKER_SCRIPT_REJECTED") {
            return result_error_code_t::invalid_input;
        }
        return result_error_code_t::handler_failed;
    case python_worker_status_t::deadline_exceeded:
    case python_worker_status_t::worker_crashed:
    case python_worker_status_t::protocol_failure:
    case python_worker_status_t::worker_failed:
    case python_worker_status_t::host_stopped:
    case python_worker_status_t::completed:
        return result_error_code_t::handler_failed;
    }
    return result_error_code_t::handler_failed;
}

std::string worker_error_text(python_worker_status_t status) {
    switch (status) {
    case python_worker_status_t::cancelled:
        return "Python worker execution was cancelled.";
    case python_worker_status_t::rejected:
        return "Python worker rejected the execution request.";
    case python_worker_status_t::deadline_exceeded:
        return "Python worker execution exceeded the configured deadline.";
    case python_worker_status_t::worker_crashed:
        return "Python worker process crashed before producing a terminal result.";
    case python_worker_status_t::protocol_failure:
        return "Python worker violated the authenticated frame protocol.";
    case python_worker_status_t::worker_failed:
        return "Python worker reported a terminal script failure.";
    case python_worker_status_t::host_stopped:
        return "Python worker host is stopped.";
    case python_worker_status_t::completed:
        return "Python worker returned an invalid terminal state.";
    }
    return "Python worker returned an unrecognized status.";
}

mcp_result_t worker_failure(const python_worker_execution_result_t& result,
                            const python_target_lease_t& lease,
                            std::uint64_t job_id) {
    json details{
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
    return mcp_result_t::failure(
        worker_error_code(result.status, result.error_code),
        worker_error_text(result.status),
        details,
        worker_metadata(result, lease, job_id));
}

json worker_structured(const python_worker_execution_result_t& result) {
    return json{
        {"result", result.result},
        {"stdout", result.stdout_text},
        {"stderr", result.stderr_text},
        {"worker_generation", result.worker_generation},
        {"worker_process_id", result.worker_process_id},
        {"diagnostics", diagnostics_array(result.diagnostics)},
    };
}

}

const std::array<std::string_view, k_python_tool_count>& python_tool_names() noexcept {
    return k_python_names;
}

python_handlers_t::python_handlers_t(python_target_acquire_t acquire_target,
                                     python_worker_execute_t executor,
                                     protocol::schema_runtime_t& schemas,
                                     python_handler_limits_t limits)
    : acquire_target_(std::move(acquire_target)),
      executor_(std::move(executor)),
      schemas_(schemas),
      limits_(std::move(limits)) {
    if (!acquire_target_) {
        throw std::invalid_argument("python handler target lease acquisition must not be null");
    }
    if (!executor_) {
        throw std::invalid_argument("python handler executor must not be null");
    }
    if (!valid_limits(limits_)) {
        throw std::invalid_argument("python handler limits are invalid or weaken pinned maxima");
    }
    const auto* descriptor = aida::standalone::mcp::compat::find_contract("py_exec_file");
    if (descriptor == nullptr) {
        throw std::runtime_error("generated py_exec_file descriptor is missing");
    }
    validate_generated_descriptor(*descriptor);
    contracts_[0] = make_tool_contract(*descriptor);
    const auto validation = protocol::validate_tool_contract(contracts_[0], schemas_);
    if (!validation.valid) {
        throw std::runtime_error(
            "generated Python contract validation failed for py_exec_file: " +
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
            exceeded_value(
                "request_bytes", static_cast<std::uint64_t>(limits_.max_request_bytes),
                static_cast<std::uint64_t>(serialized_arguments.size())));
    }
    if (auto failure = validate_routing_bounds(arguments, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python target selectors violate the bounded handler policy.",
            *failure);
    }

    const auto file_path_it = arguments.find("file_path");
    if (file_path_it == arguments.end()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python tool requires file_path.",
            invalid_value("file_path", "required", nullptr));
    }
    if (auto failure = bounded_text(
            *file_path_it, "file_path", limits_.max_script_path_bytes, false)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python file_path violates the bounded handler policy.",
            *failure);
    }
    const auto relative_path = relative_script_path(
        file_path_it->get_ref<const std::string&>());
    if (!relative_path) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python file_path must be a contained workspace-relative .py path.",
            invalid_value("file_path", "contained_relative_python_path_required", *file_path_it));
    }

    const auto approval = arguments.find("approve_unsafe");
    if (approval == arguments.end() || !approval->is_boolean()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_input,
            "Python tool requires boolean approve_unsafe.",
            invalid_value(
                "approve_unsafe", "boolean_required",
                approval == arguments.end() ? json(nullptr) : *approval));
    }
    if (!approval->get<bool>()) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::effect_policy_rejected,
            "Python tool requires explicit unsafe approval.",
            invalid_value("approve_unsafe", "explicit_approval_required", *approval));
    }

    const auto deadline = std::chrono::steady_clock::now() +
        execution_timeout(contract, limits_.max_execution_time);
    auto acquired = acquire_target_(target_selector(arguments), deadline);
    if (!acquired) {
        return target_failure(acquired.error());
    }
    auto lease = std::move(acquired).take_value();
    if (auto failure = validate_target_lease(lease, limits_)) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::target_policy_rejected,
            "Python target lease is invalid.",
            *failure);
    }
    if (lease.live) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::effect_policy_rejected,
            "Python worker execution is unavailable for live targets.",
            json{
                {"phase", "python_target_policy"},
                {"reason", "live_target_denied"},
                {"workspace_id", lease.workspace_id},
            },
            target_metadata(lease));
    }
    const auto script_root = target_script_root(lease);
    if (!script_root) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::target_policy_rejected,
            "Python target source path cannot establish an approved script root.",
            invalid_value(
                "target.normalized_source_path", "absolute_file_source_required",
                lease.normalized_source_path),
            target_metadata(lease));
    }

    json workspace_metadata = lease.workspace_metadata;
    workspace_metadata["workspace_id"] = lease.workspace_id;
    workspace_metadata["pid"] = lease.pid ? json(*lease.pid) : json(nullptr);
    workspace_metadata["bin_name"] = lease.bin_name;
    workspace_metadata["generation"] = lease.generation;
    workspace_metadata["analysis_revision"] = lease.analysis_revision;
    workspace_metadata["overlay_revision"] = lease.overlay_revision;
    workspace_metadata["target_kind"] = "static_file";
    std::string serialized_workspace_metadata;
    try {
        serialized_workspace_metadata = workspace_metadata.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::target_policy_rejected,
            "Python target metadata cannot be serialized.",
            invalid_value("target.workspace_metadata", "serialization_failed", nullptr),
            target_metadata(lease));
    }
    if (serialized_workspace_metadata.size() > limits_.max_workspace_metadata_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::target_policy_rejected,
            "Python target metadata exceeds the bounded worker quota.",
            exceeded_value(
                "target.workspace_metadata",
                static_cast<std::uint64_t>(limits_.max_workspace_metadata_bytes),
                static_cast<std::uint64_t>(serialized_workspace_metadata.size())),
            target_metadata(lease));
    }

    static std::atomic<std::uint64_t> job_counter{1};
    std::uint64_t job_id = job_counter.fetch_add(1, std::memory_order_relaxed);
    if (job_id == 0) {
        job_id = job_counter.fetch_add(1, std::memory_order_relaxed);
    }
    python_worker_execution_request_t request;
    request.job_id = job_id;
    request.script_path = (*script_root / *relative_path).lexically_normal();
    request.workspace_metadata = std::move(workspace_metadata);
    request.workspace_api = std::move(lease.workspace_api);
    request.unsafe_approved = true;
    request.cancellation = cancellation.state().get();
    request.deadline = deadline;

    python_worker_execution_result_t execution;
    try {
        execution = executor_(*script_root, request);
    } catch (const std::exception& error) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::handler_failed,
            "Python worker executor threw an exception.",
            protocol::json{
                {"phase", "python_executor_exception"},
                {"exception", error.what()},
                {"job_id", request.job_id},
            },
            target_metadata(lease));
    } catch (...) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::handler_failed,
            "Python worker executor threw a non-standard exception.",
            protocol::json{
                {"phase", "python_executor_exception"},
                {"job_id", request.job_id},
            },
            target_metadata(lease));
    }

    if (cancellation.cancelled() &&
        execution.status != python_worker_status_t::cancelled) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::cancelled,
            "Python tool invocation was cancelled during worker execution.",
            protocol::json{
                {"phase", "python_post_execute"},
                {"job_id", request.job_id},
                {"worker_status", std::string(status_name(execution.status))},
            },
            worker_metadata(execution, lease, request.job_id));
    }
    if (!execution.completed()) {
        return worker_failure(execution, lease, request.job_id);
    }

    const json structured = worker_structured(execution);
    std::string serialized_output;
    try {
        serialized_output = structured.dump();
    } catch (const std::exception&) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Python worker output cannot be serialized.",
            protocol::json{{"phase", "python_output_serialization"}},
            worker_metadata(execution, lease, request.job_id));
    }
    if (serialized_output.size() > limits_.max_result_bytes) {
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Python worker output exceeds the bounded result quota.",
            exceeded_value(
                "output_bytes", static_cast<std::uint64_t>(limits_.max_result_bytes),
                static_cast<std::uint64_t>(serialized_output.size())),
            worker_metadata(execution, lease, request.job_id));
    }
    const auto output_validation = schemas_.validate(contract.output_schema, structured);
    if (!output_validation.valid) {
        json metadata = worker_metadata(execution, lease, request.job_id);
        metadata["output_schema_source"] = "generated";
        metadata["output_schema_validation"] = "failed";
        return protocol::mcp_result_t::failure(
            protocol::result_error_code_t::invalid_output,
            "Python worker output does not satisfy the generated schema.",
            protocol::json{
                {"phase", "python_output_validation"},
                {"schema", output_validation.diagnostics()},
            },
            metadata);
    }

    json metadata = worker_metadata(execution, lease, request.job_id);
    metadata["output_bytes"] = serialized_output.size();
    metadata["output_schema_source"] = "generated";
    metadata["output_schema_validation"] = "passed";
    return protocol::mcp_result_t::success(
        execution.result.empty() ? "Python script completed." : execution.result,
        structured,
        metadata);
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
