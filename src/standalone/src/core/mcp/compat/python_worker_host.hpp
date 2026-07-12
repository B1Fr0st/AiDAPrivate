#pragma once

#include "../../../../workers/analysis_python/python_worker_protocol.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aida::standalone::mcp::compat {

using json = nlohmann::json;

enum class python_worker_status_t : std::uint8_t {
    completed,
    rejected,
    cancelled,
    deadline_exceeded,
    worker_crashed,
    protocol_failure,
    worker_failed,
    host_stopped
};

enum class python_worker_error_code_t : std::uint8_t {
    none,
    invalid_request,
    unsafe_approval_required,
    manifest_unavailable,
    manifest_hash_mismatch,
    manifest_malformed,
    worker_path_rejected,
    worker_hash_mismatch,
    script_path_rejected,
    script_too_large,
    script_encoding_invalid,
    launch_policy_rejected,
    launch_failed,
    bootstrap_failed,
    hello_failed,
    protocol_malformed,
    workspace_api_denied,
    workspace_api_failed,
    output_limit_exceeded,
    deadline_exceeded,
    cancelled,
    worker_crashed,
    worker_replaced
};

struct python_worker_diagnostic_t final {
    python_worker_error_code_t code = python_worker_error_code_t::none;
    std::string phase;
    std::string detail;
    std::uint32_t win32_error = 0;
    bool replacement = false;
};

struct python_worker_manifest_t final {
    std::uint32_t schema_version = 0;
    std::string worker_relative_path;
    python_worker::wire::digest_t worker_binary_hash;
    python_worker::wire::digest_t protocol_hash;
    std::uint32_t capabilities = 0;
};

struct python_worker_manifest_decode_t final {
    std::optional<python_worker_manifest_t> value;
    std::string error;

    bool valid() const noexcept {
        return value.has_value() && error.empty();
    }
};

struct python_worker_launch_contract_t final {
    std::filesystem::path approved_root;
    std::filesystem::path manifest_path;
    python_worker::wire::digest_t expected_manifest_hash;
    std::filesystem::path approved_script_root;
};

struct python_worker_launch_contract_resolution_t final {
    std::optional<python_worker_launch_contract_t> value;
    std::string error;

    bool valid() const noexcept {
        return value.has_value() && error.empty();
    }
};

struct python_worker_limits_t final {
    std::size_t max_script_bytes = 512U * 1024U;
    std::size_t max_frame_bytes = 1024U * 1024U;
    std::size_t max_output_bytes = 256U * 1024U;
    std::size_t max_workspace_response_bytes = 512U * 1024U;
    std::uint32_t max_workspace_requests = 128;
    std::chrono::milliseconds startup_timeout{5000};
    std::chrono::milliseconds cancellation_grace{750};
    std::chrono::milliseconds max_wall_clock{30000};
    std::uint64_t max_cpu_ms = 15000;
    std::uint64_t max_memory_bytes = 256ULL * 1024ULL * 1024ULL;
};

struct python_workspace_query_t final {
    std::string operation;
    json arguments;
};

struct python_workspace_response_t final {
    bool success = false;
    json data;
    std::string error_code;
    std::string error_message;
};

using python_workspace_api_t = std::function<python_workspace_response_t(
    const python_workspace_query_t&, const std::atomic<bool>*)>;

struct python_worker_execution_request_t final {
    std::uint64_t job_id = 0;
    std::filesystem::path script_path;
    json workspace_metadata = json::object();
    python_workspace_api_t workspace_api;
    bool unsafe_approved = false;
    const std::atomic<bool>* cancellation = nullptr;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

struct python_worker_execution_result_t final {
    python_worker_status_t status = python_worker_status_t::rejected;
    std::string result;
    std::string stdout_text;
    std::string stderr_text;
    std::string error_code;
    std::vector<python_worker_diagnostic_t> diagnostics;
    std::uint64_t worker_generation = 0;
    std::uint32_t worker_process_id = 0;
    bool worker_terminated = false;
    bool worker_replaced = false;

    bool completed() const noexcept {
        return status == python_worker_status_t::completed;
    }
};

constexpr std::uint32_t k_python_worker_manifest_schema_version = 1;
constexpr std::uint32_t k_python_worker_capability_execute_file = 1U;
inline constexpr std::string_view k_python_worker_binary_artifact_relative_path = "deps/AiDA_AnalysisPythonWorker.exe";
inline constexpr std::string_view k_python_worker_manifest_artifact_relative_path = "deps/AiDA_AnalysisPythonWorker.manifest.bin";
inline constexpr std::string_view k_python_worker_manifest_digest_relative_path = "deps/AiDA_AnalysisPythonWorker.manifest.sha256";

std::string serialize_python_worker_manifest(const python_worker_manifest_t& value);
python_worker_manifest_decode_t deserialize_python_worker_manifest(const std::string& value);
python_worker_launch_contract_resolution_t resolve_python_worker_launch_contract(
    const std::filesystem::path& package_root, const std::filesystem::path& approved_script_root);
bool python_workspace_operation_allowed(std::string_view operation) noexcept;
bool python_worker_requires_replacement(python_worker_status_t status) noexcept;

class python_worker_host_t final {
public:
    explicit python_worker_host_t(python_worker_launch_contract_t contract,
                                  python_worker_limits_t limits = {});
    ~python_worker_host_t();

    python_worker_host_t(const python_worker_host_t&) = delete;
    python_worker_host_t& operator=(const python_worker_host_t&) = delete;

    python_worker_execution_result_t execute(const python_worker_execution_request_t& request);
    void stop() noexcept;
    std::uint64_t worker_generation() const noexcept;

private:
    python_worker_launch_contract_t contract_;
    python_worker_limits_t limits_;
    mutable std::mutex mutex_;
    std::uint64_t worker_generation_ = 0;
    bool stopped_ = false;
};

}
