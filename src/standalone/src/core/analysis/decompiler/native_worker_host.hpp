#pragma once

#include "decompiler_contracts.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aida::analysis::native_worker {

constexpr std::uint32_t k_native_worker_manifest_magic = 0x464d574eU;
constexpr std::uint32_t k_native_worker_manifest_schema_version = 1;
constexpr std::uint32_t k_native_worker_capability_decompile = 1U << 0;
inline constexpr std::string_view k_native_worker_binary_artifact_relative_path = "deps/AiDA_NativeDecompilerWorker.exe";
inline constexpr std::string_view k_native_worker_manifest_artifact_relative_path = "deps/AiDA_NativeDecompilerWorker.manifest.bin";
inline constexpr std::string_view k_native_worker_manifest_digest_relative_path = "deps/AiDA_NativeDecompilerWorker.manifest.sha256";

enum class native_worker_diagnostic_code_t : std::uint16_t {
    invalid_request = 1,
    snapshot_invalid = 2,
    manifest_unavailable = 3,
    manifest_hash_mismatch = 4,
    manifest_malformed = 5,
    worker_path_rejected = 6,
    worker_hash_mismatch = 7,
    worker_identity_mismatch = 8,
    app_container_unavailable = 9,
    launch_policy_rejected = 10,
    launch_failed = 11,
    bootstrap_failed = 12,
    protocol_truncated = 13,
    protocol_oversize = 14,
    protocol_replay = 15,
    protocol_authentication_failed = 16,
    protocol_malformed = 17,
    worker_crashed = 18,
    worker_failed = 19,
    deadline_exceeded = 20,
    cancelled = 21,
    worker_replaced = 22,
    host_stopped = 23,
    protocol_nonce_mismatch = 24
};

enum class native_worker_execution_status_t : std::uint8_t {
    completed,
    failed,
    cancelled,
    deadline_exceeded
};

struct native_worker_diagnostic_t {
    native_worker_diagnostic_code_t code = native_worker_diagnostic_code_t::invalid_request;
    std::string phase;
    std::string detail;
    std::uint32_t win32_error = 0;
    std::uint64_t job_id = 0;
    std::uint64_t worker_generation = 0;
    bool retryable = false;
};

struct native_worker_manifest_t {
    std::uint32_t schema_version = k_native_worker_manifest_schema_version;
    std::string worker_relative_path;
    sha256_digest_t worker_binary_hash;
    decompiler_provider_identity_t provider;
    std::uint32_t worker_protocol_version = k_decompiler_worker_protocol_version;
    sha256_digest_t worker_protocol_hash;
    std::uint32_t capabilities = k_native_worker_capability_decompile;
    std::vector<std::string> startup_arguments;
};

struct native_worker_manifest_decode_t {
    std::optional<native_worker_manifest_t> value;
    std::string error;

    bool valid() const noexcept { return value.has_value() && error.empty(); }
};

struct native_worker_launch_contract_t {
    std::filesystem::path approved_root;
    std::filesystem::path manifest_path;
    sha256_digest_t expected_manifest_hash;
};

struct native_worker_host_limits_t {
    std::size_t max_frame_bytes = 8U * 1024U * 1024U;
    std::size_t max_snapshot_bytes = 256U * 1024U * 1024U;
    std::chrono::milliseconds startup_timeout{10000};
    std::chrono::milliseconds cancellation_grace{250};
    std::chrono::milliseconds poll_interval{10};
};

struct native_worker_snapshot_t {
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;
    sha256_digest_t hash;

    bool valid() const noexcept;
};

struct native_worker_execution_request_t {
    std::uint64_t job_id = 0;
    decompiler_pipeline_cache_key_t cache_key;
    decompiler_profile_budget_t profile;
    native_worker_snapshot_t snapshot;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    std::function<bool()> cancellation_requested;
};

struct native_worker_execution_result_t {
    native_worker_execution_status_t status = native_worker_execution_status_t::failed;
    std::optional<decompiler_document_t> document;
    std::vector<decompiler_diagnostic_t> worker_diagnostics;
    std::vector<native_worker_diagnostic_t> diagnostics;
    sha256_digest_t manifest_hash;
    sha256_digest_t snapshot_hash;
    std::uint64_t worker_generation = 0;
    std::uint32_t worker_process_id = 0;
    bool worker_terminated = false;
    bool worker_replaced = false;

    bool completed() const noexcept { return status == native_worker_execution_status_t::completed && document.has_value(); }
};

std::string serialize_native_worker_manifest(const native_worker_manifest_t& value);
native_worker_manifest_decode_t deserialize_native_worker_manifest(const std::string& value);
sha256_digest_t native_worker_protocol_hash();
std::optional<native_worker_snapshot_t> make_native_worker_snapshot(std::vector<std::uint8_t> bytes);

class native_worker_host_t final {
public:
    explicit native_worker_host_t(native_worker_launch_contract_t contract, native_worker_host_limits_t limits = {});
    ~native_worker_host_t();

    native_worker_host_t(const native_worker_host_t&) = delete;
    native_worker_host_t& operator=(const native_worker_host_t&) = delete;

    native_worker_execution_result_t execute(const native_worker_execution_request_t& request);
    void stop() noexcept;
    std::uint64_t worker_generation() const noexcept;

private:
    native_worker_launch_contract_t contract_;
    native_worker_host_limits_t limits_;
    mutable std::mutex mutex_;
    std::uint64_t worker_generation_ = 0;
    bool stopped_ = false;
};

}
