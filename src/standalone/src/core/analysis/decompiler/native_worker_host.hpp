#pragma once

#include "decompiler_provider_registry.hpp"
#include "isolated_worker_codec.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::native_worker {

class native_worker_host_t;
struct native_worker_verified_package_t;

constexpr std::uint32_t k_native_worker_manifest_magic = 0x464d574eU;
constexpr std::uint32_t k_native_worker_manifest_schema_version = 2;
constexpr std::uint32_t k_managed_worker_manifest_schema_version = 3;
constexpr std::uint32_t k_native_worker_capability_decompile = 1U << 0;
inline constexpr std::string_view k_native_worker_binary_artifact_relative_path = "deps/AiDA_NativeDecompilerWorker.exe";
inline constexpr std::string_view k_native_worker_manifest_artifact_relative_path = "deps/AiDA_NativeDecompilerWorker.manifest.bin";
inline constexpr std::string_view k_native_worker_manifest_digest_relative_path = "deps/AiDA_NativeDecompilerWorker.manifest.sha256";
inline constexpr std::string_view k_managed_worker_binary_artifact_relative_path = "deps/AiDA_ManagedDecompilerWorker.exe";
inline constexpr std::string_view k_managed_worker_manifest_artifact_relative_path = "deps/AiDA_ManagedDecompilerWorker.manifest.bin";
inline constexpr std::string_view k_managed_worker_manifest_digest_relative_path = "deps/AiDA_ManagedDecompilerWorker.manifest.sha256";
inline constexpr std::string_view k_managed_runtime_manifest_artifact_relative_path = "deps/AiDA_ManagedRuntime.manifest.json";
inline constexpr std::string_view k_managed_runtime_manifest_digest_relative_path = "deps/AiDA_ManagedRuntime.manifest.sha256";
inline constexpr std::string_view k_managed_dotnet_root_relative_path = "deps/dotnet";

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
    protocol_nonce_mismatch = 24,
    runtime_manifest_unavailable = 25,
    runtime_manifest_hash_mismatch = 26,
    runtime_manifest_malformed = 27,
    runtime_inventory_mismatch = 28
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
    sha256_digest_t managed_runtime_manifest_hash;
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

struct packaged_native_worker_runtime_t {
    std::shared_ptr<decompiler_isolated_provider_host_t> provider_host;
    std::shared_ptr<native_worker_host_t> native_host;
    decompiler_provider_identity_t provider;
    decompiler_provider_identity_t cli_provider;
    decompiler_provider_identity_t jvm_provider;
    decompiler_provider_identity_t dalvik_provider;
    sha256_digest_t worker_protocol_hash;
    sha256_digest_t manifest_hash;
    sha256_digest_t managed_manifest_hash;
    sha256_digest_t managed_runtime_manifest_hash;
    std::uint32_t worker_protocol_version = 0;
};

struct native_worker_host_limits_t {
    std::size_t max_frame_bytes = k_decompiler_worker_result_frame_max_bytes;
    std::size_t max_snapshot_bytes = 256U * 1024U * 1024U;
    std::size_t max_concurrent_workers = 8;
    std::chrono::milliseconds startup_timeout{10000};
    std::chrono::milliseconds cancellation_grace{250};
    std::chrono::milliseconds poll_interval{10};
};

struct native_worker_snapshot_t {
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;
    sha256_digest_t hash;

    bool valid() const noexcept;
};

struct native_provider_snapshot_range_t {
    std::uint64_t relative_virtual_address = 0;
    std::vector<std::uint8_t> bytes;
};

struct native_provider_snapshot_t {
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    std::vector<native_provider_snapshot_range_t> ranges;
};

struct native_worker_execution_request_t {
    std::uint64_t job_id = 0;
    decompiler_pipeline_cache_key_t cache_key;
    decompiler_profile_budget_t profile;
    native_worker_snapshot_t snapshot;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    std::function<bool()> cancellation_requested;
    std::shared_ptr<const managed_cli::request_t> managed_request;
    bool request_printc_evidence = false;
};

struct native_worker_execution_result_t {
    native_worker_execution_status_t status = native_worker_execution_status_t::failed;
    std::optional<decompiler_document_t> document;
    std::string provider_artifacts;
    sha256_digest_t provider_artifacts_hash;
    std::optional<std::string> printc_evidence;
    sha256_digest_t printc_evidence_hash;
    std::vector<decompiler_diagnostic_t> worker_diagnostics;
    std::vector<native_worker_diagnostic_t> diagnostics;
    sha256_digest_t manifest_hash;
    sha256_digest_t snapshot_hash;
    std::uint64_t worker_generation = 0;
    std::uint32_t worker_process_id = 0;
    bool worker_terminated = false;
    bool worker_replaced = false;
};

std::string serialize_native_worker_manifest(const native_worker_manifest_t& value);
native_worker_manifest_decode_t deserialize_native_worker_manifest(const std::string& value);
sha256_digest_t native_worker_protocol_hash();
std::optional<native_worker_snapshot_t> make_native_worker_snapshot(std::vector<std::uint8_t> bytes);
struct managed_worker_snapshot_binding_t {
    native_worker_snapshot_t snapshot;
    std::shared_ptr<const managed_cli::request_t> request;
};
workspace_result_t<managed_worker_snapshot_binding_t> capture_managed_worker_snapshot(
    const std::shared_ptr<const managed_cli::request_t>& request,
    std::size_t maximum_bytes,
    const cancellation_token_t& cancel = {});
inline std::string serialize_native_provider_snapshot(const native_provider_snapshot_t& snapshot)
{
    if (snapshot.image_size == 0 || snapshot.ranges.empty() ||
        snapshot.ranges.size() > 65536)
        return {};
    isolated_worker_codec::writer_t writer;
    writer.u32(0x32504e47U);
    writer.u32(2);
    writer.u64(snapshot.image_base);
    writer.u64(snapshot.image_size);
    writer.u32(static_cast<std::uint32_t>(snapshot.ranges.size()));
    std::uint64_t prior_end = 0;
    for (const auto& range : snapshot.ranges) {
        if (range.bytes.empty() || range.relative_virtual_address < prior_end ||
            range.relative_virtual_address >= snapshot.image_size ||
            range.bytes.size() > snapshot.image_size - range.relative_virtual_address)
            return {};
        writer.u64(range.relative_virtual_address);
        writer.bytes(range.bytes);
        prior_end = range.relative_virtual_address + range.bytes.size();
    }
    return writer.take();
}

inline std::optional<native_provider_snapshot_t> deserialize_native_provider_snapshot(
    const std::string& bytes, std::vector<decompiler_diagnostic_t>& diagnostics)
{
    diagnostics.clear();
    isolated_worker_codec::reader_t reader(bytes);
    native_provider_snapshot_t snapshot;
    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    std::uint32_t range_count = 0;
    if (!reader.u32(magic) || magic != 0x32504e47U || !reader.u32(version) || version != 2 ||
        !reader.u64(snapshot.image_base) || !reader.u64(snapshot.image_size) ||
        !reader.u32(range_count) || range_count == 0 || range_count > 65536 ||
        snapshot.image_size == 0 || snapshot.image_size >
            (std::numeric_limits<std::uint64_t>::max)() - snapshot.image_base) {
        decompiler_diagnostic_t diagnostic;
        diagnostic.severity = decompiler_diagnostic_severity_t::error;
        diagnostic.code = decompiler_diagnostic_code_t::malformed_serialization;
        diagnostic.localization_key = "decompiler.native_worker.snapshot_decode";
        diagnostic.confidence = 100;
        diagnostic.ordinal = 1;
        diagnostics.push_back(std::move(diagnostic));
        return std::nullopt;
    }
    std::uint64_t prior_end = 0;
    std::uint64_t total_bytes = 0;
    try {
        snapshot.ranges.reserve(range_count);
        for (std::uint32_t index = 0; index < range_count; ++index) {
            native_provider_snapshot_range_t range;
            if (!reader.u64(range.relative_virtual_address) || !reader.bytes(range.bytes) ||
                range.bytes.empty() || range.relative_virtual_address < prior_end ||
                range.relative_virtual_address >= snapshot.image_size ||
                range.bytes.size() > snapshot.image_size - range.relative_virtual_address ||
                range.bytes.size() > (256ULL << 20) - total_bytes)
                throw std::invalid_argument("native snapshot range");
            total_bytes += range.bytes.size();
            prior_end = range.relative_virtual_address + range.bytes.size();
            snapshot.ranges.push_back(std::move(range));
        }
    } catch (...) {
        snapshot.ranges.clear();
    }
    if (!reader.complete() || snapshot.ranges.size() != range_count) {
        decompiler_diagnostic_t diagnostic;
        diagnostic.severity = decompiler_diagnostic_severity_t::error;
        diagnostic.code = decompiler_diagnostic_code_t::malformed_serialization;
        diagnostic.localization_key = "decompiler.native_worker.snapshot_decode";
        diagnostic.confidence = 100;
        diagnostic.ordinal = 1;
        diagnostics.push_back(std::move(diagnostic));
        return std::nullopt;
    }
    return snapshot;
}
workspace_result_t<packaged_native_worker_runtime_t> create_packaged_native_worker_runtime(
    std::filesystem::path runtime_root = {});

class native_worker_host_t final {
public:
    explicit native_worker_host_t(native_worker_launch_contract_t contract, native_worker_host_limits_t limits = {});
    ~native_worker_host_t();

    native_worker_host_t(const native_worker_host_t&) = delete;
    native_worker_host_t& operator=(const native_worker_host_t&) = delete;

    native_worker_execution_result_t execute(const native_worker_execution_request_t& request);
    void stop() noexcept;
    std::uint64_t worker_generation() const noexcept;
    const native_worker_host_limits_t& limits() const noexcept { return limits_; }
    std::shared_ptr<native_worker_host_t> for_session_pool(std::size_t max_concurrent_workers) const;

    struct session_state_t;
    bool session_launch(const native_worker_execution_request_t& request,
                        std::uint32_t max_jobs_per_session,
                        session_state_t& session, native_worker_execution_result_t& result);
    native_worker_execution_result_t execute_on_session(session_state_t& session,
                                                        const native_worker_execution_request_t& request);
    void session_terminate(session_state_t& session, DWORD exit_code,
                           native_worker_execution_result_t* result, bool replacement) noexcept;

private:
    native_worker_host_t(
        native_worker_launch_contract_t contract,
        native_worker_host_limits_t limits,
        std::shared_ptr<const native_worker_verified_package_t> verified_package);

    friend workspace_result_t<packaged_native_worker_runtime_t>
        create_packaged_native_worker_runtime(std::filesystem::path runtime_root);

    native_worker_launch_contract_t contract_;
    native_worker_host_limits_t limits_;
    std::shared_ptr<const native_worker_verified_package_t> verified_package_;
    std::vector<native_worker_diagnostic_t> verification_diagnostics_;
    mutable std::mutex state_mutex_;
    std::condition_variable state_wake_;
    std::atomic<std::uint64_t> worker_generation_{0};
    std::atomic<bool> stopped_{false};
    std::size_t active_workers_ = 0;
};

class native_worker_provider_host_t final : public decompiler_isolated_provider_host_t {
public:
    native_worker_provider_host_t(
        std::shared_ptr<native_worker_host_t> host,
        std::shared_ptr<native_worker_host_t> managed_host = {});

    bool supports(const decompiler_provider_descriptor_t& descriptor) const noexcept override;
    decompiler_provider_result_t execute(
        const decompiler_provider_route_t& route,
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) override;

private:
    std::shared_ptr<native_worker_host_t> host_;
    std::shared_ptr<native_worker_host_t> managed_host_;
    std::atomic<std::uint64_t> next_job_id_{1};
};

struct native_worker_session_pool_config_t {
    std::uint32_t max_jobs_per_session = 256;
    std::chrono::milliseconds max_session_lifetime{600000};
    std::size_t batch_slots = 16;
    std::size_t interactive_reserved_slots = 1;
};

class pooled_native_worker_provider_host_t final : public decompiler_isolated_provider_host_t {
public:
    pooled_native_worker_provider_host_t(
        std::shared_ptr<decompiler_isolated_provider_host_t> fallback_host,
        std::shared_ptr<native_worker_host_t> session_host,
        native_worker_session_pool_config_t config = {});
    ~pooled_native_worker_provider_host_t() override;

    pooled_native_worker_provider_host_t(const pooled_native_worker_provider_host_t&) = delete;
    pooled_native_worker_provider_host_t& operator=(const pooled_native_worker_provider_host_t&) = delete;

    bool supports(const decompiler_provider_descriptor_t& descriptor) const noexcept override;
    decompiler_provider_result_t execute(
        const decompiler_provider_route_t& route,
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) override;
    void stop() noexcept;

    enum class slot_class_t : std::uint8_t { reserved, borrowed };
    std::optional<slot_class_t> classify_interactive_dispatch() const noexcept;

private:
    struct state_t;
    std::shared_ptr<state_t> state_;
};

std::shared_ptr<decompiler_isolated_provider_host_t> create_pooled_native_worker_provider_host(
    const packaged_native_worker_runtime_t& runtime,
    native_worker_session_pool_config_t config = {});

}
