#pragma once

#include "decompiler_provider_registry.hpp"
#include "isolated_worker_codec.hpp"

#include <atomic>
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
#include <utility>
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

struct packaged_native_worker_runtime_t {
    std::shared_ptr<decompiler_isolated_provider_host_t> provider_host;
    decompiler_provider_identity_t provider;
    decompiler_provider_identity_t jvm_provider;
    decompiler_provider_identity_t dalvik_provider;
    sha256_digest_t worker_protocol_hash;
    sha256_digest_t manifest_hash;
    std::uint32_t worker_protocol_version = 0;
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

struct native_provider_snapshot_t {
    std::uint64_t image_base = 0;
    std::vector<std::uint8_t> virtual_image;
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
    std::string provider_artifacts;
    sha256_digest_t provider_artifacts_hash;
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
inline std::string serialize_native_provider_snapshot(const native_provider_snapshot_t& snapshot)
{
    if (snapshot.image_base == 0 || snapshot.virtual_image.empty())
        return {};
    isolated_worker_codec::writer_t writer;
    writer.u32(0x32504e47U);
    writer.u32(1);
    writer.u64(snapshot.image_base);
    writer.bytes(snapshot.virtual_image);
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
    if (!reader.u32(magic) || magic != 0x32504e47U || !reader.u32(version) || version != 1 ||
        !reader.u64(snapshot.image_base) || !reader.bytes(snapshot.virtual_image) ||
        !reader.complete() || snapshot.image_base == 0 || snapshot.virtual_image.empty()) {
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

private:
    native_worker_launch_contract_t contract_;
    native_worker_host_limits_t limits_;
    mutable std::mutex mutex_;
    std::uint64_t worker_generation_ = 0;
    bool stopped_ = false;
};

class native_worker_provider_host_t final : public decompiler_isolated_provider_host_t {
public:
    explicit native_worker_provider_host_t(std::shared_ptr<native_worker_host_t> host);

    bool supports(const decompiler_provider_descriptor_t& descriptor) const noexcept override;
    decompiler_provider_result_t execute(
        const decompiler_provider_route_t& route,
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) override;

private:
    std::shared_ptr<native_worker_host_t> host_;
    std::atomic<std::uint64_t> next_job_id_{1};
};

}
