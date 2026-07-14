#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::c03 {

enum class build_worker_error_code_t : std::uint8_t {
    none = 0,
    invalid_argument,
    unsafe_path,
    path_escape,
    reparse_point,
    duplicate_entry,
    file_missing,
    file_type_invalid,
    file_too_large,
    file_changed,
    file_read_failed,
    hash_failed,
    hash_mismatch,
    size_mismatch,
    malformed_json,
    schema_mismatch,
    remote_reference_forbidden,
    artifact_inventory_mismatch,
    worker_inventory_mismatch,
    dependency_graph_invalid,
    notice_missing,
    forbidden_link_detected,
    protocol_mismatch,
    containment_policy_mismatch,
    protector_receipt_invalid,
    signature_receipt_invalid,
    authenticode_verification_failed,
    source_authority_invalid,
    online_fetch_marker,
    package_policy_violation,
    named_stream_forbidden,
    resource_file_limit,
    resource_directory_limit,
    resource_entry_limit,
    resource_depth_limit,
    resource_path_limit,
    resource_file_bytes_limit,
    resource_total_bytes_limit,
    resource_stream_limit,
    directory_cycle,
    required_external_artifact_missing,
    internal_error
};

struct build_worker_error_t final {
    build_worker_error_code_t code = build_worker_error_code_t::none;
    std::string_view stable_code;
    std::filesystem::path path;
    std::string detail;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;

    constexpr explicit operator bool() const noexcept {
        return code != build_worker_error_code_t::none;
    }
};

template <typename value_t>
class build_worker_result_t final {
public:
    static build_worker_result_t success(value_t value) {
        return build_worker_result_t(std::move(value));
    }

    static build_worker_result_t failure(build_worker_error_t error) {
        return build_worker_result_t(std::move(error));
    }

    bool has_value() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return has_value(); }
    const value_t& value() const & { return value_.value(); }
    value_t take_value() && { return std::move(value_).value(); }
    const build_worker_error_t& error() const noexcept { return error_; }

private:
    explicit build_worker_result_t(value_t value) : value_(std::move(value)) {}
    explicit build_worker_result_t(build_worker_error_t error) : error_(std::move(error)) {}

    std::optional<value_t> value_;
    build_worker_error_t error_{};
};

template <>
class build_worker_result_t<void> final {
public:
    static build_worker_result_t success() noexcept {
        return build_worker_result_t(true, {});
    }

    static build_worker_result_t failure(build_worker_error_t error) {
        return build_worker_result_t(false, std::move(error));
    }

    bool has_value() const noexcept { return success_; }
    explicit operator bool() const noexcept { return success_; }
    const build_worker_error_t& error() const noexcept { return error_; }

private:
    build_worker_result_t(bool success, build_worker_error_t error)
        : success_(success), error_(std::move(error)) {}

    bool success_ = false;
    build_worker_error_t error_{};
};

inline constexpr std::string_view k_canonical_preset = "ninja-msvc-release";
inline constexpr std::string_view k_distribution_manifest_schema =
    "aida.c03.distribution-manifest";
inline constexpr std::uint32_t k_distribution_manifest_schema_version = 2;
inline constexpr std::string_view k_worker_manifest_lock_schema =
    "aida.c03.worker-manifest-lock";
inline constexpr std::uint32_t k_worker_manifest_lock_schema_version = 2;
inline constexpr std::string_view k_forbidden_link_tokens[] = {
    "lmdb", "unicorn", "remill"
};
inline constexpr std::size_t k_required_worker_count = 3;
inline constexpr std::uint64_t k_default_manifest_limit = 16ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t k_default_receipt_limit = 1024ULL * 1024ULL;
inline constexpr std::uint64_t k_default_artifact_limit = 8ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t k_default_package_total_limit = 16ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t k_default_source_total_limit = 32ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t k_default_file_count_limit = 250000;
inline constexpr std::size_t k_default_directory_count_limit = 65536;
inline constexpr std::size_t k_default_total_entry_count_limit = 300000;
inline constexpr std::size_t k_default_depth_limit = 64;
inline constexpr std::size_t k_default_relative_path_limit = 32768;
inline constexpr std::size_t k_default_stream_count_limit = 16;

struct deny_link_check_request_t final {
    std::string target_name;
    std::vector<std::string> direct_links;
    std::vector<std::string> interface_links;
    std::vector<std::string> transitive_links;
};

struct deny_link_check_result_t final {
    std::size_t inspected = 0;
};

struct package_verification_request_t final {
    std::filesystem::path package_root;
    std::filesystem::path manifest_path;
    std::string expected_manifest_sha256;
    std::string expected_source_authority_sha256;
    std::string expected_protector_tool_sha256;
    std::string expected_protector_verifier_sha256;
    std::string expected_signature_verifier_sha256;
    std::uint64_t maximum_manifest_bytes = k_default_manifest_limit;
    std::uint64_t maximum_receipt_bytes = k_default_receipt_limit;
    std::uint64_t maximum_artifact_bytes = k_default_artifact_limit;
    std::uint64_t maximum_total_artifact_bytes = k_default_package_total_limit;
    std::size_t maximum_file_count = k_default_file_count_limit;
    std::size_t maximum_directory_count = k_default_directory_count_limit;
    std::size_t maximum_total_entry_count = k_default_total_entry_count_limit;
    std::size_t maximum_depth = k_default_depth_limit;
    std::size_t maximum_relative_path_bytes = k_default_relative_path_limit;
};

struct package_verification_result_t final {
    std::string manifest_sha256;
    std::uint64_t manifest_size_bytes = 0;
    std::size_t artifacts_verified = 0;
    std::size_t workers_verified = 0;
    std::size_t dependencies_verified = 0;
    std::size_t notices_verified = 0;
    std::size_t resource_manifests_verified = 0;
    std::size_t acl_receipts_verified = 0;
    std::size_t protector_receipts_verified = 0;
    std::size_t signature_receipts_verified = 0;
    std::uint64_t artifact_bytes_verified = 0;
    std::size_t directories_verified = 0;
    std::size_t entries_verified = 0;
    std::size_t stream_inventories_verified = 0;
    bool exact_package_inventory = false;
    bool no_network_fetch = false;
    bool deny_link_policy = false;
    bool disk_backed = false;
    bool arc_license_gates_required = false;
    bool camoufox_only = false;
};

struct source_authority_request_t final {
    std::filesystem::path repository_root;
    std::filesystem::path lock_path;
    std::string expected_lock_sha256;
    std::uint64_t maximum_lock_bytes = k_default_manifest_limit;
    std::uint64_t maximum_source_bytes = k_default_artifact_limit;
    std::uint64_t maximum_total_source_bytes = k_default_source_total_limit;
    std::size_t maximum_inventory_entries = 4096;
};

struct source_authority_result_t final {
    std::string lock_sha256;
    std::size_t source_files_verified = 0;
    std::size_t dependencies_verified = 0;
    std::size_t managed_packages_verified = 0;
    std::size_t notices_verified = 0;
    std::uint64_t source_bytes_verified = 0;
    bool no_network_fetch = false;
    bool dependency_decisions_complete = false;
    bool managed_graph_locked = false;
    bool analysis_python_external_blocker_confirmed = false;
};

class build_worker_packaging_integration_t final {
public:
    build_worker_packaging_integration_t() = default;

    build_worker_packaging_integration_t(const build_worker_packaging_integration_t&) = delete;
    build_worker_packaging_integration_t& operator=(const build_worker_packaging_integration_t&) = delete;
    build_worker_packaging_integration_t(build_worker_packaging_integration_t&&) = delete;
    build_worker_packaging_integration_t& operator=(build_worker_packaging_integration_t&&) = delete;

    build_worker_result_t<deny_link_check_result_t>
        check_deny_links(const deny_link_check_request_t& request) const;

    build_worker_result_t<package_verification_result_t>
        verify_distribution_package(const package_verification_request_t& request) const;

    build_worker_result_t<source_authority_result_t>
        verify_source_authority(const source_authority_request_t& request) const;

    std::uint64_t deny_link_checks_completed() const noexcept;
    std::uint64_t package_verifications_completed() const noexcept;
    std::uint64_t source_authority_verifications_completed() const noexcept;

private:
    static build_worker_error_t make_error(build_worker_error_code_t code,
                                           std::filesystem::path path = {},
                                           std::string detail = {},
                                           std::uint64_t expected = 0,
                                           std::uint64_t actual = 0);

    mutable std::atomic_uint64_t deny_link_checks_{0};
    mutable std::atomic_uint64_t package_verifications_{0};
    mutable std::atomic_uint64_t source_authority_verifications_{0};
};

}
