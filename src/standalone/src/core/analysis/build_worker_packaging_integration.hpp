#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aida::analysis::c03 {

enum class build_worker_error_code_t : std::uint8_t {
    none = 0,
    forbidden_link_detected,
    component_not_in_allowlist,
    managed_restore_failed,
    managed_restore_checksum_mismatch,
    worker_post_processing_failed,
    sidecar_manifest_invalid,
    sidecar_hash_mismatch,
    deny_link_violation,
    preset_violation,
    bootstrap_model_violation,
    target_hash_missing,
    target_not_found,
    protector_phase_failed,
    internal_error
};

struct build_worker_error_t final {
    build_worker_error_code_t code = build_worker_error_code_t::none;
    std::string_view stable_code;
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

    static build_worker_result_t failure(build_worker_error_t error) noexcept {
        return build_worker_result_t(error);
    }

    bool has_value() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return has_value(); }
    const value_t& value() const & { return value_.value(); }
    value_t take_value() && { return std::move(value_).value(); }
    const build_worker_error_t& error() const noexcept { return error_; }

private:
    explicit build_worker_result_t(value_t value) : value_(std::move(value)) {}
    explicit build_worker_result_t(build_worker_error_t error) noexcept : error_(error) {}

    std::optional<value_t> value_;
    build_worker_error_t error_{};
};

enum class static_target_kind_t : std::uint8_t {
    native = 0,
    managed = 1,
    python = 2,
    driver = 3,
    protector = 4,
    sidecar = 5
};

struct hardened_static_target_t final {
    std::string_view name;
    std::string_view canonical_path;
    static_target_kind_t kind = static_target_kind_t::native;
    std::string_view expected_sha256;
    std::uint64_t maximum_bytes = 0;
    bool requires_protector = false;
    bool requires_offline_restore = false;
    bool deny_network_fetch = true;
    bool disk_backed_bootstrap = true;
};

inline constexpr std::string_view k_canonical_preset = "ninja-msvc-release";
inline constexpr std::string_view k_forbidden_link_tokens[] = {"lmdb", "unicorn", "remill"};
inline constexpr std::size_t k_forbidden_link_count =
    sizeof(k_forbidden_link_tokens) / sizeof(k_forbidden_link_tokens[0]);

inline constexpr std::string_view k_zydis_allowlist[] = {"Zydis", "Zycore"};
inline constexpr std::string_view k_capstone_allowlist[] = {
    "ARM", "ARM64", "MIPS", "PPC", "RISCV", "X86", "detail"};
inline constexpr std::string_view k_taskflow_allowlist[] = {"taskflow"};
inline constexpr std::string_view k_managed_worker_allowlist[] = {
    "ICSharpCode.Decompiler",
    "System.Collections.Immutable",
    "System.Reflection.Metadata"};
inline constexpr std::string_view k_z3_allowlist[] = {"libz3"};
inline constexpr std::string_view k_sqlite_allowlist[] = {"sqlite3"};
inline constexpr std::string_view k_imgui_allowlist[] = {
    "imgui", "imgui_freetype", "imgui_impl_dx11", "imgui_impl_win32"};
inline constexpr std::string_view k_zlib_allowlist[] = {"zlib"};
inline constexpr std::string_view k_zstd_allowlist[] = {"zstd_static"};
inline constexpr std::string_view k_liblzma_allowlist[] = {"liblzma"};
inline constexpr std::string_view k_minizip_allowlist[] = {"mz_zip_reader"};
inline constexpr std::string_view k_pcre2_allowlist[] = {"pcre2_8"};
inline constexpr std::string_view k_nlohmann_json_allowlist[] = {"nlohmann_json"};
inline constexpr std::string_view k_json_schema_validator_allowlist[] = {
    "nlohmann_json_schema_validator"};
inline constexpr std::string_view k_llvm_allowlist[] = {"Demangle", "Support"};

inline constexpr std::size_t k_hardened_static_target_count = 14;

const std::array<hardened_static_target_t, k_hardened_static_target_count>&
    hardened_static_targets() noexcept;

struct managed_restore_entry_t final {
    std::string package_name;
    std::string package_version;
    std::string nupkg_relative_path;
    std::string expected_sha256;
    std::string target_framework;
};

struct managed_restore_result_t final {
    std::string package_name;
    bool restored = false;
    std::string restored_path;
    std::string verified_sha256;
};

struct worker_post_processing_request_t final {
    std::string worker_output_path;
    std::string worker_name;
    bool apply_protector = true;
    bool strip_debug_symbols = true;
    bool verify_signature = true;
};

struct worker_post_processing_result_t final {
    std::string processed_path;
    std::string processed_sha256;
    bool protector_applied = false;
    bool symbols_stripped = false;
    bool signature_verified = false;
};

struct sidecar_manifest_entry_t final {
    std::string name;
    std::string relative_path;
    std::string sha256;
    std::uint64_t size_bytes = 0;
    std::string kind;
};

struct sidecar_manifest_t final {
    std::string schema;
    std::uint32_t schema_version = 1;
    std::vector<sidecar_manifest_entry_t> entries;
    std::string generator_preset;
    std::string protector_phase;
};

struct deny_link_check_request_t final {
    std::string target_name;
    std::vector<std::string> link_libraries;
    std::vector<std::string> interface_link_libraries;
};

struct deny_link_check_result_t final {
    bool passed = false;
    std::string violating_target;
    std::string violating_token;
};

struct build_pipeline_validation_t final {
    bool canonical_preset_preserved = false;
    bool protector_phase_enabled = false;
    bool disk_backed_bootstrap = true;
    bool network_fetch_disabled = false;
    bool managed_offline_only = false;
    std::string preset_name;
};

class build_worker_packaging_integration_t final {
public:
    build_worker_packaging_integration_t();

    build_worker_packaging_integration_t(const build_worker_packaging_integration_t&) = delete;
    build_worker_packaging_integration_t& operator=(const build_worker_packaging_integration_t&) = delete;
    build_worker_packaging_integration_t(build_worker_packaging_integration_t&&) = delete;
    build_worker_packaging_integration_t& operator=(build_worker_packaging_integration_t&&) = delete;

    build_worker_result_t<deny_link_check_result_t>
        check_deny_links(const deny_link_check_request_t& request) const;

    build_worker_result_t<managed_restore_result_t>
        restore_managed_package(const managed_restore_entry_t& entry) const;

    build_worker_result_t<worker_post_processing_result_t>
        post_process_worker(const worker_post_processing_request_t& request) const;

    build_worker_result_t<sidecar_manifest_t>
        build_sidecar_manifest(const std::vector<sidecar_manifest_entry_t>& entries) const;

    build_worker_result_t<build_pipeline_validation_t>
        validate_build_pipeline() const;

    build_worker_result_t<void>
        verify_static_target(const hardened_static_target_t& target) const;

    build_worker_result_t<void>
        verify_component_allowlist(std::string_view dependency,
                                    std::string_view component) const;

    std::size_t hardened_target_count() const noexcept;
    std::uint64_t deny_link_checks_performed() const noexcept;
    std::uint64_t managed_restores_completed() const noexcept;
    std::uint64_t workers_processed() const noexcept;
    std::uint64_t sidecar_manifests_built() const noexcept;

private:
    static build_worker_error_t make_error(build_worker_error_code_t code,
                                           std::uint64_t expected = 0,
                                           std::uint64_t actual = 0) noexcept;
    static bool link_token_is_forbidden(std::string_view token) noexcept;
    static bool component_in_allowlist(std::string_view dependency,
                                        std::string_view component) noexcept;
    static std::string_view stable_code_for(build_worker_error_code_t code) noexcept;

    mutable std::atomic_uint64_t deny_link_checks_{0};
    mutable std::atomic_uint64_t managed_restores_{0};
    mutable std::atomic_uint64_t workers_processed_{0};
    mutable std::atomic_uint64_t sidecar_manifests_{0};
};

}
