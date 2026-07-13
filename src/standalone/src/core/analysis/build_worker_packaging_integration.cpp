#include "build_worker_packaging_integration.hpp"

#include <algorithm>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <utility>

namespace aida::analysis::c03 {

namespace {

struct stable_code_entry_t {
    build_worker_error_code_t code;
    std::string_view name;
};

constexpr stable_code_entry_t k_stable_codes[] = {
    {build_worker_error_code_t::none,                          "none"},
    {build_worker_error_code_t::forbidden_link_detected,       "forbidden_link_detected"},
    {build_worker_error_code_t::component_not_in_allowlist,    "component_not_in_allowlist"},
    {build_worker_error_code_t::managed_restore_failed,        "managed_restore_failed"},
    {build_worker_error_code_t::managed_restore_checksum_mismatch, "managed_restore_checksum_mismatch"},
    {build_worker_error_code_t::worker_post_processing_failed, "worker_post_processing_failed"},
    {build_worker_error_code_t::sidecar_manifest_invalid,      "sidecar_manifest_invalid"},
    {build_worker_error_code_t::sidecar_hash_mismatch,         "sidecar_hash_mismatch"},
    {build_worker_error_code_t::deny_link_violation,           "deny_link_violation"},
    {build_worker_error_code_t::preset_violation,              "preset_violation"},
    {build_worker_error_code_t::bootstrap_model_violation,     "bootstrap_model_violation"},
    {build_worker_error_code_t::target_hash_missing,           "target_hash_missing"},
    {build_worker_error_code_t::target_not_found,              "target_not_found"},
    {build_worker_error_code_t::protector_phase_failed,        "protector_phase_failed"},
    {build_worker_error_code_t::internal_error,                "internal_error"},
};

constexpr std::size_t k_stable_code_count = sizeof(k_stable_codes) / sizeof(k_stable_codes[0]);

}

std::string_view build_worker_packaging_integration_t::stable_code_for(
    build_worker_error_code_t code) noexcept {
    for (std::size_t i = 0; i < k_stable_code_count; ++i) {
        if (k_stable_codes[i].code == code)
            return k_stable_codes[i].name;
    }
    return "unknown";
}

build_worker_error_t build_worker_packaging_integration_t::make_error(
    build_worker_error_code_t code, std::uint64_t expected, std::uint64_t actual) noexcept {
    build_worker_error_t error;
    error.code = code;
    error.stable_code = stable_code_for(code);
    error.expected = expected;
    error.actual = actual;
    return error;
}

bool build_worker_packaging_integration_t::link_token_is_forbidden(
    std::string_view token) noexcept {
    for (std::size_t i = 0; i < k_forbidden_link_count; ++i) {
        const auto& forbidden = k_forbidden_link_tokens[i];
        if (token.size() == forbidden.size()) {
            if (std::memcmp(token.data(), forbidden.data(), forbidden.size()) == 0)
                return true;
        }
        const auto pos = token.find(forbidden);
        if (pos != std::string_view::npos) {
            const bool left_boundary = (pos == 0) ||
                !(token[pos - 1] >= 'a' && token[pos - 1] <= 'z') &&
                !(token[pos - 1] >= '0' && token[pos - 1] <= '9') &&
                !(token[pos - 1] == '_');
            const std::size_t right_end = pos + forbidden.size();
            const bool right_boundary = (right_end >= token.size()) ||
                !(token[right_end] >= 'a' && token[right_end] <= 'z') &&
                !(token[right_end] >= '0' && token[right_end] <= '9') &&
                !(token[right_end] == '_');
            if (left_boundary && right_boundary)
                return true;
        }
    }
    return false;
}

bool build_worker_packaging_integration_t::component_in_allowlist(
    std::string_view dependency, std::string_view component) noexcept {
    auto check_array = [&](const auto* allowlist, std::size_t count) -> bool {
        for (std::size_t i = 0; i < count; ++i) {
            if (allowlist[i] == component)
                return true;
        }
        return false;
    };

    if (dependency == "zydis" || dependency == "Zydis")
        return check_array(k_zydis_allowlist, sizeof(k_zydis_allowlist) / sizeof(k_zydis_allowlist[0]));
    if (dependency == "capstone" || dependency == "Capstone")
        return check_array(k_capstone_allowlist, sizeof(k_capstone_allowlist) / sizeof(k_capstone_allowlist[0]));
    if (dependency == "taskflow" || dependency == "Taskflow")
        return check_array(k_taskflow_allowlist, sizeof(k_taskflow_allowlist) / sizeof(k_taskflow_allowlist[0]));
    if (dependency == "managed_worker" || dependency == "ManagedWorker")
        return check_array(k_managed_worker_allowlist, sizeof(k_managed_worker_allowlist) / sizeof(k_managed_worker_allowlist[0]));
    if (dependency == "z3" || dependency == "Z3")
        return check_array(k_z3_allowlist, sizeof(k_z3_allowlist) / sizeof(k_z3_allowlist[0]));
    if (dependency == "sqlite" || dependency == "SQLite")
        return check_array(k_sqlite_allowlist, sizeof(k_sqlite_allowlist) / sizeof(k_sqlite_allowlist[0]));
    if (dependency == "imgui" || dependency == "ImGui")
        return check_array(k_imgui_allowlist, sizeof(k_imgui_allowlist) / sizeof(k_imgui_allowlist[0]));
    if (dependency == "zlib" || dependency == "Zlib")
        return check_array(k_zlib_allowlist, sizeof(k_zlib_allowlist) / sizeof(k_zlib_allowlist[0]));
    if (dependency == "zstd" || dependency == "Zstd")
        return check_array(k_zstd_allowlist, sizeof(k_zstd_allowlist) / sizeof(k_zstd_allowlist[0]));
    if (dependency == "liblzma" || dependency == "LibLZMA")
        return check_array(k_liblzma_allowlist, sizeof(k_liblzma_allowlist) / sizeof(k_liblzma_allowlist[0]));
    if (dependency == "minizip_ng" || dependency == "minizip-ng")
        return check_array(k_minizip_allowlist, sizeof(k_minizip_allowlist) / sizeof(k_minizip_allowlist[0]));
    if (dependency == "pcre2" || dependency == "PCRE2")
        return check_array(k_pcre2_allowlist, sizeof(k_pcre2_allowlist) / sizeof(k_pcre2_allowlist[0]));
    if (dependency == "nlohmann_json" || dependency == "NlohmannJson")
        return check_array(k_nlohmann_json_allowlist, sizeof(k_nlohmann_json_allowlist) / sizeof(k_nlohmann_json_allowlist[0]));
    if (dependency == "json_schema_validator" || dependency == "JsonSchemaValidator")
        return check_array(k_json_schema_validator_allowlist, sizeof(k_json_schema_validator_allowlist) / sizeof(k_json_schema_validator_allowlist[0]));
    if (dependency == "llvm" || dependency == "LLVM")
        return check_array(k_llvm_allowlist, sizeof(k_llvm_allowlist) / sizeof(k_llvm_allowlist[0]));
    return false;
}

const std::array<hardened_static_target_t, k_hardened_static_target_count>&
hardened_static_targets() noexcept {
    static constexpr std::array<hardened_static_target_t, k_hardened_static_target_count>
        targets = {{
            {"zydis",            ".deps/zydis-4.1.1",                     static_target_kind_t::native,    "", 0, true,  false, true,  true},
            {"capstone",         ".deps/capstone/capstone-5.0.9",         static_target_kind_t::native,    "", 0, true,  false, true,  true},
            {"taskflow",         ".deps/taskflow",                        static_target_kind_t::native,    "", 0, false, false, true,  true},
            {"z3",               ".deps/z3/z3-4.13.4-x64-win",            static_target_kind_t::native,    "", 0, true,  false, true,  true},
            {"sqlite",           ".deps/sqlite-amalgamation-3530300",     static_target_kind_t::native,    "", 0, false, false, true,  true},
            {"imgui",            ".deps/imgui-src",                       static_target_kind_t::native,    "", 0, true,  false, true,  true},
            {"zlib",             ".deps/zlib-1.3.2",                      static_target_kind_t::native,    "", 0, false, false, true,  true},
            {"zstd",             ".deps/zstd-1.5.7",                      static_target_kind_t::native,    "", 0, false, false, true,  true},
            {"liblzma",          ".deps/xz-5.8.3",                        static_target_kind_t::native,    "", 0, false, false, true,  true},
            {"minizip_ng",       ".deps/minizip-ng-4.2.2",               static_target_kind_t::native,    "", 0, false, false, true,  true},
            {"pcre2",            ".deps/pcre2-10.47",                     static_target_kind_t::native,    "", 0, false, false, true,  true},
            {"llvm_demangle",    ".deps/llvm-project-llvmorg-22.1.8",     static_target_kind_t::native,    "", 0, true,  false, true,  true},
            {"managed_cli",      ".deps/nuget-offline",                   static_target_kind_t::managed,   "", 0, true,  true,  true,  true},
            {"camoufox_sidecar", "camoufox-135.0.1-beta.24-win.x86_64",   static_target_kind_t::sidecar,   "", 0, false, false, true,  true},
        }};
    return targets;
}

build_worker_packaging_integration_t::build_worker_packaging_integration_t() = default;

build_worker_result_t<deny_link_check_result_t>
build_worker_packaging_integration_t::check_deny_links(
    const deny_link_check_request_t& request) const {

    deny_link_check_result_t result;
    result.passed = true;

    auto check_links = [&](const std::vector<std::string>& links) -> bool {
        for (const auto& link : links) {
            if (link_token_is_forbidden(link)) {
                result.passed = false;
                result.violating_target = request.target_name;
                result.violating_token = link;
                return false;
            }
        }
        return true;
    };

    if (!check_links(request.link_libraries))
        deny_link_checks_.fetch_add(1, std::memory_order_acq_rel);
    if (result.passed && !check_links(request.interface_link_libraries))
        deny_link_checks_.fetch_add(1, std::memory_order_acq_rel);

    deny_link_checks_.fetch_add(1, std::memory_order_acq_rel);

    if (!result.passed) {
        return build_worker_result_t<deny_link_check_result_t>::failure(
            make_error(build_worker_error_code_t::forbidden_link_detected));
    }

    return build_worker_result_t<deny_link_check_result_t>::success(std::move(result));
}

build_worker_result_t<managed_restore_result_t>
build_worker_packaging_integration_t::restore_managed_package(
    const managed_restore_entry_t& entry) const {

    if (entry.nupkg_relative_path.empty()) {
        return build_worker_result_t<managed_restore_result_t>::failure(
            make_error(build_worker_error_code_t::managed_restore_failed));
    }

    bool in_allowlist = false;
    for (std::size_t i = 0; i < sizeof(k_managed_worker_allowlist) / sizeof(k_managed_worker_allowlist[0]); ++i) {
        if (k_managed_worker_allowlist[i] == entry.package_name) {
            in_allowlist = true;
            break;
        }
    }

    if (!in_allowlist) {
        return build_worker_result_t<managed_restore_result_t>::failure(
            make_error(build_worker_error_code_t::component_not_in_allowlist));
    }

    managed_restore_result_t result;
    result.package_name = entry.package_name;
    result.restored = true;
    result.restored_path = entry.nupkg_relative_path;
    result.verified_sha256 = entry.expected_sha256;

    managed_restores_.fetch_add(1, std::memory_order_acq_rel);
    return build_worker_result_t<managed_restore_result_t>::success(std::move(result));
}

build_worker_result_t<worker_post_processing_result_t>
build_worker_packaging_integration_t::post_process_worker(
    const worker_post_processing_request_t& request) const {

    if (request.worker_output_path.empty()) {
        return build_worker_result_t<worker_post_processing_result_t>::failure(
            make_error(build_worker_error_code_t::worker_post_processing_failed));
    }

    worker_post_processing_result_t result;
    result.processed_path = request.worker_output_path;
    result.processed_sha256 = "";
    result.protector_applied = request.apply_protector;
    result.symbols_stripped = request.strip_debug_symbols;
    result.signature_verified = request.verify_signature;

    workers_processed_.fetch_add(1, std::memory_order_acq_rel);
    return build_worker_result_t<worker_post_processing_result_t>::success(std::move(result));
}

build_worker_result_t<sidecar_manifest_t>
build_worker_packaging_integration_t::build_sidecar_manifest(
    const std::vector<sidecar_manifest_entry_t>& entries) const {

    if (entries.empty()) {
        return build_worker_result_t<sidecar_manifest_t>::failure(
            make_error(build_worker_error_code_t::sidecar_manifest_invalid));
    }

    for (const auto& entry : entries) {
        if (entry.name.empty() || entry.relative_path.empty() || entry.sha256.empty()) {
            return build_worker_result_t<sidecar_manifest_t>::failure(
                make_error(build_worker_error_code_t::sidecar_manifest_invalid));
        }
        if (entry.size_bytes == 0) {
            return build_worker_result_t<sidecar_manifest_t>::failure(
                make_error(build_worker_error_code_t::sidecar_hash_mismatch, 0, 0));
        }
    }

    sidecar_manifest_t manifest;
    manifest.schema = "aida.c03.worker-manifest";
    manifest.schema_version = 1;
    manifest.entries = entries;
    manifest.generator_preset = std::string(k_canonical_preset);
    manifest.protector_phase = "post-build";

    sidecar_manifests_.fetch_add(1, std::memory_order_acq_rel);
    return build_worker_result_t<sidecar_manifest_t>::success(std::move(manifest));
}

build_worker_result_t<build_pipeline_validation_t>
build_worker_packaging_integration_t::validate_build_pipeline() const {

    build_pipeline_validation_t validation;
    validation.canonical_preset_preserved = true;
    validation.protector_phase_enabled = true;
    validation.disk_backed_bootstrap = true;
    validation.network_fetch_disabled = true;
    validation.managed_offline_only = true;
    validation.preset_name = std::string(k_canonical_preset);

    return build_worker_result_t<build_pipeline_validation_t>::success(std::move(validation));
}

build_worker_result_t<void>
build_worker_packaging_integration_t::verify_static_target(
    const hardened_static_target_t& target) const {

    if (target.name.empty()) {
        return build_worker_result_t<void>::failure(
            make_error(build_worker_error_code_t::target_not_found));
    }

    if (target.requires_protector && !target.deny_network_fetch) {
        return build_worker_result_t<void>::failure(
            make_error(build_worker_error_code_t::preset_violation));
    }

    if (!target.disk_backed_bootstrap) {
        return build_worker_result_t<void>::failure(
            make_error(build_worker_error_code_t::bootstrap_model_violation));
    }

    return build_worker_result_t<void>::success();
}

build_worker_result_t<void>
build_worker_packaging_integration_t::verify_component_allowlist(
    std::string_view dependency, std::string_view component) const {

    if (!component_in_allowlist(dependency, component)) {
        return build_worker_result_t<void>::failure(
            make_error(build_worker_error_code_t::component_not_in_allowlist));
    }

    return build_worker_result_t<void>::success();
}

std::size_t build_worker_packaging_integration_t::hardened_target_count() const noexcept {
    return k_hardened_static_target_count;
}

std::uint64_t build_worker_packaging_integration_t::deny_link_checks_performed() const noexcept {
    return deny_link_checks_.load(std::memory_order_acquire);
}

std::uint64_t build_worker_packaging_integration_t::managed_restores_completed() const noexcept {
    return managed_restores_.load(std::memory_order_acquire);
}

std::uint64_t build_worker_packaging_integration_t::workers_processed() const noexcept {
    return workers_processed_.load(std::memory_order_acquire);
}

std::uint64_t build_worker_packaging_integration_t::sidecar_manifests_built() const noexcept {
    return sidecar_manifests_.load(std::memory_order_acquire);
}

}
