#include "build_packaging_integration_harness.hpp"

#include "../../src/core/analysis/build_worker_packaging_integration.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using namespace aida::analysis::c03;

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

template <typename value_t>
value_t require_value(build_worker_result_t<value_t> result, std::string_view message) {
    if (!result)
        throw std::runtime_error(std::string(message) + ": " +
            std::string(result.error().stable_code));
    return std::move(result).take_value();
}

void verify_hardened_static_targets() {
    const auto& targets = hardened_static_targets();
    require(targets.size() == k_hardened_static_target_count,
            "hardened static target count mismatch");

    for (std::size_t i = 0; i < targets.size(); ++i) {
        const auto& target = targets[i];
        require(!target.name.empty(), "hardened target has empty name");
        require(!target.canonical_path.empty(), "hardened target has empty path");
        require(target.deny_network_fetch,
                "hardened target must deny network fetch");
        require(target.disk_backed_bootstrap,
                "hardened target must use disk-backed bootstrap");
    }

    bool found_managed = false;
    bool found_sidecar = false;
    bool found_native = false;
    for (const auto& target : targets) {
        if (target.kind == static_target_kind_t::managed) found_managed = true;
        if (target.kind == static_target_kind_t::sidecar) found_sidecar = true;
        if (target.kind == static_target_kind_t::native) found_native = true;
    }
    require(found_managed, "no managed kind target in hardened set");
    require(found_sidecar, "no sidecar kind target in hardened set");
    require(found_native, "no native kind target in hardened set");
}

void verify_deny_link_checks() {
    build_worker_packaging_integration_t integration;

    deny_link_check_request_t clean_request;
    clean_request.target_name = "AiDAStandalone";
    clean_request.link_libraries = {"imgui", "z3", "sqlite3", "nlohmann_json"};
    clean_request.interface_link_libraries = {"zydis", "capstone"};

    auto clean_result = integration.check_deny_links(clean_request);
    require(clean_result.has_value(), "clean deny-link check was rejected");
    require(clean_result.value().passed, "clean deny-link check did not pass");

    deny_link_check_request_t forbidden_request;
    forbidden_request.target_name = "BadTarget";
    forbidden_request.link_libraries = {"imgui", "lmdb", "z3"};

    auto forbidden_result = integration.check_deny_links(forbidden_request);
    require(!forbidden_result.has_value(), "forbidden link was accepted");
    require(forbidden_result.error().code ==
            build_worker_error_code_t::forbidden_link_detected,
            "forbidden link did not return correct error code");

    deny_link_check_request_t interface_forbidden;
    interface_forbidden.target_name = "InterfaceBad";
    interface_forbidden.link_libraries = {"imgui"};
    interface_forbidden.interface_link_libraries = {"unicorn"};

    auto interface_result = integration.check_deny_links(interface_forbidden);
    require(!interface_result.has_value(), "forbidden interface link was accepted");
    require(interface_result.error().code ==
            build_worker_error_code_t::forbidden_link_detected,
            "forbidden interface link did not return correct error code");

    deny_link_check_request_t remill_request;
    remill_request.target_name = "RemillBad";
    remill_request.link_libraries = {"remill"};

    auto remill_result = integration.check_deny_links(remill_request);
    require(!remill_result.has_value(), "remill forbidden link was accepted");
    require(remill_result.error().code ==
            build_worker_error_code_t::forbidden_link_detected,
            "remill forbidden link did not return correct error code");

    require(integration.deny_link_checks_performed() >= 4U,
            "deny-link counter did not track all checks");
}

void verify_managed_offline_restore() {
    build_worker_packaging_integration_t integration;

    managed_restore_entry_t valid_entry;
    valid_entry.package_name = "ICSharpCode.Decompiler";
    valid_entry.package_version = "10.1.0.8386";
    valid_entry.nupkg_relative_path = ".deps/nuget-offline/ICSharpCode.Decompiler.10.1.0.8386.nupkg";
    valid_entry.expected_sha256 = "a6fb2e9be86c1b73e54231e20640d4d566c52f21cba9ad99c3e9100d67e8f5af";
    valid_entry.target_framework = "net10.0";

    auto valid_result = integration.restore_managed_package(valid_entry);
    require(valid_result.has_value(), "valid managed package restore was rejected");
    require(valid_result.value().restored, "managed package was not marked restored");
    require(valid_result.value().package_name == "ICSharpCode.Decompiler",
            "restored package name mismatch");

    managed_restore_entry_t disallowed_entry;
    disallowed_entry.package_name = "Evil.Package";
    disallowed_entry.package_version = "1.0.0";
    disallowed_entry.nupkg_relative_path = ".deps/evil/Evil.Package.1.0.0.nupkg";
    disallowed_entry.expected_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    disallowed_entry.target_framework = "net10.0";

    auto disallowed_result = integration.restore_managed_package(disallowed_entry);
    require(!disallowed_result.has_value(), "disallowed managed package was restored");
    require(disallowed_result.error().code ==
            build_worker_error_code_t::component_not_in_allowlist,
            "disallowed package did not return component_not_in_allowlist");

    managed_restore_entry_t empty_entry;
    empty_entry.package_name = "ICSharpCode.Decompiler";
    auto empty_result = integration.restore_managed_package(empty_entry);
    require(!empty_result.has_value(), "empty nupkg path was accepted for restore");
    require(empty_result.error().code ==
            build_worker_error_code_t::managed_restore_failed,
            "empty nupkg path did not return managed_restore_failed");

    require(integration.managed_restores_completed() >= 1U,
            "managed restore counter did not track completions");
}

void verify_worker_post_processing() {
    build_worker_packaging_integration_t integration;

    worker_post_processing_request_t request;
    request.worker_output_path = "build-ninja/Release/AiDA_NativeWorker.dll";
    request.worker_name = "native_worker";
    request.apply_protector = true;
    request.strip_debug_symbols = true;
    request.verify_signature = true;

    auto result = integration.post_process_worker(request);
    require(result.has_value(), "worker post-processing was rejected");
    require(result.value().protector_applied,
            "protector was not applied during post-processing");
    require(result.value().symbols_stripped,
            "debug symbols were not stripped during post-processing");
    require(result.value().signature_verified,
            "signature was not verified during post-processing");

    worker_post_processing_request_t empty_request;
    empty_request.worker_output_path = "";
    auto empty_result = integration.post_process_worker(empty_request);
    require(!empty_result.has_value(), "empty worker path was accepted");
    require(empty_result.error().code ==
            build_worker_error_code_t::worker_post_processing_failed,
            "empty worker path did not return correct error code");

    require(integration.workers_processed() >= 1U,
            "worker processing counter did not track completions");
}

void verify_sidecar_manifest_handoff() {
    build_worker_packaging_integration_t integration;

    std::vector<sidecar_manifest_entry_t> entries;
    sidecar_manifest_entry_t camoufox_entry;
    camoufox_entry.name = "camoufox";
    camoufox_entry.relative_path = "camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe";
    camoufox_entry.sha256 = "768937fa6a6df581d0cdc88ecffe1cf651ffebe1ad1d5667a5f75100e96acfe0";
    camoufox_entry.size_bytes = 75000000;
    camoufox_entry.kind = "browser";
    entries.push_back(camoufox_entry);

    sidecar_manifest_entry_t mcp_entry;
    mcp_entry.name = "camoufox_mcp";
    mcp_entry.relative_path = "deps/AiDA_CamoufoxReverseMcp.exe";
    mcp_entry.sha256 = "2443649a43c92b048b7f013434d169889b41f494f391359d9cc72111c6e0ee4c";
    mcp_entry.size_bytes = 30000000;
    mcp_entry.kind = "reverse_mcp";
    entries.push_back(mcp_entry);

    auto manifest = integration.build_sidecar_manifest(entries);
    require(manifest.has_value(), "sidecar manifest build was rejected");
    require(manifest.value().schema == "aida.c03.worker-manifest",
            "sidecar manifest schema mismatch");
    require(manifest.value().schema_version == 1,
            "sidecar manifest schema version mismatch");
    require(manifest.value().entries.size() == 2,
            "sidecar manifest entry count mismatch");
    require(manifest.value().generator_preset == "ninja-msvc-release",
            "sidecar manifest generator preset mismatch");
    require(manifest.value().protector_phase == "post-build",
            "sidecar manifest protector phase mismatch");

    std::vector<sidecar_manifest_entry_t> empty_entries;
    auto empty_manifest = integration.build_sidecar_manifest(empty_entries);
    require(!empty_manifest.has_value(), "empty sidecar manifest was accepted");
    require(empty_manifest.error().code ==
            build_worker_error_code_t::sidecar_manifest_invalid,
            "empty sidecar manifest did not return correct error code");

    std::vector<sidecar_manifest_entry_t> bad_entries;
    sidecar_manifest_entry_t bad_entry;
    bad_entry.name = "";
    bad_entry.relative_path = "some/path";
    bad_entry.sha256 = "abc";
    bad_entry.size_bytes = 100;
    bad_entries.push_back(bad_entry);
    auto bad_manifest = integration.build_sidecar_manifest(bad_entries);
    require(!bad_manifest.has_value(), "manifest with empty name was accepted");
    require(bad_manifest.error().code ==
            build_worker_error_code_t::sidecar_manifest_invalid,
            "manifest with empty name did not return correct error code");

    require(integration.sidecar_manifests_built() >= 1U,
            "sidecar manifest counter did not track completions");
}

void verify_canonical_preset_preserved() {
    build_worker_packaging_integration_t integration;

    auto validation = integration.validate_build_pipeline();
    require(validation.has_value(), "build pipeline validation was rejected");
    require(validation.value().canonical_preset_preserved,
            "canonical preset was not preserved");
    require(validation.value().protector_phase_enabled,
            "protector phase was not enabled");
    require(validation.value().disk_backed_bootstrap,
            "disk-backed bootstrap was not preserved");
    require(validation.value().network_fetch_disabled,
            "network fetch was not disabled");
    require(validation.value().managed_offline_only,
            "managed offline-only mode was not enforced");
    require(validation.value().preset_name == "ninja-msvc-release",
            "preset name mismatch");
}

void verify_component_allowlist_enforcement() {
    build_worker_packaging_integration_t integration;

    auto allowed = integration.verify_component_allowlist("zydis", "Zydis");
    require(allowed.has_value(), "allowed zydis component was rejected");

    auto disallowed = integration.verify_component_allowlist("zydis", "unicorn");
    require(!disallowed.has_value(), "disallowed zydis component was accepted");
    require(disallowed.error().code ==
            build_worker_error_code_t::component_not_in_allowlist,
            "disallowed component did not return correct error code");

    auto capstone_allowed = integration.verify_component_allowlist("capstone", "X86");
    require(capstone_allowed.has_value(), "allowed capstone X86 was rejected");

    auto capstone_disallowed = integration.verify_component_allowlist("capstone", "Xtensa");
    require(!capstone_disallowed.has_value(), "disallowed capstone Xtensa was accepted");

    auto managed_allowed = integration.verify_component_allowlist(
        "managed_worker", "ICSharpCode.Decompiler");
    require(managed_allowed.has_value(), "allowed managed worker component was rejected");

    auto managed_disallowed = integration.verify_component_allowlist(
        "managed_worker", "Newtonsoft.Json");
    require(!managed_disallowed.has_value(), "disallowed managed worker component was accepted");
}

void verify_static_target_validation() {
    build_worker_packaging_integration_t integration;

    const auto& targets = hardened_static_targets();
    for (const auto& target : targets) {
        auto result = integration.verify_static_target(target);
        require(result.has_value(),
            "valid hardened static target was rejected: " + std::string(target.name));
    }

    hardened_static_target_t bad_target;
    bad_target.name = "";
    bad_target.canonical_path = "some/path";
    bad_target.deny_network_fetch = true;
    bad_target.disk_backed_bootstrap = true;
    auto bad_result = integration.verify_static_target(bad_target);
    require(!bad_result.has_value(), "target with empty name was accepted");
    require(bad_result.error().code == build_worker_error_code_t::target_not_found,
            "target with empty name did not return target_not_found");

    hardened_static_target_t fileless_target;
    fileless_target.name = "fileless";
    fileless_target.canonical_path = "some/path";
    fileless_target.deny_network_fetch = true;
    fileless_target.disk_backed_bootstrap = false;
    auto fileless_result = integration.verify_static_target(fileless_target);
    require(!fileless_result.has_value(), "fileless bootstrap target was accepted");
    require(fileless_result.error().code ==
            build_worker_error_code_t::bootstrap_model_violation,
            "fileless bootstrap did not return bootstrap_model_violation");
}

}

void run_build_packaging_integration_harness() {
    verify_hardened_static_targets();
    verify_deny_link_checks();
    verify_managed_offline_restore();
    verify_worker_post_processing();
    verify_sidecar_manifest_handoff();
    verify_canonical_preset_preserved();
    verify_component_allowlist_enforcement();
    verify_static_target_validation();
}

}

int main() {
    try {
        aida::analysis::c03_test::run_build_packaging_integration_harness();
        std::cout << "build_packaging_integration_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
