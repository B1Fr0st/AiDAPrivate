#include "assertion_telemetry/assertion_telemetry.hpp"
#include "evidence_hash.hpp"
#include "../../src/core/analysis/build_worker_packaging_integration.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

using aida::analysis::c03::build_worker_packaging_integration_t;
using aida::analysis::c03::source_authority_request_t;
using json = nlohmann::json;

void require(bool condition, std::string_view message) {
    aida::analysis::c03_test::assertion_telemetry::record_assertion(
        condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error("unable to read " + path.string());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

json read_json(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error("unable to read " + path.string());
    try {
        return json::parse(input, nullptr, true, true);
    } catch (const std::exception& error) {
        throw std::runtime_error(path.string() + " is not strict JSON: " + error.what());
    }
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

void require_contains(const std::string& text, std::string_view value,
                      const std::filesystem::path& source) {
    if (text.find(value) == std::string::npos)
        throw std::runtime_error(source.string() + " is missing " + std::string(value));
}

void require_absent_case_insensitive(const std::string& text, std::string_view value,
                                     const std::filesystem::path& source) {
    if (lowercase(text).find(lowercase(std::string(value))) != std::string::npos)
        throw std::runtime_error(source.string() + " contains prohibited " + std::string(value));
}

std::filesystem::path locate_root(std::filesystem::path path) {
    path = std::filesystem::absolute(path);
    while (!path.empty()) {
        if (std::filesystem::is_regular_file(path / "CMakeLists.txt") &&
            std::filesystem::is_directory(path / "plans"))
            return path;
        const auto parent = path.parent_path();
        if (parent == path)
            break;
        path = parent;
    }
    throw std::runtime_error("AiDA repository root was not found");
}

std::vector<std::string> gitignore_rules(std::string_view source) {
    std::vector<std::string> rules;
    std::size_t begin = 0;
    while (begin < source.size()) {
        const auto end = source.find('\n', begin);
        auto rule = std::string(source.substr(begin, end == std::string_view::npos ?
                                                       source.size() - begin : end - begin));
        if (!rule.empty() && rule.back() == '\r')
            rule.pop_back();
        if (!rule.empty() && rule.front() != '#')
            rules.push_back(std::move(rule));
        if (end == std::string_view::npos)
            break;
        begin = end + 1;
    }
    return rules;
}

const std::set<std::string>& approved_negations() {
    static const std::set<std::string> values{
        "!/src/", "!/server/", "!/tools/", "!/cmake/", "!/docs/", "!.gitignore",
        "!.aider*", "!CMakeLists.txt", "!CLAUDE.md", "!AGENTS.md", "!build-host.ps1",
        "!build-host.cmd", "!CMakePresets.json", "!/licenses/", "!/licenses/c03/",
        "!/licenses/c03/**", "!/packaging/",
        "!/packaging/c03_worker_manifest.schema.json",
        "!/packaging/c03_worker_manifest.lock.json",
        "!/packaging/c03_native_worker_manifest.json",
        "!/packaging/c03_native_worker_manifest.schema.json",
        "!/packaging/c03_native_worker_manifest.py",
        "!/packaging/c03_distribution_manifest.schema.json",
        "!/packaging/c03_distribution_manifest.ps1",
        "!/packaging/c03_distribution_manifest_spec.json",
        "!/packaging/c03_worker_runtime/",
        "!/packaging/c03_worker_runtime/**",
        "!/packaging/c03_camoufox_reverse_mcp_build.lock.json"
    };
    return values;
}

bool approved_negation(std::string_view value) {
    return approved_negations().find(std::string(value)) != approved_negations().end();
}

void verify_gitignore(const std::filesystem::path& root) {
    const auto source = root / ".gitignore";
    const auto rules = gitignore_rules(read_file(source));
    for (const auto& rule : rules) {
        if (!rule.empty() && rule.front() == '!' && !approved_negation(rule))
            throw std::runtime_error(source.string() + " contains an unapproved negation " + rule);
    }
    for (const auto& required : {
             "!/licenses/", "!/licenses/c03/", "!/licenses/c03/**", "!/packaging/",
             "!/packaging/c03_worker_manifest.schema.json",
             "!/packaging/c03_worker_manifest.lock.json",
             "!/packaging/c03_native_worker_manifest.json",
             "!/packaging/c03_native_worker_manifest.schema.json",
             "!/packaging/c03_native_worker_manifest.py",
             "!/packaging/c03_distribution_manifest.schema.json",
             "!/packaging/c03_distribution_manifest.ps1",
             "!/packaging/c03_distribution_manifest_spec.json",
             "!/packaging/c03_worker_runtime/",
             "!/packaging/c03_worker_runtime/**",
             "!/packaging/c03_camoufox_reverse_mcp_build.lock.json"})
        require(std::find(rules.begin(), rules.end(), required) != rules.end(),
                std::string("missing narrow gitignore exception: ") + required);
    for (const auto& counterexample : {
             "!licenses/unrelated.txt", "!packaging/unrelated.json", "!licenses/c03/**",
             "!packaging/c03_worker_manifest.lock.json", "!/licenses/**", "!/packaging/**",
             "!/licenses/c03/*", "!/packaging/*.json", "!/packaging/c03_*", "!*.json"})
        require(!approved_negation(counterexample),
                std::string("broad or slashless gitignore counterexample was approved: ") +
                    counterexample);
}

bool contains_remote_reference(const json& value) {
    if (value.is_object()) {
        for (const auto& item : value.items()) {
            const auto key = lowercase(item.key());
            if (key == "url" || key == "uri")
                return true;
            if ((key == "$ref" || key == "$id") && item.value().is_string() &&
                item.value().get<std::string>().rfind("#/", 0) != 0 &&
                item.value().get<std::string>().rfind("aida.", 0) != 0)
                return true;
            if (contains_remote_reference(item.value()))
                return true;
        }
    } else if (value.is_array()) {
        return std::any_of(value.begin(), value.end(), [](const json& item) {
            return contains_remote_reference(item);
        });
    } else if (value.is_string()) {
        const auto text = lowercase(value.get<std::string>());
        return text.find("http://") != std::string::npos ||
               text.find("https://") != std::string::npos ||
               text.find("ftp://") != std::string::npos ||
               text.find("git://") != std::string::npos ||
               text.find("ssh://") != std::string::npos ||
               text.find("file://") != std::string::npos ||
               text.find("ws://") != std::string::npos ||
               text.find("wss://") != std::string::npos;
    }
    return false;
}

void verify_source_authority(const std::filesystem::path& root) {
    const auto lock_path = root / "packaging/c03_worker_manifest.lock.json";
    const auto lock = read_json(lock_path);
    const auto identity_state = lock.at("analysis_python_worker")
                                    .at("prebuilt_artifact")
                                    .at("identity_state")
                                    .get<std::string>();
    const bool external_blocker = identity_state == "external_fixture_required";
    const auto lock_hash = aida::analysis::c03::sha256_evidence_file(lock_path, 16ULL * 1024ULL * 1024ULL);
    require(lock_hash.ok, lock_hash.error);
    build_worker_packaging_integration_t integration;
    source_authority_request_t request;
    request.repository_root = root;
    request.lock_path = lock_path;
    request.expected_lock_sha256 = lock_hash.sha256;
    const auto verified = integration.verify_source_authority(request);
    require(static_cast<bool>(verified), verified ? "" : verified.error().stable_code);
    require(verified.value().source_files_verified == 58 &&
                verified.value().dependencies_verified == 30 &&
                verified.value().managed_packages_verified == 3 &&
                verified.value().notices_verified >= 15 && verified.value().no_network_fetch &&
                verified.value().dependency_decisions_complete &&
                verified.value().managed_graph_locked &&
                verified.value().analysis_python_external_blocker_confirmed == external_blocker,
            "source authority evidence is incomplete");
    require(integration.source_authority_verifications_completed() == 1,
            "source authority success counter did not advance");

    auto widened_budget = request;
    widened_budget.maximum_total_source_bytes =
        aida::analysis::c03::k_default_source_total_limit + 1;
    require(!integration.verify_source_authority(widened_budget),
            "source authority accepted a caller-widened resource budget");

    auto wrong_hash = request;
    wrong_hash.expected_lock_sha256 = std::string(64, 'a');
    require(!integration.verify_source_authority(wrong_hash),
            "source authority accepted an unbound lock digest");
}

void verify_lock_semantics(const std::filesystem::path& root) {
    const auto source = root / "packaging/c03_worker_manifest.lock.json";
    const auto lock = read_json(source);
    require(lock.at("schema") == "aida.c03.worker-manifest-lock" &&
                lock.at("schema_version") == 2 && lock.at("no_network_fetch") == true,
            "worker authority schema is invalid");
    require(!contains_remote_reference(lock), "worker authority contains a remote reference");
    require(lock.at("source_inventory").size() == 58 &&
                lock.at("dependencies").size() == 30,
            "worker authority cardinality is invalid");
    std::unordered_set<std::string> paths;
    for (const auto& entry : lock.at("source_inventory")) {
        const auto path = entry.at("path").get<std::string>();
        require(paths.emplace(path).second, "worker authority source path is duplicated");
        require(entry.at("size_bytes").get<std::uint64_t>() != 0,
                "worker authority source size is zero");
        require(aida::analysis::c03::is_canonical_sha256(entry.at("sha256").get<std::string>()),
                "worker authority source digest is invalid");
    }
    std::unordered_map<std::string, std::string> decisions;
    for (const auto& dependency : lock.at("dependencies"))
        require(decisions.emplace(dependency.at("id").get<std::string>(),
                                  dependency.at("usage").get<std::string>()).second,
                "dependency decision is duplicated");
    require(decisions.at("lmdb") == "non_use" && decisions.at("unicorn") == "non_use" &&
                decisions.at("remill") == "evidence_only" && decisions.at("lief") == "evidence_only" &&
                decisions.at("dotnet-runtime") == "production" &&
                decisions.at("pyinstaller") == "build_only" &&
                decisions.at("analysis-python-worker") == "production",
            "dependency use decisions are incomplete");
    require(lock.at("production_link_denylist") == json::array({"lmdb", "unicorn", "remill"}),
            "production link denylist is invalid");
    const auto& managed = lock.at("offline_managed_restore");
    require(managed.at("locked_mode_required") == true &&
                managed.at("network_sources_forbidden") == true &&
                managed.at("packages").size() == 3,
            "offline managed graph is invalid");
    const auto& python = lock.at("analysis_python_worker");
    const auto& prebuilt = python.at("prebuilt_artifact");
    require(python.at("network_fetch_forbidden") == true &&
                python.at("pinned_freezer_required") == true &&
                python.at("runtime_coupling").at("camoufox_forbidden") == true &&
                prebuilt.at("required_for_staging") == true,
            "analysis Python external artifact contract is invalid");
    const auto prebuilt_exists = std::filesystem::is_regular_file(root /
        ".deps/AiDA_AnalysisPythonWorker/AiDA_AnalysisPythonWorker.exe");
    const auto identity_state = prebuilt.at("identity_state").get<std::string>();
    if (identity_state == "external_fixture_required") {
        require(!prebuilt_exists && prebuilt.at("expected_sha256") == "" &&
                    prebuilt.at("expected_size_bytes") == 0 &&
                    prebuilt.at("expected_signer_thumbprint_sha256") == "" &&
                    prebuilt.at("expected_protector_tool_sha256") == "" &&
                    prebuilt.at("expected_protector_verifier_sha256") == "" &&
                    prebuilt.at("expected_signature_verifier_sha256") == "",
                "analysis Python external blocker does not match repository state");
    } else {
        require(identity_state == "locked" && prebuilt_exists &&
                    prebuilt.at("expected_size_bytes").get<std::uint64_t>() != 0 &&
                    aida::analysis::c03::is_canonical_sha256(
                        prebuilt.at("expected_sha256").get<std::string>()) &&
                    aida::analysis::c03::is_canonical_sha256(
                        prebuilt.at("expected_signer_thumbprint_sha256").get<std::string>()) &&
                    aida::analysis::c03::is_canonical_sha256(
                        prebuilt.at("expected_protector_tool_sha256").get<std::string>()) &&
                    aida::analysis::c03::is_canonical_sha256(
                        prebuilt.at("expected_protector_verifier_sha256").get<std::string>()) &&
                    aida::analysis::c03::is_canonical_sha256(
                        prebuilt.at("expected_signature_verifier_sha256").get<std::string>()),
                "analysis Python locked identity is invalid");
    }
}

void verify_schema_and_worker_contracts(const std::filesystem::path& root) {
    const auto authority_schema = read_json(root / "packaging/c03_worker_manifest.schema.json");
    const auto distribution_schema = read_json(root / "packaging/c03_distribution_manifest.schema.json");
    const auto distribution_spec_schema =
        read_json(root / "packaging/c03_worker_runtime/distribution_manifest_spec.schema.json");
    require(!contains_remote_reference(authority_schema) &&
                !contains_remote_reference(distribution_schema) &&
                !contains_remote_reference(distribution_spec_schema),
            "package schema contains a remote reference");
    require(authority_schema.at("properties").at("schema_version").at("const") == 2 &&
                distribution_schema.at("properties").at("schema_version").at("const") == 2 &&
                authority_schema.at("properties").at("source_inventory").at("minItems") == 58 &&
                authority_schema.at("properties").at("source_inventory").at("maxItems") == 58 &&
                authority_schema.at("properties").at("dependencies").at("minItems") == 30 &&
                authority_schema.at("properties").at("dependencies").at("maxItems") == 30 &&
                distribution_schema.at("properties").at("dependencies").at("minItems") == 30 &&
                distribution_schema.at("properties").at("dependencies").at("maxItems") == 30 &&
                distribution_spec_schema.at("properties").at("dependencies").at("minItems") == 30 &&
                distribution_spec_schema.at("properties").at("dependencies").at("maxItems") == 30,
            "package schema version is invalid");
    const auto native_schema = read_json(root / "packaging/c03_native_worker_manifest.schema.json");
    require(!contains_remote_reference(native_schema),
            "native worker schema contains a remote reference");
    const auto native = read_json(root / "packaging/c03_native_worker_manifest.json");
    require(native.at("schema_version") == 2 && native.at("artifact").at("magic") == "NWMF" &&
                native.at("artifact").at("schema_version") == 2 &&
                native.at("worker").at("provider").at("version") == "2" &&
                native.at("worker").at("provider").at("worker_build_id") ==
                    "aida-native-decompiler-worker-v3" &&
                native.at("worker").at("provider").at("worker_build_hash_material") ==
                    "aida-native-decompiler-worker-build-v3|bounded-printc-evidence" &&
                native.at("worker").at("protocol").at("version") == 3 &&
                native.at("worker").at("protocol").at("hash_material") ==
                    "aida.isolated-decompiler.worker.frame.v3|bootstrap.v1|hmac-sha256|strict-sequence|readonly-provider-input|attested-provider-artifacts|bounded-native-printc-evidence|control-frame-8m|result-frame-80m|provider-artifacts-48m|printc-8m",
            "native worker manifest contract is stale");
    const auto managed = read_json(root / "src/standalone/workers/managed_decompiler/worker_manifest.json");
    require(managed.at("schema_version") == 3 &&
                managed.at("artifact").at("schema_version") == 3 &&
                managed.at("worker").at("provider").at("worker_build_id") ==
                    "aida-managed-decompiler-worker-v3" &&
                managed.at("worker").at("protocol").at("version") == 3 &&
                managed.at("worker").at("protocol").at("hash_material") ==
                    "aida.isolated-decompiler.worker.frame.v3|bootstrap.v1|hmac-sha256|strict-sequence|readonly-provider-input|attested-provider-artifacts|bounded-native-printc-evidence|control-frame-8m|result-frame-80m|provider-artifacts-48m|printc-8m" &&
                managed.at("worker").at("protocol").at("contract_hash_material") ==
                    "aida.c03.managed-cli.contract.v3|readonly-inherited-mapping.v1|source-kind|logical-identity|module-sha256|module-size|entity|generation|type-revision|profile|runtime-manifest|provider|cache|request-binding|exact-response" &&
                managed.at("worker").at("runtime").at("target_framework") == "net10.0" &&
                managed.at("worker").at("runtime").at("framework") == "Microsoft.NETCore.App" &&
                managed.at("worker").at("runtime").at("framework_version") == "10.0.9" &&
                managed.at("worker").at("runtime").at("runtime_identifier") == "win-x64" &&
                managed.at("worker").at("runtime").at("machine_runtime_fallback") == false,
            "managed worker manifest contract is stale");
}

void verify_offline_scripts(const std::filesystem::path& root) {
    const auto camoufox_path = root / "tools/build_camoufox_reverse_mcp_exe.ps1";
    const auto camoufox = read_file(camoufox_path);
    for (const auto& required : {"c03_camoufox_reverse_mcp_build.lock.json",
                                 "Assert-WheelRecordEntries",
                                 "Resolve-OfflineFrozenMcpBuildEnvironment",
                                 "network_fetch_forbidden", "PyInstaller"})
        require_contains(camoufox, required, camoufox_path);
    for (const auto& prohibited : {"pip install", "-m venv", "ensurepip", "nuitka",
                                   "assume-yes-for-downloads", "invoke-webrequest",
                                   "start-bitstransfer", "git clone"})
        require_absent_case_insensitive(camoufox, prohibited, camoufox_path);

    const auto python_path = root /
        "src/standalone/workers/analysis_python/build_frozen_worker.ps1";
    const auto python = read_file(python_path);
    for (const auto& required : {"missing locked prebuilt artifact",
                                 "Get-AuthenticodeSignature", "expected_signer_thumbprint_sha256",
                                 "aida.protector.receipt", "aida.signature.receipt"})
        require_contains(python, required, python_path);
    for (const auto& prohibited : {"PyInstaller", "pip install", "-m venv", "PythonExe",
                                   "Invoke-WebRequest", "AIDA_CAMOUFOX_PYTHON"})
        require_absent_case_insensitive(python, prohibited, python_path);

    const auto distribution_path = root / "packaging/c03_distribution_manifest.ps1";
    const auto distribution = read_file(distribution_path);
    for (const auto& required : {"detached distribution manifest", "exact_inventory",
                                 "unlisted file", "source_authority_sha256",
                                 "managed_runtime_manifest_v1", "ghidra_spec_manifest_v1",
                                 "worker-runtime-acl-receipt", "protector_receipt_artifact",
                                 "signature_receipt_artifact", "dependency authority",
                                 "distribution_manifest_spec"})
        require_contains(distribution, required, distribution_path);
    for (const auto& prohibited : {"Invoke-WebRequest", "Invoke-AidaPEInMemory",
                                   "AIDA_FILELESS_LAUNCH", "create_bootstrap_package"})
        require_absent_case_insensitive(distribution, prohibited, distribution_path);

    const auto deploy_path = root / "deploy_to_server.ps1";
    const auto deploy = read_file(deploy_path);
    for (const auto& prohibited : {"Publish-StandalonePackage", "Publish-StandalonePrivateBase",
                                   "Update-BootstrapMetadata", "create_bootstrap_package.js",
                                   "AIDA_FILELESS_LAUNCH", "Invoke-AidaPEInMemory",
                                   "AIDA_BOOTSTRAP_ARTIFACT", "AIDA_STANDALONE_BASE"})
        require_absent_case_insensitive(deploy, prohibited, deploy_path);
}

void verify_integration_registry(const std::filesystem::path& root) {
    const auto dependencies_path = root / "cmake/aida_c03_dependencies.cmake";
    const auto dependencies = read_file(dependencies_path);
    for (const auto& required : {"AIDA_C03_NO_NETWORK_FETCH", "FETCHCONTENT_FULLY_DISCONNECTED",
                                 "FETCHCONTENT_UPDATES_DISCONNECTED",
                                 "c03_distribution_manifest.schema.json",
                                 "c03_distribution_manifest.ps1",
                                  "c03_camoufox_reverse_mcp_build.lock.json",
                                  "managed_runtime_source_spec.json",
                                  "ghidra_spec_source_spec.json",
                                  "apply_worker_runtime_acl.ps1",
                                 "build_frozen_worker.ps1", "LINK_LIBRARIES",
                                 "INTERFACE_LINK_LIBRARIES"})
        require_contains(dependencies, required, dependencies_path);
    require_absent_case_insensitive(dependencies,
        "materialize_python_worker_manifest.py", dependencies_path);

    const auto registry_path = root / "cmake/aida_c03_safe_headless_manifest.cmake";
    const auto registry = read_file(registry_path);
    for (const auto& required : {"c03_build_packaging_integration_harness",
                                 "c03_dependency_inventory_harness",
                                 "build_worker_packaging_integration.cpp",
                                 "c03_safe_headless"})
        require_contains(registry, required, registry_path);
    require_absent_case_insensitive(registry,
        "materialize_python_worker_manifest.py", registry_path);
}

void verify_notices(const std::filesystem::path& root) {
    const auto source = root / "licenses/c03/THIRD_PARTY_NOTICES.md";
    const auto notices = read_file(source);
    for (const auto& required : {"Zydis", "Capstone", "Taskflow", "Ghidra", "Triton",
                                 "Z3", "SQLite", "Dear ImGui", "zlib", "Zstandard",
                                 "liblzma", "minizip-ng", "PCRE2", "nlohmann JSON",
                                  "LLVM Demangle", "Microsoft.NETCore.App", ".NET SDK", "ICSharpCode.Decompiler",
                                 "System.Collections.Immutable", "System.Reflection.Metadata",
                                 "PyInstaller", "LIEF", "Remill"})
        require_contains(notices, required, source);
}

}

int main(int argc, char** argv) {
    try {
        const auto root = locate_root(argc > 1 ? std::filesystem::path(argv[1]) :
                                                std::filesystem::current_path());
        verify_gitignore(root);
        verify_source_authority(root);
        verify_lock_semantics(root);
        verify_schema_and_worker_contracts(root);
        verify_offline_scripts(root);
        verify_integration_registry(root);
        verify_notices(root);
        std::cout << "C03 dependency and offline distribution authority verified\n";
        return 0;
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
