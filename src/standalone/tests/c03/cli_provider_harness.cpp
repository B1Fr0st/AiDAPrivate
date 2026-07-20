#include "cli_provider_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/providers/cli_provider.hpp"
#include "../../src/core/analysis/workspace/workspace_identity.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using json = nlohmann::json;

constexpr std::string_view k_fixture_manifest = "src/standalone/tests/c03/managed_cli/fixture_manifest.json";

struct build_package_fixture_t {
    std::string id;
    std::string version;
    std::string file_name;
    sha256_digest_t content_hash;
};

struct build_lock_fixture_t {
    std::string package_root;
    std::string sdk_path;
    sha256_digest_t sdk_hash;
    std::vector<build_package_fixture_t> packages;
};

void require(bool condition, const std::string& message)
{
    assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

sha256_digest_t digest(const std::string& value)
{
    return stable_serialization_hash(value);
}

sha256_digest_t digest_hex(const char* value)
{
    const auto parsed = sha256_digest_t::from_hex(value);
    require(parsed.has_value(), "fixture digest is invalid");
    return *parsed;
}

std::optional<std::filesystem::path> locate_root_from(std::filesystem::path candidate)
{
    std::error_code error;
    candidate = std::filesystem::absolute(candidate, error);
    if (error)
        return std::nullopt;
    if (std::filesystem::is_regular_file(candidate, error))
        candidate = candidate.parent_path();
    while (!candidate.empty()) {
        if (std::filesystem::is_regular_file(candidate / "AGENTS.md", error) &&
            std::filesystem::is_directory(candidate / ".deps", error))
            return candidate;
        const auto parent = candidate.parent_path();
        if (parent == candidate)
            break;
        candidate = parent;
    }
    return std::nullopt;
}

std::filesystem::path source_root()
{
    if (const auto root = locate_root_from(std::filesystem::path(__FILE__)); root)
        return *root;
    if (const auto root = locate_root_from(std::filesystem::current_path()); root)
        return *root;
    throw std::runtime_error("AiDA source root is unavailable");
}

std::string path_text(const std::filesystem::path& path)
{
    return std::filesystem::absolute(path).lexically_normal().string();
}

std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    require(stream.is_open(), "managed CLI immutable fixture is unavailable");
    const auto size = stream.tellg();
    require(size > 0, "managed CLI immutable fixture is empty");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(bytes.data()),
        static_cast<std::streamsize>(size));
    require(stream.good(), "managed CLI immutable fixture could not be read");
    return bytes;
}

json load_manifest(const std::filesystem::path& root)
{
    std::ifstream stream(root / std::string(k_fixture_manifest), std::ios::binary);
    require(stream.is_open(), "managed CLI fixture manifest is unavailable");
    json manifest;
    stream >> manifest;
    require(stream.good() || stream.eof(), "managed CLI fixture manifest could not be read");
    return manifest;
}

bool coverage_contains(const json& fixture, std::string_view value)
{
    const auto& coverage = fixture.at("coverage");
    return std::any_of(coverage.begin(), coverage.end(), [value](const json& entry) {
        return entry.is_string() && std::string_view(entry.get_ref<const std::string&>()) == value;
    });
}

void validate_manifest(const json& manifest)
{
    require(manifest.is_object() && manifest.value("schema", std::string{}) == "aida.c03.managed-cli-fixtures" &&
        manifest.value("schema_version", 0) == 1 && manifest.value("assembly", std::string{}) == "ManagedCliFixtures",
        "managed CLI fixture manifest header is invalid");
    const auto& methods = manifest.at("methods");
    require(methods.is_array() && methods.size() >= 6, "managed CLI fixture method inventory is incomplete");
    std::set<std::string> symbols;
    std::set<std::string> coverage;
    for (const auto& method : methods) {
        require(method.is_object() && method.at("symbol").is_string() && !method.at("symbol").get_ref<const std::string&>().empty() &&
            method.at("method_generic_arity").is_number_unsigned() && method.at("coverage").is_array() && !method.at("coverage").empty() &&
            method.at("expected_source_fragments").is_array() && !method.at("expected_source_fragments").empty(),
            "managed CLI fixture method contract is invalid");
        require(symbols.insert(method.at("symbol").get<std::string>()).second, "managed CLI fixture symbol is duplicated");
        for (const auto& entry : method.at("coverage")) {
            require(entry.is_string() && !entry.get_ref<const std::string&>().empty(), "managed CLI fixture coverage value is invalid");
            coverage.insert(entry.get<std::string>());
        }
    }
    for (const auto required : {"generic", "async", "async_iterator", "iterator", "exceptions", "filters", "finally", "switch", "throw", "stable_token", "cancellation"})
        require(coverage.find(required) != coverage.end(), std::string("managed CLI fixture coverage is absent: ") + required);

    const auto& malformed = manifest.at("malformed");
    require(malformed.is_array() && malformed.size() >= 3, "managed CLI malformed fixture inventory is incomplete");
    std::set<std::string> mutations;
    for (const auto& value : malformed) {
        require(value.is_object() && value.value("expected_code", std::string{}) == "malformed_metadata" &&
            value.value("expected_key", std::string{}) == "managed_cli.malformed_metadata" &&
            !value.value("source_contract", std::string{}).empty(),
            "managed CLI malformed fixture contract is invalid");
        mutations.insert(value.at("mutation").get<std::string>());
    }
    for (const auto required : {"corrupt_metadata_signature", "truncate_metadata_root", "non_method_token"})
        require(mutations.find(required) != mutations.end(), std::string("managed CLI malformed mutation is absent: ") + required);

    const auto& validation = manifest.at("validation");
    require(validation.is_object() && validation.value("deterministic_runs", 0) >= 2 && validation.value("cancellation", false) &&
        validation.value("runtime_identity_gate", false) && validation.value("snapshot_binding", false),
        "managed CLI fixture validation contract is incomplete");
    std::set<std::string> resources;
    for (const auto& value : validation.at("resource_limits"))
        resources.insert(value.get<std::string>());
    require(resources == std::set<std::string>{"maxCpuMs", "maxMemoryBytes"}, "managed CLI fixture resource contract is incomplete");
}

build_lock_fixture_t fixture_build_lock(const std::filesystem::path& root)
{
    build_lock_fixture_t result;
    result.package_root = path_text(root / ".deps/nuget-offline");
    result.sdk_path = path_text(root / ".deps/dotnet-sdk-10.0.301-win-x64/dotnet.exe");
    result.sdk_hash = digest_hex("a5ccdc3a41d5e5c6014ff64509aed176db39f4f14caffff3dd1997f8907e94d7");
    result.packages = {
        {"ICSharpCode.Decompiler", "10.1.0.8386", "ICSharpCode.Decompiler.10.1.0.8386.nupkg", digest_hex("a6fb2e9be86c1b73e54231e20640d4d566c52f21cba9ad99c3e9100d67e8f5af")},
        {"System.Collections.Immutable", "9.0.0", "System.Collections.Immutable.9.0.0.nupkg", digest_hex("fbaab954c7a87396e6e1616ca15ea705703d755e696bf3b8c96fa039d8bcc9a7")},
        {"System.Reflection.Metadata", "9.0.0", "System.Reflection.Metadata.9.0.0.nupkg", digest_hex("6af1166dc0a1ed7829b127ac9d1dff4a0c568bfe82e4ec6347cf497ff49f4634")}
    };
    return result;
}

sha256_digest_t file_digest(const std::filesystem::path& path)
{
    auto bytes = read_bytes(path);
    const auto value = sha256_bytes(bytes.data(), bytes.size());
    require(value.has_value(), "managed CLI build input could not be hashed");
    return value.value();
}

std::optional<sha256_digest_t> verify_fixture_build_lock(
    const std::filesystem::path& root,
    const build_lock_fixture_t& lock)
{
    const std::vector<build_package_fixture_t> expected{
        {"ICSharpCode.Decompiler", "10.1.0.8386", "ICSharpCode.Decompiler.10.1.0.8386.nupkg", digest_hex("a6fb2e9be86c1b73e54231e20640d4d566c52f21cba9ad99c3e9100d67e8f5af")},
        {"System.Collections.Immutable", "9.0.0", "System.Collections.Immutable.9.0.0.nupkg", digest_hex("fbaab954c7a87396e6e1616ca15ea705703d755e696bf3b8c96fa039d8bcc9a7")},
        {"System.Reflection.Metadata", "9.0.0", "System.Reflection.Metadata.9.0.0.nupkg", digest_hex("6af1166dc0a1ed7829b127ac9d1dff4a0c568bfe82e4ec6347cf497ff49f4634")}};
    if (lock.package_root != path_text(root / ".deps/nuget-offline") ||
        lock.sdk_path != path_text(root / ".deps/dotnet-sdk-10.0.301-win-x64/dotnet.exe") ||
        lock.sdk_hash != digest_hex("a5ccdc3a41d5e5c6014ff64509aed176db39f4f14caffff3dd1997f8907e94d7") ||
        lock.packages.size() != expected.size())
        return std::nullopt;
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const auto& actual = lock.packages[index];
        const auto& pinned = expected[index];
        if (actual.id != pinned.id || actual.version != pinned.version ||
            actual.file_name != pinned.file_name ||
            actual.content_hash != pinned.content_hash)
            return std::nullopt;
    }
    if (file_digest(lock.sdk_path) != lock.sdk_hash)
        return std::nullopt;
    for (const auto& package : lock.packages) {
        if (file_digest(std::filesystem::path(lock.package_root) /
                package.file_name) != package.content_hash)
            return std::nullopt;
    }
    return digest(
        "ICSharpCode.Decompiler|10.1.0.8386|a6fb2e9be86c1b73e54231e20640d4d566c52f21cba9ad99c3e9100d67e8f5af\n"
        "System.Collections.Immutable|9.0.0|fbaab954c7a87396e6e1616ca15ea705703d755e696bf3b8c96fa039d8bcc9a7\n"
        "System.Reflection.Metadata|9.0.0|6af1166dc0a1ed7829b127ac9d1dff4a0c568bfe82e4ec6347cf497ff49f4634");
}

decompiler_profile_budget_t fixture_profile()
{
    decompiler_profile_budget_t result;
    result.profile = decompiler_profile_id_t::balanced;
    result.max_wall_clock_ms = 5'000;
    result.max_cpu_ms = 4'000;
    result.max_memory_bytes = 256ULL << 20;
    result.max_provider_ir_nodes = 100'000;
    result.max_hir_nodes = 100'000;
    result.max_ast_nodes = 100'000;
    return result;
}

decompiler_entity_key_t fixture_entity(const json& fixture, std::size_t index,
                                       const sha256_digest_t& module_hash)
{
    const auto symbol = fixture.at("symbol").get<std::string>();
    const auto separator = symbol.rfind('.');
    require(separator != std::string::npos && separator != 0 && separator + 1 < symbol.size(), "managed CLI fixture symbol is malformed");
    cli_decompiler_entity_identity_t identity;
    identity.module_hash = module_hash;
    identity.assembly_identity = "ManagedCliFixtures, Version=1.0.0.0";
    identity.module_name = "ManagedCliFixtures.dll";
    identity.metadata_token = 0x06000001U + static_cast<std::uint32_t>(index);
    identity.declaring_type = symbol.substr(0, separator);
    identity.method_name = symbol.substr(separator + 1);
    identity.method_signature = "fixture_signature_" + std::to_string(index);
    identity.generic_arity = fixture.at("method_generic_arity").get<std::uint32_t>();
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::cli_method;
    result.format = format_id_t::pe32_plus;
    result.identity = std::move(identity);
    return result;
}

managed_cli::request_t fixture_request(
    const std::filesystem::path& root,
    const managed_cli::immutable_module_snapshot_t& snapshot,
    const json& fixture,
    std::size_t index)
{
    managed_cli::worker_identity_t worker;
    worker.provider_version = "10.1.0.8386";
    worker.decompiler_assembly_hash = digest_hex("bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345");
    worker.worker_build_id = "aida-managed-decompiler-worker-v3";
    worker.worker_build_hash = digest(
        "aida-managed-decompiler-worker-build-v3|snapshot-bound-contract=4fe173593d2e044466706c58b3573ec528930a1762a3177ac53e7b84c166cfa6|tfm=net10.0|runtime=Microsoft.NETCore.App/10.0.9");
    worker.runtime_manifest_hash = digest("managed-runtime-fixture-v1");
    const auto request = managed_cli::make_embedded_request(
        1,
        "fixture-request-" + std::to_string(index + 1),
        path_text(root / "src/standalone/tests/c03/managed_cli/ManagedCliFixtures.csproj") +
            "#member:ManagedCliFixtures.dll",
        snapshot,
        fixture_entity(fixture, index, snapshot.hash),
        7,
        9,
        fixture_profile(),
        std::move(worker));
    require(request.has_value(), "managed CLI fixture request was rejected");
    return request.value();
}

json response_binding(const managed_cli::request_t& request)
{
    const auto& identity = std::get<cli_decompiler_entity_identity_t>(
        request.entity.identity);
    return {
        {"moduleSource", {
            {"kind", "embedded_member"},
            {"logicalIdentity", request.module_source.logical_identity},
            {"moduleHash", request.module_source.module_hash.to_hex()},
            {"moduleSize", request.module_source.module_size}
        }},
        {"entityHash", request.entity_hash.to_hex()},
        {"metadataToken", identity.metadata_token},
        {"workspaceGeneration", request.workspace_generation},
        {"typeGraphRevision", request.type_graph_revision},
        {"budget", {
            {"profile", "balanced"},
            {"maxWallClockMs", request.profile.max_wall_clock_ms},
            {"maxCpuMs", request.profile.max_cpu_ms},
            {"maxMemoryBytes", request.profile.max_memory_bytes},
            {"maxProviderIrNodes", request.profile.max_provider_ir_nodes},
            {"maxHirNodes", request.profile.max_hir_nodes},
            {"maxAstNodes", request.profile.max_ast_nodes},
            {"maxSemanticQueries", request.profile.max_semantic_queries},
            {"semanticProofsEnabled", request.profile.semantic_proofs_enabled}
        }},
        {"runtimeManifestHash", request.worker.runtime_manifest_hash.to_hex()},
        {"contractHash", request.contract_hash.to_hex()},
        {"cacheIdentity", request.cache_identity.to_hex()},
        {"requestBindingHash", request.request_binding_hash.to_hex()},
        {"provider", {
            {"version", request.worker.provider_version},
            {"decompilerAssemblyHash", request.worker.decompiler_assembly_hash.to_hex()},
            {"workerBuildId", request.worker.worker_build_id},
            {"workerBuildHash", request.worker.worker_build_hash.to_hex()}
        }}
    };
}

json fixture_response(const managed_cli::request_t& request, const json& fixture)
{
    const auto& identity = std::get<cli_decompiler_entity_identity_t>(request.entity.identity);
    std::string source = fixture.at("symbol").get<std::string>();
    for (const auto& fragment : fixture.at("expected_source_fragments"))
        source += " " + fragment.get<std::string>();
    json result = {
        {"schema", "aida.c03.managed-cli.worker"},
        {"schemaVersion", managed_cli::k_managed_cli_worker_protocol_version},
        {"kind", "result"},
        {"sequence", request.sequence},
        {"requestId", request.request_id},
        {"identity", {
            {"assemblyIdentity", identity.assembly_identity}, {"moduleName", identity.module_name}, {"declaringType", identity.declaring_type},
            {"methodName", identity.method_name}, {"methodSignature", identity.method_signature}, {"genericArity", identity.generic_arity}
        }},
        {"source", {{"text", source}, {"sha256", digest(source).to_hex()}}},
        {"tokenMap", json::array({{
            {"token", identity.metadata_token},
            {"stableIdentity", "0x" + std::to_string(identity.metadata_token) + "|" + identity.declaring_type + "|" + identity.method_name + "|" + identity.method_signature + "|" + std::to_string(identity.generic_arity)},
            {"declaringType", identity.declaring_type}, {"methodName", identity.method_name}, {"methodSignature", identity.method_signature},
            {"genericArity", identity.generic_arity}, {"isAsync", coverage_contains(fixture, "async")},
            {"isIterator", coverage_contains(fixture, "iterator") || coverage_contains(fixture, "async_iterator")},
            {"hasExceptionRegions", coverage_contains(fixture, "exceptions")}
        }})},
        {"typeGraph", {
            {"revision", request.type_graph_revision},
            {"nodes", json::array({
                {{"id", 1}, {"kind", "reference"}, {"canonicalName", "System.Object"}, {"displayName", "System.Object"}, {"byteSize", nullptr}, {"alignment", 0}, {"signed", false}, {"confidence", 0}},
                {{"id", 2}, {"kind", "signed_integer"}, {"canonicalName", "System.Int32"}, {"displayName", "System.Int32"}, {"byteSize", 4}, {"alignment", 0}, {"signed", true}, {"confidence", 100}},
                {{"id", 3}, {"kind", "void"}, {"canonicalName", "System.Void"}, {"displayName", "System.Void"}, {"byteSize", nullptr}, {"alignment", 0}, {"signed", false}, {"confidence", 100}}
            })},
            {"edges", json::array()}
        }},
        {"returnTypeId", 2},
        {"ir", {
            {"entryBlockId", 1},
            {"blocks", json::array({{
                {"id", 1}, {"predecessorIds", json::array()}, {"successorIds", json::array()}, {"exceptionSuccessorIds", json::array()}, {"startOffset", 0},
                {"values", json::array({
                    {{"id", 1}, {"opcode", "parameter"}, {"typeId", 2}, {"operandIds", json::array()}, {"stableImmediate", "IL_0000|ldarg|"}, {"stableSymbol", ""}, {"ilOffset", 0}, {"metadataToken", identity.metadata_token}, {"confidence", 100}, {"provenance", "loader_metadata"}},
                    {{"id", 2}, {"opcode", "return_value"}, {"typeId", 3}, {"operandIds", json::array({1})}, {"stableImmediate", "IL_0001|ret|"}, {"stableSymbol", ""}, {"ilOffset", 1}, {"metadataToken", identity.metadata_token}, {"confidence", 100}, {"provenance", "loader_metadata"}}
                })}
            }})}
        }},
        {"unknowns", json::array()},
        {"diagnostics", json::array()}
    };
    result.update(response_binding(request));
    return result;
}

json failure_response(const managed_cli::request_t& request, const std::string& code, const std::string& key)
{
    json result = {
        {"schema", "aida.c03.managed-cli.worker"},
        {"schemaVersion", managed_cli::k_managed_cli_worker_protocol_version},
        {"kind", "failure"}, {"sequence", request.sequence},
        {"requestId", request.request_id},
        {"diagnostics", json::array({{{"severity", "error"}, {"code", code}, {"key", key}, {"args", json::array()},
            {"ilOffset", nullptr}, {"confidence", 100}, {"retryable", false}, {"ordinal", 1}}})}
    };
    result.update(response_binding(request));
    return result;
}

void validate_build_runtime_separation(
    const std::filesystem::path& root,
    const build_lock_fixture_t& lock,
    const managed_cli::immutable_module_snapshot_t& snapshot)
{
    const auto verified = verify_fixture_build_lock(root, lock);
    require(verified.has_value() && !verified.value().empty(), "managed CLI build lock verification failed");
    auto tampered = lock;
    tampered.packages.front().content_hash = digest("tampered-package");
    require(!verify_fixture_build_lock(root, tampered).has_value(), "managed CLI accepted a tampered build lock");

    const auto manifest = load_manifest(root);
    const auto request = fixture_request(
        root, snapshot, manifest.at("methods").front(), 0);
    const auto encoded = managed_cli::serialize_request(request);
    require(encoded.has_value(), "managed CLI runtime request was rejected");
    const auto value = json::parse(encoded.value());
    require(value.contains("runtimeManifestHash") &&
        !value.contains("offlineLockHash") && !value.contains("packageRoot") &&
        !value.contains("sdkPath") &&
        value.at("runtimeManifestHash") == request.worker.runtime_manifest_hash.to_hex(),
        "managed CLI runtime request leaked build-only package state");
}

void validate_method_contract(
    const std::filesystem::path& root,
    const managed_cli::immutable_module_snapshot_t& snapshot,
    const json& fixture,
    std::size_t index)
{
    const auto request = fixture_request(root, snapshot, fixture, index);
    const auto encoded = managed_cli::serialize_request(request);
    require(encoded.has_value(), "managed CLI request encoding failed");
    const auto encoded_json = json::parse(encoded.value());
    require(encoded_json["kind"] == "decompile" && encoded_json["metadataToken"] ==
        std::get<cli_decompiler_entity_identity_t>(request.entity.identity).metadata_token &&
        encoded_json["moduleSource"]["kind"] == "embedded_member" &&
        encoded_json["moduleSource"]["logicalIdentity"] == request.module_source.logical_identity &&
        encoded_json["moduleSource"]["moduleHash"] == request.module_source.module_hash.to_hex() &&
        encoded_json["moduleSource"]["moduleSize"] == request.module_source.module_size &&
        encoded_json.find("modulePath") == encoded_json.end() &&
        encoded_json["entityHash"] == request.entity_hash.to_hex() &&
        encoded_json["workspaceGeneration"] == request.workspace_generation &&
        encoded_json["budget"]["maxCpuMs"] == request.profile.max_cpu_ms &&
        encoded_json["budget"]["maxMemoryBytes"] == request.profile.max_memory_bytes &&
        encoded_json["budget"]["maxHirNodes"] == request.profile.max_hir_nodes &&
        encoded_json["budget"]["maxAstNodes"] == request.profile.max_ast_nodes &&
        encoded_json["budget"]["maxSemanticQueries"] == request.profile.max_semantic_queries &&
        encoded_json["budget"]["semanticProofsEnabled"] == request.profile.semantic_proofs_enabled &&
        encoded_json["typeGraphRevision"] == request.type_graph_revision &&
        encoded_json["runtimeManifestHash"] == request.worker.runtime_manifest_hash.to_hex() &&
        encoded_json["contractHash"] == request.contract_hash.to_hex() &&
        encoded_json["cacheIdentity"] == request.cache_identity.to_hex() &&
        encoded_json["requestBindingHash"] == request.request_binding_hash.to_hex(),
        "managed CLI request contract drifted");

    const auto cancellation = managed_cli::serialize_cancellation(request, request.sequence + 1, "fixture_cancel");
    require(cancellation.has_value(), "managed CLI cancellation encoding failed");
    const auto cancellation_json = json::parse(cancellation.value());
    require(cancellation_json["kind"] == "cancel" &&
        cancellation_json["requestBindingHash"] == request.request_binding_hash.to_hex(),
        "managed CLI cancellation encoding failed");

    const auto response_json = fixture_response(request, fixture);
    const auto decoded = managed_cli::deserialize_response(request, response_json.dump());
    require(decoded.has_value() && decoded.value().analysis.has_value() && !decoded.value().failure.has_value(),
        "managed CLI result response was rejected");
    const auto& analysis = *decoded.value().analysis;
    require(validate_provider_ir(analysis.provider_ir).valid(), "managed CLI provider IR failed validation");
    require(validate_type_graph(analysis.type_graph).valid(), "managed CLI type graph failed validation");
    require(analysis.token_map.size() == 1 && analysis.token_map.front().is_async == coverage_contains(fixture, "async") &&
        analysis.token_map.front().is_iterator == (coverage_contains(fixture, "iterator") || coverage_contains(fixture, "async_iterator")) &&
        analysis.token_map.front().has_exception_regions == coverage_contains(fixture, "exceptions"),
        "managed CLI manifest token classification drifted");
    require(analysis.decompiled_source_hash == digest(analysis.decompiled_source), "managed CLI source hash drifted");

    if (index == 0) {
        auto dangling_operand = response_json;
        dangling_operand["ir"]["blocks"][0]["values"][1]["operandIds"] = json::array({999999});
        require(!managed_cli::deserialize_response(request, dangling_operand.dump()).has_value(),
            "managed CLI accepted a dangling provider IR operand");

        auto duplicate_value = response_json;
        duplicate_value["ir"]["blocks"][0]["values"][1]["id"] = 1;
        require(!managed_cli::deserialize_response(request, duplicate_value.dump()).has_value(),
            "managed CLI accepted duplicate provider IR value IDs");

        auto mismatched_hash = response_json;
        mismatched_hash["moduleSource"]["moduleHash"] = std::string(64, '0');
        require(!managed_cli::deserialize_response(request, mismatched_hash.dump()).has_value(),
            "managed CLI accepted a mismatched module hash");

        auto mismatched_budget = response_json;
        mismatched_budget["budget"]["maxMemoryBytes"] =
            request.profile.max_memory_bytes + 1;
        require(!managed_cli::deserialize_response(request, mismatched_budget.dump()).has_value(),
            "managed CLI accepted a mismatched response budget");

        auto mismatched_runtime = response_json;
        mismatched_runtime["runtimeManifestHash"] = std::string(64, '0');
        require(!managed_cli::deserialize_response(request, mismatched_runtime.dump()).has_value(),
            "managed CLI accepted a mismatched runtime identity");

        auto mismatched_provider = response_json;
        mismatched_provider["provider"]["workerBuildHash"] = std::string(64, '0');
        require(!managed_cli::deserialize_response(request, mismatched_provider.dump()).has_value(),
            "managed CLI accepted a mismatched response provider");

        auto malformed_token = response_json;
        malformed_token["tokenMap"][0]["token"] = 0x02000001U;
        require(!managed_cli::deserialize_response(request, malformed_token.dump()).has_value(),
            "managed CLI accepted a non-method token map entry");

        cancellation_source_t source;
        source.request_cancel();
        const auto cancelled = managed_cli::deserialize_response(request, response_json.dump(), source.token());
        require(!cancelled.has_value() && cancelled.error().code == workspace_error_code_t::cancelled,
            "managed CLI response decoding ignored cancellation");

        const auto resource = managed_cli::deserialize_response(request,
            failure_response(request, "resource_limit", "managed_cli.resource_limit").dump());
        require(resource.has_value() && resource.value().failure.has_value() &&
            resource.value().failure->diagnostics.front().code == decompiler_diagnostic_code_t::resource_limit,
            "managed CLI resource-limit failure was rejected");
    }
}

void validate_malformed_contracts(
    const std::filesystem::path& root,
    const managed_cli::immutable_module_snapshot_t& snapshot,
    const json& manifest)
{
    const auto request = fixture_request(
        root, snapshot, manifest.at("methods").front(), 0);
    for (const auto& malformed : manifest.at("malformed")) {
        const auto decoded = managed_cli::deserialize_response(request,
            failure_response(request, malformed.at("expected_code").get<std::string>(), malformed.at("expected_key").get<std::string>()).dump());
        require(decoded.has_value() && decoded.value().failure.has_value() &&
            decoded.value().failure->diagnostics.front().localization_key == malformed.at("expected_key").get<std::string>(),
            "managed CLI malformed metadata failure was rejected");
    }
}

void validate_resource_budget_bounds(
    const std::filesystem::path& root,
    const managed_cli::immutable_module_snapshot_t& snapshot,
    const json& manifest)
{
    const auto request = fixture_request(
        root, snapshot, manifest.at("methods").front(), 0);
    const auto require_rejected = [&request](const decompiler_profile_budget_t& profile, const char* message) {
        require(!validate_decompiler_profile(profile).valid(), message);
        auto candidate = request;
        candidate.profile = profile;
        require(!managed_cli::serialize_request(candidate).has_value(), message);
    };

    auto cpu_uint64_max = request.profile;
    cpu_uint64_max.max_cpu_ms = (std::numeric_limits<std::uint64_t>::max)();
    require_rejected(cpu_uint64_max, "managed CLI accepted UINT64_MAX CPU budget");

    auto cpu_oversized = request.profile;
    cpu_oversized.max_cpu_ms = k_decompiler_profile_max_cpu_ms + 1;
    require_rejected(cpu_oversized, "managed CLI accepted oversized CPU budget");

    auto memory_uint64_max = request.profile;
    memory_uint64_max.max_memory_bytes = (std::numeric_limits<std::uint64_t>::max)();
    require_rejected(memory_uint64_max, "managed CLI accepted UINT64_MAX memory budget");

    auto memory_oversized = request.profile;
    memory_oversized.max_memory_bytes = k_decompiler_profile_max_memory_bytes + 1;
    require_rejected(memory_oversized, "managed CLI accepted oversized memory budget");

    auto tiny = request;
    tiny.profile.max_cpu_ms = 1;
    tiny.profile.max_memory_bytes = tiny.module_source.module_size * 2;
    tiny.cache_identity = {};
    tiny.request_binding_hash = {};
    require(validate_decompiler_profile(tiny.profile).valid(), "managed CLI rejected tiny bounded profile");
    require(managed_cli::serialize_request(tiny).has_value(), "managed CLI rejected tiny bounded request");
}

}

void run_cli_provider_harness()
{
    const auto root = source_root();
    const auto manifest = load_manifest(root);
    validate_manifest(manifest);
    const auto build_lock = fixture_build_lock(root);
    const auto snapshot = managed_cli::make_immutable_module_snapshot(read_bytes(
        root / "src/standalone/tests/c03/managed_cli/GenericAsyncIteratorFixture.cs"));
    require(snapshot.has_value(), "managed CLI immutable fixture snapshot was rejected");
    validate_build_runtime_separation(root, build_lock, snapshot.value());
    std::size_t index = 0;
    for (const auto& fixture : manifest.at("methods"))
        validate_method_contract(root, snapshot.value(), fixture, index++);
    validate_malformed_contracts(root, snapshot.value(), manifest);
    validate_resource_budget_bounds(root, snapshot.value(), manifest);
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_cli_provider_harness();
        std::cout << "cli_provider_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& exception) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(
            exception.what());
        std::cerr << exception.what() << '\n';
        return 1;
    } catch (...) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(
            "cli provider harness failed with a non-standard exception");
        std::cerr << "cli provider harness failed with a non-standard exception\n";
        return 1;
    }
}
