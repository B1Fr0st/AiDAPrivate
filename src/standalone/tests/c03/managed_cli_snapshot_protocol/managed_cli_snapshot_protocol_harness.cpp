#include "managed_cli_snapshot_protocol_harness.hpp"
#include "../assertion_telemetry/assertion_telemetry.hpp"

#include "../../../src/core/analysis/decompiler/native_worker_host.hpp"
#include "../../../src/core/analysis/decompiler/providers/cli_provider.hpp"
#include "../../../src/core/analysis/workspace/workspace_identity.hpp"

#include <nlohmann/json.hpp>
#include <windows.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using nlohmann::json;

void require(bool value, const char* message)
{
    assertion_telemetry::record_assertion(value, message, __FILE__, __LINE__);
    if (!value)
        throw std::runtime_error(message);
}

sha256_digest_t digest_hex(const char* value)
{
    const auto parsed = sha256_digest_t::from_hex(value);
    require(parsed.has_value(), "fixture digest is malformed");
    return *parsed;
}

sha256_digest_t digest_bytes(const std::vector<std::uint8_t>& bytes)
{
    const auto value = sha256_bytes(bytes.data(), bytes.size());
    require(value.has_value(), "fixture bytes could not be hashed");
    return value.value();
}

std::filesystem::path source_root()
{
    std::error_code error;
    auto current = std::filesystem::absolute(std::filesystem::path(__FILE__), error);
    require(!error, "fixture source path is unavailable");
    current = current.parent_path();
    while (!current.empty()) {
        if (std::filesystem::is_regular_file(current / "AGENTS.md", error) &&
            std::filesystem::is_directory(current / ".deps", error))
            return current;
        const auto parent = current.parent_path();
        if (parent == current)
            break;
        current = parent;
    }
    throw std::runtime_error("AiDA source root is unavailable");
}

std::string path_text(const std::filesystem::path& path)
{
    return std::filesystem::absolute(path).lexically_normal().string();
}

managed_cli::worker_identity_t worker_identity()
{
    managed_cli::worker_identity_t result;
    result.provider_version = "10.1.0.8386";
    result.decompiler_assembly_hash = digest_hex("bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345");
    result.worker_build_id = "aida-managed-decompiler-worker-v3";
    result.worker_build_hash = stable_serialization_hash(
        "aida-managed-decompiler-worker-build-v3|snapshot-bound-contract=4fe173593d2e044466706c58b3573ec528930a1762a3177ac53e7b84c166cfa6|tfm=net10.0|runtime=Microsoft.NETCore.App/10.0.9");
    result.runtime_manifest_hash = stable_serialization_hash(
        "aida-managed-runtime-snapshot-fixture-v1");
    return result;
}

decompiler_profile_budget_t profile(std::uint64_t memory_bytes = 512ULL << 20)
{
    decompiler_profile_budget_t result;
    result.profile = decompiler_profile_id_t::balanced;
    result.max_wall_clock_ms = 5'000;
    result.max_cpu_ms = 4'000;
    result.max_memory_bytes = memory_bytes;
    result.max_provider_ir_nodes = 100'000;
    result.max_hir_nodes = 100'000;
    result.max_ast_nodes = 100'000;
    return result;
}

decompiler_entity_key_t entity(const sha256_digest_t& module_hash, std::uint32_t token,
                               std::string method)
{
    cli_decompiler_entity_identity_t identity;
    identity.module_hash = module_hash;
    identity.assembly_identity = "SnapshotFixture, Version=1.0.0.0";
    identity.module_name = "SnapshotFixture.dll";
    identity.metadata_token = token;
    identity.declaring_type = "SnapshotFixture.Entry";
    identity.method_name = std::move(method);
    identity.method_signature = "System.Int32()";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::cli_method;
    result.format = format_id_t::pe32_plus;
    result.identity = std::move(identity);
    return result;
}

json module_source_json(const managed_cli::request_t& request)
{
    return {
        {"kind", request.module_source.kind == managed_cli::module_source_kind_t::regular_file
            ? "regular_file" : "embedded_member"},
        {"logicalIdentity", request.module_source.logical_identity},
        {"moduleHash", request.module_source.module_hash.to_hex()},
        {"moduleSize", request.module_source.module_size}
    };
}

json budget_json(const managed_cli::request_t& request)
{
    return {
        {"profile", "balanced"},
        {"maxWallClockMs", request.profile.max_wall_clock_ms},
        {"maxCpuMs", request.profile.max_cpu_ms},
        {"maxMemoryBytes", request.profile.max_memory_bytes},
        {"maxProviderIrNodes", request.profile.max_provider_ir_nodes},
        {"maxHirNodes", request.profile.max_hir_nodes},
        {"maxAstNodes", request.profile.max_ast_nodes},
        {"maxSemanticQueries", request.profile.max_semantic_queries},
        {"semanticProofsEnabled", request.profile.semantic_proofs_enabled}
    };
}

json provider_json(const managed_cli::request_t& request)
{
    return {
        {"version", request.worker.provider_version},
        {"decompilerAssemblyHash", request.worker.decompiler_assembly_hash.to_hex()},
        {"workerBuildId", request.worker.worker_build_id},
        {"workerBuildHash", request.worker.worker_build_hash.to_hex()}
    };
}

std::string failure_payload(const managed_cli::request_t& request)
{
    const auto& identity = std::get<cli_decompiler_entity_identity_t>(request.entity.identity);
    return json{
        {"schema", "aida.c03.managed-cli.worker"},
        {"schemaVersion", managed_cli::k_managed_cli_worker_protocol_version},
        {"kind", "failure"},
        {"sequence", request.sequence},
        {"requestId", request.request_id},
        {"moduleSource", module_source_json(request)},
        {"entityHash", request.entity_hash.to_hex()},
        {"metadataToken", identity.metadata_token},
        {"workspaceGeneration", request.workspace_generation},
        {"typeGraphRevision", request.type_graph_revision},
        {"budget", budget_json(request)},
        {"runtimeManifestHash", request.worker.runtime_manifest_hash.to_hex()},
        {"contractHash", request.contract_hash.to_hex()},
        {"cacheIdentity", request.cache_identity.to_hex()},
        {"requestBindingHash", request.request_binding_hash.to_hex()},
        {"provider", provider_json(request)},
        {"diagnostics", json::array({{
            {"severity", "error"}, {"code", "cancelled"},
            {"key", "managed_cli.cancelled"}, {"args", json::array()},
            {"ilOffset", nullptr}, {"confidence", 100},
            {"retryable", false}, {"ordinal", 1}
        }})}
    }.dump();
}

class temporary_directory_t final {
public:
    temporary_directory_t()
    {
        wchar_t root[MAX_PATH]{};
        require(GetTempPathW(MAX_PATH, root) != 0, "temporary root is unavailable");
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = std::filesystem::path(root) /
            (L"aida-c03-managed-snapshot-" + std::to_wstring(GetCurrentProcessId()) +
                L"-" + std::to_wstring(nonce));
        require(std::filesystem::create_directory(path_), "temporary fixture directory could not be created");
    }

    ~temporary_directory_t()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

void write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "fixture file could not be opened");
    output.write(reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    output.flush();
    require(output.good(), "fixture file could not be written");
}

managed_cli::request_t embedded_request(
    const std::filesystem::path& root,
    const std::vector<std::uint8_t>& bytes,
    std::uint64_t generation,
    std::uint32_t token,
    std::string member)
{
    const auto value = managed_cli::make_embedded_request(1,
        "snapshot-" + std::to_string(generation) + "-" + std::to_string(token),
        path_text(root / "fixture.zip") + "#member:" + member,
        bytes, entity(digest_bytes(bytes), token, "Method" + std::to_string(token)),
        generation, 9, profile(), worker_identity());
    require(value.has_value(), "embedded request was rejected");
    return value.value();
}

void verify_embedded_and_response(const std::filesystem::path& root)
{
    const std::vector<std::uint8_t> bytes{'M', 'Z', 0, 1, 2, 3, 4, 5};
    auto request = embedded_request(root, bytes, 7, 0x06000001U, "lib/SnapshotFixture.dll");
    require(request.module_source.kind == managed_cli::module_source_kind_t::embedded_member &&
        request.module_source.module_size == bytes.size() && request.module_snapshot &&
        request.cache_identity != sha256_digest_t{} &&
        request.request_binding_hash != sha256_digest_t{},
        "embedded request is not fully bound");
    const auto serialized = managed_cli::serialize_request(request);
    require(serialized.has_value(), "embedded request serialization failed");
    const auto wire = json::parse(serialized.value());
    require(wire.at("moduleSource").at("kind") == "embedded_member" &&
        wire.find("modulePath") == wire.end() &&
        wire.find("offlineLockHash") == wire.end() &&
        wire.at("runtimeManifestHash") ==
            request.worker.runtime_manifest_hash.to_hex() &&
        wire.at("requestBindingHash") == request.request_binding_hash.to_hex(),
        "embedded wire contract is incomplete");
    const auto captured = native_worker::capture_managed_worker_snapshot(
        std::make_shared<const managed_cli::request_t>(request),
        managed_cli::k_managed_cli_maximum_module_bytes);
    require(captured.has_value() && captured.value().snapshot.bytes ==
        captured.value().request->module_snapshot,
        "embedded host capture did not preserve immutable ownership");
    const auto response = managed_cli::deserialize_response(request, failure_payload(request));
    require(response.has_value() && response.value().failure.has_value(),
        "bound terminal failure response was rejected");
    auto reordered = json::parse(failure_payload(request));
    reordered["sequence"] = request.sequence + 1;
    require(!managed_cli::deserialize_response(request, reordered.dump()),
        "reordered terminal response was accepted");
    auto wrong_runtime = json::parse(failure_payload(request));
    wrong_runtime["runtimeManifestHash"] = std::string(64, '0');
    require(!managed_cli::deserialize_response(request, wrong_runtime.dump()),
        "runtime-unbound terminal response was accepted");
    require(!managed_cli::serialize_cancellation(request, request.sequence, "duplicate"),
        "duplicate cancellation sequence was accepted");
    require(managed_cli::serialize_cancellation(
            request, request.sequence + 1, "cancelled").has_value(),
        "bound cancellation was rejected");
}

void verify_regular_and_tamper(const std::filesystem::path& root,
                               const std::filesystem::path& temporary)
{
    const std::vector<std::uint8_t> original{'M', 'Z', 8, 7, 6, 5, 4, 3, 2, 1};
    const std::vector<std::uint8_t> changed{'M', 'Z', 1, 1, 2, 3, 5, 8, 13, 21};
    const auto module = temporary / "SnapshotFixture.dll";
    write_bytes(module, original);
    auto request = managed_cli::make_request(1, "regular-snapshot", path_text(module),
        entity(digest_bytes(original), 0x06000002U, "Regular"), 11, 13,
        profile(), worker_identity());
    require(request.has_value() && !request.value().module_snapshot,
        "regular request admission is not deferred to immutable capture");
    auto captured = native_worker::capture_managed_worker_snapshot(
        std::make_shared<const managed_cli::request_t>(request.value()),
        managed_cli::k_managed_cli_maximum_module_bytes);
    require(captured.has_value() &&
        captured.value().request->module_source.module_size == original.size(),
        "regular module capture failed");
    write_bytes(module, changed);
    require(managed_cli::serialize_request(
            *captured.value().request).has_value(),
        "captured regular snapshot changed after source replacement");
    auto stale = managed_cli::make_request(1, "regular-stale", path_text(module),
        entity(digest_bytes(original), 0x06000003U, "Stale"), 12, 13,
        profile(), worker_identity());
    require(stale.has_value() && !native_worker::capture_managed_worker_snapshot(
        std::make_shared<const managed_cli::request_t>(stale.value()),
        managed_cli::k_managed_cli_maximum_module_bytes),
        "tampered regular module was accepted before capture");

    const auto link = temporary / "SnapshotFixture.link.dll";
    static_cast<void>(CreateSymbolicLinkW(link.c_str(), module.c_str(), 0x2U));
    auto linked = managed_cli::make_request(1, "regular-reparse", path_text(link),
        entity(digest_bytes(changed), 0x06000004U, "Reparse"), 13, 13,
        profile(), worker_identity());
    if (linked.has_value()) {
        require(!native_worker::capture_managed_worker_snapshot(
            std::make_shared<const managed_cli::request_t>(linked.value()),
            managed_cli::k_managed_cli_maximum_module_bytes),
            "reparse alias was accepted");
    }
}

void verify_mutation_rejections(const std::filesystem::path& root)
{
    const std::vector<std::uint8_t> bytes{'M', 'Z', 9, 8, 7, 6};
    auto request = embedded_request(root, bytes, 17, 0x06000005U, "nested/Fixture.dll");

    auto wrong_size = request;
    ++wrong_size.module_source.module_size;
    require(!managed_cli::serialize_request(wrong_size), "wrong module size was accepted");

    auto wrong_kind = request;
    wrong_kind.module_source.kind = static_cast<managed_cli::module_source_kind_t>(255);
    require(!managed_cli::serialize_request(wrong_kind), "wrong source kind was accepted");

    auto stale_generation = request;
    ++stale_generation.workspace_generation;
    require(!managed_cli::serialize_request(stale_generation), "stale generation was accepted");

    auto stale_entity = request;
    std::get<cli_decompiler_entity_identity_t>(stale_entity.entity.identity).method_name = "Changed";
    require(!managed_cli::serialize_request(stale_entity), "stale entity was accepted");

    auto stale_runtime = request;
    stale_runtime.worker.runtime_manifest_hash = stable_serialization_hash("wrong-runtime-manifest");
    require(!managed_cli::serialize_request(stale_runtime), "stale runtime identity was accepted");

    auto stale_contract = request;
    stale_contract.contract_hash = stable_serialization_hash("wrong-contract");
    require(!managed_cli::serialize_request(stale_contract), "wrong contract hash was accepted");

    auto wrong_sequence = request;
    wrong_sequence.sequence = 2;
    require(!managed_cli::serialize_request(wrong_sequence), "reordered request sequence was accepted");

    auto wrong_hash_entity = entity(stable_serialization_hash("wrong-module"),
        0x06000006U, "WrongHash");
    require(!managed_cli::make_embedded_request(1, "wrong-hash",
        path_text(root / "fixture.zip") + "#member:wrong.dll", bytes,
        std::move(wrong_hash_entity), 18, 9, profile(), worker_identity()),
        "wrong embedded hash was accepted");

    require(!managed_cli::make_embedded_request(1, "traversal",
        path_text(root / "fixture.zip") + "#member:../escape.dll", bytes,
        entity(digest_bytes(bytes), 0x06000007U, "Traversal"), 19, 9,
        profile(), worker_identity()),
        "embedded path traversal was accepted");

    require(!managed_cli::make_embedded_request(1, "oversized-budget",
        path_text(root / "fixture.zip") + "#member:large.dll", bytes,
        entity(digest_bytes(bytes), 0x06000008U, "Oversized"), 20, 9,
        profile(8), worker_identity()),
        "profile-oversized embedded module was accepted");
}

void verify_cancellation_and_cleanup(const std::filesystem::path& root)
{
    const std::vector<std::uint8_t> bytes{'M', 'Z', 4, 3, 2, 1};
    cancellation_source_t cancelled;
    cancelled.request_cancel();
    require(!managed_cli::make_embedded_request(1, "cancelled",
        path_text(root / "fixture.zip") + "#member:cancelled.dll", bytes,
        entity(digest_bytes(bytes), 0x06000009U, "Cancelled"), 21, 9,
        profile(), worker_identity(), cancelled.token()),
        "cancelled embedded admission was accepted");

    cancellation_source_t expired(std::chrono::steady_clock::now());
    require(!managed_cli::make_embedded_request(1, "expired",
        path_text(root / "fixture.zip") + "#member:expired.dll", bytes,
        entity(digest_bytes(bytes), 0x0600000aU, "Expired"), 22, 9,
        profile(), worker_identity(), expired.token()),
        "expired embedded admission was accepted");

    std::weak_ptr<const std::vector<std::uint8_t>> released;
    {
        auto terminal = embedded_request(root, bytes, 23, 0x0600000bU,
            "terminal/Fixture.dll");
        released = terminal.module_snapshot;
        auto crashed = terminal;
        crashed.request_binding_hash = stable_serialization_hash("crashed-binding");
        require(!native_worker::capture_managed_worker_snapshot(
            std::make_shared<const managed_cli::request_t>(std::move(crashed)),
            managed_cli::k_managed_cli_maximum_module_bytes),
            "crash-corrupted binding was accepted");
    }
    require(released.expired(), "terminal snapshot ownership was retained");
}

void verify_concurrent_isolation(const std::filesystem::path& root)
{
    const std::vector<std::uint8_t> first{'M', 'Z', 1, 2, 3, 4};
    const std::vector<std::uint8_t> second{'M', 'Z', 5, 6, 7, 8};
    auto first_request = embedded_request(root, first, 31, 0x0600000cU,
        "workspace-a/Fixture.dll");
    auto second_request = embedded_request(root, second, 32, 0x0600000dU,
        "workspace-b/Fixture.dll");
    auto shared_snapshot = managed_cli::make_immutable_module_snapshot(first);
    require(shared_snapshot.has_value(), "shared immutable module snapshot was rejected");
    auto shared_first = managed_cli::make_embedded_request(1, "shared-first",
        path_text(root / "fixture.zip") + "#member:shared/Fixture.dll",
        shared_snapshot.value(), entity(digest_bytes(first), 0x0600000eU, "SharedFirst"),
        33, 9, profile(), worker_identity());
    auto shared_second = managed_cli::make_embedded_request(1, "shared-second",
        path_text(root / "fixture.zip") + "#member:shared/Fixture.dll",
        shared_snapshot.value(), entity(digest_bytes(first), 0x0600000fU, "SharedSecond"),
        33, 9, profile(), worker_identity());
    require(shared_first.has_value() && shared_second.has_value() &&
        shared_first.value().module_snapshot == shared_second.value().module_snapshot,
        "same-module entity requests duplicated immutable module ownership");
    auto capture = [](managed_cli::request_t request) {
        return native_worker::capture_managed_worker_snapshot(
            std::make_shared<const managed_cli::request_t>(std::move(request)),
            managed_cli::k_managed_cli_maximum_module_bytes);
    };
    auto left = std::async(std::launch::async, capture, std::move(first_request));
    auto right = std::async(std::launch::async, capture, std::move(second_request));
    auto left_result = left.get();
    auto right_result = right.get();
    require(left_result.has_value() && right_result.has_value() &&
        left_result.value().request->workspace_generation == 31 &&
        right_result.value().request->workspace_generation == 32 &&
        left_result.value().snapshot.hash != right_result.value().snapshot.hash &&
        left_result.value().snapshot.bytes != right_result.value().snapshot.bytes,
        "concurrent managed snapshots were not isolated");
}

}

int run_managed_cli_snapshot_protocol_harness()
{
    try {
        const auto root = source_root();
        temporary_directory_t temporary;
        verify_embedded_and_response(root);
        verify_regular_and_tamper(root, temporary.path());
        verify_mutation_rejections(root);
        verify_cancellation_and_cleanup(root);
        verify_concurrent_isolation(root);
        std::cout << "managed_cli_snapshot_protocol_harness: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        assertion_telemetry::record_exception(error.what());
        std::cerr << "managed_cli_snapshot_protocol_harness: FAIL: " << error.what() << '\n';
        return 1;
    } catch (...) {
        assertion_telemetry::record_exception(
            "managed CLI snapshot protocol harness failed with a non-standard exception");
        std::cerr << "managed_cli_snapshot_protocol_harness: FAIL: non-standard exception\n";
        return 1;
    }
}

}
