#include "decompiler_service_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/decompiler_service.hpp"
#include "../../src/core/analysis/decompiler/legacy_document_adapter.hpp"
#include "../../src/core/analysis/workspace/workspace_database.hpp"
#include "../../src/core/analysis/workspace/workspace_identity.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <variant>

namespace aida::analysis::c03_test {
namespace {

void require(const bool condition, const char* message)
{
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

sha256_digest_t digest(const std::string& value)
{
    return stable_serialization_hash(value);
}

address_t native_address(const std::uint64_t value)
{
    address_t result;
    result.space = address_space_id_t::relative_virtual;
    result.value = value;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_entity_key_t native_entity(const std::uint64_t function_id = 606)
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = function_id;
    identity.entry = native_address(0x3000);
    identity.end = native_address(0x3040);
    identity.function_bytes_hash = digest("c03-service-function-" + std::to_string(function_id));
    identity.canonical_symbol = "service_fixture";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::native_function;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.identity = std::move(identity);
    return result;
}

decompiler_entity_key_t cli_entity()
{
    cli_decompiler_entity_identity_t identity;
    identity.module_hash = digest("c03-service-cli-module");
    identity.assembly_identity = "ServiceFixture, Version=1.0.0.0";
    identity.module_name = "ServiceFixture.dll";
    identity.metadata_token = 0x06000001U;
    identity.declaring_type = "ServiceFixture.Program";
    identity.method_name = "Run";
    identity.method_signature = "int32()";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::cli_method;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.identity = std::move(identity);
    return result;
}

decompiler_entity_key_t jvm_entity()
{
    jvm_decompiler_entity_identity_t identity;
    identity.class_artifact_hash = digest("c03-service-jvm-class");
    identity.class_internal_name = "fixture/Service";
    identity.method_name = "run";
    identity.method_descriptor = "()I";
    identity.method_index = 1;
    identity.code_offset = 16;
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::jvm_method;
    result.format = format_id_t::classfile;
    result.architecture = architecture_id_t::jvm_bytecode;
    result.mode = architecture_mode_t::jvm;
    result.identity = std::move(identity);
    return result;
}

decompiler_entity_key_t dalvik_entity()
{
    dalvik_decompiler_entity_identity_t identity;
    identity.dex_hash = digest("c03-service-dalvik-dex");
    identity.dex_ordinal = 1;
    identity.class_descriptor = "Lfixture/Service;";
    identity.method_name = "run";
    identity.prototype = "()I";
    identity.method_id = 1;
    identity.code_item_offset = 64;
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::dalvik_method;
    result.format = format_id_t::dex;
    result.architecture = architecture_id_t::dalvik_bytecode;
    result.mode = architecture_mode_t::dalvik;
    result.identity = std::move(identity);
    return result;
}

decompiler_provider_identity_t provider_identity(
    const decompiler_provider_id_t provider,
    const std::string& name)
{
    decompiler_provider_identity_t result;
    result.provider = provider;
    result.provider_name = name;
    result.provider_version = "c03.1";
    result.provider_binary_hash = digest(name + ".binary");
    result.worker_build_id = name + ".worker";
    result.worker_build_hash = digest(name + ".worker.build");
    return result;
}

decompiler_language_identity_t native_language()
{
    decompiler_language_identity_t result;
    result.language_id = "x86:LE:64:default";
    result.language_version = "c03.1";
    result.compiler_spec_id = "windows";
    result.language_spec_hash = digest("c03-service-native-language");
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_language_identity_t cli_language()
{
    decompiler_language_identity_t result;
    result.language_id = "cli-il";
    result.language_version = "ecma-335";
    result.compiler_spec_id = "managed-cli";
    result.language_spec_hash = digest("cli-il|ecma-335|c03.1");
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_language_identity_t jvm_language()
{
    decompiler_language_identity_t result;
    result.language_id = "jvm:classfile";
    result.language_version = "c03.1";
    result.compiler_spec_id = "jvm-verifier";
    result.language_spec_hash = digest("c03-service-jvm-language");
    result.architecture = architecture_id_t::jvm_bytecode;
    result.mode = architecture_mode_t::jvm;
    result.endian = endian_t::big;
    return result;
}

decompiler_language_identity_t dalvik_language()
{
    decompiler_language_identity_t result;
    result.language_id = "dalvik:dex";
    result.language_version = "c03.1";
    result.compiler_spec_id = "dex-verifier";
    result.language_spec_hash = digest("c03-service-dalvik-language");
    result.architecture = architecture_id_t::dalvik_bytecode;
    result.mode = architecture_mode_t::dalvik;
    return result;
}

source_coordinate_t coordinate(
    const decompiler_pipeline_cache_key_t& key,
    const decompiler_coordinate_layer_t layer)
{
    source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = key.workspace_generation;
    result.entity = key.entity;
    const auto& identity = std::get<native_decompiler_entity_identity_t>(key.entity.identity);
    result.address_range = decompiler_address_range_t{identity.entry, identity.end};
    result.instruction_range = decompiler_instruction_range_t{1, 2};
    return result;
}

decompiler_diagnostic_t host_diagnostic(
    const decompiler_diagnostic_code_t code,
    std::string key)
{
    decompiler_diagnostic_t result;
    result.severity = decompiler_diagnostic_severity_t::error;
    result.code = code;
    result.localization_key = std::move(key);
    result.confidence = 100;
    result.ordinal = 1;
    return result;
}

class fake_native_provider_t final : public decompiler_provider_t {
public:
    explicit fake_native_provider_t(decompiler_provider_identity_t identity)
    {
        descriptor_.registration_id = "c03.decompiler.fake.native";
        descriptor_.identity = std::move(identity);
        descriptor_.entity_kind = decompiler_entity_kind_t::native_function;
        descriptor_.profiles = {
            decompiler_profile_id_t::fast,
            decompiler_profile_id_t::balanced,
            decompiler_profile_id_t::thorough};
        descriptor_.priority = 1000;
        descriptor_.isolated = true;
    }

    decompiler_provider_descriptor_t descriptor() const override
    {
        return descriptor_;
    }

    bool supports_language(const decompiler_language_identity_t& language) const noexcept override
    {
        return language.language_id == "x86:LE:64:default" &&
               language.architecture == architecture_id_t::x86_64 &&
               language.mode == architecture_mode_t::x86_64;
    }

    decompiler_provider_result_t decompile(
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) override
    {
        ++invocations_;
        decompiler_provider_result_t result;
        if (cancel.stop_requested()) {
            result.status = decompiler_provider_execution_status_t::cancelled;
            result.diagnostics.push_back(host_diagnostic(
                decompiler_diagnostic_code_t::cancelled,
                "c03.decompiler.fake.cancelled"));
            return result;
        }

        decompiler_type_node_t integer;
        integer.id = 1;
        integer.kind = decompiler_type_kind_t::signed_integer;
        integer.canonical_name = "int";
        integer.display_name = "int";
        integer.byte_size = 4;
        integer.alignment = 4;
        integer.is_signed = true;
        integer.confidence = 100;
        integer.provenance = decompiler_fact_provenance_t::provider_semantics;
        type_graph_t types;
        types.entity = request.cache_key.entity;
        types.revision = request.cache_key.type_graph_revision;
        types.nodes.push_back(std::move(integer));

        provider_ir_value_t literal;
        literal.id = 1;
        literal.opcode = provider_ir_opcode_t::constant;
        literal.type_id = 1;
        literal.stable_immediate = "7";
        literal.coordinate = coordinate(request.cache_key, decompiler_coordinate_layer_t::provider_ir);
        literal.confidence = 100;
        literal.provenance = decompiler_fact_provenance_t::provider_semantics;
        provider_ir_value_t return_value;
        return_value.id = 2;
        return_value.opcode = provider_ir_opcode_t::return_value;
        return_value.type_id = 1;
        return_value.operand_ids = {1};
        return_value.coordinate = coordinate(request.cache_key, decompiler_coordinate_layer_t::provider_ir);
        return_value.confidence = 100;
        return_value.provenance = decompiler_fact_provenance_t::provider_semantics;
        provider_ir_block_t provider_block;
        provider_block.id = 1;
        provider_block.values = {std::move(literal), std::move(return_value)};
        provider_block.coordinate = coordinate(request.cache_key, decompiler_coordinate_layer_t::provider_ir);
        provider_ir_t provider_ir;
        provider_ir.provider = descriptor_.identity;
        provider_ir.language = request.cache_key.language;
        provider_ir.entity = request.cache_key.entity;
        provider_ir.entry_block_id = 1;
        provider_ir.blocks.push_back(std::move(provider_block));

        hir_value_t hir_literal;
        hir_literal.id = 1;
        hir_literal.kind = hir_node_kind_t::literal;
        hir_literal.type_id = 1;
        hir_literal.stable_value = "7";
        hir_literal.coordinate = coordinate(request.cache_key, decompiler_coordinate_layer_t::hir);
        hir_literal.confidence = 100;
        hir_literal.provenance = decompiler_fact_provenance_t::provider_semantics;
        hir_value_t hir_return;
        hir_return.id = 2;
        hir_return.kind = hir_node_kind_t::return_value;
        hir_return.type_id = 1;
        hir_return.operand_ids = {1};
        hir_return.coordinate = coordinate(request.cache_key, decompiler_coordinate_layer_t::hir);
        hir_return.confidence = 100;
        hir_return.provenance = decompiler_fact_provenance_t::provider_semantics;
        hir_block_t hir_block;
        hir_block.id = 1;
        hir_block.values = {std::move(hir_literal), std::move(hir_return)};
        hir_block.coordinate = coordinate(request.cache_key, decompiler_coordinate_layer_t::hir);
        hir_function_t hir;
        hir.entity = request.cache_key.entity;
        hir.provider_ir_hash = stable_serialization_hash(provider_ir);
        hir.type_graph_revision = request.cache_key.type_graph_revision;
        hir.return_type_id = 1;
        hir.blocks.push_back(std::move(hir_block));

        decompiler_provider_artifacts_t artifacts;
        artifacts.provider_ir = std::move(provider_ir);
        artifacts.hir = std::move(hir);
        artifacts.type_graph = std::move(types);
        artifacts.return_type_id = 1;
        result.artifacts = std::move(artifacts);
        result.status = decompiler_provider_execution_status_t::completed;
        return result;
    }

    std::uint64_t invocations() const noexcept
    {
        return invocations_.load(std::memory_order_acquire);
    }

private:
    decompiler_provider_descriptor_t descriptor_;
    std::atomic<std::uint64_t> invocations_{0};
};

class fake_provider_context_t final : public decompiler_provider_context_t {
};

class fake_isolated_host_t final : public decompiler_isolated_provider_host_t {
public:
    enum class mode_t : std::uint8_t {
        execute,
        mismatch,
        crash,
        timeout
    };

    bool supports(const decompiler_provider_descriptor_t& descriptor) const noexcept override
    {
        return descriptor.registration_id == "c03.decompiler.fake.native" && descriptor.isolated;
    }

    decompiler_provider_result_t execute(
        const decompiler_provider_route_t& route,
        const decompiler_provider_request_t& request,
        const cancellation_token_t& cancel) override
    {
        ++invocations_;
        const auto mode = mode_.load(std::memory_order_acquire);
        if (mode == mode_t::crash)
            throw std::runtime_error("isolated worker terminated");
        if (mode == mode_t::timeout) {
            decompiler_provider_result_t result;
            result.status = decompiler_provider_execution_status_t::timed_out;
            result.diagnostics.push_back(host_diagnostic(
                decompiler_diagnostic_code_t::deadline_exceeded,
                "c03.decompiler.fake.worker_timeout"));
            return result;
        }

        auto result = route.provider->decompile(request, cancel);
        if (!result.succeeded() || !result.artifacts->hir)
            return result;
        const auto ast = build_typed_ast(
            *result.artifacts->hir, result.artifacts->type_graph);
        if (!ast.succeeded() || !ast.ast) {
            result.status = decompiler_provider_execution_status_t::failed;
            result.diagnostics.insert(result.diagnostics.end(),
                ast.diagnostics.begin(), ast.diagnostics.end());
            return result;
        }
        pseudocode_renderer_request_t render_request;
        render_request.profile = request.cache_key.profile.profile;
        render_request.settings = request.cache_key.renderer;
        auto rendered = render_pseudocode(
            *ast.ast, result.artifacts->type_graph, render_request);
        if (!rendered.succeeded() || !rendered.document) {
            result.status = decompiler_provider_execution_status_t::failed;
            result.diagnostics.insert(result.diagnostics.end(),
                rendered.diagnostics.begin(), rendered.diagnostics.end());
            return result;
        }
        result.attested_document = std::move(*rendered.document);
        result.authenticated_artifacts = true;
        if (mode == mode_t::mismatch)
            result.attested_document->renderer.style_id = "c03-attestation-mismatch";
        return result;
    }

    void set_mode(const mode_t mode) noexcept
    {
        mode_.store(mode, std::memory_order_release);
    }

    std::uint64_t invocations() const noexcept
    {
        return invocations_.load(std::memory_order_acquire);
    }

private:
    std::atomic<mode_t> mode_{mode_t::execute};
    std::atomic<std::uint64_t> invocations_{0};
};

decompiler_builtin_provider_config_t builtin_config()
{
    decompiler_builtin_provider_config_t result;
    result.native.identity = provider_identity(
        decompiler_provider_id_t::ghidra_native, "c03.native");
    result.cli.identity = provider_identity(
        decompiler_provider_id_t::ilspy_cli, "c03.cli");
    result.jvm.identity = provider_identity(
        decompiler_provider_id_t::jvm_ssa, "c03.jvm");
    result.dalvik.identity = provider_identity(
        decompiler_provider_id_t::dalvik_ssa, "c03.dalvik");
    return result;
}

decompiler_pipeline_request_t request(
    std::string workspace_id = "c03-service-workspace",
    const std::uint64_t generation = 1)
{
    decompiler_pipeline_request_t result;
    result.invocation = decompiler_pipeline_invocation_t::explicit_ui;
    result.workspace_id = std::move(workspace_id);
    result.workspace_generation = generation;
    result.analysis_revision = 11;
    result.entity = native_entity();
    result.language = native_language();
    result.profile = decompiler_profile_id_t::balanced;
    result.provider_registration_id = "c03.decompiler.fake.native";
    result.cache_identity.worker_protocol_hash = digest("c03-service-worker-protocol");
    result.cache_identity.loader_layout_hash = digest("c03-service-loader-layout");
    result.cache_identity.function_bytes_hash =
        std::get<native_decompiler_entity_identity_t>(result.entity.identity).function_bytes_hash;
    result.cache_identity.chunk_fingerprints.push_back({
        native_address(0x3000), native_address(0x3040), digest("c03-service-function-chunk")});
    result.cache_identity.metadata_revision = 13;
    result.cache_identity.type_graph_revision = 17;
    result.cache_identity.overlay_revision = 19;
    result.cache_identity.dependencies.push_back({
        "c03.fixture.provider", "1", digest("c03-service-provider-dependency")});
    return result;
}

struct service_fixture_t {
    std::shared_ptr<fake_native_provider_t> provider;
    std::shared_ptr<fake_isolated_host_t> host;
    std::shared_ptr<decompiler_cache_t> cache;
    std::shared_ptr<decompiler_pipeline_service_t> service;
};

service_fixture_t service_fixture()
{
    service_fixture_t result;
    auto registry = std::make_shared<decompiler_provider_registry_t>();
    result.provider = std::make_shared<fake_native_provider_t>(provider_identity(
        decompiler_provider_id_t::ghidra_native, "c03.fake.native"));
    require(static_cast<bool>(registry->register_provider(result.provider)),
        "failed to register the isolated service fixture provider");
    auto cache = decompiler_cache_t::create();
    require(static_cast<bool>(cache), "failed to create the decompiler cache fixture");
    result.cache = cache.value();
    result.host = std::make_shared<fake_isolated_host_t>();
    decompiler_pipeline_service_config_t config;
    config.max_parallel_requests = 4;
    config.isolated_provider_host = result.host;
    auto service = decompiler_pipeline_service_t::create(
        std::move(registry), result.cache, {}, std::move(config));
    require(static_cast<bool>(service), "failed to create the decompiler service fixture");
    result.service = service.value();
    return result;
}

void verify_builtin_registry()
{
    decompiler_provider_registry_t atomic_registry;
    auto invalid = builtin_config();
    invalid.jvm.identity.provider_name.clear();
    require(!static_cast<bool>(register_builtin_decompiler_providers(atomic_registry, invalid)),
        "built-in provider registration accepted an invalid batch");
    require(atomic_registry.snapshot().providers.empty() &&
            atomic_registry.snapshot().revision == 0,
        "built-in provider registration partially committed an invalid batch");

    decompiler_provider_registry_t registry;
    const auto config = builtin_config();
    require(static_cast<bool>(register_builtin_decompiler_providers(registry, config)),
        "concrete built-in provider registration failed");
    const auto snapshot = registry.snapshot();
    require(snapshot.providers.size() == 4 && snapshot.revision == 1,
        "built-in provider registry did not commit exactly four providers atomically");

    const auto profiles = default_decompiler_profile_policy();
    const auto native_fast = registry.resolve(
        native_entity(), native_language(), profiles.fast);
    const auto native_balanced = registry.resolve(
        native_entity(), native_language(), profiles.balanced);
    const auto native_thorough = registry.resolve(
        native_entity(), native_language(), profiles.thorough);
    const auto cli = registry.resolve(cli_entity(), cli_language(), profiles.balanced);
    const auto jvm = registry.resolve(jvm_entity(), jvm_language(), profiles.balanced);
    const auto dalvik = registry.resolve(dalvik_entity(), dalvik_language(), profiles.balanced);
    require(static_cast<bool>(native_fast) && static_cast<bool>(native_balanced) &&
            static_cast<bool>(native_thorough) && static_cast<bool>(cli) &&
            static_cast<bool>(jvm) && static_cast<bool>(dalvik),
        "concrete provider routing rejected an entity/profile route");
    require(native_fast.value().provider && cli.value().provider &&
            jvm.value().provider && dalvik.value().provider,
        "provider registry returned a descriptor without a concrete provider object");
    require(native_fast.value().descriptor.isolated &&
            !cli.value().descriptor.isolated &&
            !jvm.value().descriptor.isolated &&
            !dalvik.value().descriptor.isolated,
        "built-in provider isolation policy changed");

    auto mismatched_cli_language = cli_language();
    mismatched_cli_language.architecture = architecture_id_t::aarch64;
    mismatched_cli_language.mode = architecture_mode_t::aarch64;
    require(!registry.resolve(
            cli_entity(), mismatched_cli_language, profiles.balanced),
        "managed CLI routing accepted a mismatched module architecture");
}

void verify_lazy_provider_context(service_fixture_t& fixture)
{
    auto cached = request("c03-lazy-provider-context");
    std::atomic<std::uint64_t> factory_invocations{0};
    cached.provider_context_factory = [&factory_invocations](
        const decompiler_provider_request_t& provider_request,
        const cancellation_token_t&) {
        ++factory_invocations;
        require(provider_request.cache_key.stage == decompiler_cache_stage_t::provider_ir,
            "provider context factory did not receive the canonical provider cache key");
        std::shared_ptr<const decompiler_provider_context_t> context =
            std::make_shared<fake_provider_context_t>();
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::success(
            std::move(context));
    };
    const auto before_factory = factory_invocations.load(std::memory_order_acquire);
    const auto first = fixture.service->decompile(cached);
    const auto after_first = factory_invocations.load(std::memory_order_acquire);
    const auto second = fixture.service->decompile(cached);
    const auto after_second = factory_invocations.load(std::memory_order_acquire);
    require(first.succeeded() && second.succeeded() &&
            after_first > before_factory && after_second == after_first &&
            second.cache_hit_stage == decompiler_cache_stage_t::rendered_document,
        "rendered cache hit eagerly invoked the provider context factory");

    auto rejected = request("c03-provider-context-failure");
    rejected.cache_mode = decompiler_pipeline_cache_mode_t::bypass;
    rejected.provider_context_factory = [](
        const decompiler_provider_request_t&,
        const cancellation_token_t&) {
        return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                "fixture provider context unavailable", "c03.provider_context"));
    };
    const auto before_provider = fixture.provider->invocations();
    const auto failed = fixture.service->decompile(rejected);
    const auto after_provider = fixture.provider->invocations();
    require(failed.status == decompiler_pipeline_status_t::provider_unavailable &&
            before_provider == after_provider && !failed.diagnostics.empty() &&
            failed.diagnostics.front().code == decompiler_diagnostic_code_t::unsupported_provider,
        "provider context failure was not surfaced as a typed provider-unavailable result");
}

void verify_isolated_host_is_required()
{
    auto registry = std::make_shared<decompiler_provider_registry_t>();
    auto provider = std::make_shared<fake_native_provider_t>(provider_identity(
        decompiler_provider_id_t::ghidra_native, "c03.fake.native"));
    require(static_cast<bool>(registry->register_provider(provider)),
        "failed to register the host-rejection provider fixture");
    auto cache = decompiler_cache_t::create();
    require(static_cast<bool>(cache), "failed to create the host-rejection cache fixture");
    auto service = decompiler_pipeline_service_t::create(registry, cache.value());
    require(static_cast<bool>(service), "failed to create the host-rejection service fixture");
    auto miss = request("c03-host-required");
    miss.cache_mode = decompiler_pipeline_cache_mode_t::bypass;
    const auto rejected = service.value()->decompile(miss);
    require(rejected.status == decompiler_pipeline_status_t::provider_unavailable &&
            provider->invocations() == 0 &&
            service.value()->snapshot().isolated_host_rejections == 1,
        "isolated provider executed without a supporting worker host");
}

void verify_cache_and_explicit_routing(service_fixture_t& fixture)
{
    const auto base = request();
    const auto first = fixture.service->decompile(base);
    const auto second = fixture.service->decompile(base);
    require(first.succeeded() && second.succeeded(),
        "decompiler service rejected the cache fixture");
    require(!first.cache_hit_stage.has_value() &&
            second.cache_hit_stage == decompiler_cache_stage_t::rendered_document,
        "decompiler service did not produce a rendered-document cache hit");
    require(fixture.provider->invocations() == 1 && fixture.host->invocations() == 1,
        "rendered cache hit invoked the provider again");

    auto metadata = base;
    ++metadata.cache_identity.metadata_revision;
    require(fixture.service->decompile(metadata).succeeded(),
        "metadata-revision cache dimension failed");
    auto dependency = base;
    dependency.cache_identity.dependencies.front().content_hash = digest("c03-service-provider-dependency-2");
    require(fixture.service->decompile(dependency).succeeded(),
        "dependency cache dimension failed");
    auto profile = base;
    profile.profile = decompiler_profile_id_t::fast;
    require(fixture.service->decompile(profile).succeeded(),
        "profile cache dimension failed");
    require(fixture.provider->invocations() == 4 && fixture.host->invocations() == 4,
        "cache identity dimensions did not isolate provider results");

    auto baseline = base;
    baseline.invocation = decompiler_pipeline_invocation_t::baseline_analysis;
    const auto before_baseline = fixture.provider->invocations();
    const auto rejected = fixture.service->decompile(baseline);
    require(rejected.status == decompiler_pipeline_status_t::explicit_request_required &&
            fixture.provider->invocations() == before_baseline,
        "baseline analysis reached the explicit-only decompiler provider");

    auto unsupported = base;
    unsupported.language.language_id = "unsupported-native-language";
    unsupported.language.language_spec_hash = digest("unsupported-native-language");
    const auto before_unsupported = fixture.provider->invocations();
    const auto unsupported_result = fixture.service->decompile(unsupported);
    require(unsupported_result.status == decompiler_pipeline_status_t::provider_unavailable &&
            fixture.provider->invocations() == before_unsupported &&
            !unsupported_result.diagnostics.empty() &&
            unsupported_result.diagnostics.front().code ==
                decompiler_diagnostic_code_t::unsupported_provider,
        "unsupported native target did not return typed provider diagnostics");

    const auto cache_snapshot = fixture.cache->snapshot();
    require(cache_snapshot.provider_ir.stores >= 4 &&
            cache_snapshot.normalized_hir_ast.stores >= 4 &&
            cache_snapshot.rendered_document.stores >= 4 &&
            cache_snapshot.rendered_document.hits >= 1,
        "three-stage cache accounting omitted a service stage");
}

void verify_worker_failures(service_fixture_t& fixture)
{
    auto bypass = request("c03-worker-failure");
    bypass.cache_mode = decompiler_pipeline_cache_mode_t::bypass;
    fixture.host->set_mode(fake_isolated_host_t::mode_t::crash);
    require(fixture.service->decompile(bypass).status ==
            decompiler_pipeline_status_t::provider_crashed,
        "isolated worker crash was not surfaced as provider_crashed");
    fixture.host->set_mode(fake_isolated_host_t::mode_t::timeout);
    require(fixture.service->decompile(bypass).status ==
            decompiler_pipeline_status_t::deadline_exceeded,
        "isolated worker timeout was not surfaced as deadline_exceeded");
    fixture.host->set_mode(fake_isolated_host_t::mode_t::execute);
    const auto snapshot = fixture.service->snapshot();
    require(snapshot.isolated_provider_invocations >= 2 &&
            snapshot.provider_failures >= 1 && snapshot.deadline_exceeded >= 1,
        "isolated worker metrics omitted crash or timeout execution");
}

void verify_attestation_cache_transaction(service_fixture_t& fixture)
{
    const auto isolated = request("c03-attestation-transaction");
    const auto before_cache = fixture.cache->snapshot();
    const auto before_provider = fixture.provider->invocations();
    const auto before_host = fixture.host->invocations();
    fixture.host->set_mode(fake_isolated_host_t::mode_t::mismatch);
    const auto rejected = fixture.service->decompile(isolated);
    fixture.host->set_mode(fake_isolated_host_t::mode_t::execute);
    const auto after_rejection_cache = fixture.cache->snapshot();
    require(rejected.status == decompiler_pipeline_status_t::provider_failed,
        "isolated document attestation mismatch was accepted");
    require(after_rejection_cache.provider_ir.stores == before_cache.provider_ir.stores &&
            after_rejection_cache.normalized_hir_ast.stores ==
                before_cache.normalized_hir_ast.stores &&
            after_rejection_cache.rendered_document.stores ==
                before_cache.rendered_document.stores,
        "failed isolated attestation persisted a cache stage");

    const auto retry = fixture.service->decompile(isolated);
    require(retry.succeeded() && !retry.cache_hit_stage.has_value() &&
            fixture.provider->invocations() == before_provider + 2 &&
            fixture.host->invocations() == before_host + 2,
        "failed isolated attestation poisoned the retry cache path");
}

void verify_determinism_and_generations(service_fixture_t& fixture)
{
    auto bypass = request("c03-determinism");
    bypass.cache_mode = decompiler_pipeline_cache_mode_t::bypass;
    const auto first = fixture.service->decompile(bypass);
    const auto second = fixture.service->decompile(bypass);
    require(first.succeeded() && second.succeeded() &&
            serialize_decompiler_document(first.rendered_stage->document) ==
                serialize_decompiler_document(second.rendered_stage->document) &&
            hash_decompiler_source_maps(first.rendered_stage->document.source_maps) ==
                hash_decompiler_source_maps(second.rendered_stage->document.source_maps),
        "decompiler service output or source maps are nondeterministic");

    const auto current = fixture.service->decompile(request("c03-stale-generation", 2));
    const auto stale = fixture.service->decompile(request("c03-stale-generation", 1));
    require(current.succeeded() &&
            stale.status == decompiler_pipeline_status_t::stale_generation,
        "decompiler service accepted a stale workspace generation");
}

void verify_concurrent_workspace_isolation(service_fixture_t& fixture)
{
    const auto first_request = request("c03-concurrent-a");
    const auto second_request = request("c03-concurrent-b");
    auto first_future = std::async(std::launch::async,
        [&fixture, first_request]() { return fixture.service->decompile(first_request); });
    auto second_future = std::async(std::launch::async,
        [&fixture, second_request]() { return fixture.service->decompile(second_request); });
    const auto first = first_future.get();
    const auto second = second_future.get();
    require(first.succeeded() && second.succeeded(),
        "concurrent workspace decompilation failed");
    require(!first.cache_hit_stage.has_value() && !second.cache_hit_stage.has_value(),
        "concurrent workspaces leaked a cache entry across workspace identity");

    const auto first_hit = fixture.service->decompile(first_request);
    const auto second_hit = fixture.service->decompile(second_request);
    require(first_hit.cache_hit_stage == decompiler_cache_stage_t::rendered_document &&
            second_hit.cache_hit_stage == decompiler_cache_stage_t::rendered_document,
        "concurrent workspaces did not retain isolated cache entries");
}

void verify_verdict_cache_equivalence(service_fixture_t& fixture)
{
    const auto base = request("c03-verdict-cache");
    const auto before_provider = fixture.provider->invocations();
    const auto before_host = fixture.host->invocations();
    const auto first = fixture.service->decompile(base);
    require(first.succeeded() && first.readability.has_value() &&
            !first.cache_hit_stage.has_value(),
        "verdict-cache fixture failed the miss-path decompile");
    const auto second = fixture.service->decompile(base);
    require(second.succeeded() &&
            second.cache_hit_stage == decompiler_cache_stage_t::rendered_document &&
            second.readability.has_value(),
        "verdict-cache fixture failed the hit-path decompile");
    require(fixture.provider->invocations() == before_provider + 1 &&
            fixture.host->invocations() == before_host + 1,
        "verdict hit invoked the provider again");
    require(second.readability->document_hash == first.readability->document_hash &&
            second.readability->ast_hash == first.readability->ast_hash &&
            second.readability->source_map_hash == first.readability->source_map_hash &&
            second.readability->ast_node_count == first.readability->ast_node_count &&
            second.readability->document_bytes == first.readability->document_bytes &&
            second.readability->source_mapped_bytes == first.readability->source_mapped_bytes &&
            second.readability->metrics.declaration_count == first.readability->metrics.declaration_count,
        "verdict hit returned a report that diverged from the full analysis");

    pseudocode_readability_request_t analysis_request;
    const auto reanalyzed = analyze_pseudocode_readability(
        first.rendered_stage->document.ast, first.rendered_stage->document, analysis_request);
    require(reanalyzed.succeeded() && reanalyzed.report.has_value(),
        "independent reanalysis of the cached document failed");
    require(reanalyzed.report->document_hash == first.readability->document_hash &&
            reanalyzed.report->ast_hash == first.readability->ast_hash &&
            reanalyzed.report->source_map_hash == first.readability->source_map_hash &&
            reanalyzed.report->ast_node_count == first.readability->ast_node_count &&
            reanalyzed.report->document_bytes == first.readability->document_bytes,
        "stored verdict diverged from an independent full analysis");

    auto mutated = first.rendered_stage->document;
    mutated.rendered_text.push_back(' ');
    const auto original_digest = serialize_decompiler_document_measured(
        first.rendered_stage->document).digest;
    const auto mutated_digest = serialize_decompiler_document_measured(mutated).digest;
    require(!(mutated_digest == original_digest),
        "one-byte document mutation did not change the verdict cache key digest");
}

void verify_nondeterminism_rejection()
{
    auto cache = decompiler_cache_t::create();
    require(static_cast<bool>(cache), "failed to create the nondeterminism cache fixture");
    const auto entity = native_entity();
    decompiler_pipeline_cache_key_t key;
    key.stage = decompiler_cache_stage_t::rendered_document;
    key.workspace_id = "c03-nondeterminism";
    key.workspace_generation = 1;
    key.analysis_revision = 11;
    key.entity = entity;
    key.provider = provider_identity(decompiler_provider_id_t::ghidra_native, "c03.fake.native");
    key.worker_protocol_hash = digest("c03-service-worker-protocol");
    key.language = native_language();
    key.loader_layout_hash = digest("c03-service-loader-layout");
    key.function_bytes_hash =
        std::get<native_decompiler_entity_identity_t>(entity.identity).function_bytes_hash;
    key.chunk_fingerprints.push_back({
        native_address(0x3000), native_address(0x3040), digest("c03-service-function-chunk")});
    key.metadata_revision = 13;
    key.type_graph_revision = 17;
    key.overlay_revision = 19;
    key.profile = default_decompiler_profile_policy().balanced;
    key.renderer = pseudocode_renderer_style_settings(pseudocode_renderer_style_profile_t::balanced);
    key.dependencies.push_back({
        "c03.fixture.provider", "1", digest("c03-service-provider-dependency")});
    require(validate_decompiler_pipeline_cache_key(key).valid(),
        "nondeterminism fixture cache key is invalid");
    require(static_cast<bool>(cache.value()->activate_workspace_generation(key.workspace_id, 1)),
        "nondeterminism fixture failed to activate the workspace generation");

    const auto rendered_value = [&](const std::string& text_seed) {
        typed_pseudocode_ast_node_t root;
        root.id = 1;
        root.kind = typed_pseudocode_ast_node_kind_t::function_definition;
        root.type_id = 1;
        root.child_ids = {2};
        root.stable_text = "fixture";
        root.coordinate = coordinate(key, decompiler_coordinate_layer_t::typed_ast);
        root.confidence = 100;
        root.provenance = decompiler_fact_provenance_t::provider_semantics;
        typed_pseudocode_ast_node_t body;
        body.id = 2;
        body.kind = typed_pseudocode_ast_node_kind_t::compound_statement;
        body.type_id = 1;
        body.child_ids = {3};
        body.coordinate = coordinate(key, decompiler_coordinate_layer_t::typed_ast);
        body.confidence = 100;
        body.provenance = decompiler_fact_provenance_t::provider_semantics;
        typed_pseudocode_ast_node_t statement;
        statement.id = 3;
        statement.kind = typed_pseudocode_ast_node_kind_t::return_statement;
        statement.type_id = 1;
        statement.child_ids = {4};
        statement.coordinate = coordinate(key, decompiler_coordinate_layer_t::typed_ast);
        statement.confidence = 100;
        statement.provenance = decompiler_fact_provenance_t::provider_semantics;
        typed_pseudocode_ast_node_t literal;
        literal.id = 4;
        literal.kind = typed_pseudocode_ast_node_kind_t::literal;
        literal.type_id = 1;
        literal.stable_text = "7";
        literal.coordinate = coordinate(key, decompiler_coordinate_layer_t::typed_ast);
        literal.confidence = 100;
        literal.provenance = decompiler_fact_provenance_t::provider_semantics;
        typed_pseudocode_ast_v2_t ast;
        ast.entity = entity;
        ast.hir_hash = digest("c03-nondeterminism-hir");
        ast.type_graph_hash = digest("c03-nondeterminism-types");
        ast.root_node_id = 1;
        ast.body_node_id = 2;
        ast.nodes = {std::move(root), std::move(body), std::move(statement), std::move(literal)};
        decompiler_document_t document;
        document.entity = entity;
        document.ast = ast;
        document.ast_hash = stable_serialization_hash(ast);
        document.type_graph_hash = ast.type_graph_hash;
        document.profile = key.profile.profile;
        document.renderer = key.renderer;
        document.rendered_text = "int fixture() { return " + text_seed + "; }";
        document.tokens.push_back({decompiler_document_token_kind_t::identifier,
            {0, static_cast<std::uint32_t>(document.rendered_text.size())}, 1});
        decompiler_document_source_map_t map;
        map.document_range = {0, static_cast<std::uint32_t>(document.rendered_text.size())};
        source_coordinate_t document_coordinate;
        document_coordinate.layer = decompiler_coordinate_layer_t::document;
        document_coordinate.workspace_generation = key.workspace_generation;
        document_coordinate.entity = entity;
        document_coordinate.document_range = map.document_range;
        map.coordinates.push_back(document_coordinate);
        document.source_maps.push_back(std::move(map));
        decompiler_rendered_cache_value_t value;
        value.document = std::move(document);
        return value;
    };

    const auto first = cache.value()->store_rendered(key, rendered_value("7"));
    require(static_cast<bool>(first), "nondeterminism fixture rejected the baseline store");
    const auto repeat = cache.value()->store_rendered(key, rendered_value("7"));
    require(static_cast<bool>(repeat),
        "nondeterminism fixture rejected an identical repeat store");
    const auto diverged = cache.value()->store_rendered(key, rendered_value("8"));
    require(!static_cast<bool>(diverged) &&
            diverged.error().code == workspace_error_code_t::integrity_failure,
        "preserialized-era cache accepted two differing artifacts under one key");

    decompiler_pipeline_cache_key_t second_key = key;
    second_key.workspace_id = "c03-nondeterminism-preserialized";
    require(static_cast<bool>(cache.value()->activate_workspace_generation(second_key.workspace_id, 1)),
        "nondeterminism fixture failed to activate the preserialized workspace generation");
    const auto second_value = rendered_value("7");
    decompiler_cache_component_blobs_t blobs;
    blobs.primary_blob = serialize_decompiler_document(second_value.document);
    const auto measured_digest = stable_serialization_hash(blobs.primary_blob);
    const auto preserialized = cache.value()->store_rendered_preserialized(
        second_key, second_value, std::move(blobs), measured_digest, std::nullopt);
    require(static_cast<bool>(preserialized),
        "preserialized store rejected the baseline artifact");
    const auto diverged_value = rendered_value("8");
    decompiler_cache_component_blobs_t diverged_blobs;
    diverged_blobs.primary_blob = serialize_decompiler_document(diverged_value.document);
    const auto diverged_digest = stable_serialization_hash(diverged_blobs.primary_blob);
    const auto preserialized_diverged = cache.value()->store_rendered_preserialized(
        second_key, diverged_value, std::move(diverged_blobs), diverged_digest, std::nullopt);
    require(!static_cast<bool>(preserialized_diverged) &&
            preserialized_diverged.error().code == workspace_error_code_t::integrity_failure,
        "preserialized store accepted two differing artifacts under one key");
}

struct persistent_fixture_t {
    std::shared_ptr<workspace_database_t> database;
    std::string database_path;
    std::string source_path;
    decompiler_pipeline_cache_key_t rendered_key;
    std::string canonical_key;
    decompiler_pipeline_request_t base_request;
    decompiler_pipeline_result_t first_result;
};

persistent_fixture_t persistent_fixture()
{
    persistent_fixture_t fixture;
    fixture.source_path = (std::filesystem::temp_directory_path() /
        ("aida-c03-prefetch-source-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + ".bin")).string();
    {
        std::ofstream source(fixture.source_path, std::ios::binary | std::ios::trunc);
        source << "AiDA c03 persistent prefetch fixture";
    }
    workspace_identity_input_t identity_input;
    identity_input.bin_name = "c03-prefetch.bin";
    identity_input.source_path = fixture.source_path;
    identity_input.content_hash = digest("c03-prefetch-content");
    identity_input.load_profile_hash = digest("c03-prefetch-profile");
    identity_input.target_kind = target_kind_t::static_file;
    identity_input.format = format_id_t::pe32_plus;
    identity_input.architecture = architecture_id_t::x86_64;
    identity_input.architecture_mode = architecture_mode_t::x86_64;
    identity_input.abi = abi_id_t::windows_x64;
    identity_input.endian = endian_t::little;
    identity_input.image_base = 0x140000000ULL;
    auto identity = make_workspace_identity(std::move(identity_input));
    require(static_cast<bool>(identity), "failed to create the prefetch workspace identity");
    workspace_database_options_t options;
    options.identity = identity.take_value();
    options.versions.engine_version = "c03-service-harness";
    options.versions.specification_version = "c03";
    options.versions.analysis_settings_hash = "c03-prefetch-settings";
    auto opened = workspace_database_t::open(std::move(options));
    require(static_cast<bool>(opened), "failed to open the prefetch workspace database");
    fixture.database = opened.take_value();
    fixture.database_path = fixture.database->path();

    auto registry = std::make_shared<decompiler_provider_registry_t>();
    auto provider = std::make_shared<fake_native_provider_t>(provider_identity(
        decompiler_provider_id_t::ghidra_native, "c03.fake.native"));
    require(static_cast<bool>(registry->register_provider(provider)),
        "failed to register the prefetch provider");
    auto cache = decompiler_cache_t::create();
    require(static_cast<bool>(cache), "failed to create the prefetch cache");
    auto host = std::make_shared<fake_isolated_host_t>();
    decompiler_pipeline_service_config_t config;
    config.isolated_provider_host = host;
    config.database = fixture.database;
    auto service = decompiler_pipeline_service_t::create(
        std::move(registry), cache.value(), {}, std::move(config));
    require(static_cast<bool>(service), "failed to create the prefetch service");

    fixture.base_request = request("c03-prefetch-workspace", 1);
    std::optional<decompiler_pipeline_cache_key_t> captured_provider_key;
    fixture.base_request.provider_context_factory =
        [&captured_provider_key](
            const decompiler_provider_request_t& provider_request,
            const cancellation_token_t&) {
            captured_provider_key = provider_request.cache_key;
            std::shared_ptr<const decompiler_provider_context_t> context =
                std::make_shared<fake_provider_context_t>();
            return workspace_result_t<std::shared_ptr<const decompiler_provider_context_t>>::success(
                std::move(context));
        };
    fixture.first_result = service.value()->decompile(fixture.base_request);
    require(fixture.first_result.succeeded() && fixture.first_result.rendered_stage &&
            captured_provider_key.has_value(),
        "prefetch fixture failed the initial decompile");
    require(provider->invocations() == 1, "prefetch fixture provider accounting drifted");
    fixture.base_request.provider_context_factory = {};

    fixture.rendered_key = *captured_provider_key;
    fixture.rendered_key.stage = decompiler_cache_stage_t::rendered_document;
    const auto pass_chain = decompiler_render_pass_chain(
        fixture.rendered_key.renderer.readability, fixture.rendered_key.renderer, nullptr);
    decompiler_dependency_version_t pass_dependency;
    pass_dependency.name = "aida.render.pass_chain";
    pass_dependency.version = "1";
    pass_dependency.content_hash = decompiler_render_pass_chain_hash(pass_chain);
    fixture.rendered_key.dependencies.push_back(std::move(pass_dependency));
    std::sort(fixture.rendered_key.dependencies.begin(),
        fixture.rendered_key.dependencies.end(),
        [](const decompiler_dependency_version_t& left,
           const decompiler_dependency_version_t& right) {
            return left.name < right.name;
        });
    require(validate_decompiler_pipeline_cache_key(fixture.rendered_key).valid(),
        "prefetch fixture reconstructed an invalid rendered key");
    fixture.canonical_key = serialize_decompiler_pipeline_cache_key(fixture.rendered_key);

    decompiler_pipeline_cache_v1_row_t row;
    const auto* key_begin = reinterpret_cast<const std::uint8_t*>(fixture.canonical_key.data());
    row.cache_key.assign(key_begin, key_begin + fixture.canonical_key.size());
    row.stage = static_cast<std::int64_t>(decompiler_cache_stage_t::rendered_document);
    row.workspace_id = fixture.base_request.workspace_id;
    row.generation = fixture.base_request.workspace_generation;
    row.analysis_revision = fixture.base_request.analysis_revision;
    row.overlay_revision = fixture.base_request.cache_identity.overlay_revision;
    row.function_rva = 0x3000;
    const auto serialized = serialize_decompiler_rendered_cache_value(
        *fixture.first_result.rendered_stage);
    row.value.assign(reinterpret_cast<const std::uint8_t*>(serialized.data()),
        reinterpret_cast<const std::uint8_t*>(serialized.data()) + serialized.size());
    auto ticket = fixture.database->store_pipeline_cache(std::move(row), {});
    require(ticket.accepted, "prefetch fixture row write was not accepted");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(30000);
    while (ticket.completion.wait_for(std::chrono::milliseconds(10)) !=
               std::future_status::ready &&
           std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    require(ticket.completion.wait_for(std::chrono::milliseconds(0)) ==
                std::future_status::ready,
        "prefetch fixture row write did not complete");
    require(static_cast<bool>(ticket.completion.get()),
        "prefetch fixture row write failed");
    return fixture;
}

void verify_persistent_prefetch_integration()
{
    auto fixture = persistent_fixture();

    auto make_service = [](std::shared_ptr<workspace_database_t> database,
                           std::shared_ptr<fake_native_provider_t>& provider_out,
                           std::shared_ptr<fake_isolated_host_t>& host_out) {
        auto registry = std::make_shared<decompiler_provider_registry_t>();
        provider_out = std::make_shared<fake_native_provider_t>(provider_identity(
            decompiler_provider_id_t::ghidra_native, "c03.fake.native"));
        require(static_cast<bool>(registry->register_provider(provider_out)),
            "failed to register the persistent-hit provider");
        auto cache = decompiler_cache_t::create();
        require(static_cast<bool>(cache), "failed to create the persistent-hit cache");
        host_out = std::make_shared<fake_isolated_host_t>();
        decompiler_pipeline_service_config_t config;
        config.isolated_provider_host = host_out;
        config.database = std::move(database);
        auto service = decompiler_pipeline_service_t::create(
            std::move(registry), cache.value(), {}, std::move(config));
        require(static_cast<bool>(service), "failed to create the persistent-hit service");
        return service.take_value();
    };

    std::shared_ptr<fake_native_provider_t> hit_provider;
    std::shared_ptr<fake_isolated_host_t> hit_host;
    auto hit_service = make_service(fixture.database, hit_provider, hit_host);
    hit_service->prefetch_persistent_rendered(
        fixture.base_request.workspace_id, fixture.base_request.workspace_generation,
        {fixture.rendered_key});
    const auto hydrated = hit_service->decompile(fixture.base_request);
    require(hydrated.succeeded() &&
            hydrated.cache_hit_stage == decompiler_cache_stage_t::rendered_document,
        "prefetch-then-decompile did not produce a persistent rendered hit");
    require(hit_provider->invocations() == 0 && hit_host->invocations() == 0,
        "persistent prefetched hit invoked the provider");
    require(hydrated.readability.has_value() &&
            hydrated.readability->document_hash == fixture.first_result.readability->document_hash,
        "persistent prefetched hit returned a divergent readability verdict");
    require(serialize_decompiler_document(hydrated.rendered_stage->document) ==
            serialize_decompiler_document(fixture.first_result.rendered_stage->document),
        "persistent prefetched hit returned a divergent document");

    std::shared_ptr<fake_native_provider_t> stale_provider;
    std::shared_ptr<fake_isolated_host_t> stale_host;
    auto stale_service = make_service(fixture.database, stale_provider, stale_host);
    stale_service->prefetch_persistent_rendered(
        fixture.base_request.workspace_id, fixture.base_request.workspace_generation,
        {fixture.rendered_key});
    auto stale_request = fixture.base_request;
    stale_request.workspace_generation = 2;
    const auto stale = stale_service->decompile(stale_request);
    require(stale.succeeded() && !stale.cache_hit_stage.has_value() &&
            stale_provider->invocations() == 1 && stale_host->invocations() == 1,
        "stale-generation prefetch hydrated a rendered row");

    hit_service->request_stop();
    stale_service->request_stop();
    hit_service.reset();
    stale_service.reset();
    fixture.database.reset();
    std::error_code cleanup_error;
    std::filesystem::remove(std::filesystem::u8path(fixture.database_path), cleanup_error);
    std::filesystem::remove(std::filesystem::u8path(fixture.database_path + "-wal"), cleanup_error);
    std::filesystem::remove(std::filesystem::u8path(fixture.database_path + "-shm"), cleanup_error);
    std::filesystem::remove(std::filesystem::u8path(fixture.source_path), cleanup_error);
}

}

void run_decompiler_service_harness()
{
    verify_builtin_registry();
    verify_isolated_host_is_required();
    auto fixture = service_fixture();
    verify_cache_and_explicit_routing(fixture);
    verify_lazy_provider_context(fixture);
    verify_worker_failures(fixture);
    verify_attestation_cache_transaction(fixture);
    verify_determinism_and_generations(fixture);
    verify_concurrent_workspace_isolation(fixture);
    verify_verdict_cache_equivalence(fixture);
    verify_nondeterminism_rejection();
    verify_persistent_prefetch_integration();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_decompiler_service_harness();
        std::cout << "decompiler_service_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
