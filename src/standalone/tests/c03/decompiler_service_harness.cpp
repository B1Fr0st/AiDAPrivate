#include "decompiler_service_harness.hpp"

#include "../../src/core/analysis/decompiler/decompiler_service.hpp"
#include "../../src/core/analysis/decompiler/legacy_document_adapter.hpp"

#include <atomic>
#include <cstdint>
#include <exception>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace aida::analysis::c03_test {
namespace {

void require(const bool condition, const char* message)
{
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
        const auto ast = build_typed_ast_v2(
            *result.artifacts->hir, result.artifacts->type_graph);
        if (!ast.succeeded() || !ast.ast) {
            result.status = decompiler_provider_execution_status_t::failed;
            result.diagnostics.insert(result.diagnostics.end(),
                ast.diagnostics.begin(), ast.diagnostics.end());
            return result;
        }
        pseudocode_renderer_v2_request_t render_request;
        render_request.profile = request.cache_key.profile.profile;
        render_request.settings = request.cache_key.renderer;
        auto rendered = render_pseudocode_v2(
            *ast.ast, result.artifacts->type_graph, render_request);
        if (!rendered.succeeded() || !rendered.document) {
            result.status = decompiler_provider_execution_status_t::failed;
            result.diagnostics.insert(result.diagnostics.end(),
                rendered.diagnostics.begin(), rendered.diagnostics.end());
            return result;
        }
        result.attested_document = std::move(*rendered.document);
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
    std::shared_ptr<decompiler_cache_v9_t> cache;
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
    auto cache = decompiler_cache_v9_t::create();
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
    auto cache = decompiler_cache_v9_t::create();
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
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_decompiler_service_harness();
        std::cout << "decompiler_service_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
