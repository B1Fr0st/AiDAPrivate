#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/flirt/static_recognition_service.hpp"
#include "../../src/core/analysis/flirt/type_seed_exporter.hpp"
#include "../../src/core/analysis/decompiler/api_prototype_table.hpp"
#include "../../src/core/analysis/decompiler/decompiler_service.hpp"

#include <atomic>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

void require(bool condition, const char* message)
{
    assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

sha256_digest_t digest(const std::string& value)
{
    return stable_serialization_hash(value);
}

address_t native_address(std::uint64_t value)
{
    return address_t{address_space_id_t::relative_virtual, value,
                     architecture_id_t::x86_64, architecture_mode_t::x86_64};
}

source_coordinate_t coordinate(const decompiler_entity_key_t& entity,
                               decompiler_coordinate_layer_t layer)
{
    source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = 1;
    result.entity = entity;
    result.address_range = decompiler_address_range_t{native_address(0x3000), native_address(0x3040)};
    result.instruction_range = decompiler_instruction_range_t{1, 8};
    return result;
}

decompiler_entity_key_t native_entity(std::uint64_t function_id)
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = function_id;
    identity.entry = native_address(0x3000);
    identity.end = native_address(0x3040);
    identity.function_bytes_hash = digest("srec-seed-function-" + std::to_string(function_id));
    identity.canonical_symbol = "seed_fixture";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::native_function;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.identity = std::move(identity);
    return result;
}

decompiler_language_identity_t native_language()
{
    decompiler_language_identity_t result;
    result.language_id = "x86:LE:64:default";
    result.language_version = "10.0";
    result.compiler_spec_id = "default";
    result.language_spec_hash = digest("srec-language");
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_provider_identity_t provider_identity(std::string suffix)
{
    decompiler_provider_identity_t result;
    result.provider = decompiler_provider_id_t::ghidra_native;
    result.provider_name = "c03.srec.fake.native";
    result.provider_version = "1";
    result.provider_binary_hash = digest("srec-provider-" + suffix);
    result.worker_build_id = "c03";
    result.worker_build_hash = digest("srec-worker-" + suffix);
    return result;
}

const decompiler_type_node_t* node_by_canonical(const type_graph_t& graph,
                                                const std::string& canonical)
{
    for (const auto& node : graph.nodes)
        if (node.canonical_name == canonical)
            return &node;
    return nullptr;
}

void verify_seed_batches_merge()
{
    static_recognition::recognition_records_t records;
    records.generation = 7;
    records.status = static_recognition::k_status_complete;
    {
        re::rtti::static_rtti_type_t widget;
        widget.name = "Widget";
        widget.decorated_name = ".?AVWidget@@";
        widget.type_descriptor_rva = 0x2100;
        widget.col_rva = 0x2200;
        widget.vtable_rvas = {0x2308};
        widget.score = 100;
        records.rtti.types.push_back(std::move(widget));
        re::rtti::static_rtti_type_t gadget;
        gadget.name = "Gadget";
        gadget.decorated_name = ".?AVGadget@@";
        gadget.type_descriptor_rva = 0x2140;
        gadget.col_rva = 0x2220;
        gadget.score = 90;
        re::rtti::base_class_record_t base;
        base.name = "Widget";
        base.decorated_name = ".?AVWidget@@";
        base.type_descriptor_va = 0x2100;
        gadget.bases.push_back(std::move(base));
        records.rtti.types.push_back(std::move(gadget));
        records.rtti.status = re::rtti::k_static_rtti_completed;
    }
    {
        flirt::flirt_match_t match;
        match.rva = 0x1010;
        match.name = "malloc";
        match.tier = flirt::k_flirt_tier_exact_crc;
        match.confidence = 200;
        match.db_entry = 0;
        records.flirt.push_back(match);
        const auto prototype = api_prototypes::find("ucrtbase", "malloc");
        require(prototype.has_value(), "api table must resolve malloc for the seed harness");
        static_recognition::prototype_out_t out;
        out.rva = match.rva;
        out.name = match.name;
        out.prototype_text = std::string(prototype->signature);
        out.is_noreturn = prototype->is_noreturn;
        out.confidence = match.confidence;
        records.prototypes.push_back(std::move(out));
    }
    {
        re::vmt::static_vfunc_slot_t slot;
        slot.vtable_rva = 0x2308;
        slot.slot_index = 0;
        slot.function_rva = 0x1010;
        slot.confidence = 200;
        records.vtables.slots.push_back(slot);
        records.vtables.status = re::vmt::k_static_vtables_completed;
        static_recognition::vtable_slot_out_t slot_out;
        slot_out.vtable_rva = 0x2308;
        slot_out.slot_index = 0;
        slot_out.function_rva = 0x1010;
        slot_out.class_name = "Widget";
        slot_out.method_name = "Widget::method_0";
        slot_out.confidence = 200;
        records.vtable_slots.push_back(std::move(slot_out));
    }

    const auto entity = native_entity(901);
    static_recognition::type_seed_export_options_t options;
    options.min_confidence = 70;
    auto batches = static_recognition::make_recognition_seed_batches(records, entity, 7, options);
    require(batches.has_value(), "seed batch export failed");
    require(batches.value().size() == 2, "seed export must produce rtti + prototype batches");
    bool found_rtti_batch = false;
    bool found_prototype_batch = false;
    for (const auto& batch : batches.value()) {
        if (batch.source == decompiler_fact_provenance_t::rtti &&
            batch.source_label == "static_rtti_types") {
            found_rtti_batch = true;
            require(batch.candidates.size() == 2, "rtti batch must carry both classes");
        }
        if (batch.source == decompiler_fact_provenance_t::call_signature &&
            batch.source_label == "flirt_crt_prototypes") {
            found_prototype_batch = true;
            require(batch.candidates.size() == 1, "prototype batch must carry malloc");
        }
    }
    require(found_rtti_batch && found_prototype_batch, "seed batches are incomplete");

    type_graph_t provider_graph;
    provider_graph.entity = entity;
    provider_graph.revision = 17;
    decompiler_type_node_t integer;
    integer.id = 1;
    integer.kind = decompiler_type_kind_t::signed_integer;
    integer.canonical_name = "long long";
    integer.display_name = "long long";
    integer.byte_size = 8;
    integer.alignment = 8;
    integer.is_signed = true;
    integer.confidence = 100;
    integer.provenance = decompiler_fact_provenance_t::provider_semantics;
    decompiler_type_node_t widget_node;
    widget_node.id = 2;
    widget_node.kind = decompiler_type_kind_t::class_type;
    widget_node.canonical_name = "class Widget";
    widget_node.display_name = "Widget";
    widget_node.confidence = 40;
    widget_node.provenance = decompiler_fact_provenance_t::provider_semantics;
    decompiler_type_node_t pointer;
    pointer.id = 3;
    pointer.kind = decompiler_type_kind_t::pointer;
    pointer.canonical_name = "class Widget*";
    pointer.display_name = "Widget*";
    pointer.byte_size = 8;
    pointer.confidence = 40;
    pointer.provenance = decompiler_fact_provenance_t::provider_semantics;
    provider_graph.nodes.push_back(std::move(integer));
    provider_graph.nodes.push_back(std::move(widget_node));
    provider_graph.nodes.push_back(std::move(pointer));
    decompiler_type_edge_t pointee;
    pointee.source_type_id = 3;
    pointee.target_type_id = 2;
    pointee.kind = decompiler_type_edge_kind_t::pointee;
    pointee.stable_name = "pointee";
    pointee.ordinal = 1;
    pointee.confidence = 40;
    pointee.provenance = decompiler_fact_provenance_t::provider_semantics;
    provider_graph.edges.push_back(std::move(pointee));

    hir_function_t stub_hir;
    stub_hir.entity = entity;
    stub_hir.type_graph_revision = 17;
    stub_hir.return_type_id = 3;
    hir_value_t returned;
    returned.id = 1;
    returned.kind = hir_node_kind_t::return_value;
    returned.type_id = 3;
    returned.stable_value = "0";
    returned.coordinate = coordinate(entity, decompiler_coordinate_layer_t::hir);
    returned.confidence = 100;
    returned.provenance = decompiler_fact_provenance_t::provider_semantics;
    hir_block_t stub_block;
    stub_block.id = 1;
    stub_block.coordinate = coordinate(entity, decompiler_coordinate_layer_t::hir);
    stub_block.values.push_back(std::move(returned));
    stub_hir.blocks.push_back(std::move(stub_block));

    auto merged = type_graph::merge_type_evidence(
        provider_graph, batches.value(), stub_hir);
    require(merged.has_value(), "merge_type_evidence rejected the recognition seed batches");
    const auto& graph = merged.value();
    const auto* widget = node_by_canonical(graph, "class Widget");
    const auto* gadget = node_by_canonical(graph, "class Gadget");
    require(widget && gadget, "merged graph must contain both class canonical names");
    require(gadget->provenance == decompiler_fact_provenance_t::rtti,
            "merged class must carry rtti provenance");
    const auto prototype_text = std::string(api_prototypes::find("ucrtbase", "malloc")->signature);
    const auto* malloc_node = node_by_canonical(graph, prototype_text);
    require(malloc_node, "merged graph must contain the CRT function-type candidate");
    require(malloc_node->kind == decompiler_type_kind_t::function &&
            malloc_node->provenance == decompiler_fact_provenance_t::call_signature,
            "CRT function-type candidate must carry call_signature provenance");
    require(validate_type_graph(graph).valid(), "merged type graph must validate");

    static_recognition::type_seed_export_options_t strict;
    strict.min_confidence = 210;
    auto filtered = static_recognition::make_recognition_seed_batches(records, entity, 7, strict);
    require(filtered.has_value(), "strict seed batch export failed");
    for (const auto& batch : filtered.value())
        for (const auto& candidate : batch.candidates)
            require(candidate.confidence >= 210, "min_confidence filtering violated");
}

hir_value_t hir_param(std::uint64_t id, std::uint64_t type_id, const decompiler_entity_key_t& entity)
{
    hir_value_t value;
    value.id = id;
    value.kind = hir_node_kind_t::parameter;
    value.type_id = type_id;
    value.coordinate = coordinate(entity, decompiler_coordinate_layer_t::hir);
    value.confidence = 100;
    value.provenance = decompiler_fact_provenance_t::provider_semantics;
    return value;
}

hir_value_t hir_literal(std::uint64_t id, std::uint64_t type_id, std::string text,
                        const decompiler_entity_key_t& entity)
{
    hir_value_t value;
    value.id = id;
    value.kind = hir_node_kind_t::literal;
    value.type_id = type_id;
    value.stable_value = std::move(text);
    value.coordinate = coordinate(entity, decompiler_coordinate_layer_t::hir);
    value.confidence = 100;
    value.provenance = decompiler_fact_provenance_t::provider_semantics;
    return value;
}

hir_value_t hir_binary(std::uint64_t id, std::uint64_t type_id, std::string op,
                       std::uint64_t lhs, std::uint64_t rhs, const decompiler_entity_key_t& entity)
{
    hir_value_t value;
    value.id = id;
    value.kind = hir_node_kind_t::binary;
    value.type_id = type_id;
    value.operand_ids = {lhs, rhs};
    value.stable_value = std::move(op);
    value.coordinate = coordinate(entity, decompiler_coordinate_layer_t::hir);
    value.confidence = 100;
    value.provenance = decompiler_fact_provenance_t::provider_semantics;
    return value;
}

hir_value_t hir_conditional(std::uint64_t id, std::uint64_t type_id, std::uint64_t condition,
                            const decompiler_entity_key_t& entity)
{
    hir_value_t value;
    value.id = id;
    value.kind = hir_node_kind_t::conditional;
    value.type_id = type_id;
    value.operand_ids = {condition};
    value.coordinate = coordinate(entity, decompiler_coordinate_layer_t::hir);
    value.confidence = 100;
    value.provenance = decompiler_fact_provenance_t::provider_semantics;
    return value;
}

hir_value_t hir_return(std::uint64_t id, std::uint64_t type_id, std::uint64_t operand,
                       const decompiler_entity_key_t& entity)
{
    hir_value_t value;
    value.id = id;
    value.kind = hir_node_kind_t::return_value;
    value.type_id = type_id;
    value.operand_ids = {operand};
    value.stable_value = "0";
    value.coordinate = coordinate(entity, decompiler_coordinate_layer_t::hir);
    value.confidence = 100;
    value.provenance = decompiler_fact_provenance_t::provider_semantics;
    return value;
}

enum class semantic_fixture_kind_t : std::uint8_t {
    unsatisfiable_and,
    tautology,
    opaque_predicate
};

class semantic_fixture_provider_t final : public decompiler_provider_t {
public:
    explicit semantic_fixture_provider_t(decompiler_provider_identity_t identity,
                                         semantic_fixture_kind_t fixture)
        : fixture_(fixture)
    {
        descriptor_.registration_id = "c03.srec.semantic.native";
        descriptor_.identity = std::move(identity);
        descriptor_.entity_kind = decompiler_entity_kind_t::native_function;
        descriptor_.profiles = {
            decompiler_profile_id_t::fast,
            decompiler_profile_id_t::balanced,
            decompiler_profile_id_t::thorough};
        descriptor_.priority = 1000;
        descriptor_.isolated = true;
    }

    decompiler_provider_descriptor_t descriptor() const override { return descriptor_; }

    bool supports_language(const decompiler_language_identity_t& language) const noexcept override
    {
        return language.language_id == "x86:LE:64:default" &&
               language.architecture == architecture_id_t::x86_64 &&
               language.mode == architecture_mode_t::x86_64;
    }

    decompiler_provider_result_t decompile(const decompiler_provider_request_t& request,
                                           const cancellation_token_t&) override
    {
        decompiler_provider_result_t result;
        type_graph_t types;
        types.entity = request.cache_key.entity;
        types.revision = request.cache_key.type_graph_revision;
        decompiler_type_node_t integer;
        integer.id = 1;
        integer.kind = decompiler_type_kind_t::signed_integer;
        integer.canonical_name = "long long";
        integer.display_name = "long long";
        integer.byte_size = 8;
        integer.alignment = 8;
        integer.is_signed = true;
        integer.confidence = 100;
        integer.provenance = decompiler_fact_provenance_t::provider_semantics;
        types.nodes.push_back(std::move(integer));

        const auto& entity = request.cache_key.entity;
        std::vector<hir_value_t> values;
        switch (fixture_) {
        case semantic_fixture_kind_t::unsatisfiable_and:
            values = {
                hir_param(1, 1, entity),
                hir_literal(2, 1, "1", entity),
                hir_binary(3, 1, "&", 1, 2, entity),
                hir_literal(4, 1, "2", entity),
                hir_binary(5, 1, "==", 3, 4, entity),
                hir_conditional(6, 1, 5, entity),
                hir_return(7, 1, 5, entity)};
            break;
        case semantic_fixture_kind_t::tautology:
            values = {
                hir_param(1, 1, entity),
                hir_binary(2, 1, "==", 1, 1, entity),
                hir_conditional(3, 1, 2, entity),
                hir_return(4, 1, 2, entity)};
            break;
        case semantic_fixture_kind_t::opaque_predicate:
            values = {
                hir_param(1, 1, entity),
                hir_literal(2, 1, "1", entity),
                hir_binary(3, 1, "+", 1, 2, entity),
                hir_binary(4, 1, "*", 1, 3, entity),
                hir_binary(5, 1, "&", 4, 2, entity),
                hir_literal(6, 1, "1", entity),
                hir_binary(7, 1, "==", 5, 6, entity),
                hir_conditional(8, 1, 7, entity),
                hir_return(9, 1, 7, entity)};
            break;
        }

        provider_ir_block_t provider_block;
        provider_block.id = 1;
        provider_block.coordinate = coordinate(entity, decompiler_coordinate_layer_t::provider_ir);
        std::vector<provider_ir_value_t> provider_values;
        std::uint64_t ordinal = 0;
        for (const auto& value : values) {
            provider_ir_value_t provider_value;
            provider_value.id = value.id;
            provider_value.type_id = value.type_id;
            provider_value.operand_ids = value.operand_ids;
            provider_value.coordinate = coordinate(entity, decompiler_coordinate_layer_t::provider_ir);
            provider_value.confidence = 100;
            provider_value.provenance = decompiler_fact_provenance_t::provider_semantics;
            switch (value.kind) {
            case hir_node_kind_t::parameter:
                provider_value.opcode = provider_ir_opcode_t::parameter;
                provider_value.stable_symbol = "x" + std::to_string(++ordinal);
                break;
            case hir_node_kind_t::literal:
                provider_value.opcode = provider_ir_opcode_t::constant;
                provider_value.stable_immediate = value.stable_value;
                break;
            case hir_node_kind_t::binary:
                provider_value.opcode = provider_ir_opcode_t::binary;
                provider_value.stable_immediate = value.stable_value;
                break;
            case hir_node_kind_t::conditional:
                provider_value.opcode = provider_ir_opcode_t::conditional_branch;
                break;
            default:
                provider_value.opcode = provider_ir_opcode_t::return_value;
                break;
            }
            provider_values.push_back(std::move(provider_value));
        }
        provider_block.values = std::move(provider_values);
        provider_ir_t provider_ir;
        provider_ir.provider = descriptor_.identity;
        provider_ir.language = request.cache_key.language;
        provider_ir.entity = entity;
        provider_ir.entry_block_id = 1;
        provider_ir.blocks.push_back(std::move(provider_block));

        hir_block_t block;
        block.id = 1;
        block.coordinate = coordinate(entity, decompiler_coordinate_layer_t::hir);
        for (auto& value : values)
            block.values.push_back(value);
        hir_function_t hir;
        hir.entity = entity;
        hir.provider_ir_hash = stable_serialization_hash(provider_ir);
        hir.type_graph_revision = request.cache_key.type_graph_revision;
        hir.return_type_id = 1;
        hir.blocks.push_back(std::move(block));

        decompiler_provider_artifacts_t artifacts;
        artifacts.provider_ir = std::move(provider_ir);
        artifacts.hir = std::move(hir);
        artifacts.type_graph = std::move(types);
        artifacts.return_type_id = 1;
        result.artifacts = std::move(artifacts);
        result.status = decompiler_provider_execution_status_t::completed;
        return result;
    }

private:
    decompiler_provider_descriptor_t descriptor_;
    semantic_fixture_kind_t fixture_;
};

class passthrough_isolated_host_t final : public decompiler_isolated_provider_host_t {
public:
    bool supports(const decompiler_provider_descriptor_t& descriptor) const noexcept override
    {
        return descriptor.registration_id == "c03.srec.semantic.native" && descriptor.isolated;
    }

    decompiler_provider_result_t execute(const decompiler_provider_route_t& route,
                                         const decompiler_provider_request_t& request,
                                         const cancellation_token_t& cancel) override
    {
        auto result = route.provider->decompile(request, cancel);
        if (!result.succeeded() || !result.artifacts->hir)
            return result;
        const auto ast = build_typed_ast_v2(*result.artifacts->hir, result.artifacts->type_graph);
        if (!ast.succeeded() || !ast.ast) {
            result.status = decompiler_provider_execution_status_t::failed;
            result.diagnostics.insert(result.diagnostics.end(),
                ast.diagnostics.begin(), ast.diagnostics.end());
            return result;
        }
        pseudocode_renderer_v2_request_t render_request;
        render_request.profile = request.cache_key.profile.profile;
        render_request.settings = request.cache_key.renderer;
        auto rendered = render_pseudocode_v2(*ast.ast, result.artifacts->type_graph, render_request);
        if (!rendered.succeeded() || !rendered.document) {
            result.status = decompiler_provider_execution_status_t::failed;
            result.diagnostics.insert(result.diagnostics.end(),
                rendered.diagnostics.begin(), rendered.diagnostics.end());
            return result;
        }
        result.attested_document = std::move(*rendered.document);
        result.authenticated_artifacts = true;
        return result;
    }
};

decompiler_pipeline_result_t run_semantic_fixture(semantic_fixture_kind_t fixture,
                                                  std::uint64_t function_id)
{
    auto registry = std::make_shared<decompiler_provider_registry_t>();
    auto provider = std::make_shared<semantic_fixture_provider_t>(
        provider_identity(std::to_string(function_id)), fixture);
    require(static_cast<bool>(registry->register_provider(provider)),
            "failed to register the semantic fixture provider");
    auto cache = decompiler_cache_v9_t::create();
    require(static_cast<bool>(cache), "failed to create the semantic fixture cache");
    decompiler_pipeline_service_config_t config;
    config.isolated_provider_host = std::make_shared<passthrough_isolated_host_t>();
    auto service = decompiler_pipeline_service_t::create(
        std::move(registry), cache.value(), {}, std::move(config));
    require(static_cast<bool>(service), "failed to create the semantic fixture service");

    decompiler_pipeline_request_t request;
    request.invocation = decompiler_pipeline_invocation_t::explicit_ui;
    request.workspace_id = "c03-srec-semantic-" + std::to_string(function_id);
    request.workspace_generation = 1;
    request.analysis_revision = 11;
    request.entity = native_entity(function_id);
    request.language = native_language();
    request.profile = decompiler_profile_id_t::thorough;
    request.provider_registration_id = "c03.srec.semantic.native";
    request.cache_identity.worker_protocol_hash = digest("srec-worker-protocol");
    request.cache_identity.loader_layout_hash = digest("srec-loader-layout");
    request.cache_identity.function_bytes_hash =
        std::get<native_decompiler_entity_identity_t>(request.entity.identity).function_bytes_hash;
    request.cache_identity.metadata_revision = 13;
    request.cache_identity.type_graph_revision = 17;
    request.cache_identity.overlay_revision = 19;
    return service.value()->decompile(request);
}

std::size_t count_branch_facts(const decompiler_pipeline_result_t& result,
                               const std::string& expected_key)
{
    if (!result.normalized_stage)
        return 0;
    std::size_t count = 0;
    for (const auto& fact : result.normalized_stage->semantic_facts) {
        if (fact.provenance != decompiler_fact_provenance_t::semantic_proof)
            continue;
        if (fact.refinement_key == expected_key)
            ++count;
    }
    return count;
}

void verify_semantic_branch_proofs()
{
    {
        const auto result = run_semantic_fixture(semantic_fixture_kind_t::unsatisfiable_and, 951);
        require(result.succeeded(), "unsatisfiable-condition fixture did not decompile");
        require(result.semantic_proof_availability == decompiler_semantic_proof_availability_t::ready,
                "semantic adapter must be ready on this build");
        require(count_branch_facts(result, "branch_cond_eq0.v6") == 1,
                "unsatisfiable condition must prove exactly one branch_cond_eq0 fact");
    }
    {
        const auto result = run_semantic_fixture(semantic_fixture_kind_t::opaque_predicate, 952);
        require(result.succeeded(), "opaque-predicate fixture did not decompile");
        require(count_branch_facts(result, "branch_cond_eq0.v8") == 1,
                "opaque predicate must prove exactly one branch_cond_eq0 fact");
    }
    {
        const auto result = run_semantic_fixture(semantic_fixture_kind_t::tautology, 953);
        require(result.succeeded(), "tautology fixture did not decompile");
        require(result.normalized_stage &&
                result.normalized_stage->semantic_facts.empty(),
                "tautology control must produce zero semantic facts");
    }
}

}

void run_type_seed_exporter_harness()
{
    verify_seed_batches_merge();
    verify_semantic_branch_proofs();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_type_seed_exporter_harness();
        std::cout << "type_seed_exporter_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
