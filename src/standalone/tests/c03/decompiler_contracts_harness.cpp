#include "decompiler_contracts_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"
#include "../../src/core/analysis/decompiler/decompiler_contracts.hpp"
#include "../../src/core/analysis/decompiler/type_graph_builder.hpp"
#include "../../src/core/analysis/decompiler/typed_ast.hpp"
#include "../../src/core/crypto/sha256_cng.hpp"
#include "../../workers/native_decompiler/native_worker_runtime.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

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

address_t address(std::uint64_t value)
{
    address_t result;
    result.space = address_space_id_t::relative_virtual;
    result.value = value;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_entity_key_t native_entity()
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = 42;
    identity.entry = address(0x1000);
    identity.end = address(0x1010);
    identity.function_bytes_hash = digest("native-function");
    identity.canonical_symbol = "fixture::native";
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
    identity.module_hash = digest("cli-module");
    identity.assembly_identity = "Fixture, Version=1.0.0.0";
    identity.module_name = "Fixture.dll";
    identity.metadata_token = 0x06000001U;
    identity.declaring_type = "Fixture.Program";
    identity.method_name = "Main";
    identity.method_signature = "void()";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::cli_method;
    result.format = format_id_t::pe32_plus;
    result.identity = std::move(identity);
    return result;
}

decompiler_entity_key_t jvm_entity()
{
    jvm_decompiler_entity_identity_t identity;
    identity.class_artifact_hash = digest("jvm-class");
    identity.class_internal_name = "fixture/Program";
    identity.method_name = "run";
    identity.method_descriptor = "()V";
    identity.method_index = 1;
    identity.code_offset = 12;
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
    identity.dex_hash = digest("dalvik-dex");
    identity.dex_ordinal = 1;
    identity.class_descriptor = "Lfixture/Program;";
    identity.method_name = "run";
    identity.prototype = "()V";
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

source_coordinate_t coordinate(const decompiler_entity_key_t& entity, decompiler_coordinate_layer_t layer)
{
    source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = 7;
    result.entity = entity;
    result.address_range = decompiler_address_range_t{address(0x1000), address(0x1004)};
    result.instruction_range = decompiler_instruction_range_t{101, 102};
    return result;
}

source_coordinate_t document_coordinate(const decompiler_entity_key_t& entity, std::uint32_t end)
{
    auto result = coordinate(entity, decompiler_coordinate_layer_t::document);
    result.document_range = decompiler_token_range_t{0, end};
    return result;
}

decompiler_provider_identity_t provider()
{
    decompiler_provider_identity_t result;
    result.provider = decompiler_provider_id_t::ghidra_native;
    result.provider_name = "ghidra";
    result.provider_version = "11.3.0";
    result.provider_binary_hash = digest("ghidra-worker");
    result.worker_build_id = "fixture-worker";
    result.worker_build_hash = digest("fixture-worker-build");
    return result;
}

decompiler_language_identity_t language()
{
    decompiler_language_identity_t result;
    result.language_id = "x86:LE:64:default";
    result.language_version = "11.3";
    result.compiler_spec_id = "windows";
    result.language_spec_hash = digest("language-spec");
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_unknown_t unknown(const decompiler_entity_key_t& entity)
{
    decompiler_unknown_t result;
    result.reason = decompiler_unknown_reason_t::unresolved_reference;
    result.stable_token = "unknown_call_target";
    result.coordinate = coordinate(entity, decompiler_coordinate_layer_t::typed_ast);
    result.confidence = 35;
    result.provenance = decompiler_fact_provenance_t::provider_semantics;
    return result;
}

decompiler_profile_budget_t profile(decompiler_profile_id_t profile_id = decompiler_profile_id_t::balanced)
{
    decompiler_profile_budget_t result;
    result.profile = profile_id;
    result.max_wall_clock_ms = 5000;
    result.max_cpu_ms = 4000;
    result.max_memory_bytes = 256ULL << 20;
    result.max_provider_ir_nodes = 100000;
    result.max_hir_nodes = 100000;
    result.max_ast_nodes = 100000;
    if (profile_id == decompiler_profile_id_t::thorough) {
        result.max_semantic_queries = 1;
        result.semantic_proofs_enabled = true;
    }
    return result;
}

decompiler_diagnostic_t diagnostic(const decompiler_entity_key_t& entity, decompiler_coordinate_layer_t layer)
{
    decompiler_diagnostic_t result;
    result.severity = decompiler_diagnostic_severity_t::error;
    result.code = decompiler_diagnostic_code_t::provider_failure;
    result.localization_key = "decompiler.fixture.failure";
    result.coordinate = coordinate(entity, layer);
    result.confidence = 100;
    result.ordinal = 1;
    return result;
}

type_graph_t type_graph(const decompiler_entity_key_t& entity)
{
    decompiler_type_node_t unknown_type;
    unknown_type.id = 1;
    unknown_type.kind = decompiler_type_kind_t::unknown;
    unknown_type.canonical_name = "unknown";
    unknown_type.display_name = "unknown";
    unknown_type.confidence = 0;
    unknown_type.provenance = decompiler_fact_provenance_t::unknown;
    type_graph_t result;
    result.entity = entity;
    result.revision = 11;
    result.nodes.push_back(std::move(unknown_type));
    result.unknowns.push_back(unknown(entity));
    result.diagnostics.push_back(diagnostic(entity, decompiler_coordinate_layer_t::provider_ir));
    return result;
}

provider_ir_t provider_ir(const decompiler_entity_key_t& entity)
{
    provider_ir_value_t value;
    value.id = 1;
    value.opcode = provider_ir_opcode_t::return_value;
    value.type_id = 1;
    value.stable_immediate = "0";
    value.coordinate = coordinate(entity, decompiler_coordinate_layer_t::provider_ir);
    value.confidence = 100;
    value.provenance = decompiler_fact_provenance_t::provider_semantics;
    provider_ir_block_t block;
    block.id = 1;
    block.values.push_back(std::move(value));
    block.coordinate = coordinate(entity, decompiler_coordinate_layer_t::provider_ir);
    provider_ir_t result;
    result.provider = provider();
    result.language = language();
    result.entity = entity;
    result.entry_block_id = 1;
    result.blocks.push_back(std::move(block));
    result.unknowns.push_back(unknown(entity));
    result.diagnostics.push_back(diagnostic(entity, decompiler_coordinate_layer_t::provider_ir));
    return result;
}

hir_function_t hir(const decompiler_entity_key_t& entity, const provider_ir_t& provider_value)
{
    hir_value_t value;
    value.id = 1;
    value.kind = hir_node_kind_t::return_value;
    value.type_id = 1;
    value.stable_value = "0";
    value.coordinate = coordinate(entity, decompiler_coordinate_layer_t::hir);
    value.confidence = 100;
    value.provenance = decompiler_fact_provenance_t::provider_semantics;
    hir_block_t block;
    block.id = 1;
    block.values.push_back(std::move(value));
    block.coordinate = coordinate(entity, decompiler_coordinate_layer_t::hir);
    hir_function_t result;
    result.entity = entity;
    result.provider_ir_hash = stable_serialization_hash(provider_value);
    result.type_graph_revision = 11;
    result.return_type_id = 1;
    result.blocks.push_back(std::move(block));
    result.unknowns.push_back(unknown(entity));
    result.diagnostics.push_back(diagnostic(entity, decompiler_coordinate_layer_t::hir));
    return result;
}

source_coordinate_t exception_coordinate(
    const decompiler_entity_key_t& entity,
    const decompiler_coordinate_layer_t layer,
    const std::uint64_t offset)
{
    auto result = coordinate(entity, layer);
    result.address_range = decompiler_address_range_t{
        address(0x1000 + offset * 0x10), address(0x1004 + offset * 0x10)};
    result.instruction_range = decompiler_instruction_range_t{
        100 + offset, 101 + offset};
    return result;
}

type_graph_t exception_type_graph(const decompiler_entity_key_t& entity)
{
    decompiler_type_node_t void_type;
    void_type.id = 1;
    void_type.kind = decompiler_type_kind_t::void_type;
    void_type.canonical_name = "void";
    void_type.display_name = "void";
    void_type.confidence = 100;
    void_type.provenance = decompiler_fact_provenance_t::provider_semantics;
    void_type.coordinates.push_back(exception_coordinate(entity,
        decompiler_coordinate_layer_t::hir, 0));
    type_graph_t result;
    result.entity = entity;
    result.revision = 23;
    result.nodes.push_back(std::move(void_type));
    return result;
}

hir_value_t exception_call(
    const decompiler_entity_key_t& entity,
    const std::uint64_t id,
    std::string value,
    const std::uint64_t block_offset)
{
    hir_value_t result;
    result.id = id;
    result.kind = hir_node_kind_t::call;
    result.type_id = 1;
    result.stable_value = std::move(value);
    result.coordinate = exception_coordinate(entity,
        decompiler_coordinate_layer_t::hir, block_offset);
    result.confidence = 100;
    result.provenance = decompiler_fact_provenance_t::bytecode_verifier;
    return result;
}

hir_value_t exception_return(
    const decompiler_entity_key_t& entity,
    const std::uint64_t id,
    const std::uint64_t block_offset)
{
    hir_value_t result;
    result.id = id;
    result.kind = hir_node_kind_t::return_value;
    result.type_id = 1;
    result.coordinate = exception_coordinate(entity,
        decompiler_coordinate_layer_t::hir, block_offset);
    result.confidence = 100;
    result.provenance = decompiler_fact_provenance_t::bytecode_verifier;
    return result;
}

hir_function_t exception_hir(
    const decompiler_entity_key_t& entity,
    const bool second_handler = false)
{
    hir_block_t protected_block;
    protected_block.id = 1;
    protected_block.successor_ids = {2};
    protected_block.exception_successor_ids = second_handler
        ? std::vector<std::uint64_t>{3, 4}
        : std::vector<std::uint64_t>{3};
    protected_block.values.push_back(exception_call(entity, 1,
        "may_throw", 1));
    protected_block.coordinate = exception_coordinate(entity,
        decompiler_coordinate_layer_t::hir, 1);

    hir_block_t continuation;
    continuation.id = 2;
    continuation.predecessor_ids = second_handler
        ? std::vector<std::uint64_t>{1, 3, 4}
        : std::vector<std::uint64_t>{1, 3};
    continuation.values.push_back(exception_return(entity, 2, 2));
    continuation.coordinate = exception_coordinate(entity,
        decompiler_coordinate_layer_t::hir, 2);

    hir_block_t handler;
    handler.id = 3;
    handler.predecessor_ids = {1};
    handler.successor_ids = {2};
    handler.values.push_back(exception_call(entity, 3,
        "recover_primary", 3));
    handler.coordinate = exception_coordinate(entity,
        decompiler_coordinate_layer_t::hir, 3);

    hir_function_t result;
    result.entity = entity;
    result.provider_ir_hash = digest("exception-provider-ir");
    result.type_graph_revision = 23;
    result.return_type_id = 1;
    result.blocks = {std::move(protected_block), std::move(continuation),
        std::move(handler)};
    if (second_handler) {
        hir_block_t alternate_handler;
        alternate_handler.id = 4;
        alternate_handler.predecessor_ids = {1};
        alternate_handler.successor_ids = {2};
        alternate_handler.values.push_back(exception_call(entity, 4,
            "recover_alternate", 4));
        alternate_handler.coordinate = exception_coordinate(entity,
            decompiler_coordinate_layer_t::hir, 4);
        result.blocks.push_back(std::move(alternate_handler));
    }
    return result;
}

const typed_pseudocode_ast_node_t* first_ast_node(
    const typed_pseudocode_ast_v2_t& ast_value,
    const typed_pseudocode_ast_node_kind_t kind)
{
    const auto found = std::find_if(ast_value.nodes.begin(), ast_value.nodes.end(),
        [kind](const typed_pseudocode_ast_node_t& node) {
            return node.kind == kind;
        });
    return found == ast_value.nodes.end() ? nullptr : &*found;
}

bool has_diagnostic(
    const typed_ast_build_result_t& result,
    const std::string& localization_key)
{
    return std::any_of(result.diagnostics.begin(), result.diagnostics.end(),
        [&localization_key](const decompiler_diagnostic_t& diagnostic_value) {
            return diagnostic_value.localization_key == localization_key;
        });
}

void verify_exception_ast_contract(const decompiler_entity_key_t& entity,
                                   const bool second_handler)
{
    const auto types = exception_type_graph(entity);
    const auto hir_value = exception_hir(entity, second_handler);
    const auto first = build_typed_ast(hir_value, types);
    const auto second = build_typed_ast(hir_value, types);
    require(first.succeeded() && second.succeeded(),
        "typed AST rejected a valid exception-only handler region");
    require(serialize_typed_ast(*first.ast) ==
            serialize_typed_ast(*second.ast) &&
        stable_serialization_hash(*first.ast) ==
            stable_serialization_hash(*second.ast),
        "typed AST exception structure was nondeterministic");
    const auto* try_node = first_ast_node(*first.ast,
        typed_pseudocode_ast_node_kind_t::try_statement);
    require(try_node != nullptr && try_node->child_ids.size() ==
            (second_handler ? 3U : 2U),
        "typed AST lost the try body or a handler");
    const auto catch_count = static_cast<std::size_t>(std::count_if(first.ast->nodes.begin(),
        first.ast->nodes.end(), [](const typed_pseudocode_ast_node_t& node) {
            return node.kind == typed_pseudocode_ast_node_kind_t::catch_clause &&
                node.stable_text == "unknown_exception";
        }));
    require(catch_count == (second_handler ? 2U : 1U),
        "typed AST did not preserve every explicit-unknown handler");
    const auto unknown_count = static_cast<std::size_t>(std::count_if(first.ast->unknowns.begin(),
        first.ast->unknowns.end(), [](const decompiler_unknown_t& value) {
            return value.reason == decompiler_unknown_reason_t::unresolved_reference &&
                value.stable_token.find("exception.handler_type.block_") == 0;
        }));
    require(unknown_count == (second_handler ? 2U : 1U),
        "typed AST did not preserve unresolved handler types explicitly");
    require(try_node->coordinate.layer ==
            decompiler_coordinate_layer_t::typed_ast &&
        try_node->coordinate.address_range.has_value() &&
        try_node->coordinate.address_range->begin.value == 0x1010,
        "typed AST try coordinate lost the protected-region anchor");
    const auto* catch_node = first_ast_node(*first.ast,
        typed_pseudocode_ast_node_kind_t::catch_clause);
    require(catch_node != nullptr && catch_node->coordinate.address_range.has_value() &&
            catch_node->coordinate.address_range->begin.value == 0x1030 &&
            catch_node->provenance ==
                decompiler_fact_provenance_t::bytecode_verifier,
        "typed AST catch lost the handler coordinate or provenance");
    require(validate_typed_ast_semantics(*first.ast, types).valid(),
        "typed AST exception structure failed semantic validation");
}

void verify_exception_ast_rejections()
{
    const auto entity = jvm_entity();
    const auto types = exception_type_graph(entity);

    auto asymmetric = exception_hir(entity);
    asymmetric.blocks[2].predecessor_ids.clear();
    const auto asymmetric_result = build_typed_ast(asymmetric, types);
    require(!asymmetric_result.succeeded() && has_diagnostic(asymmetric_result,
            "decompiler.ast.v2.asymmetric_predecessor"),
        "typed AST accepted an asymmetric exceptional predecessor");

    auto missing = exception_hir(entity);
    missing.blocks[0].exception_successor_ids = {99};
    const auto missing_result = build_typed_ast(missing, types);
    require(!missing_result.succeeded(),
        "typed AST accepted a missing exceptional target");

    auto ambiguous_edge = exception_hir(entity);
    ambiguous_edge.blocks[0].exception_successor_ids = {2, 3};
    const auto ambiguous_edge_result = build_typed_ast(ambiguous_edge, types);
    require(!ambiguous_edge_result.succeeded() &&
            has_diagnostic(ambiguous_edge_result,
                "decompiler.ast.v2.ambiguous_exception_edge"),
        "typed AST accepted one target as both normal and exceptional");

    auto overlap = exception_hir(entity);
    overlap.blocks[1].exception_successor_ids = {3, 4};
    overlap.blocks[2].predecessor_ids = {1, 2};
    hir_block_t overlap_handler;
    overlap_handler.id = 4;
    overlap_handler.predecessor_ids = {2};
    overlap_handler.values.push_back(exception_return(entity, 4, 4));
    overlap_handler.coordinate = exception_coordinate(entity,
        decompiler_coordinate_layer_t::hir, 4);
    overlap.blocks.push_back(std::move(overlap_handler));
    const auto overlap_result = build_typed_ast(overlap, types);
    require(!overlap_result.succeeded() && has_diagnostic(overlap_result,
            "decompiler.ast.v2.ambiguous_exception_overlap"),
        "typed AST accepted an ambiguous overlapping exception region");

    typed_ast_build_request_t bounded_request;
    bounded_request.limits.max_ast_nodes = 5;
    const auto bounded_result = build_typed_ast(exception_hir(entity),
        types, bounded_request);
    require(!bounded_result.succeeded() &&
            std::any_of(bounded_result.diagnostics.begin(),
                bounded_result.diagnostics.end(),
                [](const decompiler_diagnostic_t& value) {
                    return value.code == decompiler_diagnostic_code_t::resource_limit;
                }),
        "typed AST exception structuring ignored the AST node budget");
}

typed_pseudocode_ast_v2_t ast(const decompiler_entity_key_t& entity, const hir_function_t& hir_value, const type_graph_t& types)
{
    typed_pseudocode_ast_node_t root;
    root.id = 1;
    root.kind = typed_pseudocode_ast_node_kind_t::function_definition;
    root.type_id = 1;
    root.child_ids = {2};
    root.stable_text = "fixture";
    root.coordinate = coordinate(entity, decompiler_coordinate_layer_t::typed_ast);
    root.confidence = 100;
    root.provenance = decompiler_fact_provenance_t::provider_semantics;
    typed_pseudocode_ast_node_t body;
    body.id = 2;
    body.kind = typed_pseudocode_ast_node_kind_t::compound_statement;
    body.type_id = 1;
    body.child_ids = {3};
    body.coordinate = coordinate(entity, decompiler_coordinate_layer_t::typed_ast);
    body.confidence = 100;
    body.provenance = decompiler_fact_provenance_t::provider_semantics;
    typed_pseudocode_ast_node_t statement;
    statement.id = 3;
    statement.kind = typed_pseudocode_ast_node_kind_t::return_statement;
    statement.type_id = 1;
    statement.stable_text = "return 0";
    statement.coordinate = coordinate(entity, decompiler_coordinate_layer_t::typed_ast);
    statement.confidence = 100;
    statement.provenance = decompiler_fact_provenance_t::provider_semantics;
    typed_pseudocode_ast_v2_t result;
    result.entity = entity;
    result.hir_hash = stable_serialization_hash(hir_value);
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes = {std::move(root), std::move(body), std::move(statement)};
    result.unknowns.push_back(unknown(entity));
    result.diagnostics.push_back(diagnostic(entity, decompiler_coordinate_layer_t::typed_ast));
    return result;
}

decompiler_document_t document(const decompiler_entity_key_t& entity, const typed_pseudocode_ast_v2_t& ast_value)
{
    decompiler_document_t result;
    result.entity = entity;
    result.ast = ast_value;
    result.ast_hash = stable_serialization_hash(ast_value);
    result.type_graph_hash = ast_value.type_graph_hash;
    result.profile = decompiler_profile_id_t::balanced;
    result.renderer.style_id = "aida.c03";
    result.rendered_text = "unknown fixture() { return 0; }";
    result.tokens.push_back({decompiler_document_token_kind_t::identifier,
        {0, static_cast<std::uint32_t>(result.rendered_text.size())}, 1});
    decompiler_document_source_map_t map;
    map.document_range = {0, static_cast<std::uint32_t>(result.rendered_text.size())};
    map.coordinates.push_back(document_coordinate(entity, map.document_range.end));
    result.source_maps.push_back(std::move(map));
    result.unknowns.push_back(unknown(entity));
    result.diagnostics.push_back(diagnostic(entity, decompiler_coordinate_layer_t::document));
    return result;
}

decompiler_pipeline_cache_key_t cache_key(const decompiler_entity_key_t& entity)
{
    decompiler_pipeline_cache_key_t result;
    result.stage = decompiler_cache_stage_t::rendered_document;
    result.workspace_id = "c03-fixture";
    result.workspace_generation = 7;
    result.analysis_revision = 9;
    result.entity = entity;
    result.provider = provider();
    result.worker_protocol_hash = digest("protocol");
    result.language = language();
    result.loader_layout_hash = digest("layout");
    result.function_bytes_hash = digest("function-bytes");
    result.chunk_fingerprints.push_back({address(0x1000), address(0x1004), digest("chunk-1")});
    result.metadata_revision = 5;
    result.type_graph_revision = 11;
    result.overlay_revision = 3;
    result.profile = profile();
    result.renderer.style_id = "aida.c03";
    result.dependencies.push_back({"ghidra", "11.3.0", digest("ghidra-dependency")});
    result.dependencies.push_back({"renderer", "2", digest("renderer-dependency")});
    return result;
}

decompiler_diagnostic_t failure_diagnostic(const decompiler_entity_key_t& entity)
{
    return diagnostic(entity, decompiler_coordinate_layer_t::provider_ir);
}

void verify_entity_round_trip(const decompiler_entity_key_t& value)
{
    const auto bytes = serialize_decompiler_entity_key(value);
    const auto decoded = deserialize_decompiler_entity_key(bytes);
    require(decoded.valid(), "entity decode failed");
    require(*decoded.value == value, "entity round trip changed identity");
    require(stable_serialization_hash(value) == stable_serialization_hash(*decoded.value), "entity hash drifted");
}

void verify_profile_contract_rules()
{
    const auto fast = profile(decompiler_profile_id_t::fast);
    const auto balanced = profile(decompiler_profile_id_t::balanced);
    const auto thorough = profile(decompiler_profile_id_t::thorough);
    require(validate_decompiler_profile(fast).valid(), "fast profile contract rejected");
    require(validate_decompiler_profile(balanced).valid(), "balanced profile contract rejected");
    require(validate_decompiler_profile(thorough).valid(), "thorough profile contract rejected");

    auto fast_with_proofs = fast;
    fast_with_proofs.semantic_proofs_enabled = true;
    require(!validate_decompiler_profile(fast_with_proofs).valid(), "fast profile accepted semantic proofs");

    auto balanced_with_queries = balanced;
    balanced_with_queries.max_semantic_queries = 1;
    require(!validate_decompiler_profile(balanced_with_queries).valid(), "balanced profile accepted semantic queries");

    auto thorough_without_proofs = thorough;
    thorough_without_proofs.semantic_proofs_enabled = false;
    thorough_without_proofs.max_semantic_queries = 0;
    require(!validate_decompiler_profile(thorough_without_proofs).valid(), "thorough profile accepted missing proof budget");
}

void verify_cache_identity_dimensions(const decompiler_pipeline_cache_key_t& cache)
{
    const auto baseline_hash = stable_serialization_hash(cache);
    const auto require_distinct = [&cache, baseline_hash](auto&& mutate, const char* message) {
        auto changed = cache;
        mutate(changed);
        require(stable_serialization_hash(changed) != baseline_hash, message);
    };

    require_distinct([](auto& value) { value.stage = decompiler_cache_stage_t::provider_ir; }, "cache hash ignored stage");
    require_distinct([](auto& value) { ++value.workspace_generation; }, "cache hash ignored workspace generation");
    require_distinct([](auto& value) { ++value.analysis_revision; }, "cache hash ignored analysis revision");
    require_distinct([](auto& value) { value.provider.provider_version = "11.3.1"; }, "cache hash ignored provider identity");
    require_distinct([](auto& value) { value.worker_protocol_hash = digest("protocol-2"); }, "cache hash ignored worker protocol");
    require_distinct([](auto& value) { value.language.language_spec_hash = digest("language-spec-2"); }, "cache hash ignored language identity");
    require_distinct([](auto& value) { value.loader_layout_hash = digest("layout-2"); }, "cache hash ignored loader layout");
    require_distinct([](auto& value) { value.function_bytes_hash = digest("function-bytes-2"); }, "cache hash ignored function bytes");
    require_distinct([](auto& value) { value.chunk_fingerprints.front().bytes_hash = digest("chunk-2"); }, "cache hash ignored chunk fingerprint");
    require_distinct([](auto& value) { ++value.metadata_revision; }, "cache hash ignored metadata revision");
    require_distinct([](auto& value) { ++value.type_graph_revision; }, "cache hash ignored type graph revision");
    require_distinct([](auto& value) { ++value.overlay_revision; }, "cache hash ignored overlay revision");
    require_distinct([](auto& value) { value.profile = profile(decompiler_profile_id_t::fast); }, "cache hash ignored profile");
    require_distinct([](auto& value) { value.renderer.style_id = "aida.c03.alt"; }, "cache hash ignored renderer style");
    require_distinct([](auto& value) { value.dependencies.front().content_hash = digest("ghidra-dependency-2"); }, "cache hash ignored dependency version");

    require_distinct([](auto& value) { value.entity.kind = decompiler_entity_kind_t::cli_method; }, "cache hash ignored entity kind");
    require_distinct([](auto& value) {
        std::get<native_decompiler_entity_identity_t>(value.entity.identity).function_bytes_hash = digest("native-function-2");
    }, "cache hash ignored entity identity bytes");
    require_distinct([](auto& value) { value.entity.architecture = architecture_id_t::arm; }, "cache hash ignored entity architecture");

    require_distinct([](auto& value) { value.language.architecture = architecture_id_t::arm; }, "cache hash ignored language architecture");
    require_distinct([](auto& value) { value.language.mode = architecture_mode_t::aarch64; }, "cache hash ignored language mode");
    require_distinct([](auto& value) { value.language.endian = endian_t::big; }, "cache hash ignored language endian");

    require_distinct([](auto& value) { value.hir_schema_version = 2; }, "cache hash ignored HIR schema version");
    require_distinct([](auto& value) { value.ast_schema_version = 3; }, "cache hash ignored AST schema version");
    require_distinct([](auto& value) { value.document_schema_version = 2; }, "cache hash ignored document schema version");

    require_distinct([](auto& value) { value.provider_ir_schema_version = 2; }, "cache hash ignored provider IR schema version");
    require_distinct([](auto& value) { value.type_graph_schema_version = 2; }, "cache hash ignored type graph schema version");

    require_distinct([](auto& value) { value.renderer.schema_version = 1; }, "cache hash ignored renderer schema version");

    auto invalid_provider_ir_schema = cache;
    invalid_provider_ir_schema.provider_ir_schema_version = 0;
    require(!validate_decompiler_pipeline_cache_key(invalid_provider_ir_schema).valid(), "cache key accepted provider IR schema drift");

    auto invalid_type_graph_schema = cache;
    invalid_type_graph_schema.type_graph_schema_version = 0;
    require(!validate_decompiler_pipeline_cache_key(invalid_type_graph_schema).valid(), "cache key accepted type graph schema drift");

    auto invalid_hir_schema = cache;
    invalid_hir_schema.hir_schema_version = 0;
    require(!validate_decompiler_pipeline_cache_key(invalid_hir_schema).valid(), "cache key accepted HIR schema drift");

    auto invalid_ast_schema = cache;
    invalid_ast_schema.ast_schema_version = 0;
    require(!validate_decompiler_pipeline_cache_key(invalid_ast_schema).valid(), "cache key accepted AST schema drift");

    auto invalid_document_schema = cache;
    invalid_document_schema.document_schema_version = 0;
    require(!validate_decompiler_pipeline_cache_key(invalid_document_schema).valid(), "cache key accepted document schema drift");

    auto invalid_stage = cache;
    invalid_stage.stage = static_cast<decompiler_cache_stage_t>(0xFFU);
    require(!validate_decompiler_pipeline_cache_key(invalid_stage).valid(), "cache key accepted invalid stage");
}

void verify_nested_diagnostic_coordinates(
    const decompiler_entity_key_t& entity,
    const type_graph_t& types,
    const hir_function_t& hir_value,
    const typed_pseudocode_ast_v2_t& ast_value,
    const decompiler_document_t& document_value)
{
    auto invalid_hir = hir_value;
    invalid_hir.diagnostics.front().coordinate->workspace_generation = 0;
    require(!validate_hir_function(invalid_hir).valid(), "HIR accepted invalid diagnostic coordinate");

    auto foreign_type_graph = types;
    foreign_type_graph.diagnostics.front().coordinate->entity = cli_entity();
    require(!validate_type_graph(foreign_type_graph).valid(), "type graph accepted foreign diagnostic coordinate");

    auto invalid_ast = ast_value;
    invalid_ast.diagnostics.front().coordinate->layer = decompiler_coordinate_layer_t::hir;
    require(!validate_typed_pseudocode_ast(invalid_ast).valid(), "AST accepted wrong-layer diagnostic coordinate");

    auto invalid_document = document_value;
    invalid_document.diagnostics.front().coordinate->layer = decompiler_coordinate_layer_t::typed_ast;
    require(!validate_decompiler_document(invalid_document).valid(), "document accepted wrong-layer diagnostic coordinate");

    auto foreign_document = document_value;
    foreign_document.diagnostics.front().coordinate->entity = entity == native_entity() ? cli_entity() : native_entity();
    require(!validate_decompiler_document(foreign_document).valid(), "document accepted foreign diagnostic coordinate");
}

decompiler_worker_envelope_t worker_envelope(decompiler_worker_message_kind_t kind, std::uint64_t sequence)
{
    decompiler_worker_envelope_t result;
    result.kind = kind;
    result.session_nonce_hash = digest("session");
    result.sequence = sequence;
    return result;
}

void verify_worker_round_trip(const decompiler_worker_message_t& value, const char* message)
{
    const auto bytes = serialize_decompiler_worker_message(value);
    const auto decoded = deserialize_decompiler_worker_message(bytes);
    require(decoded.valid(), message);
    require(stable_serialization_hash(value) == stable_serialization_hash(*decoded.value), "worker message hash drifted");
}

void verify_worker_variants(
    const decompiler_pipeline_cache_key_t& cache,
    const decompiler_document_t& document_value,
    const decompiler_diagnostic_t& diagnostic_value)
{
    decompiler_worker_hello_t hello;
    hello.envelope = worker_envelope(decompiler_worker_message_kind_t::hello, 1);
    hello.provider = provider();
    hello.manifest_hash = digest("worker-manifest");
    verify_worker_round_trip(decompiler_worker_message_t{hello}, "worker hello decode failed");

    decompiler_worker_job_request_t job;
    job.envelope = worker_envelope(decompiler_worker_message_kind_t::job_request, 2);
    job.job_id = 17;
    job.cache_key = cache;
    job.profile = cache.profile;
    job.snapshot_hash = digest("snapshot");
    job.request_printc_evidence = true;
    verify_worker_round_trip(decompiler_worker_message_t{job}, "worker job decode failed");

    auto wrong_printc_provider = job;
    wrong_printc_provider.cache_key.provider.provider = decompiler_provider_id_t::ilspy_cli;
    require(!validate_decompiler_worker_message(decompiler_worker_message_t{wrong_printc_provider}).valid(),
        "worker job accepted PrintC evidence for a managed provider");

    auto profile_mismatch = job;
    profile_mismatch.profile = profile(decompiler_profile_id_t::fast);
    require(!validate_decompiler_worker_message(decompiler_worker_message_t{profile_mismatch}).valid(),
        "worker job accepted cache profile mismatch");

    auto budget_mismatch = job;
    ++budget_mismatch.profile.max_wall_clock_ms;
    require(!validate_decompiler_worker_message(decompiler_worker_message_t{budget_mismatch}).valid(),
        "worker job accepted cache budget mismatch");

    auto proof_profile_mismatch = job;
    proof_profile_mismatch.cache_key.profile = profile(decompiler_profile_id_t::thorough);
    require(!validate_decompiler_worker_message(decompiler_worker_message_t{proof_profile_mismatch}).valid(),
        "worker job accepted cache semantic-proof profile mismatch");

    decompiler_worker_cancel_request_t cancel;
    cancel.envelope = worker_envelope(decompiler_worker_message_kind_t::cancel_request, 3);
    cancel.job_id = 17;
    cancel.stable_reason = "fixture_cancelled";
    verify_worker_round_trip(decompiler_worker_message_t{cancel}, "worker cancel decode failed");

    decompiler_worker_document_message_t document_message;
    document_message.envelope = worker_envelope(decompiler_worker_message_kind_t::document, 4);
    document_message.job_id = 17;
    document_message.provider_artifacts = "authenticated-provider-artifacts";
    document_message.provider_artifacts_hash = stable_serialization_hash(document_message.provider_artifacts);
    document_message.printc_evidence = "int fixture(void) { return 7; }";
    document_message.printc_evidence_hash = stable_serialization_hash(*document_message.printc_evidence);
    document_message.document = document_value;
    verify_worker_round_trip(decompiler_worker_message_t{document_message}, "worker document decode failed");
    const auto prepared_document = native_worker::runtime::prepare_document_payload(
        document_message);
    require(prepared_document.status == native_worker::runtime::document_send_status_t::sent &&
        !prepared_document.payload.empty() &&
        prepared_document.payload.size() <= k_decompiler_worker_result_frame_max_bytes,
        "worker pre-send path rejected a valid combined document payload");

    auto boundary_provider_artifacts = document_message;
    boundary_provider_artifacts.provider_artifacts.assign(
        k_decompiler_worker_provider_artifacts_max_bytes, 'p');
    boundary_provider_artifacts.provider_artifacts_hash =
        stable_serialization_hash(boundary_provider_artifacts.provider_artifacts);
    require(validate_decompiler_worker_message(
        decompiler_worker_message_t{boundary_provider_artifacts}).valid(),
        "worker document rejected provider artifacts at the exact bound");

    auto oversized_provider_artifacts = boundary_provider_artifacts;
    oversized_provider_artifacts.provider_artifacts.push_back('p');
    oversized_provider_artifacts.provider_artifacts_hash =
        stable_serialization_hash(oversized_provider_artifacts.provider_artifacts);
    require(!validate_decompiler_worker_message(
        decompiler_worker_message_t{oversized_provider_artifacts}).valid(),
        "worker document accepted provider artifacts one byte above the bound");

    auto boundary_printc = document_message;
    boundary_printc.printc_evidence = std::string(
        k_decompiler_worker_printc_evidence_max_bytes, 'c');
    boundary_printc.printc_evidence_hash =
        stable_serialization_hash(*boundary_printc.printc_evidence);
    require(validate_decompiler_worker_message(
        decompiler_worker_message_t{boundary_printc}).valid(),
        "worker document rejected PrintC evidence at the exact bound");

    auto combined_boundary = boundary_provider_artifacts;
    combined_boundary.printc_evidence = std::string(
        k_decompiler_worker_printc_evidence_max_bytes, 'c');
    combined_boundary.printc_evidence_hash =
        stable_serialization_hash(*combined_boundary.printc_evidence);
    const auto prepared_boundary = native_worker::runtime::prepare_document_payload(
        combined_boundary);
    require(prepared_boundary.status == native_worker::runtime::document_send_status_t::sent &&
        !prepared_boundary.payload.empty() &&
        prepared_boundary.payload.size() <= k_decompiler_worker_result_frame_max_bytes,
        "worker pre-send path rejected accepted provider-artifact and PrintC boundaries");

    const auto prepared_provider_over = native_worker::runtime::prepare_document_payload(
        oversized_provider_artifacts);
    require(prepared_provider_over.status ==
        native_worker::runtime::document_send_status_t::resource_limit &&
        prepared_provider_over.payload.empty(),
        "worker pre-send path did not reject one-byte-over provider artifacts");

    auto oversized_printc_preflight = boundary_printc;
    oversized_printc_preflight.printc_evidence->push_back('c');
    oversized_printc_preflight.printc_evidence_hash =
        stable_serialization_hash(*oversized_printc_preflight.printc_evidence);
    const auto prepared_printc_over = native_worker::runtime::prepare_document_payload(
        oversized_printc_preflight);
    require(prepared_printc_over.status ==
        native_worker::runtime::document_send_status_t::resource_limit &&
        prepared_printc_over.payload.empty(),
        "worker pre-send path did not reject one-byte-over PrintC evidence");

    auto tampered_printc = document_message;
    tampered_printc.printc_evidence->append("tampered");
    require(!validate_decompiler_worker_message(decompiler_worker_message_t{tampered_printc}).valid(),
        "worker document accepted tampered PrintC evidence");

    auto orphaned_printc_hash = document_message;
    orphaned_printc_hash.printc_evidence.reset();
    require(!validate_decompiler_worker_message(decompiler_worker_message_t{orphaned_printc_hash}).valid(),
        "worker document accepted a PrintC hash without evidence");

    auto oversized_printc = document_message;
    oversized_printc.printc_evidence = std::string(k_decompiler_worker_printc_evidence_max_bytes + 1U, 'x');
    oversized_printc.printc_evidence_hash = stable_serialization_hash(*oversized_printc.printc_evidence);
    require(!validate_decompiler_worker_message(decompiler_worker_message_t{oversized_printc}).valid(),
        "worker document accepted oversized PrintC evidence");

    decompiler_worker_failure_message_t failure;
    failure.envelope = worker_envelope(decompiler_worker_message_kind_t::failure, 5);
    failure.job_id = 17;
    failure.diagnostics.push_back(diagnostic_value);
    verify_worker_round_trip(decompiler_worker_message_t{failure}, "worker failure decode failed");

    decompiler_worker_heartbeat_t heartbeat;
    heartbeat.envelope = worker_envelope(decompiler_worker_message_kind_t::heartbeat, 6);
    heartbeat.active_job_id = 17;
    verify_worker_round_trip(decompiler_worker_message_t{heartbeat}, "worker heartbeat decode failed");
}

void verify_conditional_kind_contract(
    const decompiler_entity_key_t& entity,
    const type_graph_t& types)
{
    const auto make_node = [&entity](const std::uint64_t id,
                                     const typed_pseudocode_ast_node_kind_t kind,
                                     const std::uint64_t type_id,
                                     std::vector<std::uint64_t> children,
                                     std::string text) {
        typed_pseudocode_ast_node_t result;
        result.id = id;
        result.kind = kind;
        result.type_id = type_id;
        result.child_ids = std::move(children);
        result.stable_text = std::move(text);
        result.coordinate = coordinate(entity, decompiler_coordinate_layer_t::typed_ast);
        result.confidence = 100;
        result.provenance = decompiler_fact_provenance_t::provider_semantics;
        return result;
    };
    typed_pseudocode_ast_v2_t conditional;
    conditional.entity = entity;
    conditional.hir_hash = digest("c03-conditional-kind-hir");
    conditional.type_graph_hash = stable_serialization_hash(types);
    conditional.root_node_id = 1;
    conditional.body_node_id = 2;
    conditional.nodes = {
        make_node(1, typed_pseudocode_ast_node_kind_t::function_definition, 1, {2}, "conditional_fixture"),
        make_node(2, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {3}, {}),
        make_node(3, typed_pseudocode_ast_node_kind_t::expression_statement, 1, {4}, {}),
        make_node(4, typed_pseudocode_ast_node_kind_t::conditional_expression, 1, {5, 8, 9}, "?:"),
        make_node(5, typed_pseudocode_ast_node_kind_t::binary_expression, 1, {6, 7}, "<"),
        make_node(6, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "a"),
        make_node(7, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "b"),
        make_node(8, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "x"),
        make_node(9, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "y")};
    require(validate_typed_pseudocode_ast(conditional).valid(),
        "conditional-kind fixture is not a valid typed AST");
    const auto encoded = serialize_typed_pseudocode_ast(conditional);
    const auto decoded = deserialize_typed_pseudocode_ast(encoded);
    require(decoded.valid(), "conditional-kind typed AST decode failed");
    require(stable_serialization_hash(conditional) == stable_serialization_hash(*decoded.value),
        "conditional-kind typed AST hash drifted");
    require(decoded.value->nodes[3].kind == typed_pseudocode_ast_node_kind_t::conditional_expression &&
            decoded.value->nodes[3].child_ids == (std::vector<std::uint64_t>{5, 8, 9}),
        "conditional-kind node did not round-trip its kind or children");
    require(typed_ast_node_layout(typed_pseudocode_ast_node_kind_t::conditional_expression) ==
            "condition_then_else",
        "conditional-kind per-kind layout string diverged");
    require(k_typed_pseudocode_ast_schema_version == 3,
        "typed AST schema version was not bumped for the conditional kind");

    decompiler_document_t renderer_document = document(entity, conditional);
    renderer_document.renderer.schema_version = 5;
    renderer_document.renderer.emit_calling_convention_annotations = true;
    const auto renderer_bytes = serialize_decompiler_document(renderer_document);
    const auto decoded_renderer = deserialize_decompiler_document(renderer_bytes);
    require(decoded_renderer.valid(), "renderer schema v5 document decode failed");
    require(decoded_renderer.value->renderer.schema_version == 5 &&
            decoded_renderer.value->renderer.emit_calling_convention_annotations,
        "renderer schema v5 lost the calling-convention flag in round-trip");
    require(stable_serialization_hash(renderer_document) ==
            stable_serialization_hash(*decoded_renderer.value),
        "renderer schema v5 document hash drifted");

    decompiler_render_evidence_t evidence;
    decompiler_symbol_evidence_t symbol;
    symbol.unresolved_text = "sub_1000";
    symbol.resolved_name = "Config::Load";
    symbol.module_name = "fixture";
    symbol.argument_count = 1;
    symbol.confidence = 100;
    evidence.symbols.push_back(std::move(symbol));
    decompiler_prototype_evidence_t prototype;
    prototype.api_name = "Config::Load";
    prototype.return_type_display = "int";
    prototype.argument_names = {"path"};
    prototype.argument_type_displays = {"char*"};
    prototype.calling_convention = "__thiscall";
    prototype.class_qualifier = "Config";
    prototype.confidence = 100;
    evidence.prototypes.push_back(std::move(prototype));
    require(validate_decompiler_render_evidence(evidence).valid(),
        "render evidence with calling-convention and class qualifier was rejected");
    const auto evidence_bytes = serialize_decompiler_render_evidence(evidence);
    const auto decoded_evidence = deserialize_decompiler_render_evidence(evidence_bytes);
    require(decoded_evidence.valid(), "render evidence with calling-convention decode failed");
    require(decoded_evidence.value->prototypes.front().calling_convention == "__thiscall" &&
            decoded_evidence.value->prototypes.front().class_qualifier == "Config",
        "render evidence lost calling-convention or class qualifier in round-trip");
    require(stable_serialization_hash(evidence) == stable_serialization_hash(*decoded_evidence.value),
        "render evidence with calling-convention hash drifted");
}

void verify_measured_writer_equivalence(
    const provider_ir_t& provider_value,
    const hir_function_t& hir_value,
    const type_graph_t& types,
    const typed_pseudocode_ast_v2_t& ast_value,
    const decompiler_document_t& document_value,
    const decompiler_diagnostic_t& diagnostic_value,
    const decompiler_pipeline_cache_key_t& cache,
    const decompiler_render_evidence_t& evidence_value)
{
    const auto check = [](const std::string& canonical,
                          const measured_serialization_t& measured,
                          const char* message) {
        require(measured.bytes == canonical, message);
        require(measured.size == static_cast<std::uint64_t>(canonical.size()), message);
        require(measured.digest == stable_serialization_hash(canonical), message);
    };
    check(serialize_provider_ir(provider_value), serialize_provider_ir_measured(provider_value),
        "measured provider IR writer diverged from the canonical writer");
    check(serialize_hir_function(hir_value), serialize_hir_function_measured(hir_value),
        "measured HIR writer diverged from the canonical writer");
    check(serialize_type_graph(types), serialize_type_graph_measured(types),
        "measured type graph writer diverged from the canonical writer");
    check(serialize_typed_pseudocode_ast(ast_value), serialize_typed_pseudocode_ast_measured(ast_value),
        "measured typed AST writer diverged from the canonical writer");
    check(serialize_decompiler_document(document_value), serialize_decompiler_document_measured(document_value),
        "measured document writer diverged from the canonical writer");
    check(serialize_decompiler_diagnostic(diagnostic_value), serialize_decompiler_diagnostic_measured(diagnostic_value),
        "measured diagnostic writer diverged from the canonical writer");
    check(serialize_decompiler_pipeline_cache_key(cache), serialize_decompiler_pipeline_cache_key_measured(cache),
        "measured cache key writer diverged from the canonical writer");
    check(serialize_decompiler_render_evidence(evidence_value), serialize_decompiler_render_evidence_measured(evidence_value),
        "measured render evidence writer diverged from the canonical writer");
}

class software_sha256_t {
public:
    software_sha256_t() noexcept { reset(); }

    void update(const std::uint8_t* data, const std::size_t size) noexcept
    {
        total_bytes_ += size;
        const std::uint8_t* cursor = data;
        std::size_t remaining = size;
        while (remaining != 0) {
            const std::size_t amount = (std::min)(remaining, buffer_.size() - buffer_size_);
            for (std::size_t index = 0; index < amount; ++index)
                buffer_[buffer_size_ + index] = cursor[index];
            buffer_size_ += amount;
            cursor += amount;
            remaining -= amount;
            if (buffer_size_ == buffer_.size()) {
                transform(buffer_.data());
                buffer_size_ = 0;
            }
        }
    }

    std::array<std::uint8_t, 32> finish() noexcept
    {
        const std::uint64_t bit_length = total_bytes_ * 8;
        buffer_[buffer_size_++] = 0x80U;
        if (buffer_size_ > 56) {
            while (buffer_size_ < 64)
                buffer_[buffer_size_++] = 0;
            transform(buffer_.data());
            buffer_size_ = 0;
        }
        while (buffer_size_ < 56)
            buffer_[buffer_size_++] = 0;
        for (std::size_t index = 0; index < 8; ++index)
            buffer_[63 - index] = static_cast<std::uint8_t>(bit_length >> (index * 8));
        transform(buffer_.data());
        std::array<std::uint8_t, 32> output{};
        for (std::size_t index = 0; index < 8; ++index) {
            output[index * 4] = static_cast<std::uint8_t>(state_[index] >> 24U);
            output[index * 4 + 1] = static_cast<std::uint8_t>(state_[index] >> 16U);
            output[index * 4 + 2] = static_cast<std::uint8_t>(state_[index] >> 8U);
            output[index * 4 + 3] = static_cast<std::uint8_t>(state_[index]);
        }
        reset();
        return output;
    }

private:
    void reset() noexcept
    {
        state_ = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                  0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
        buffer_.fill(0);
        buffer_size_ = 0;
        total_bytes_ = 0;
    }

    static std::uint32_t rotate_right(const std::uint32_t value, const std::uint32_t amount) noexcept
    {
        return (value >> amount) | (value << (32U - amount));
    }

    void transform(const std::uint8_t* block) noexcept
    {
        static constexpr std::uint32_t constants[64] = {
            0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
            0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
            0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
            0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
            0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
            0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
            0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
            0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};
        std::array<std::uint32_t, 64> words{};
        for (std::size_t index = 0; index < 16; ++index) {
            const auto* input = block + index * 4;
            words[index] = (static_cast<std::uint32_t>(input[0]) << 24U) |
                (static_cast<std::uint32_t>(input[1]) << 16U) |
                (static_cast<std::uint32_t>(input[2]) << 8U) |
                static_cast<std::uint32_t>(input[3]);
        }
        for (std::size_t index = 16; index < words.size(); ++index) {
            const std::uint32_t s0 = rotate_right(words[index - 15], 7) ^ rotate_right(words[index - 15], 18) ^ (words[index - 15] >> 3U);
            const std::uint32_t s1 = rotate_right(words[index - 2], 17) ^ rotate_right(words[index - 2], 19) ^ (words[index - 2] >> 10U);
            words[index] = words[index - 16] + s0 + words[index - 7] + s1;
        }
        auto a = state_[0];
        auto b = state_[1];
        auto c = state_[2];
        auto d = state_[3];
        auto e = state_[4];
        auto f = state_[5];
        auto g = state_[6];
        auto h = state_[7];
        for (std::size_t index = 0; index < words.size(); ++index) {
            const std::uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            const std::uint32_t choose = (e & f) ^ ((~e) & g);
            const std::uint32_t temporary1 = h + s1 + choose + constants[index] + words[index];
            const std::uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temporary2 = s0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + temporary1;
            d = c;
            c = b;
            b = a;
            a = temporary1 + temporary2;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t buffer_size_ = 0;
    std::uint64_t total_bytes_ = 0;
};

bool software_sha256_reference(const std::uint8_t* data, const std::size_t size,
                               std::array<std::uint8_t, 32>& out) noexcept
{
    software_sha256_t hash;
    hash.update(data, size);
    out = hash.finish();
    return true;
}

void verify_cng_digest_vectors()
{
    const auto patterned = [](const std::size_t size) {
        std::string bytes(size, '\0');
        for (std::size_t index = 0; index < size; ++index)
            bytes[index] = static_cast<char>((index * 31U + (index >> 8U) + 7U) & 0xFFU);
        return bytes;
    };
    const auto require_identical = [](const std::string& bytes, const char* message) {
        std::array<std::uint8_t, 32> software{};
        require(software_sha256_reference(
            reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size(), software), message);
        std::array<std::uint8_t, 32> cng{};
        require(aida::crypto::sha256_cng_digest(bytes.data(), bytes.size(), cng), message);
        sha256_digest_t dispatched;
        dispatched.bytes = software;
        require(cng == software, message);
        require(stable_serialization_hash(bytes) == dispatched, message);
    };
    for (const std::size_t size : {0U, 1U, 55U, 56U, 57U, 63U, 64U, 65U, 119U, 120U, 127U, 128U, 129U})
        require_identical(patterned(size), "CNG and software SHA-256 diverged at a block boundary");
    require_identical(patterned(1U << 20), "CNG and software SHA-256 diverged on the patterned 1MB input");
    static constexpr std::array<std::uint8_t, 32> k_nist_abc = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    std::array<std::uint8_t, 32> software_abc{};
    require(software_sha256_reference(
        reinterpret_cast<const std::uint8_t*>("abc"), 3, software_abc),
        "software SHA-256 reference was unavailable for the NIST vector");
    require(software_abc == k_nist_abc, "software SHA-256 reference failed the NIST abc vector");
    sha256_digest_t nist_digest;
    nist_digest.bytes = k_nist_abc;
    require(stable_serialization_hash("abc") == nist_digest,
        "stable_serialization_hash failed the NIST abc vector");
    std::array<std::uint8_t, 32> cng_abc{};
    require(aida::crypto::sha256_cng_digest("abc", 3, cng_abc) && cng_abc == k_nist_abc,
        "CNG SHA-256 failed the NIST abc vector");
    require(aida::crypto::sha256_cng_available(&software_sha256_reference),
        "CNG SHA-256 self-test rejected the software reference");
}

bool reference_attestation_equivalence(
    const decompiler_document_t& left,
    const decompiler_document_t& right)
{
    auto canonical_left = left;
    canonical_left.diagnostics.clear();
    auto canonical_right = right;
    canonical_right.diagnostics.clear();
    return serialize_decompiler_document(canonical_left) ==
        serialize_decompiler_document(canonical_right);
}

void verify_attestation_equivalence_goldens(
    const decompiler_entity_key_t& entity,
    const decompiler_document_t& document_value)
{
    auto diagnostics_only = document_value;
    diagnostics_only.diagnostics.push_back(diagnostic(entity, decompiler_coordinate_layer_t::provider_ir));
    const auto baseline_digest = attestation_equivalence_digest(document_value);
    const auto diagnostics_only_digest = attestation_equivalence_digest(diagnostics_only);
    require(baseline_digest.constant_time_equal(diagnostics_only_digest),
        "attestation equivalence digest included top-level diagnostics");
    require(reference_attestation_equivalence(document_value, diagnostics_only),
        "reference attestation equivalence changed for a top-level-diagnostic difference");

    auto nested = document_value;
    nested.ast.diagnostics.push_back(diagnostic(entity, decompiler_coordinate_layer_t::typed_ast));
    nested.ast_hash = stable_serialization_hash(nested.ast);
    require(!(attestation_equivalence_digest(document_value) == attestation_equivalence_digest(nested)),
        "attestation equivalence digest ignored nested ast diagnostics");
    require(!reference_attestation_equivalence(document_value, nested),
        "reference attestation equivalence ignored nested ast diagnostics");

    auto one_token = document_value;
    one_token.tokens.front().range.end -= 1;
    require(!(attestation_equivalence_digest(document_value) == attestation_equivalence_digest(one_token)),
        "attestation equivalence digest ignored a one-token difference");
    require(!reference_attestation_equivalence(document_value, one_token),
        "reference attestation equivalence ignored a one-token difference");

    require(!(attestation_equivalence_digest(document_value) == stable_serialization_hash(document_value)),
        "attestation equivalence digest lost domain separation from the plain document hash");
    require(attestation_equivalence_digest(document_value).constant_time_equal(baseline_digest),
        "attestation equivalence digest is not deterministic across calls");
}

void verify_type_graph_merge_determinism(const decompiler_entity_key_t& entity)
{
    const auto make_node = [](const std::uint64_t id, const decompiler_type_kind_t kind,
                              const std::string& name, const std::uint32_t size,
                              const std::uint32_t alignment, const bool is_signed,
                              const std::uint8_t confidence) {
        decompiler_type_node_t result;
        result.id = id;
        result.kind = kind;
        result.canonical_name = name;
        result.display_name = name;
        result.byte_size = size;
        result.alignment = alignment;
        result.is_signed = is_signed;
        result.confidence = confidence;
        result.provenance = decompiler_fact_provenance_t::provider_semantics;
        return result;
    };
    const auto make_edge = [](const std::uint64_t source, const std::uint64_t target,
                              const decompiler_type_edge_kind_t kind, const std::string& name,
                              const std::optional<std::uint64_t> offset, const std::uint32_t ordinal,
                              const std::uint8_t confidence) {
        decompiler_type_edge_t result;
        result.source_type_id = source;
        result.target_type_id = target;
        result.kind = kind;
        result.stable_name = name;
        result.byte_offset = offset;
        result.ordinal = ordinal;
        result.confidence = confidence;
        result.provenance = decompiler_fact_provenance_t::provider_semantics;
        return result;
    };
    type_graph_t graph;
    graph.entity = entity;
    graph.revision = 13;
    graph.nodes = {
        make_node(1, decompiler_type_kind_t::signed_integer, "int", 4, 4, true, 100),
        make_node(2, decompiler_type_kind_t::unsigned_integer, "unsigned long long", 8, 8, false, 100),
        make_node(3, decompiler_type_kind_t::pointer, "int*", 8, 8, false, 100),
        make_node(4, decompiler_type_kind_t::structure, "Config", 16, 8, false, 100),
        make_node(5, decompiler_type_kind_t::enumeration, "Kind", 4, 4, true, 100),
        make_node(6, decompiler_type_kind_t::array, "int[16]", 64, 4, false, 100)};
    graph.edges = {
        make_edge(3, 1, decompiler_type_edge_kind_t::pointee, "pointee", std::nullopt, 1, 100),
        make_edge(4, 1, decompiler_type_edge_kind_t::member, "count", 0, 2, 50),
        make_edge(4, 2, decompiler_type_edge_kind_t::member, "size", 8, 3, 60),
        make_edge(4, 2, decompiler_type_edge_kind_t::member, "size_alias", 8, 4, 90),
        make_edge(5, 1, decompiler_type_edge_kind_t::member, "one", 1, 5, 40),
        make_edge(5, 1, decompiler_type_edge_kind_t::member, "one_alias", 1, 6, 40),
        make_edge(6, 1, decompiler_type_edge_kind_t::element, "element", std::nullopt, 7, 100)};
    require(validate_type_graph(graph).valid(), "type-graph finder fixture is invalid");

    const auto* offset_winner = type_graph::find_member_edge_by_offset(graph, 4, 8);
    require(offset_winner != nullptr && offset_winner->stable_name == "size_alias" &&
            offset_winner->confidence == 90,
        "member-by-offset lookup did not return the confidence winner");
    auto index = type_graph::build_type_graph_index(graph);
    require(!index.empty(), "type graph index is empty over a populated graph");
    for (std::uint64_t id = 1; id <= 6; ++id) {
        const auto* linear = type_graph::find_type_node(graph, id);
        const auto* indexed = index.node(id);
        require(linear != nullptr && indexed == linear, "type graph index diverged from find_type_node");
    }
    require(index.node(0) == nullptr && index.node(99) == nullptr &&
            type_graph::find_type_node(graph, 0) == nullptr &&
            type_graph::find_type_node(graph, 99) == nullptr,
        "type graph index diverged from find_type_node on absent ids");
    require(index.members_at(4, 0) == type_graph::find_member_edge_by_offset(graph, 4, 0) &&
            index.members_at(4, 8) == offset_winner &&
            index.members_at(4, 16) == type_graph::find_member_edge_by_offset(graph, 4, 16) &&
            index.member_named(4, "count") == type_graph::find_member_edge_by_name(graph, 4, "count") &&
            index.member_named(4, "size_alias") == type_graph::find_member_edge_by_name(graph, 4, "size_alias") &&
            index.member_named(4, "absent") == type_graph::find_member_edge_by_name(graph, 4, "absent") &&
            index.pointee(3) == type_graph::find_pointee_edge(graph, 3) &&
            index.pointee(4) == type_graph::find_pointee_edge(graph, 4) &&
            index.enumerator(5, 1) == type_graph::find_enumerator_edge(graph, 5, 1) &&
            index.enumerator(5, 2) == type_graph::find_enumerator_edge(graph, 5, 2),
        "type graph index diverged from the linear edge finders");
    require(index.members_at(5, 1) == type_graph::find_enumerator_edge(graph, 5, 1),
        "type graph index diverged from the enumerator finder on a confidence tie");

    const auto corpus_case = [&](const std::uint32_t node_count, const std::uint32_t edges_per_node) {
        type_graph_t corpus;
        corpus.entity = entity;
        corpus.revision = 17;
        for (std::uint32_t id = 1; id <= node_count; ++id) {
            const auto kind = id % 3 == 0 ? decompiler_type_kind_t::structure
                : id % 3 == 1 ? decompiler_type_kind_t::signed_integer
                : decompiler_type_kind_t::unsigned_integer;
            corpus.nodes.push_back(make_node(id, kind, "T" + std::to_string(id),
                4 + (id % 4) * 4, 4, id % 3 == 1, 80));
        }
        std::uint32_t ordinal = 1;
        for (std::uint32_t id = 1; id <= node_count; ++id) {
            for (std::uint32_t edge = 0; edge < edges_per_node; ++edge) {
                const std::uint64_t target = (static_cast<std::uint64_t>(id) * 7 + edge * 3) % node_count + 1;
                corpus.edges.push_back(make_edge(id, target,
                    decompiler_type_edge_kind_t::member, "m" + std::to_string(edge),
                    static_cast<std::uint64_t>(edge * 8), ordinal++,
                    static_cast<std::uint8_t>(40 + (id + edge) % 60)));
            }
        }
        require(validate_type_graph(corpus).valid(), "type-graph merge corpus is invalid");
        return corpus;
    };
    for (const auto& shape : {std::pair<std::uint32_t, std::uint32_t>{1, 0}, {10, 2}, {100, 3}, {1000, 5}}) {
        auto corpus = corpus_case(shape.first, shape.second);
        type_seed_batch_t batch;
        batch.source = decompiler_fact_provenance_t::debug_metadata;
        batch.source_label = "c03_merge_seed";
        for (std::uint32_t extra = 1; extra <= 4; ++extra) {
            type_candidate_t candidate;
            candidate.kind = decompiler_type_kind_t::structure;
            candidate.canonical_name = "Seed" + std::to_string(extra);
            candidate.display_name = candidate.canonical_name;
            candidate.byte_size = 16 * extra;
            candidate.alignment = 8;
            candidate.confidence = 70;
            candidate.provenance = decompiler_fact_provenance_t::debug_metadata;
            type_edge_candidate_t edge;
            edge.kind = decompiler_type_edge_kind_t::member;
            edge.target_canonical_name = "T1";
            edge.stable_name = "embedded";
            edge.byte_offset = 0;
            edge.confidence = 70;
            edge.provenance = decompiler_fact_provenance_t::debug_metadata;
            candidate.edges.push_back(std::move(edge));
            type_edge_candidate_t unresolved;
            unresolved.kind = decompiler_type_edge_kind_t::member;
            unresolved.target_canonical_name = "Absent" + std::to_string(extra);
            unresolved.stable_name = "missing";
            unresolved.byte_offset = 8;
            unresolved.confidence = 70;
            unresolved.provenance = decompiler_fact_provenance_t::debug_metadata;
            candidate.edges.push_back(std::move(unresolved));
            batch.candidates.push_back(std::move(candidate));
        }
        const auto first = type_graph::merge_type_evidence(corpus, {batch});
        const auto second = type_graph::merge_type_evidence(corpus, {batch});
        require(static_cast<bool>(first) && static_cast<bool>(second),
            "type-graph evidence merge rejected a valid corpus");
        require(serialize_type_graph(first.value()) == serialize_type_graph(second.value()),
            "type-graph evidence merge is not byte-identical across runs");
        require(stable_serialization_hash(first.value()) == stable_serialization_hash(second.value()),
            "type-graph evidence merge hash drifted across runs");
    }
}

struct cfg_outcome_loop_t {
    std::uint64_t header = 0;
    std::set<std::uint64_t> members;
    std::set<std::uint64_t> latches;
};

struct cfg_outcome_ncpd_t {
    std::uint64_t branch = 0;
    std::uint64_t left = 0;
    std::uint64_t right = 0;
    std::uint64_t join = 0;
};

struct cfg_outcomes_t {
    std::vector<cfg_outcome_loop_t> loops;
    std::vector<cfg_outcome_ncpd_t> ncpds;
};

class cfg_bitset_t {
public:
    void reset(const std::size_t bits)
    {
        words_.assign((bits + 63U) / 64U, 0);
    }

    void fill(const std::size_t bits)
    {
        reset(bits);
        for (std::size_t index = 0; index < bits; ++index)
            set(index);
    }

    void set(const std::size_t bit)
    {
        words_[bit / 64U] |= (std::uint64_t{1} << (bit % 64U));
    }

    bool test(const std::size_t bit) const
    {
        return ((words_[bit / 64U] >> (bit % 64U)) & 1ULL) != 0;
    }

    std::size_t count() const
    {
        std::size_t total = 0;
        for (const auto word : words_) {
            auto value = word;
            while (value != 0) {
                value &= value - 1;
                ++total;
            }
        }
        return total;
    }

    friend cfg_bitset_t operator&(const cfg_bitset_t& left, const cfg_bitset_t& right)
    {
        cfg_bitset_t result;
        result.words_.resize(left.words_.size());
        for (std::size_t index = 0; index < left.words_.size(); ++index)
            result.words_[index] = left.words_[index] & right.words_[index];
        return result;
    }

    bool operator==(const cfg_bitset_t& other) const { return words_ == other.words_; }
    bool operator!=(const cfg_bitset_t& other) const { return words_ != other.words_; }

private:
    std::vector<std::uint64_t> words_;
};

cfg_outcomes_t reference_cfg_outcomes(
    const std::map<std::uint64_t, std::vector<std::uint64_t>>& edges,
    const std::uint64_t entry)
{
    const std::size_t block_count = edges.size();
    const auto block_index = [](const std::uint64_t block) { return block - 1; };
    const std::size_t exit_index = block_count;
    std::map<std::uint64_t, std::vector<std::uint64_t>> predecessors;
    for (const auto& [block, successors] : edges) {
        predecessors[block];
        for (const auto successor : successors)
            predecessors[successor].push_back(block);
    }
    std::map<std::uint64_t, cfg_bitset_t> dominators;
    for (const auto& [block, successors] : edges) {
        (void)successors;
        if (block == entry) {
            dominators[block].reset(block_count + 1);
            dominators[block].set(block_index(block));
        } else {
            dominators[block].fill(block_count);
        }
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& [block, successors] : edges) {
            (void)successors;
            if (block == entry)
                continue;
            const auto& preds = predecessors.at(block);
            auto intersection = dominators.at(preds.front());
            for (std::size_t index = 1; index < preds.size(); ++index)
                intersection = intersection & dominators.at(preds[index]);
            intersection.set(block_index(block));
            if (intersection != dominators.at(block)) {
                dominators.at(block) = std::move(intersection);
                changed = true;
            }
        }
    }
    std::map<std::uint64_t, cfg_outcome_loop_t> loops;
    for (const auto& [block, successors] : edges) {
        for (const auto successor : successors) {
            if (!dominators.at(block).test(block_index(successor)))
                continue;
            auto& loop = loops[successor];
            loop.header = successor;
            loop.members.insert(successor);
            loop.members.insert(block);
            loop.latches.insert(block);
            std::vector<std::uint64_t> pending{block};
            while (!pending.empty()) {
                const auto current = pending.back();
                pending.pop_back();
                for (const auto predecessor : predecessors.at(current)) {
                    if (predecessor != successor &&
                        dominators.at(predecessor).test(block_index(successor)) &&
                        loop.members.insert(predecessor).second)
                        pending.push_back(predecessor);
                }
            }
        }
    }
    std::map<std::uint64_t, cfg_bitset_t> postdominators;
    postdominators[0].reset(block_count + 1);
    postdominators[0].set(exit_index);
    for (const auto& [block, successors] : edges) {
        (void)successors;
        postdominators[block].fill(block_count + 1);
    }
    changed = true;
    while (changed) {
        changed = false;
        for (auto iterator = edges.rbegin(); iterator != edges.rend(); ++iterator) {
            const auto block = iterator->first;
            auto successors = iterator->second;
            if (successors.empty())
                successors.push_back(0);
            auto intersection = postdominators.at(successors.front());
            for (std::size_t index = 1; index < successors.size(); ++index)
                intersection = intersection & postdominators.at(successors[index]);
            intersection.set(block_index(block));
            if (intersection != postdominators.at(block)) {
                postdominators.at(block) = std::move(intersection);
                changed = true;
            }
        }
    }
    cfg_outcomes_t outcomes;
    for (auto& [header, loop] : loops)
        outcomes.loops.push_back(std::move(loop));
    for (const auto& [block, successors] : edges) {
        if (successors.size() != 2)
            continue;
        const auto left = successors.front();
        const auto right = successors.back();
        cfg_outcome_ncpd_t outcome;
        outcome.branch = block;
        outcome.left = left;
        outcome.right = right;
        std::set<std::uint64_t> common;
        for (std::size_t candidate = 0; candidate <= block_count; ++candidate) {
            const auto block_id = candidate == exit_index ? 0 : candidate + 1;
            if (postdominators.at(left).test(candidate) &&
                postdominators.at(right).test(candidate))
                common.insert(block_id);
        }
        common.erase(block);
        std::uint64_t best = 0;
        std::size_t best_depth = 0;
        for (const auto candidate : common) {
            const auto depth = postdominators.at(candidate).count();
            if (depth > best_depth || (depth == best_depth && candidate < best)) {
                best = candidate;
                best_depth = depth;
            }
        }
        outcome.join = best;
        outcomes.ncpds.push_back(outcome);
    }
    return outcomes;
}

std::string cfg_canonical_text(
    const std::string& id,
    const std::map<std::uint64_t, std::vector<std::uint64_t>>& edges,
    const std::uint64_t entry,
    const cfg_outcomes_t& outcomes)
{
    std::string text = "case " + id + "\nentry " + std::to_string(entry) + "\n";
    const auto join_ids = [](const auto& values) {
        std::string joined;
        bool first = true;
        for (const auto value : values) {
            if (!first)
                joined.push_back(',');
            joined += std::to_string(value);
            first = false;
        }
        return joined;
    };
    for (const auto& [block, successors] : edges)
        text += "block " + std::to_string(block) + " " + join_ids(successors) + "\n";
    text += "loops " + std::to_string(outcomes.loops.size()) + "\n";
    for (const auto& loop : outcomes.loops) {
        text += "loop header=" + std::to_string(loop.header) +
            " members=" + join_ids(loop.members) +
            " latches=" + join_ids(loop.latches) + "\n";
    }
    text += "ncpds " + std::to_string(outcomes.ncpds.size()) + "\n";
    for (const auto& ncpd : outcomes.ncpds) {
        text += "ncpd branch=" + std::to_string(ncpd.branch) +
            " left=" + std::to_string(ncpd.left) +
            " right=" + std::to_string(ncpd.right) +
            " join=" + std::to_string(ncpd.join) + "\n";
    }
    return text;
}

decompiler_entity_key_t cfg_entity()
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = 4242;
    identity.entry = address(0x1000);
    identity.end = address(0x1000 + 0x100000);
    identity.function_bytes_hash = digest("c03-dominator-equivalence-function");
    identity.canonical_symbol = "cfg_fixture";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::native_function;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.identity = std::move(identity);
    return result;
}

source_coordinate_t cfg_coordinate(
    const decompiler_entity_key_t& entity,
    const std::uint64_t block)
{
    source_coordinate_t result;
    result.layer = decompiler_coordinate_layer_t::hir;
    result.workspace_generation = 7;
    result.entity = entity;
    result.address_range = decompiler_address_range_t{
        address(0x1000 + block * 0x10), address(0x1004 + block * 0x10)};
    result.instruction_range = decompiler_instruction_range_t{
        static_cast<std::uint32_t>(100 + block), static_cast<std::uint32_t>(101 + block)};
    return result;
}

hir_function_t cfg_hir(
    const decompiler_entity_key_t& entity,
    const std::map<std::uint64_t, std::vector<std::uint64_t>>& edges,
    const std::uint64_t type_graph_revision)
{
    std::uint64_t next_value = 1;
    hir_function_t result;
    result.entity = entity;
    result.provider_ir_hash = digest("c03-dominator-equivalence-provider-ir");
    result.type_graph_revision = type_graph_revision;
    result.return_type_id = 1;
    hir_variable_t target;
    target.id = next_value++;
    target.stable_name = "x";
    target.type_id = 1;
    target.coordinate = cfg_coordinate(entity, edges.begin()->first);
    target.confidence = 100;
    target.provenance = decompiler_fact_provenance_t::debug_metadata;
    result.locals.push_back(target);
    const auto add_value = [&entity, &next_value](hir_block_t& block,
                                                  const hir_node_kind_t kind,
                                                  std::string stable,
                                                  std::vector<std::uint64_t> operands) {
        hir_value_t value;
        value.id = next_value++;
        value.kind = kind;
        value.type_id = 1;
        value.operand_ids = std::move(operands);
        value.stable_value = std::move(stable);
        value.coordinate = block.coordinate;
        value.confidence = 100;
        value.provenance = decompiler_fact_provenance_t::provider_semantics;
        const auto id = value.id;
        block.values.push_back(std::move(value));
        return id;
    };
    for (const auto& [block_id, successors] : edges) {
        hir_block_t block;
        block.id = block_id;
        block.coordinate = cfg_coordinate(entity, block_id);
        block.successor_ids = successors;
        if (successors.size() == 2) {
            hir_variable_t condition;
            condition.id = next_value++;
            condition.stable_name = "c" + std::to_string(block_id);
            condition.type_id = 1;
            condition.coordinate = block.coordinate;
            condition.confidence = 100;
            condition.provenance = decompiler_fact_provenance_t::debug_metadata;
            const auto reference = add_value(block, hir_node_kind_t::reference,
                condition.stable_name, {});
            condition.id = reference;
            result.locals.push_back(condition);
            add_value(block, hir_node_kind_t::conditional,
                "condition.true=" + std::to_string(successors.front()) + ";negated=0",
                {reference});
        } else if (successors.size() == 1) {
            const auto reference = add_value(block, hir_node_kind_t::reference, "x", {});
            const auto literal = add_value(block, hir_node_kind_t::literal, "1", {});
            add_value(block, hir_node_kind_t::assignment, {}, {reference, literal});
        } else {
            const auto literal = add_value(block, hir_node_kind_t::literal, "0", {});
            add_value(block, hir_node_kind_t::return_value, {}, {literal});
        }
        result.blocks.push_back(std::move(block));
    }
    return result;
}

std::uint64_t cfg_block_of(const typed_pseudocode_ast_node_t& node)
{
    if (!node.coordinate.address_range.has_value())
        return 0;
    const auto begin = node.coordinate.address_range->begin.value;
    if (begin < 0x1000 || (begin - 0x1000) % 0x10 != 0)
        return 0;
    return (begin - 0x1000) / 0x10;
}

void cfg_collect_loop_statements(
    const typed_pseudocode_ast_v2_t& ast,
    std::vector<std::pair<typed_pseudocode_ast_node_kind_t, std::uint64_t>>& output)
{
    for (const auto& node : ast.nodes) {
        if (node.kind == typed_pseudocode_ast_node_kind_t::while_statement ||
            node.kind == typed_pseudocode_ast_node_kind_t::do_while_statement ||
            node.kind == typed_pseudocode_ast_node_kind_t::for_statement)
            output.emplace_back(node.kind, cfg_block_of(node));
    }
    std::sort(output.begin(), output.end(), [](const auto& left, const auto& right) {
        return left.second < right.second;
    });
}

void verify_cfg_builder_structure(
    const typed_pseudocode_ast_v2_t& ast,
    const cfg_outcomes_t& outcomes,
    const nlohmann::json& expected_loop_statements)
{
    std::vector<std::pair<typed_pseudocode_ast_node_kind_t, std::uint64_t>> loop_statements;
    cfg_collect_loop_statements(ast, loop_statements);
    require(loop_statements.size() == expected_loop_statements.size(),
        "typed AST builder emitted an unexpected number of loop statements");
    for (std::size_t index = 0; index < loop_statements.size(); ++index) {
        const auto& expected = expected_loop_statements.at(index);
        const auto expected_kind = expected.at("kind").get<std::string>() == "while_statement"
            ? typed_pseudocode_ast_node_kind_t::while_statement
            : typed_pseudocode_ast_node_kind_t::do_while_statement;
        require(loop_statements[index].first == expected_kind &&
                loop_statements[index].second == expected.at("header").get<std::uint64_t>(),
            "typed AST builder emitted a loop statement at an unexpected header");
    }

    std::map<std::uint64_t, const typed_pseudocode_ast_node_t*> nodes;
    std::map<std::uint64_t, const typed_pseudocode_ast_node_t*> parents;
    for (const auto& node : ast.nodes) {
        nodes.emplace(node.id, &node);
        for (const auto child : node.child_ids)
            parents.emplace(child, &node);
    }
    std::set<std::uint64_t> loop_headers;
    std::set<std::uint64_t> loop_latches;
    for (const auto& loop : outcomes.loops) {
        loop_headers.insert(loop.header);
        loop_latches.insert(loop.latches.begin(), loop.latches.end());
    }
    for (const auto& ncpd : outcomes.ncpds) {
        if (loop_headers.count(ncpd.branch) != 0 || loop_latches.count(ncpd.branch) != 0)
            continue;
        const typed_pseudocode_ast_node_t* if_node = nullptr;
        for (const auto& node : ast.nodes) {
            if (node.kind == typed_pseudocode_ast_node_kind_t::if_statement &&
                cfg_block_of(node) == ncpd.branch) {
                if_node = &node;
                break;
            }
        }
        require(if_node != nullptr, "typed AST builder lost the if statement for a corpus branch");
        const auto parent = parents.find(if_node->id);
        require(parent != parents.end() &&
                parent->second->kind == typed_pseudocode_ast_node_kind_t::compound_statement,
            "typed AST corpus if statement is not parented by a compound");
        const auto& siblings = parent->second->child_ids;
        const auto position = std::find(siblings.begin(), siblings.end(), if_node->id);
        require(position != siblings.end() && position + 1 != siblings.end(),
            "typed AST corpus if statement has no following join sibling");
        const auto join_node = nodes.find(*(position + 1));
        require(join_node != nodes.end() && cfg_block_of(*join_node->second) == ncpd.join,
            "typed AST corpus if statement is not followed by its NCPD block");
    }
}

void verify_dominator_equivalence_corpus()
{
    const auto entity = cfg_entity();
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
    types.entity = entity;
    types.revision = 41;
    types.nodes.push_back(std::move(integer));
    require(validate_type_graph(types).valid(), "dominator-equivalence type graph is invalid");
    const auto locate_root = []() {
        auto candidate = std::filesystem::absolute(std::filesystem::path(__FILE__));
        candidate = candidate.parent_path();
        std::error_code error;
        while (!candidate.empty()) {
            if (std::filesystem::is_regular_file(candidate / "AGENTS.md", error) &&
                std::filesystem::is_directory(candidate / ".deps", error))
                return candidate;
            const auto parent = candidate.parent_path();
            if (parent == candidate)
                break;
            candidate = parent;
        }
        throw std::runtime_error("AiDA source root is unavailable for the dominator corpus");
    };
    const auto fixture_path = locate_root() /
        "src/standalone/tests/c03/fixtures/typed_ast_hashes_pre_lt.json";
    std::ifstream stream(fixture_path, std::ios::binary);
    require(stream.is_open(), "dominator-equivalence fixture is unavailable");
    const auto fixture = nlohmann::json::parse(stream, nullptr, false);
    require(!fixture.is_discarded() &&
            fixture.value("schema", std::string{}) == "aida.c03.typed-ast-hashes-pre-lt.v1",
        "dominator-equivalence fixture schema drifted");

    for (const auto& fixture_case : fixture.at("cases")) {
        const auto id = fixture_case.at("id").get<std::string>();
        const auto entry = fixture_case.at("entry").get<std::uint64_t>();
        std::map<std::uint64_t, std::vector<std::uint64_t>> edges;
        if (fixture_case.contains("edges")) {
            for (const auto& [block, successors] : fixture_case.at("edges").items()) {
                const auto block_id = std::stoull(block);
                for (const auto& successor : successors)
                    edges[block_id].push_back(successor.get<std::uint64_t>());
                if (edges[block_id].empty())
                    edges[block_id] = {};
            }
        } else if (fixture_case.value("generator", std::string{}) == "chain") {
            const auto blocks = fixture_case.at("blocks").get<std::uint64_t>();
            for (std::uint64_t block = 1; block <= blocks; ++block)
                edges[block] = block < blocks ? std::vector<std::uint64_t>{block + 1}
                                              : std::vector<std::uint64_t>{};
        } else if (fixture_case.value("generator", std::string{}) == "diamond_chain") {
            const auto diamonds = fixture_case.at("diamonds").get<std::uint64_t>();
            const auto total = diamonds * 4;
            for (std::uint64_t diamond = 0; diamond < diamonds; ++diamond) {
                const auto branch = diamond * 4 + 1;
                const auto left = diamond * 4 + 2;
                const auto right = diamond * 4 + 3;
                const auto join = diamond * 4 + 4;
                edges[branch] = {left, right};
                edges[left] = {join};
                edges[right] = {join};
                edges[join] = join == total ? std::vector<std::uint64_t>{}
                                            : std::vector<std::uint64_t>{join + 1};
            }
        }
        require(!edges.empty(), "dominator-equivalence fixture case has no CFG");

        const auto outcomes = reference_cfg_outcomes(edges, entry);
        if (fixture_case.contains("expected_loops")) {
            const auto& expected_loops = fixture_case.at("expected_loops");
            require(outcomes.loops.size() == expected_loops.size(),
                "reference loop count diverged from the fixture");
            for (std::size_t index = 0; index < outcomes.loops.size(); ++index) {
                const auto& expected = expected_loops.at(index);
                const auto& loop = outcomes.loops[index];
                std::set<std::uint64_t> expected_members;
                for (const auto& member : expected.at("members"))
                    expected_members.insert(member.get<std::uint64_t>());
                std::set<std::uint64_t> expected_latches;
                for (const auto& latch : expected.at("latches"))
                    expected_latches.insert(latch.get<std::uint64_t>());
                require(loop.header == expected.at("header").get<std::uint64_t>() &&
                        loop.members == expected_members && loop.latches == expected_latches,
                    "reference loop outcome diverged from the fixture");
            }
            const auto& expected_ncpds = fixture_case.at("expected_ncpds");
            require(outcomes.ncpds.size() == expected_ncpds.size(),
                "reference NCPD count diverged from the fixture");
            for (std::size_t index = 0; index < outcomes.ncpds.size(); ++index) {
                const auto& expected = expected_ncpds.at(index);
                const auto& ncpd = outcomes.ncpds[index];
                require(ncpd.branch == expected.at("branch").get<std::uint64_t>() &&
                        ncpd.left == expected.at("left").get<std::uint64_t>() &&
                        ncpd.right == expected.at("right").get<std::uint64_t>() &&
                        ncpd.join == expected.at("join").get<std::uint64_t>(),
                    "reference NCPD outcome diverged from the fixture");
            }
        } else {
            require(outcomes.loops.size() == fixture_case.at("expected_loop_count").get<std::uint64_t>() &&
                    outcomes.ncpds.size() == fixture_case.at("expected_ncpd_count").get<std::uint64_t>(),
                "reference stress outcome counts diverged from the fixture");
        }
        const auto canonical = cfg_canonical_text(id, edges, entry, outcomes);
        require(stable_serialization_hash(canonical).to_hex() ==
                fixture_case.at("expectation_sha256").get<std::string>(),
            "reference outcome digest diverged from the fixture");

        const auto hir_value = cfg_hir(entity, edges, types.revision);
        const auto first = build_typed_ast(hir_value, types);
        const auto second = build_typed_ast(hir_value, types);
        require(first.succeeded() && second.succeeded(),
            "typed AST builder rejected a dominator-equivalence corpus CFG");
        require(serialize_typed_ast(*first.ast) == serialize_typed_ast(*second.ast) &&
                stable_serialization_hash(*first.ast) == stable_serialization_hash(*second.ast),
            "typed AST builder is nondeterministic on a dominator-equivalence corpus CFG");
        if (fixture_case.contains("expected_loop_statements")) {
            verify_cfg_builder_structure(*first.ast, outcomes,
                fixture_case.at("expected_loop_statements"));
        } else {
            std::vector<std::pair<typed_pseudocode_ast_node_kind_t, std::uint64_t>> loop_statements;
            cfg_collect_loop_statements(*first.ast, loop_statements);
            require(loop_statements.size() == outcomes.loops.size(),
                "typed AST builder loop statement count diverged on a stress CFG");
            if (fixture_case.value("generator", std::string{}) == "diamond_chain") {
                std::size_t if_count = 0;
                for (const auto& node : first.ast->nodes) {
                    if (node.kind == typed_pseudocode_ast_node_kind_t::if_statement)
                        ++if_count;
                }
                require(if_count == fixture_case.at("diamonds").get<std::uint64_t>(),
                    "typed AST builder lost if statements on the diamond stress CFG");
            }
        }
    }
}

}

void run_decompiler_contracts_harness()
{
    const auto native = native_entity();
    verify_entity_round_trip(native);
    verify_entity_round_trip(cli_entity());
    verify_entity_round_trip(jvm_entity());
    verify_entity_round_trip(dalvik_entity());

    const auto coordinate_value = coordinate(native, decompiler_coordinate_layer_t::provider_ir);
    const auto coordinate_bytes = serialize_source_coordinate(coordinate_value);
    const auto decoded_coordinate = deserialize_source_coordinate(coordinate_bytes);
    require(decoded_coordinate.valid(), "source coordinate decode failed");
    require(serialize_source_coordinate(*decoded_coordinate.value) == coordinate_bytes, "source coordinate round trip changed bytes");

    verify_profile_contract_rules();

    const auto provider_value = provider_ir(native);
    const auto provider_bytes = serialize_provider_ir(provider_value);
    const auto decoded_provider = deserialize_provider_ir(provider_bytes);
    require(decoded_provider.valid(), "provider IR decode failed");
    require(stable_serialization_hash(provider_value) == stable_serialization_hash(*decoded_provider.value), "provider IR hash drifted");

    const auto types = type_graph(native);
    const auto type_bytes = serialize_type_graph(types);
    const auto decoded_types = deserialize_type_graph(type_bytes);
    require(decoded_types.valid(), "type graph decode failed");
    require(stable_serialization_hash(types) == stable_serialization_hash(*decoded_types.value), "type graph hash drifted");

    const auto hir_value = hir(native, provider_value);
    const auto hir_bytes = serialize_hir_function(hir_value);
    const auto decoded_hir = deserialize_hir_function(hir_bytes);
    require(decoded_hir.valid(), "HIR decode failed");
    require(stable_serialization_hash(hir_value) == stable_serialization_hash(*decoded_hir.value), "HIR hash drifted");

    verify_exception_ast_contract(jvm_entity(), false);
    verify_exception_ast_contract(dalvik_entity(), true);
    verify_exception_ast_rejections();

    const auto ast_value = ast(native, hir_value, types);
    const auto ast_bytes = serialize_typed_pseudocode_ast(ast_value);
    const auto decoded_ast = deserialize_typed_pseudocode_ast(ast_bytes);
    require(decoded_ast.valid(), "typed AST decode failed");
    require(stable_serialization_hash(ast_value) == stable_serialization_hash(*decoded_ast.value), "typed AST hash drifted");

    const auto document_value = document(native, ast_value);
    const auto document_bytes = serialize_decompiler_document(document_value);
    const auto decoded_document = deserialize_decompiler_document(document_bytes);
    require(decoded_document.valid(), "document decode failed");
    require(stable_serialization_hash(document_value) == stable_serialization_hash(*decoded_document.value), "document hash drifted");
    require(!decoded_document.value->source_maps.empty() && !decoded_document.value->unknowns.empty(), "document lost source maps or unknowns");
    verify_nested_diagnostic_coordinates(native, types, hir_value, ast_value, document_value);

    const auto diagnostic = failure_diagnostic(native);
    const auto diagnostic_bytes = serialize_decompiler_diagnostic(diagnostic);
    const auto decoded_diagnostic = deserialize_decompiler_diagnostic(diagnostic_bytes);
    require(decoded_diagnostic.valid(), "diagnostic decode failed");
    require(stable_serialization_hash(diagnostic) == stable_serialization_hash(*decoded_diagnostic.value), "diagnostic hash drifted");

    const auto cache = cache_key(native);
    const auto cache_bytes = serialize_decompiler_pipeline_cache_key(cache);
    const auto decoded_cache = deserialize_decompiler_pipeline_cache_key(cache_bytes);
    require(decoded_cache.valid(), "cache key decode failed");
    require(stable_serialization_hash(cache) == stable_serialization_hash(*decoded_cache.value), "cache key hash drifted");
    require(decoded_cache.value->provider_ir_schema_version == k_provider_ir_schema_version,
        "cache key lost provider IR schema version");
    require(decoded_cache.value->type_graph_schema_version == k_type_graph_schema_version,
        "cache key lost type graph schema version");
    verify_cache_identity_dimensions(cache);
    verify_worker_variants(cache, document_value, diagnostic);

    auto empty_body = ast_value;
    empty_body.nodes[1].child_ids.clear();
    require(!validate_typed_pseudocode_ast(empty_body).valid(), "empty AST body was accepted");

    verify_conditional_kind_contract(native, types);
    decompiler_render_evidence_t evidence_value;
    decompiler_prototype_evidence_t prototype;
    prototype.api_name = "printf";
    prototype.return_type_display = "int";
    prototype.argument_names = {"format"};
    prototype.argument_type_displays = {"const char*"};
    prototype.is_variadic = true;
    prototype.calling_convention = "__cdecl";
    prototype.confidence = 100;
    evidence_value.prototypes.push_back(std::move(prototype));
    verify_measured_writer_equivalence(provider_value, hir_value, types, ast_value,
        document_value, diagnostic, cache, evidence_value);
    verify_cng_digest_vectors();
    verify_attestation_equivalence_goldens(native, document_value);
    verify_type_graph_merge_determinism(native);
    verify_dominator_equivalence_corpus();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_decompiler_contracts_harness();
        std::cout << "decompiler_contracts_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
