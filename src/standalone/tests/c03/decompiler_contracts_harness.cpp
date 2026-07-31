#include "decompiler_contracts_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"
#include "../../src/core/analysis/decompiler/decompiler_contracts.hpp"
#include "../../src/core/analysis/decompiler/typed_ast_v2.hpp"
#include "../../workers/native_decompiler/native_worker_runtime.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

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
    const typed_ast_v2_build_result_t& result,
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
    const auto first = build_typed_ast_v2(hir_value, types);
    const auto second = build_typed_ast_v2(hir_value, types);
    require(first.succeeded() && second.succeeded(),
        "typed AST rejected a valid exception-only handler region");
    require(serialize_typed_ast_v2(*first.ast) ==
            serialize_typed_ast_v2(*second.ast) &&
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
    require(validate_typed_ast_v2_semantics(*first.ast, types).valid(),
        "typed AST exception structure failed semantic validation");
}

void verify_exception_ast_rejections()
{
    const auto entity = jvm_entity();
    const auto types = exception_type_graph(entity);

    auto asymmetric = exception_hir(entity);
    asymmetric.blocks[2].predecessor_ids.clear();
    const auto asymmetric_result = build_typed_ast_v2(asymmetric, types);
    require(!asymmetric_result.succeeded() && has_diagnostic(asymmetric_result,
            "decompiler.ast.v2.asymmetric_predecessor"),
        "typed AST accepted an asymmetric exceptional predecessor");

    auto missing = exception_hir(entity);
    missing.blocks[0].exception_successor_ids = {99};
    const auto missing_result = build_typed_ast_v2(missing, types);
    require(!missing_result.succeeded(),
        "typed AST accepted a missing exceptional target");

    auto ambiguous_edge = exception_hir(entity);
    ambiguous_edge.blocks[0].exception_successor_ids = {2, 3};
    const auto ambiguous_edge_result = build_typed_ast_v2(ambiguous_edge, types);
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
    const auto overlap_result = build_typed_ast_v2(overlap, types);
    require(!overlap_result.succeeded() && has_diagnostic(overlap_result,
            "decompiler.ast.v2.ambiguous_exception_overlap"),
        "typed AST accepted an ambiguous overlapping exception region");

    typed_ast_v2_build_request_t bounded_request;
    bounded_request.limits.max_ast_nodes = 5;
    const auto bounded_result = build_typed_ast_v2(exception_hir(entity),
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
