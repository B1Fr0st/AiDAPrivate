#include "pseudocode_renderer_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/pseudocode_renderer_v2.hpp"
#include "../../src/core/analysis/workspace/decompiler_service.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

void require(const bool condition, const char* message)
{
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

address_t address(const std::uint64_t value)
{
    address_t result;
    result.space = address_space_id_t::relative_virtual;
    result.value = value;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_entity_key_t entity(const std::uint64_t function_id = 911)
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = function_id;
    identity.entry = address(0x140001000ULL);
    identity.end = address(0x140001080ULL);
    identity.function_bytes_hash = stable_serialization_hash("c03-pseudocode-renderer-fixture");
    identity.canonical_symbol = "renderer_fixture";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::native_function;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.identity = std::move(identity);
    return result;
}

source_coordinate_t coordinate(const decompiler_entity_key_t& entity_value, const decompiler_coordinate_layer_t layer)
{
    source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = 17;
    result.entity = entity_value;
    result.address_range = decompiler_address_range_t{address(0x140001000ULL), address(0x140001004ULL)};
    result.instruction_range = decompiler_instruction_range_t{1, 1};
    return result;
}

type_graph_t type_graph(const decompiler_entity_key_t& entity_value)
{
    decompiler_type_node_t integer;
    integer.id = 1;
    integer.kind = decompiler_type_kind_t::signed_integer;
    integer.canonical_name = "int";
    integer.display_name = "int";
    integer.byte_size = 4;
    integer.alignment = 4;
    integer.is_signed = true;
    integer.confidence = 100;
    integer.provenance = decompiler_fact_provenance_t::debug_metadata;
    decompiler_type_node_t boolean;
    boolean.id = 2;
    boolean.kind = decompiler_type_kind_t::boolean;
    boolean.canonical_name = "bool";
    boolean.display_name = "bool";
    boolean.byte_size = 1;
    boolean.alignment = 1;
    boolean.confidence = 100;
    boolean.provenance = decompiler_fact_provenance_t::debug_metadata;
    type_graph_t result;
    result.entity = entity_value;
    result.revision = 17;
    result.nodes = {std::move(integer), std::move(boolean)};
    return result;
}

provider_ir_t provider_ir(const decompiler_entity_key_t& entity_value)
{
    decompiler_provider_identity_t provider;
    provider.provider = decompiler_provider_id_t::ghidra_native;
    provider.provider_name = "ghidra";
    provider.provider_version = "11.3.0";
    provider.provider_binary_hash = stable_serialization_hash("c03-provider-binary");
    provider.worker_build_id = "c03-provider-worker";
    provider.worker_build_hash = stable_serialization_hash("c03-provider-worker");
    decompiler_language_identity_t language;
    language.language_id = "x86:LE:64:default";
    language.language_version = "11.3";
    language.compiler_spec_id = "windows";
    language.language_spec_hash = stable_serialization_hash("c03-provider-language");
    language.architecture = architecture_id_t::x86_64;
    language.mode = architecture_mode_t::x86_64;
    provider_ir_value_t value;
    value.id = 1;
    value.opcode = provider_ir_opcode_t::return_value;
    value.type_id = 1;
    value.stable_immediate = "result";
    value.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::provider_ir);
    value.confidence = 100;
    value.provenance = decompiler_fact_provenance_t::provider_semantics;
    provider_ir_block_t block;
    block.id = 1;
    block.values.push_back(std::move(value));
    block.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::provider_ir);
    provider_ir_t result;
    result.provider = std::move(provider);
    result.language = std::move(language);
    result.entity = entity_value;
    result.entry_block_id = 1;
    result.blocks.push_back(std::move(block));
    return result;
}

hir_variable_t variable(
    const std::uint64_t id,
    std::string name,
    const decompiler_entity_key_t& entity_value)
{
    hir_variable_t result;
    result.id = id;
    result.stable_name = std::move(name);
    result.type_id = 1;
    result.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::hir);
    result.confidence = 100;
    result.provenance = decompiler_fact_provenance_t::debug_metadata;
    return result;
}

hir_value_t value(
    const std::uint64_t id,
    const hir_node_kind_t kind,
    std::string stable_value,
    std::vector<std::uint64_t> operands,
    const decompiler_entity_key_t& entity_value)
{
    hir_value_t result;
    result.id = id;
    result.kind = kind;
    result.type_id = 1;
    result.operand_ids = std::move(operands);
    result.stable_value = std::move(stable_value);
    result.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::hir);
    result.confidence = 100;
    result.provenance = decompiler_fact_provenance_t::provider_semantics;
    return result;
}

hir_function_t straight_line_hir(const decompiler_entity_key_t& entity_value,
                                 const type_graph_t& types,
                                 const provider_ir_t& provider)
{
    hir_block_t block;
    block.id = 1;
    block.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::hir);
    block.values = {
        value(1, hir_node_kind_t::literal, "1", {}, entity_value),
        value(2, hir_node_kind_t::reference, "arg0", {}, entity_value),
        value(3, hir_node_kind_t::binary, "+", {1, 2}, entity_value),
        value(4, hir_node_kind_t::reference, "result", {}, entity_value),
        value(5, hir_node_kind_t::cast, {}, {3}, entity_value),
        value(6, hir_node_kind_t::assignment, {}, {4, 5}, entity_value),
        value(7, hir_node_kind_t::return_value, {}, {4}, entity_value)};
    hir_function_t result;
    result.entity = entity_value;
    result.provider_ir_hash = stable_serialization_hash(provider);
    result.type_graph_revision = types.revision;
    result.return_type_id = 1;
    result.parameters.push_back(variable(1, "arg0", entity_value));
    result.locals.push_back(variable(2, "result", entity_value));
    result.blocks.push_back(std::move(block));
    return result;
}

typed_pseudocode_ast_node_t node(
    const std::uint64_t id,
    const typed_pseudocode_ast_node_kind_t kind,
    const std::uint64_t type_id,
    std::vector<std::uint64_t> children,
    std::string stable_text,
    const decompiler_entity_key_t& entity_value)
{
    typed_pseudocode_ast_node_t result;
    result.id = id;
    result.kind = kind;
    result.type_id = type_id;
    result.child_ids = std::move(children);
    result.stable_text = std::move(stable_text);
    result.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::typed_ast);
    result.confidence = 100;
    result.provenance = decompiler_fact_provenance_t::semantic_proof;
    return result;
}

typed_pseudocode_ast_v2_t structured_ast(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    typed_pseudocode_ast_v2_t result;
    result.entity = entity_value;
    result.hir_hash = stable_serialization_hash("c03-structured-hir");
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes = {
        node(1, typed_pseudocode_ast_node_kind_t::function_definition, 1, {2}, "structured_fixture", entity_value),
        node(2, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {3, 13}, {}, entity_value),
        node(3, typed_pseudocode_ast_node_kind_t::if_statement, 1, {4, 5, 8}, {}, entity_value),
        node(4, typed_pseudocode_ast_node_kind_t::identifier, 2, {}, "ready", entity_value),
        node(5, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {6}, {}, entity_value),
        node(6, typed_pseudocode_ast_node_kind_t::return_statement, 1, {7}, {}, entity_value),
        node(7, typed_pseudocode_ast_node_kind_t::literal, 1, {}, "1", entity_value),
        node(8, typed_pseudocode_ast_node_kind_t::else_clause, 1, {9}, {}, entity_value),
        node(9, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {10}, {}, entity_value),
        node(10, typed_pseudocode_ast_node_kind_t::throw_statement, 1, {11}, {}, entity_value),
        node(11, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "error", entity_value),
        node(13, typed_pseudocode_ast_node_kind_t::try_statement, 1, {14, 17, 19}, {}, entity_value),
        node(14, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {15}, {}, entity_value),
        node(15, typed_pseudocode_ast_node_kind_t::expression_statement, 1, {16}, {}, entity_value),
        node(16, typed_pseudocode_ast_node_kind_t::call_expression, 1, {11}, {}, entity_value),
        node(17, typed_pseudocode_ast_node_kind_t::catch_clause, 1, {18}, "runtime_error", entity_value),
        node(18, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {20}, {}, entity_value),
        node(19, typed_pseudocode_ast_node_kind_t::finally_clause, 1, {22}, {}, entity_value),
        node(20, typed_pseudocode_ast_node_kind_t::return_statement, 1, {21}, {}, entity_value),
        node(21, typed_pseudocode_ast_node_kind_t::literal, 1, {}, "-1", entity_value),
        node(22, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {23}, {}, entity_value),
        node(23, typed_pseudocode_ast_node_kind_t::expression_statement, 1, {24}, {}, entity_value),
        node(24, typed_pseudocode_ast_node_kind_t::call_expression, 1, {25}, {}, entity_value),
        node(25, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "cleanup", entity_value)};
    return result;
}

void require_source_map_coverage(const decompiler_document_t& document)
{
    require(document.tokens.size() == document.source_maps.size(), "renderer did not emit one source map per token");
    std::vector<bool> covered(document.rendered_text.size(), false);
    for (const auto& source_map : document.source_maps) {
        for (std::uint32_t index = source_map.document_range.begin; index < source_map.document_range.end; ++index)
            covered[index] = true;
    }
    for (const bool value : covered)
        require(value, "renderer source maps do not cover the rendered document");
}

void require_deterministic_document(const decompiler_document_t& first,
                                    const decompiler_document_t& second)
{
    const auto first_bytes = serialize_pseudocode_document_v2(first);
    const auto second_bytes = serialize_pseudocode_document_v2(second);
    require(first_bytes == second_bytes, "V2 document serialization is nondeterministic");
    require(stable_serialization_hash(first) == stable_serialization_hash(second),
        "V2 document hash is nondeterministic");
}

struct local_v2_result_t {
    typed_ast_v2_build_result_t ast_build;
    std::optional<pseudocode_renderer_v2_result_t> rendering;
    std::vector<decompiler_diagnostic_t> diagnostics;

    bool succeeded() const noexcept {
        return ast_build.succeeded() && rendering.has_value() && rendering->succeeded();
    }
};

local_v2_result_t render_provider_document_v2_local(
    const provider_ir_t&,
    const hir_function_t& hir,
    const type_graph_t& type_graph,
    const pseudocode_renderer_v2_request_t& request = {}) {
    local_v2_result_t result;
    result.ast_build = build_typed_ast_v2(hir, type_graph);
    result.diagnostics = result.ast_build.diagnostics;
    if (!result.ast_build.succeeded())
        return result;
    result.rendering = render_pseudocode_v2(*result.ast_build.ast, type_graph, request);
    result.diagnostics.insert(result.diagnostics.end(),
        result.rendering->diagnostics.begin(), result.rendering->diagnostics.end());
    return result;
}

void verify_generated_ast_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto provider = provider_ir(entity_value);
    const auto hir = straight_line_hir(entity_value, types, provider);
    pseudocode_renderer_v2_request_t request;
    request.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced);
    const auto first = render_provider_document_v2_local(provider, hir, types, request);
    const auto second = render_provider_document_v2_local(provider, hir, types, request);
    require(first.succeeded() && second.succeeded(), "decompiler service production V2 path rejected a proven straight-line body");
    require(validate_typed_ast_v2_semantics(*first.ast_build.ast, types).valid(), "typed AST semantic validation failed");
    require(stable_serialization_hash(*first.ast_build.ast) == stable_serialization_hash(*second.ast_build.ast),
        "typed AST construction is nondeterministic");
    const auto encoded_ast = serialize_typed_ast_v2(*first.ast_build.ast);
    const auto decoded_ast = deserialize_typed_ast_v2(encoded_ast);
    require(decoded_ast.valid(), "typed AST serialization did not round-trip");
    require(stable_serialization_hash(*first.ast_build.ast) == stable_serialization_hash(*decoded_ast.value),
        "typed AST serialization hash drifted");

    const auto& rendered = *first.rendering;
    const auto& rendered_second = *second.rendering;
    const std::string expected =
        "int renderer_fixture(int arg0) {\n"
        "    int result;\n"
        "    result = (int)(1 + arg0);\n"
        "    return result;\n"
        "}\n";
    require(rendered.document->rendered_text == expected, "generated AST golden text drifted");
    require(rendered_second.document->rendered_text == expected, "second generated AST render drifted");
    require_deterministic_document(*rendered.document, *rendered_second.document);
    require_source_map_coverage(*rendered.document);
    const auto encoded_document = serialize_pseudocode_document_v2(*rendered.document);
    const auto decoded_document = deserialize_pseudocode_document_v2(encoded_document);
    require(decoded_document.valid(), "renderer document serialization did not round-trip");
    require(stable_serialization_hash(*rendered.document) == stable_serialization_hash(*decoded_document.value),
        "renderer document serialization hash drifted");

    auto mismatched_hir = hir;
    mismatched_hir.provider_ir_hash = stable_serialization_hash("c03-mismatched-provider-ir");
    const auto mismatch = render_provider_document_v2_local(provider, mismatched_hir, types, request);
    require(!mismatch.succeeded(), "decompiler service accepted an HIR/provider-IR hash mismatch");
    require(std::any_of(mismatch.diagnostics.begin(), mismatch.diagnostics.end(),
        [](const decompiler_diagnostic_t& diagnostic) {
            return diagnostic.code == decompiler_diagnostic_code_t::malformed_hir &&
                   diagnostic.localization_key == "decompiler.service.v2.provider_ir_hash";
        }), "decompiler service omitted the strict provider-IR binding diagnostic");

    auto mismatched_types = types;
    ++mismatched_types.revision;
    require(validate_type_graph(mismatched_types).valid(), "type-graph mismatch fixture is invalid");
    const auto type_graph_mismatch = render_provider_document_v2_local(
        provider, hir, mismatched_types, request);
    require(!type_graph_mismatch.succeeded(), "decompiler service accepted an HIR/type-graph revision mismatch");
    require(!type_graph_mismatch.rendering.has_value(), "decompiler service rendered an HIR/type-graph revision mismatch");
    require(std::any_of(type_graph_mismatch.diagnostics.begin(), type_graph_mismatch.diagnostics.end(),
        [](const decompiler_diagnostic_t& diagnostic) {
            return diagnostic.code == decompiler_diagnostic_code_t::malformed_type_graph &&
                   diagnostic.localization_key == "decompiler.service.v2.type_graph_revision";
        }), "decompiler service omitted the strict type-graph revision diagnostic");

    const auto mismatched_entity_types = type_graph(entity(912));
    require(validate_type_graph(mismatched_entity_types).valid(), "entity-binding mismatch type graph fixture is invalid");
    const auto entity_binding_mismatch = render_provider_document_v2_local(
        provider, hir, mismatched_entity_types, request);
    require(!entity_binding_mismatch.succeeded(), "decompiler service accepted a provider/HIR/type-graph entity mismatch");
    require(!entity_binding_mismatch.rendering.has_value(), "decompiler service rendered a provider/HIR/type-graph entity mismatch");
    require(std::any_of(entity_binding_mismatch.diagnostics.begin(), entity_binding_mismatch.diagnostics.end(),
        [](const decompiler_diagnostic_t& diagnostic) {
            return diagnostic.code == decompiler_diagnostic_code_t::malformed_hir &&
                   diagnostic.localization_key == "decompiler.service.v2.entity_binding";
        }), "decompiler service omitted the strict entity-binding diagnostic");
}

void verify_structured_semantic_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto ast = structured_ast(entity_value, types);
    require(validate_typed_ast_v2_semantics(ast, types).valid(), "structured control-flow AST was rejected");
    pseudocode_renderer_v2_request_t request;
    request.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced);
    const auto rendered = render_pseudocode_v2(ast, types, request);
    const auto rendered_second = render_pseudocode_v2(ast, types, request);
    require(rendered.succeeded(), "renderer rejected structured control flow and exceptions");
    require(rendered_second.succeeded(), "second renderer pass rejected structured control flow and exceptions");
    const std::string expected =
        "int structured_fixture() {\n"
        "    if (ready) {\n"
        "        return 1;\n"
        "    }\n"
        "    else {\n"
        "        throw error;\n"
        "    }\n"
        "    try {\n"
        "        error();\n"
        "    }\n"
        "    catch (runtime_error) {\n"
        "        return -1;\n"
        "    }\n"
        "    finally {\n"
        "        cleanup();\n"
        "    }\n"
        "}\n";
    require(rendered.document->rendered_text == expected, "structured semantic golden text drifted");
    require(rendered_second.document->rendered_text == expected, "second structured semantic render drifted");
    require_deterministic_document(*rendered.document, *rendered_second.document);
    require_source_map_coverage(*rendered.document);
}

void verify_no_fabricated_body(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto provider = provider_ir(entity_value);
    auto hir = straight_line_hir(entity_value, types, provider);
    hir.blocks.front().values.push_back(value(8, hir_node_kind_t::conditional, {}, {2}, entity_value));
    const auto result = render_provider_document_v2_local(provider, hir, types);
    require(!result.succeeded(), "decompiler service fabricated a structured body for an unproven conditional region");
    require(!result.rendering.has_value(), "decompiler service rendered an AST after strict lowering rejection");
    require(std::any_of(result.ast_build.diagnostics.begin(), result.ast_build.diagnostics.end(),
        [](const decompiler_diagnostic_t& diagnostic) {
            return diagnostic.code == decompiler_diagnostic_code_t::malformed_ast &&
                   diagnostic.localization_key == "decompiler.ast.v2.unstructured_control_flow";
        }), "decompiler service omitted the unstructured-control-flow diagnostic");
}

void verify_incomplete_ir_diagnostic(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto provider = provider_ir(entity_value);
    auto hir = straight_line_hir(entity_value, types, provider);
    hir.blocks.clear();
    const auto result = render_provider_document_v2_local(provider, hir, types);
    require(!result.succeeded(), "decompiler service accepted incomplete HIR");
    require(!result.rendering.has_value(), "decompiler service rendered incomplete HIR");
    require(std::any_of(result.ast_build.diagnostics.begin(), result.ast_build.diagnostics.end(),
        [](const decompiler_diagnostic_t& diagnostic) {
            return diagnostic.code == decompiler_diagnostic_code_t::malformed_hir &&
                   diagnostic.localization_key == "decompiler.hir.header";
        }), "decompiler service lost the strict incomplete-HIR diagnostic");
}

typed_pseudocode_ast_v2_t while_loop_ast(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    typed_pseudocode_ast_v2_t result;
    result.entity = entity_value;
    result.hir_hash = stable_serialization_hash("c03-while-loop-hir");
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes = {
        node(1, typed_pseudocode_ast_node_kind_t::function_definition, 1, {2}, "while_fixture", entity_value),
        node(2, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {3}, {}, entity_value),
        node(3, typed_pseudocode_ast_node_kind_t::while_statement, 1, {4, 5}, {}, entity_value),
        node(4, typed_pseudocode_ast_node_kind_t::identifier, 2, {}, "cond", entity_value),
        node(5, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {6, 7}, {}, entity_value),
        node(6, typed_pseudocode_ast_node_kind_t::break_statement, 1, {}, {}, entity_value),
        node(7, typed_pseudocode_ast_node_kind_t::continue_statement, 1, {}, {}, entity_value)};
    return result;
}

void verify_while_loop_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto ast = while_loop_ast(entity_value, types);
    require(validate_typed_ast_v2_semantics(ast, types).valid(), "while loop AST was rejected");
    pseudocode_renderer_v2_request_t request;
    request.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced);
    const auto rendered = render_pseudocode_v2(ast, types, request);
    const auto rendered_second = render_pseudocode_v2(ast, types, request);
    require(rendered.succeeded(), "renderer rejected while loop with break and continue");
    require(rendered_second.succeeded(), "second renderer pass rejected while loop");
    const std::string expected =
        "int while_fixture() {\n"
        "    while (cond) {\n"
        "        break;\n"
        "        continue;\n"
        "    }\n"
        "}\n";
    require(rendered.document->rendered_text == expected, "while loop golden text drifted");
    require(rendered_second.document->rendered_text == expected, "second while loop render drifted");
    require_deterministic_document(*rendered.document, *rendered_second.document);
    require_source_map_coverage(*rendered.document);
}

typed_pseudocode_ast_v2_t do_while_loop_ast(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    typed_pseudocode_ast_v2_t result;
    result.entity = entity_value;
    result.hir_hash = stable_serialization_hash("c03-do-while-loop-hir");
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes = {
        node(1, typed_pseudocode_ast_node_kind_t::function_definition, 1, {2}, "do_while_fixture", entity_value),
        node(2, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {3}, {}, entity_value),
        node(3, typed_pseudocode_ast_node_kind_t::do_while_statement, 1, {4, 5}, {}, entity_value),
        node(4, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {6}, {}, entity_value),
        node(5, typed_pseudocode_ast_node_kind_t::identifier, 2, {}, "cond", entity_value),
        node(6, typed_pseudocode_ast_node_kind_t::continue_statement, 1, {}, {}, entity_value)};
    return result;
}

void verify_do_while_loop_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto ast = do_while_loop_ast(entity_value, types);
    require(validate_typed_ast_v2_semantics(ast, types).valid(), "do-while loop AST was rejected");
    pseudocode_renderer_v2_request_t request;
    request.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced);
    const auto rendered = render_pseudocode_v2(ast, types, request);
    const auto rendered_second = render_pseudocode_v2(ast, types, request);
    require(rendered.succeeded(), "renderer rejected do-while loop with continue");
    require(rendered_second.succeeded(), "second renderer pass rejected do-while loop");
    const std::string expected =
        "int do_while_fixture() {\n"
        "    do {\n"
        "        continue;\n"
        "    }\n"
        "    while (cond);\n"
        "}\n";
    require(rendered.document->rendered_text == expected, "do-while loop golden text drifted");
    require(rendered_second.document->rendered_text == expected, "second do-while loop render drifted");
    require_deterministic_document(*rendered.document, *rendered_second.document);
    require_source_map_coverage(*rendered.document);
}

typed_pseudocode_ast_v2_t for_loop_ast(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    typed_pseudocode_ast_v2_t result;
    result.entity = entity_value;
    result.hir_hash = stable_serialization_hash("c03-for-loop-hir");
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes = {
        node(1, typed_pseudocode_ast_node_kind_t::function_definition, 1, {2}, "for_fixture", entity_value),
        node(2, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {3}, {}, entity_value),
        node(3, typed_pseudocode_ast_node_kind_t::for_statement, 1, {4, 7, 10, 13}, {}, entity_value),
        node(4, typed_pseudocode_ast_node_kind_t::declaration, 1, {5}, "i", entity_value),
        node(5, typed_pseudocode_ast_node_kind_t::literal, 1, {}, "0", entity_value),
        node(7, typed_pseudocode_ast_node_kind_t::binary_expression, 2, {8, 9}, "<", entity_value),
        node(8, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "i", entity_value),
        node(9, typed_pseudocode_ast_node_kind_t::literal, 1, {}, "10", entity_value),
        node(10, typed_pseudocode_ast_node_kind_t::assignment_expression, 1, {11, 12}, {}, entity_value),
        node(11, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "i", entity_value),
        node(12, typed_pseudocode_ast_node_kind_t::binary_expression, 1, {14, 15}, "+", entity_value),
        node(14, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "i", entity_value),
        node(15, typed_pseudocode_ast_node_kind_t::literal, 1, {}, "1", entity_value),
        node(13, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {16}, {}, entity_value),
        node(16, typed_pseudocode_ast_node_kind_t::break_statement, 1, {}, {}, entity_value)};
    return result;
}

void verify_for_loop_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto ast = for_loop_ast(entity_value, types);
    require(validate_typed_ast_v2_semantics(ast, types).valid(), "for loop AST was rejected");
    pseudocode_renderer_v2_request_t request;
    request.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced);
    const auto rendered = render_pseudocode_v2(ast, types, request);
    const auto rendered_second = render_pseudocode_v2(ast, types, request);
    require(rendered.succeeded(), "renderer rejected for loop with declaration initializer");
    require(rendered_second.succeeded(), "second renderer pass rejected for loop");
    const std::string expected =
        "int for_fixture() {\n"
        "    for (int i = 0; i < 10; i = i + 1) {\n"
        "        break;\n"
        "    }\n"
        "}\n";
    require(rendered.document->rendered_text == expected, "for loop golden text drifted");
    require(rendered_second.document->rendered_text == expected, "second for loop render drifted");
    require_deterministic_document(*rendered.document, *rendered_second.document);
    require_source_map_coverage(*rendered.document);
}

typed_pseudocode_ast_v2_t switch_ast(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    typed_pseudocode_ast_v2_t result;
    result.entity = entity_value;
    result.hir_hash = stable_serialization_hash("c03-switch-hir");
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes = {
        node(1, typed_pseudocode_ast_node_kind_t::function_definition, 1, {2}, "switch_fixture", entity_value),
        node(2, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {3}, {}, entity_value),
        node(3, typed_pseudocode_ast_node_kind_t::switch_statement, 1, {4, 5, 8}, {}, entity_value),
        node(4, typed_pseudocode_ast_node_kind_t::identifier, 2, {}, "sel", entity_value),
        node(5, typed_pseudocode_ast_node_kind_t::switch_case, 1, {6, 7}, "case", entity_value),
        node(6, typed_pseudocode_ast_node_kind_t::literal, 1, {}, "1", entity_value),
        node(7, typed_pseudocode_ast_node_kind_t::break_statement, 1, {}, {}, entity_value),
        node(8, typed_pseudocode_ast_node_kind_t::switch_case, 1, {9}, "default", entity_value),
        node(9, typed_pseudocode_ast_node_kind_t::continue_statement, 1, {}, {}, entity_value)};
    return result;
}

void verify_switch_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto ast = switch_ast(entity_value, types);
    require(validate_typed_ast_v2_semantics(ast, types).valid(), "switch AST was rejected");
    pseudocode_renderer_v2_request_t request;
    request.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced);
    const auto rendered = render_pseudocode_v2(ast, types, request);
    const auto rendered_second = render_pseudocode_v2(ast, types, request);
    require(rendered.succeeded(), "renderer rejected switch with case and default");
    require(rendered_second.succeeded(), "second renderer pass rejected switch");
    const std::string expected =
        "int switch_fixture() {\n"
        "    switch (sel) {\n"
        "        case 1:\n"
        "            break;\n"
        "        default:\n"
        "            continue;\n"
        "    }\n"
        "}\n";
    require(rendered.document->rendered_text == expected, "switch golden text drifted");
    require(rendered_second.document->rendered_text == expected, "second switch render drifted");
    require_deterministic_document(*rendered.document, *rendered_second.document);
    require_source_map_coverage(*rendered.document);
}

typed_pseudocode_ast_v2_t expression_ast(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    typed_pseudocode_ast_v2_t result;
    result.entity = entity_value;
    result.hir_hash = stable_serialization_hash("c03-expression-hir");
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes = {
        node(1, typed_pseudocode_ast_node_kind_t::function_definition, 1, {2}, "expr_fixture", entity_value),
        node(2, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {3, 5, 7, 9, 11, 13}, {}, entity_value),
        node(3, typed_pseudocode_ast_node_kind_t::expression_statement, 1, {4}, {}, entity_value),
        node(4, typed_pseudocode_ast_node_kind_t::member_expression, 1, {14}, "field", entity_value),
        node(5, typed_pseudocode_ast_node_kind_t::expression_statement, 1, {6}, {}, entity_value),
        node(6, typed_pseudocode_ast_node_kind_t::index_expression, 1, {15, 16}, {}, entity_value),
        node(7, typed_pseudocode_ast_node_kind_t::expression_statement, 1, {8}, {}, entity_value),
        node(8, typed_pseudocode_ast_node_kind_t::unary_expression, 1, {17}, "!", entity_value),
        node(9, typed_pseudocode_ast_node_kind_t::expression_statement, 1, {10}, {}, entity_value),
        node(10, typed_pseudocode_ast_node_kind_t::unary_expression, 1, {18}, "*", entity_value),
        node(11, typed_pseudocode_ast_node_kind_t::expression_statement, 1, {12}, {}, entity_value),
        node(12, typed_pseudocode_ast_node_kind_t::unary_expression, 1, {19}, "-", entity_value),
        node(13, typed_pseudocode_ast_node_kind_t::expression_statement, 1, {20}, {}, entity_value),
        node(14, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "obj", entity_value),
        node(15, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "arr", entity_value),
        node(16, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "index", entity_value),
        node(17, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "flag", entity_value),
        node(18, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "ptr", entity_value),
        node(19, typed_pseudocode_ast_node_kind_t::identifier, 1, {}, "val", entity_value),
        node(20, typed_pseudocode_ast_node_kind_t::unknown_expression, 1, {}, "stuff", entity_value)};
    return result;
}

void verify_expression_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto ast = expression_ast(entity_value, types);
    require(validate_typed_ast_v2_semantics(ast, types).valid(), "expression AST was rejected");
    pseudocode_renderer_v2_request_t request;
    request.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced);
    const auto rendered = render_pseudocode_v2(ast, types, request);
    const auto rendered_second = render_pseudocode_v2(ast, types, request);
    require(rendered.succeeded(), "renderer rejected member, index, unary, and unknown expressions");
    require(rendered_second.succeeded(), "second renderer pass rejected expression fixture");
    const std::string expected =
        "int expr_fixture() {\n"
        "    obj.field;\n"
        "    arr[index];\n"
        "    !flag;\n"
        "    *ptr;\n"
        "    -val;\n"
        "    unknown<\"stuff\">;\n"
        "}\n";
    require(rendered.document->rendered_text == expected, "expression golden text drifted");
    require(rendered_second.document->rendered_text == expected, "second expression render drifted");
    require_deterministic_document(*rendered.document, *rendered_second.document);
    require_source_map_coverage(*rendered.document);
}

typed_pseudocode_ast_v2_t compact_loop_ast(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    typed_pseudocode_ast_v2_t result;
    result.entity = entity_value;
    result.hir_hash = stable_serialization_hash("c03-compact-loop-hir");
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes = {
        node(1, typed_pseudocode_ast_node_kind_t::function_definition, 1, {2}, "compact_fixture", entity_value),
        node(2, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {3}, {}, entity_value),
        node(3, typed_pseudocode_ast_node_kind_t::while_statement, 1, {4, 5}, {}, entity_value),
        node(4, typed_pseudocode_ast_node_kind_t::identifier, 2, {}, "cond", entity_value),
        node(5, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {6}, {}, entity_value),
        node(6, typed_pseudocode_ast_node_kind_t::break_statement, 1, {}, {}, entity_value)};
    return result;
}

void verify_compact_profile_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto ast = compact_loop_ast(entity_value, types);
    require(validate_typed_ast_v2_semantics(ast, types).valid(), "compact profile AST was rejected");
    pseudocode_renderer_v2_request_t request;
    request.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::compact);
    const auto rendered = render_pseudocode_v2(ast, types, request);
    const auto rendered_second = render_pseudocode_v2(ast, types, request);
    require(rendered.succeeded(), "renderer rejected compact profile while loop");
    require(rendered_second.succeeded(), "second renderer pass rejected compact profile");
    require(!rendered.document->renderer.emit_provenance_annotations, "compact profile emitted provenance annotations");
    require(rendered.document->renderer.indentation_spaces == 2, "compact profile did not use 2-space indentation");
    const std::string expected =
        "int compact_fixture() {\n"
        "  while (cond) {\n"
        "    break;\n"
        "  }\n"
        "}\n";
    require(rendered.document->rendered_text == expected, "compact profile golden text drifted");
    require(rendered_second.document->rendered_text == expected, "second compact profile render drifted");
    require_deterministic_document(*rendered.document, *rendered_second.document);
    require_source_map_coverage(*rendered.document);
}

typed_pseudocode_ast_v2_t audit_loop_ast(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    typed_pseudocode_ast_v2_t result;
    result.entity = entity_value;
    result.hir_hash = stable_serialization_hash("c03-audit-loop-hir");
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes = {
        node(1, typed_pseudocode_ast_node_kind_t::function_definition, 1, {2}, "audit_fixture", entity_value),
        node(2, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {3}, {}, entity_value),
        node(3, typed_pseudocode_ast_node_kind_t::while_statement, 1, {4, 5}, {}, entity_value),
        node(4, typed_pseudocode_ast_node_kind_t::identifier, 2, {}, "cond", entity_value),
        node(5, typed_pseudocode_ast_node_kind_t::compound_statement, 1, {6}, {}, entity_value),
        node(6, typed_pseudocode_ast_node_kind_t::break_statement, 1, {}, {}, entity_value)};
    return result;
}

void verify_audit_profile_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto ast = audit_loop_ast(entity_value, types);
    require(validate_typed_ast_v2_semantics(ast, types).valid(), "audit profile AST was rejected");
    pseudocode_renderer_v2_request_t request;
    request.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::audit);
    const auto rendered = render_pseudocode_v2(ast, types, request);
    const auto rendered_second = render_pseudocode_v2(ast, types, request);
    require(rendered.succeeded(), "renderer rejected audit profile while loop");
    require(rendered_second.succeeded(), "second renderer pass rejected audit profile");
    require(rendered.document->renderer.emit_provenance_annotations, "audit profile did not emit provenance annotations");
    require(rendered.document->renderer.indentation_spaces == 4, "audit profile did not use 4-space indentation");
    const std::string expected =
        "[[aida::confidence(100), aida::provenance(semantic_proof)]]\n"
        "int audit_fixture() {\n"
        "    [[aida::confidence(100), aida::provenance(semantic_proof)]]\n"
        "    while (cond) {\n"
        "        break;\n"
        "    }\n"
        "}\n";
    require(rendered.document->rendered_text == expected, "audit profile golden text drifted");
    require(rendered_second.document->rendered_text == expected, "second audit profile render drifted");
    require_deterministic_document(*rendered.document, *rendered_second.document);
    require_source_map_coverage(*rendered.document);
}

}

void run_pseudocode_renderer_harness()
{
    const auto entity_value = entity();
    const auto types = type_graph(entity_value);
    require(validate_type_graph(types).valid(), "type graph fixture is invalid");
    verify_generated_ast_fixture(entity_value, types);
    verify_structured_semantic_fixture(entity_value, types);
    verify_no_fabricated_body(entity_value, types);
    verify_incomplete_ir_diagnostic(entity_value, types);
    verify_while_loop_fixture(entity_value, types);
    verify_do_while_loop_fixture(entity_value, types);
    verify_for_loop_fixture(entity_value, types);
    verify_switch_fixture(entity_value, types);
    verify_expression_fixture(entity_value, types);
    verify_compact_profile_fixture(entity_value, types);
    verify_audit_profile_fixture(entity_value, types);
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_pseudocode_renderer_harness();
        std::cout << "pseudocode_renderer_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
