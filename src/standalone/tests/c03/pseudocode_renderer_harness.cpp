#include "pseudocode_renderer_harness.hpp"

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

decompiler_entity_key_t entity()
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = 911;
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

hir_function_t straight_line_hir(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
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
    result.provider_ir_hash = stable_serialization_hash("c03-pseudocode-provider");
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

void verify_generated_ast_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto hir = straight_line_hir(entity_value, types);
    decompiler_service_v2_request_t request;
    request.renderer.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced);
    const auto first = decompiler_service_t::render_typed_pseudocode_v2(hir, types, request);
    const auto second = decompiler_service_t::render_typed_pseudocode_v2(hir, types, request);
    require(first.succeeded() && second.succeeded(), "decompiler service V2 path rejected a proven straight-line body");
    require(validate_typed_ast_v2_semantics(*first.ast_build.ast, types).valid(), "typed AST semantic validation failed");
    require(stable_serialization_hash(*first.ast_build.ast) == stable_serialization_hash(*second.ast_build.ast),
        "typed AST construction is nondeterministic");
    const auto encoded_ast = serialize_typed_ast_v2(*first.ast_build.ast);
    const auto decoded_ast = deserialize_typed_ast_v2(encoded_ast);
    require(decoded_ast.valid(), "typed AST serialization did not round-trip");
    require(stable_serialization_hash(*first.ast_build.ast) == stable_serialization_hash(*decoded_ast.value),
        "typed AST serialization hash drifted");

    const auto& rendered = *first.rendering;
    const std::string expected =
        "int renderer_fixture(int arg0) {\n"
        "    int result;\n"
        "    result = (int)(1 + arg0);\n"
        "    return result;\n"
        "}\n";
    require(rendered.document->rendered_text == expected, "generated AST golden text drifted");
    require_source_map_coverage(*rendered.document);
    const auto encoded_document = serialize_pseudocode_document_v2(*rendered.document);
    const auto decoded_document = deserialize_pseudocode_document_v2(encoded_document);
    require(decoded_document.valid(), "renderer document serialization did not round-trip");
    require(stable_serialization_hash(*rendered.document) == stable_serialization_hash(*decoded_document.value),
        "renderer document serialization hash drifted");
}

void verify_structured_semantic_fixture(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    const auto ast = structured_ast(entity_value, types);
    require(validate_typed_ast_v2_semantics(ast, types).valid(), "structured control-flow AST was rejected");
    pseudocode_renderer_v2_request_t request;
    request.settings = pseudocode_renderer_v2_style_settings(pseudocode_renderer_v2_style_profile_t::balanced);
    const auto rendered = render_pseudocode_v2(ast, types, request);
    require(rendered.succeeded(), "renderer rejected structured control flow and exceptions");
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
    require_source_map_coverage(*rendered.document);
}

void verify_no_fabricated_body(const decompiler_entity_key_t& entity_value, const type_graph_t& types)
{
    auto hir = straight_line_hir(entity_value, types);
    hir.blocks.front().values.push_back(value(8, hir_node_kind_t::conditional, {}, {2}, entity_value));
    const auto result = decompiler_service_t::render_typed_pseudocode_v2(hir, types);
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
    auto hir = straight_line_hir(entity_value, types);
    hir.blocks.clear();
    const auto result = decompiler_service_t::render_typed_pseudocode_v2(hir, types);
    require(!result.succeeded(), "decompiler service accepted incomplete HIR");
    require(!result.rendering.has_value(), "decompiler service rendered incomplete HIR");
    require(std::any_of(result.ast_build.diagnostics.begin(), result.ast_build.diagnostics.end(),
        [](const decompiler_diagnostic_t& diagnostic) {
            return diagnostic.code == decompiler_diagnostic_code_t::malformed_hir &&
                   diagnostic.localization_key == "decompiler.hir.header";
        }), "decompiler service lost the strict incomplete-HIR diagnostic");
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
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_pseudocode_renderer_harness();
        std::cout << "pseudocode_renderer_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
