#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/builtin_typelib.hpp"
#include "../../src/core/analysis/decompiler/decompiler_service.hpp"
#include "../../src/core/analysis/decompiler/pseudocode_readability.hpp"
#include "../../src/core/analysis/decompiler/pseudocode_renderer.hpp"
#include "../../src/core/analysis/decompiler/type_graph_builder.hpp"
#include "../../src/core/analysis/decompiler/typed_ast.hpp"
#include "../../src/core/workbench/adapters/pseudocode_document.hpp"
#include "../../workers/native_decompiler/snapshot_sidecar.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
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

decompiler_entity_key_t entity()
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = 909;
    identity.entry = address(0x2000);
    identity.end = address(0x2400);
    identity.function_bytes_hash = stable_serialization_hash("c03-quality-differential-function");
    identity.canonical_symbol = "quality_fixture";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::native_function;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.identity = std::move(identity);
    return result;
}

source_coordinate_t coordinate(const decompiler_entity_key_t& entity_value,
                               const decompiler_coordinate_layer_t layer,
                               const std::uint64_t begin = 0x2000,
                               const std::uint64_t end = 0x2004)
{
    source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = 31;
    result.entity = entity_value;
    result.address_range = decompiler_address_range_t{address(begin), address(end)};
    result.instruction_range = decompiler_instruction_range_t{1, 1};
    return result;
}

decompiler_type_node_t make_type(const std::uint64_t id,
                                 const decompiler_type_kind_t kind,
                                 const std::string& name,
                                 const std::optional<std::uint64_t> byte_size,
                                 const bool is_signed = false)
{
    decompiler_type_node_t result;
    result.id = id;
    result.kind = kind;
    result.canonical_name = name;
    result.display_name = name;
    result.byte_size = byte_size;
    result.alignment = byte_size ? static_cast<std::uint32_t>(*byte_size) : 1;
    result.is_signed = is_signed;
    result.confidence = 100;
    result.provenance = decompiler_fact_provenance_t::provider_semantics;
    return result;
}

decompiler_type_edge_t make_member_edge(const std::uint64_t source,
                                        const std::uint64_t target,
                                        const decompiler_type_edge_kind_t kind,
                                        const std::string& name,
                                        const std::optional<std::uint64_t> offset)
{
    decompiler_type_edge_t result;
    result.source_type_id = source;
    result.target_type_id = target;
    result.kind = kind;
    result.stable_name = name;
    result.byte_offset = offset;
    result.confidence = 100;
    result.provenance = decompiler_fact_provenance_t::debug_metadata;
    return result;
}

struct fixture_graph_t {
    type_graph_t graph;

    static constexpr std::uint64_t int32 = 1;
    static constexpr std::uint64_t uint32 = 2;
    static constexpr std::uint64_t uint8 = 3;
    static constexpr std::uint64_t uint64 = 4;
    static constexpr std::uint64_t char_ptr = 5;
    static constexpr std::uint64_t sint32 = 6;
    static constexpr std::uint64_t struct_a = 10;
    static constexpr std::uint64_t struct_b = 11;
    static constexpr std::uint64_t ptr_a = 12;
    static constexpr std::uint64_t ptr_b = 13;
    static constexpr std::uint64_t struct_e = 14;
    static constexpr std::uint64_t ptr_e = 15;
    static constexpr std::uint64_t struct_s = 16;
    static constexpr std::uint64_t ptr_s = 17;
    static constexpr std::uint64_t union_u = 18;
    static constexpr std::uint64_t ptr_u = 19;
    static constexpr std::uint64_t float32 = 20;
    static constexpr std::uint64_t sint16 = 21;
    static constexpr std::uint64_t int_ptr = 22;
    static constexpr std::uint64_t uchar_ptr = 23;
    static constexpr std::uint64_t uchar = 24;
    static constexpr std::uint64_t int64 = 25;
    static constexpr std::uint64_t uint16 = 26;
};

fixture_graph_t fixture_graph(const decompiler_entity_key_t& entity_value)
{
    fixture_graph_t fixture;
    fixture.graph.entity = entity_value;
    fixture.graph.revision = 41;
    auto& g = fixture.graph;
    g.nodes.push_back(make_type(fixture_graph_t::int32, decompiler_type_kind_t::signed_integer, "int", 4, true));
    g.nodes.push_back(make_type(fixture_graph_t::uint32, decompiler_type_kind_t::unsigned_integer, "DWORD", 4));
    g.nodes.push_back(make_type(fixture_graph_t::uint8, decompiler_type_kind_t::unsigned_integer, "unsigned char", 1));
    g.nodes.push_back(make_type(fixture_graph_t::uint64, decompiler_type_kind_t::unsigned_integer, "unsigned __int64", 8));
    g.nodes.push_back(make_type(fixture_graph_t::char_ptr, decompiler_type_kind_t::pointer, "char *", 8));
    g.nodes.push_back(make_type(fixture_graph_t::sint32, decompiler_type_kind_t::signed_integer, "signed int", 4, true));
    g.nodes.push_back(make_type(fixture_graph_t::struct_a, decompiler_type_kind_t::structure, "struct_a", 16));
    g.nodes.push_back(make_type(fixture_graph_t::struct_b, decompiler_type_kind_t::structure, "struct_b", 16));
    g.nodes.push_back(make_type(fixture_graph_t::ptr_a, decompiler_type_kind_t::pointer, "struct_a *", 8));
    g.nodes.push_back(make_type(fixture_graph_t::ptr_b, decompiler_type_kind_t::pointer, "struct_b *", 8));
    g.nodes.push_back(make_type(fixture_graph_t::struct_e, decompiler_type_kind_t::structure, "struct_e", 8));
    g.nodes.push_back(make_type(fixture_graph_t::ptr_e, decompiler_type_kind_t::pointer, "struct_e *", 8));
    g.nodes.push_back(make_type(fixture_graph_t::struct_s, decompiler_type_kind_t::structure, "struct_s", 16));
    g.nodes.push_back(make_type(fixture_graph_t::ptr_s, decompiler_type_kind_t::pointer, "struct_s *", 8));
    g.nodes.push_back(make_type(fixture_graph_t::union_u, decompiler_type_kind_t::union_type, "union_u", 4));
    g.nodes.push_back(make_type(fixture_graph_t::ptr_u, decompiler_type_kind_t::pointer, "union_u *", 8));
    g.nodes.push_back(make_type(fixture_graph_t::float32, decompiler_type_kind_t::floating_point, "float", 4, true));
    g.nodes.push_back(make_type(fixture_graph_t::sint16, decompiler_type_kind_t::signed_integer, "short", 2, true));
    g.nodes.push_back(make_type(fixture_graph_t::int_ptr, decompiler_type_kind_t::pointer, "int *", 8));
    g.nodes.push_back(make_type(fixture_graph_t::uchar_ptr, decompiler_type_kind_t::pointer, "unsigned char *", 8));
    g.nodes.push_back(make_type(fixture_graph_t::uchar, decompiler_type_kind_t::unsigned_integer, "unsigned char", 1));
    g.nodes.push_back(make_type(fixture_graph_t::int64, decompiler_type_kind_t::signed_integer, "__int64", 8, true));
    g.nodes.push_back(make_type(fixture_graph_t::uint16, decompiler_type_kind_t::unsigned_integer, "unsigned short", 2));
    g.edges.push_back(make_member_edge(fixture_graph_t::struct_a, fixture_graph_t::ptr_b,
        decompiler_type_edge_kind_t::member, "b", 0));
    g.edges.push_back(make_member_edge(fixture_graph_t::struct_b, fixture_graph_t::int32,
        decompiler_type_edge_kind_t::member, "c", 8));
    g.edges.push_back(make_member_edge(fixture_graph_t::struct_e, fixture_graph_t::int32,
        decompiler_type_edge_kind_t::member, "field", 4));
    g.edges.push_back(make_member_edge(fixture_graph_t::struct_s, fixture_graph_t::int32,
        decompiler_type_edge_kind_t::member, "field", 8));
    g.edges.push_back(make_member_edge(fixture_graph_t::union_u, fixture_graph_t::sint32,
        decompiler_type_edge_kind_t::member, "as_int", 0));
    g.edges.push_back(make_member_edge(fixture_graph_t::union_u, fixture_graph_t::float32,
        decompiler_type_edge_kind_t::member, "as_float", 0));
    g.edges.push_back(make_member_edge(fixture_graph_t::ptr_a, fixture_graph_t::struct_a,
        decompiler_type_edge_kind_t::pointee, "pointee", std::nullopt));
    g.edges.push_back(make_member_edge(fixture_graph_t::ptr_b, fixture_graph_t::struct_b,
        decompiler_type_edge_kind_t::pointee, "pointee", std::nullopt));
    g.edges.push_back(make_member_edge(fixture_graph_t::ptr_e, fixture_graph_t::struct_e,
        decompiler_type_edge_kind_t::pointee, "pointee", std::nullopt));
    g.edges.push_back(make_member_edge(fixture_graph_t::ptr_s, fixture_graph_t::struct_s,
        decompiler_type_edge_kind_t::pointee, "pointee", std::nullopt));
    g.edges.push_back(make_member_edge(fixture_graph_t::ptr_u, fixture_graph_t::union_u,
        decompiler_type_edge_kind_t::pointee, "pointee", std::nullopt));
    g.edges.push_back(make_member_edge(fixture_graph_t::char_ptr, fixture_graph_t::uchar,
        decompiler_type_edge_kind_t::pointee, "pointee", std::nullopt));
    g.edges.push_back(make_member_edge(fixture_graph_t::int_ptr, fixture_graph_t::int32,
        decompiler_type_edge_kind_t::pointee, "pointee", std::nullopt));
    g.edges.push_back(make_member_edge(fixture_graph_t::uchar_ptr, fixture_graph_t::uchar,
        decompiler_type_edge_kind_t::pointee, "pointee", std::nullopt));
    return fixture;
}

typed_pseudocode_ast_node_t node(const std::uint64_t id,
                                 const typed_pseudocode_ast_node_kind_t kind,
                                 const std::uint64_t type_id,
                                 std::vector<std::uint64_t> children,
                                 std::string text,
                                 const decompiler_entity_key_t& entity_value,
                                 const std::uint64_t address_begin = 0x2000)
{
    typed_pseudocode_ast_node_t result;
    result.id = id;
    result.kind = kind;
    result.type_id = type_id;
    result.child_ids = std::move(children);
    result.stable_text = std::move(text);
    result.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::typed_ast,
        address_begin, address_begin + 4);
    result.confidence = 100;
    result.provenance = decompiler_fact_provenance_t::semantic_proof;
    return result;
}

struct ast_builder_t {
    typed_pseudocode_ast_v2_t ast;
    std::uint64_t next_id = 1;

    explicit ast_builder_t(const decompiler_entity_key_t& entity_value,
                           const type_graph_t& types,
                           const char* hir_seed)
    {
        ast.entity = entity_value;
        ast.hir_hash = stable_serialization_hash(hir_seed);
        ast.type_graph_hash = stable_serialization_hash(types);
    }

    std::uint64_t add(const typed_pseudocode_ast_node_kind_t kind,
                      const std::uint64_t type_id,
                      std::vector<std::uint64_t> children,
                      std::string text,
                      const decompiler_entity_key_t& entity_value)
    {
        const auto id = next_id++;
        ast.nodes.push_back(node(id, kind, type_id, std::move(children), std::move(text), entity_value));
        return id;
    }

    typed_pseudocode_ast_v2_t finish(const std::uint64_t root, const std::uint64_t body)
    {
        ast.root_node_id = root;
        ast.body_node_id = body;
        return ast;
    }
};

struct render_result_t {
    decompiler_document_t document;
    std::string text;
};

render_result_t render_checked(const typed_pseudocode_ast_v2_t& ast_value,
                               const type_graph_t& types,
                               const decompiler_render_evidence_t* evidence = nullptr)
{
    pseudocode_renderer_request_t request;
    request.profile = decompiler_profile_id_t::balanced;
    request.settings = pseudocode_renderer_style_settings(
        pseudocode_renderer_style_profile_t::balanced);
    if (evidence != nullptr) {
        static std::shared_ptr<const decompiler_render_evidence_t> shared_evidence;
        shared_evidence = std::make_shared<const decompiler_render_evidence_t>(*evidence);
        request.evidence = shared_evidence;
    }
    auto rendered = render_pseudocode(ast_value, types, request);
    require(rendered.succeeded() && rendered.document.has_value(),
        "quality fixture renderer rejected a valid typed AST");
    render_result_t result;
    result.text = rendered.document->rendered_text;
    result.document = std::move(*rendered.document);
    return result;
}

struct transform_result_t {
    typed_pseudocode_ast_v2_t ast;
    readability_transform_result_t result;
};

transform_result_t transform_checked(typed_pseudocode_ast_v2_t ast_value,
                                     const type_graph_t& types,
                                     const decompiler_render_evidence_t& evidence,
                                     const readability_transform_settings_t& settings = {})
{
    transform_result_t outcome;
    outcome.result = apply_readability_transforms(ast_value, types, settings, evidence);
    outcome.ast = std::move(ast_value);
    require(outcome.result.diagnostics.empty() ||
            std::none_of(outcome.result.diagnostics.begin(), outcome.result.diagnostics.end(),
                [](const decompiler_diagnostic_t& diagnostic) {
                    return diagnostic.localization_key == "readability.node_limit_exceeded";
                }),
        "quality fixture hit the transform node limit");
    return outcome;
}

struct skeleton_t {
    std::size_t goto_count = 0;
    std::size_t statement_count = 0;
    std::size_t switch_count = 0;
    std::size_t return_count = 0;
};

skeleton_t skeleton_of(const std::string& text)
{
    skeleton_t result;
    const auto count_occurrences = [&text](const std::string& needle) {
        std::size_t count = 0;
        std::size_t position = 0;
        while ((position = text.find(needle, position)) != std::string::npos) {
            ++count;
            position += needle.size();
        }
        return count;
    };
    result.goto_count = count_occurrences("goto ");
    result.switch_count = count_occurrences("switch (");
    result.return_count = count_occurrences("return ");
    std::size_t statements = 0;
    for (const char character : text) {
        if (character == ';')
            ++statements;
    }
    result.statement_count = statements;
    return result;
}

void require_deterministic_transforms(const typed_pseudocode_ast_v2_t& source,
                                      const type_graph_t& types,
                                      const decompiler_render_evidence_t& evidence)
{
    auto first_ast = source;
    auto second_ast = source;
    const auto first = apply_readability_transforms(first_ast, types, {}, evidence);
    const auto second = apply_readability_transforms(second_ast, types, {}, evidence);
    require(stable_serialization_hash(first_ast) == stable_serialization_hash(second_ast),
        "readability transforms are not byte-identical across two runs on a quality fixture");
    require(first.diagnostics.size() == second.diagnostics.size(),
        "readability transform diagnostics diverged across two runs");
}

decompiler_string_evidence_t string_evidence(const std::uint64_t absolute_address,
                                             const std::string& content,
                                             const bool is_wide = false,
                                             const bool truncated = false)
{
    decompiler_string_evidence_t entry;
    entry.reference_text = "sub_" + std::to_string(absolute_address);
    entry.utf8_content = content;
    entry.is_wide = is_wide;
    entry.confidence = 100;
    entry.absolute_address = absolute_address;
    entry.truncated = truncated;
    entry.original_byte_length = static_cast<std::uint32_t>(content.size() * (is_wide ? 2 : 1));
    return entry;
}

void verify_string_inline(const decompiler_entity_key_t& entity_value,
                          const type_graph_t& types)
{
    constexpr std::uint64_t string_address = 0x400210;
    ast_builder_t builder(entity_value, types, "c03-quality-string-inline");
    const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
        fixture_graph_t::int32, {}, "string_inline_fixture", entity_value);
    const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto call = builder.add(typed_pseudocode_ast_node_kind_t::call_expression,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto callee = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "print_text", entity_value);
    const auto argument = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::char_ptr, {}, "4202512", entity_value);
    auto& ast = builder.ast;
    ast.nodes[root - 1].child_ids = {body};
    ast.nodes[body - 1].child_ids = {statement};
    ast.nodes[statement - 1].child_ids = {call};
    ast.nodes[call - 1].child_ids = {callee, argument};
    const auto source = builder.finish(root, body);
    require(validate_typed_pseudocode_ast(source).valid(),
        "string_inline fixture is not a valid typed AST");

    decompiler_render_evidence_t evidence;
    evidence.strings.push_back(string_evidence(string_address, "Hello, AiDA"));
    require_deterministic_transforms(source, types, evidence);
    auto transformed = transform_checked(source, types, evidence);
    require(transformed.result.metrics.string_literals_inlined == 1,
        "string_inline substitution did not fire exactly once");
    const auto rendered = render_checked(transformed.ast, types, &evidence);
    require(rendered.text.find("\"Hello, AiDA\"") != std::string::npos,
        "string_inline render lacks the quoted literal at the call argument");
    const auto call_line = rendered.text.substr(rendered.text.find("print_text"));
    require(call_line.find("4202512") == std::string::npos,
        "string_inline render retained the literal address at the call argument");

    pseudocode_readability_request_t analysis_request;
    const auto report = analyze_pseudocode_readability(transformed.ast, rendered.document, analysis_request);
    require(report.succeeded() && report.report.has_value(),
        "string_inline readability analysis failed");
    require(report.report->metrics.naming_consistency_ratio >= 0.9,
        "string_inline naming consistency fell below the acceptance floor with evidence present");
    require(report.report->metrics.fabricated_body_count == 0 &&
            report.report->source_map_coverage_ratio == 1.0,
        "string_inline violated the fabricated-body or source-map gates");

    decompiler_render_evidence_t wide_evidence;
    wide_evidence.strings.push_back(string_evidence(string_address, "Wide", true, true));
    auto wide_transformed = transform_checked(source, types, wide_evidence);
    const auto wide_rendered = render_checked(wide_transformed.ast, types, &wide_evidence);
    require(wide_rendered.text.find("L\"Wide\"") != std::string::npos,
        "string_inline wide fixture lacks the L-prefixed literal");
}

void verify_scalar_and_comment_channels(const decompiler_entity_key_t& entity_value,
                                        const type_graph_t& types)
{
    constexpr std::uint64_t scalar_address = 0x401000;
    ast_builder_t builder(entity_value, types, "c03-quality-scalar-comment");
    const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
        fixture_graph_t::int32, {}, "scalar_fixture", entity_value);
    const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto call = builder.add(typed_pseudocode_ast_node_kind_t::call_expression,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto callee = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "print_value", entity_value);
    const auto literal = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::uint64, {}, "4198400", entity_value);
    auto& ast = builder.ast;
    ast.nodes[root - 1].child_ids = {body};
    ast.nodes[body - 1].child_ids = {statement};
    ast.nodes[statement - 1].child_ids = {call};
    ast.nodes[call - 1].child_ids = {callee, literal};
    const auto source = builder.finish(root, body);

    decompiler_render_evidence_t evidence;
    decompiler_global_scalar_evidence_t scalar;
    scalar.absolute_address = scalar_address;
    scalar.value = 42;
    scalar.size_log2 = 2;
    evidence.global_scalars.push_back(scalar);
    decompiler_user_comment_evidence_t comment;
    comment.comment_text = "entry comment";
    comment.before_statement = true;
    comment.confidence = 100;
    comment.rva = 0x2000;
    evidence.user_comments.push_back(comment);
    auto transformed = transform_checked(source, types, evidence);
    require(transformed.result.metrics.global_scalar_comments_injected == 1,
        "global scalar trailing comment did not fire exactly once");
    require(transformed.result.metrics.user_comments_injected == 1,
        "address-anchored user comment did not fire exactly once");
    const auto rendered = render_checked(transformed.ast, types, &evidence);
    require(rendered.text.find("// = 42 (0x2a)") != std::string::npos,
        "global scalar comment text missing from the render");
    require(rendered.text.find("// entry comment") != std::string::npos,
        "address-anchored user comment text missing from the render");
}

void verify_member_chain(const decompiler_entity_key_t& entity_value,
                         const type_graph_t& types)
{
    ast_builder_t builder(entity_value, types, "c03-quality-member-chain");
    const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
        fixture_graph_t::int32, {}, "member_chain_fixture", entity_value);
    const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto declaration = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::ptr_a, {}, "base", entity_value);
    const auto statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto outer_deref = builder.add(typed_pseudocode_ast_node_kind_t::unary_expression,
        fixture_graph_t::int32, {}, "*", entity_value);
    const auto outer_add = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::ptr_b, {}, "+", entity_value);
    const auto inner_deref = builder.add(typed_pseudocode_ast_node_kind_t::unary_expression,
        fixture_graph_t::ptr_b, {}, "*", entity_value);
    const auto inner_add = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::ptr_a, {}, "+", entity_value);
    const auto base_identifier = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::ptr_a, {}, "base", entity_value);
    const auto zero = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::uint32, {}, "0", entity_value);
    const auto eight = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::uint32, {}, "8", entity_value);
    auto& ast = builder.ast;
    ast.nodes[root - 1].child_ids = {declaration, body};
    ast.nodes[body - 1].child_ids = {statement};
    ast.nodes[statement - 1].child_ids = {outer_deref};
    ast.nodes[outer_deref - 1].child_ids = {outer_add};
    ast.nodes[outer_add - 1].child_ids = {inner_deref, eight};
    ast.nodes[inner_deref - 1].child_ids = {inner_add};
    ast.nodes[inner_add - 1].child_ids = {base_identifier, zero};
    const auto source = builder.finish(root, body);

    const decompiler_render_evidence_t evidence;
    require_deterministic_transforms(source, types, evidence);
    auto transformed = transform_checked(source, types, evidence);
    require(transformed.result.metrics.member_accesses_rewritten >= 2,
        "member_chain did not rewrite both deref levels");
    const auto rendered = render_checked(transformed.ast, types, &evidence);
    require(rendered.text.find("base->b->c") != std::string::npos,
        "member_chain render lacks base->b->c");
}

void verify_array_member(const decompiler_entity_key_t& entity_value,
                         const type_graph_t& types)
{
    ast_builder_t builder(entity_value, types, "c03-quality-array-member");
    const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
        fixture_graph_t::int32, {}, "array_member_fixture", entity_value);
    const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto base_decl = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::ptr_e, {}, "base", entity_value);
    const auto index_decl = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::int32, {}, "i", entity_value);
    const auto statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto deref = builder.add(typed_pseudocode_ast_node_kind_t::unary_expression,
        fixture_graph_t::int32, {}, "*", entity_value);
    const auto outer_add = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::ptr_e, {}, "+", entity_value);
    const auto inner_add = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::ptr_e, {}, "+", entity_value);
    const auto base_identifier = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::ptr_e, {}, "base", entity_value);
    const auto scale = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::uint64, {}, "*", entity_value);
    const auto index_identifier = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "i", entity_value);
    const auto eight = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::uint32, {}, "8", entity_value);
    const auto four = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::uint32, {}, "4", entity_value);
    auto& ast = builder.ast;
    ast.nodes[root - 1].child_ids = {base_decl, index_decl, body};
    ast.nodes[body - 1].child_ids = {statement};
    ast.nodes[statement - 1].child_ids = {deref};
    ast.nodes[deref - 1].child_ids = {outer_add};
    ast.nodes[outer_add - 1].child_ids = {inner_add, four};
    ast.nodes[inner_add - 1].child_ids = {base_identifier, scale};
    ast.nodes[scale - 1].child_ids = {index_identifier, eight};
    const auto source = builder.finish(root, body);

    const decompiler_render_evidence_t evidence;
    require_deterministic_transforms(source, types, evidence);
    auto transformed = transform_checked(source, types, evidence);
    require(transformed.result.metrics.member_accesses_rewritten == 1,
        "array_member did not rewrite exactly once");
    const auto rendered = render_checked(transformed.ast, types, &evidence);
    require(rendered.text.find("base[i].field") != std::string::npos,
        "array_member render lacks base[i].field");
}

void verify_thiscall_this(const decompiler_entity_key_t& entity_value,
                          const type_graph_t& types)
{
    ast_builder_t builder(entity_value, types, "c03-quality-thiscall");
    const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
        fixture_graph_t::int32, {}, "thiscall_fixture", entity_value);
    const auto this_decl = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::ptr_s, {}, "param_1", entity_value);
    const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto deref = builder.add(typed_pseudocode_ast_node_kind_t::unary_expression,
        fixture_graph_t::int32, {}, "*", entity_value);
    const auto add = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::ptr_s, {}, "+", entity_value);
    const auto this_identifier = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::ptr_s, {}, "param_1", entity_value);
    const auto eight = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::uint32, {}, "8", entity_value);
    auto& ast = builder.ast;
    ast.nodes[root - 1].child_ids = {this_decl, body};
    ast.nodes[body - 1].child_ids = {statement};
    ast.nodes[statement - 1].child_ids = {deref};
    ast.nodes[deref - 1].child_ids = {add};
    ast.nodes[add - 1].child_ids = {this_identifier, eight};
    const auto source = builder.finish(root, body);

    const decompiler_render_evidence_t evidence;
    require_deterministic_transforms(source, types, evidence);
    auto transformed = transform_checked(source, types, evidence);
    require(transformed.result.metrics.member_accesses_rewritten == 1,
        "thiscall member rewrite did not fire exactly once");
    const auto rendered = render_checked(transformed.ast, types, &evidence);
    require(rendered.text.find("this->field") != std::string::npos,
        "thiscall render lacks this->field");
    require(rendered.text.find("param_1") == std::string::npos,
        "thiscall render retained the generated parameter name");
}

void verify_union_selection(const decompiler_entity_key_t& entity_value,
                            const type_graph_t& types)
{
    const auto make_union_ast = [&entity_value, &types](const std::uint64_t read_type) {
        ast_builder_t builder(entity_value, types, "c03-quality-union");
        const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
            fixture_graph_t::int32, {}, "union_fixture", entity_value);
        const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
            fixture_graph_t::int32, {}, {}, entity_value);
        const auto declaration = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
            fixture_graph_t::ptr_u, {}, "base", entity_value);
        const auto statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
            fixture_graph_t::int32, {}, {}, entity_value);
        const auto deref = builder.add(typed_pseudocode_ast_node_kind_t::unary_expression,
            read_type, {}, "*", entity_value);
        const auto add = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
            fixture_graph_t::ptr_u, {}, "+", entity_value);
        const auto base_identifier = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
            fixture_graph_t::ptr_u, {}, "base", entity_value);
        const auto zero = builder.add(typed_pseudocode_ast_node_kind_t::literal,
            fixture_graph_t::uint32, {}, "0", entity_value);
        auto& ast = builder.ast;
        ast.nodes[root - 1].child_ids = {declaration, body};
        ast.nodes[body - 1].child_ids = {statement};
        ast.nodes[statement - 1].child_ids = {deref};
        ast.nodes[deref - 1].child_ids = {add};
        ast.nodes[add - 1].child_ids = {base_identifier, zero};
        return builder.finish(root, body);
    };
    const decompiler_render_evidence_t evidence;
    const auto int_source = make_union_ast(fixture_graph_t::sint32);
    require_deterministic_transforms(int_source, types, evidence);
    auto int_transformed = transform_checked(int_source, types, evidence);
    require(int_transformed.result.metrics.member_accesses_rewritten == 1,
        "union int-typed read did not rewrite exactly once");
    const auto int_rendered = render_checked(int_transformed.ast, types, &evidence);
    require(int_rendered.text.find("base->as_int") != std::string::npos,
        "union int-typed read did not select as_int");

    const auto short_source = make_union_ast(fixture_graph_t::sint16);
    auto short_transformed = transform_checked(short_source, types, evidence);
    require(short_transformed.result.metrics.member_accesses_rewritten == 0,
        "union ambiguous read rewrote instead of degrading gracefully");
    const auto short_rendered = render_checked(short_transformed.ast, types, &evidence);
    require(short_rendered.text.find("as_float") == std::string::npos &&
            short_rendered.text.find("as_int") == std::string::npos,
        "union ambiguous read selected a member");
}

void verify_cast_noise(const decompiler_entity_key_t& entity_value,
                       const type_graph_t& types)
{
    ast_builder_t builder(entity_value, types, "c03-quality-cast-noise");
    const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
        fixture_graph_t::int32, {}, "cast_noise_fixture", entity_value);
    const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto decl_x = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::uint32, {}, "x", entity_value);
    const auto decl_y = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::uint32, {}, "y", entity_value);
    const auto mask_statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto mask_assign = builder.add(typed_pseudocode_ast_node_kind_t::assignment_expression,
        fixture_graph_t::int32, {}, "=", entity_value);
    const auto mask_target = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, "x", entity_value);
    const auto mask_cast = builder.add(typed_pseudocode_ast_node_kind_t::cast_expression,
        fixture_graph_t::uint8, {}, "unsigned char", entity_value);
    const auto mask_and = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::uint32, {}, "&", entity_value);
    const auto mask_x = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, "y", entity_value);
    const auto mask_literal = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::uint32, {}, "255", entity_value);
    const auto same_statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto same_assign = builder.add(typed_pseudocode_ast_node_kind_t::assignment_expression,
        fixture_graph_t::int32, {}, "=", entity_value);
    const auto same_target = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, "x", entity_value);
    const auto same_cast = builder.add(typed_pseudocode_ast_node_kind_t::cast_expression,
        fixture_graph_t::uint32, {}, "unsigned int", entity_value);
    const auto same_y = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, "y", entity_value);
    const auto nested_statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto nested_cast_outer = builder.add(typed_pseudocode_ast_node_kind_t::cast_expression,
        fixture_graph_t::uint32, {}, "unsigned int", entity_value);
    const auto nested_cast_inner = builder.add(typed_pseudocode_ast_node_kind_t::cast_expression,
        fixture_graph_t::uint32, {}, "unsigned int", entity_value);
    const auto nested_x = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, "x", entity_value);
    auto& ast = builder.ast;
    ast.nodes[root - 1].child_ids = {decl_x, decl_y, body};
    ast.nodes[body - 1].child_ids = {mask_statement, same_statement, nested_statement};
    ast.nodes[mask_statement - 1].child_ids = {mask_assign};
    ast.nodes[mask_assign - 1].child_ids = {mask_target, mask_cast};
    ast.nodes[mask_cast - 1].child_ids = {mask_and};
    ast.nodes[mask_and - 1].child_ids = {mask_x, mask_literal};
    ast.nodes[same_statement - 1].child_ids = {same_assign};
    ast.nodes[same_assign - 1].child_ids = {same_target, same_cast};
    ast.nodes[same_cast - 1].child_ids = {same_y};
    ast.nodes[nested_statement - 1].child_ids = {nested_cast_outer};
    ast.nodes[nested_cast_outer - 1].child_ids = {nested_cast_inner};
    ast.nodes[nested_cast_inner - 1].child_ids = {nested_x};
    const auto source = builder.finish(root, body);

    const decompiler_render_evidence_t evidence;
    const auto count_casts = [](const typed_pseudocode_ast_v2_t& value) {
        std::uint64_t count = 0;
        for (const auto& node_value : value.nodes) {
            if (node_value.kind == typed_pseudocode_ast_node_kind_t::cast_expression)
                ++count;
        }
        return count;
    };
    const std::uint64_t pre_casts = count_casts(source);
    require_deterministic_transforms(source, types, evidence);
    auto transformed = transform_checked(source, types, evidence);
    const std::uint64_t post_casts = count_casts(transformed.ast);
    require(pre_casts == 4, "cast_noise fixture shape drifted before transforms");
    require(post_casts * 10 <= pre_casts * 7,
        "cast_noise cast count was not reduced by at least 30 percent");
    require(transformed.result.metrics.cast_masks_folded == 1,
        "cast_noise mask fold did not fire exactly once");
    const auto rendered = render_checked(transformed.ast, types, &evidence);
    require(rendered.text.find("(unsigned char)(y & 255)") == std::string::npos &&
            rendered.text.find("(unsigned char)") == std::string::npos,
        "cast_noise render retained the folded mask cast");
}

typed_pseudocode_ast_v2_t make_loop_ast(const decompiler_entity_key_t& entity_value,
                                        const type_graph_t& types,
                                        const bool memcpy_form,
                                        const char* seed)
{
    ast_builder_t builder(entity_value, types, seed);
    const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
        fixture_graph_t::int32, {}, memcpy_form ? "loop_memcpy_fixture" : "loop_memset_fixture",
        entity_value);
    const auto dst_type = memcpy_form ? fixture_graph_t::int_ptr : fixture_graph_t::uchar_ptr;
    const auto dst_decl = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        dst_type, {}, "dst", entity_value);
    const auto src_decl = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::int_ptr, {}, "src", entity_value);
    const auto count_decl = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::int32, {}, "n", entity_value);
    const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto loop = builder.add(typed_pseudocode_ast_node_kind_t::for_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto init = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::int32, {}, "i", entity_value);
    const auto zero = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::int32, {}, "0", entity_value);
    const auto condition = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::int32, {}, "<", entity_value);
    const auto condition_i = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "i", entity_value);
    const auto condition_n = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "n", entity_value);
    const auto increment = builder.add(typed_pseudocode_ast_node_kind_t::assignment_expression,
        fixture_graph_t::int32, {}, "=", entity_value);
    const auto increment_target = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "i", entity_value);
    const auto increment_add = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::int32, {}, "+", entity_value);
    const auto increment_i = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "i", entity_value);
    const auto one = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::int32, {}, "1", entity_value);
    const auto loop_body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto store_statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto store = builder.add(typed_pseudocode_ast_node_kind_t::assignment_expression,
        fixture_graph_t::int32, {}, "=", entity_value);
    const auto dst_index = builder.add(typed_pseudocode_ast_node_kind_t::index_expression,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto dst_identifier = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        dst_type, {}, "dst", entity_value);
    const auto dst_subscript = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "i", entity_value);
    const auto value = memcpy_form
        ? builder.add(typed_pseudocode_ast_node_kind_t::index_expression,
            fixture_graph_t::int32, {}, {}, entity_value)
        : builder.add(typed_pseudocode_ast_node_kind_t::literal,
            fixture_graph_t::int32, {}, "0", entity_value);
    std::uint64_t src_identifier = 0;
    std::uint64_t src_subscript = 0;
    if (memcpy_form) {
        src_identifier = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
            fixture_graph_t::int_ptr, {}, "src", entity_value);
        src_subscript = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
            fixture_graph_t::int32, {}, "i", entity_value);
    }
    auto& ast = builder.ast;
    std::vector<std::uint64_t> root_children{dst_decl, count_decl, body};
    if (memcpy_form)
        root_children.insert(root_children.begin() + 1, src_decl);
    ast.nodes[root - 1].child_ids = std::move(root_children);
    ast.nodes[body - 1].child_ids = {loop};
    ast.nodes[loop - 1].child_ids = {init, condition, increment, loop_body};
    ast.nodes[init - 1].child_ids = {zero};
    ast.nodes[condition - 1].child_ids = {condition_i, condition_n};
    ast.nodes[increment - 1].child_ids = {increment_target, increment_add};
    ast.nodes[increment_add - 1].child_ids = {increment_i, one};
    ast.nodes[loop_body - 1].child_ids = {store_statement};
    ast.nodes[store_statement - 1].child_ids = {store};
    ast.nodes[dst_index - 1].child_ids = {dst_identifier, dst_subscript};
    if (memcpy_form) {
        ast.nodes[store - 1].child_ids = {dst_index, value};
        ast.nodes[value - 1].child_ids = {src_identifier, src_subscript};
    } else {
        ast.nodes[store - 1].child_ids = {dst_index, value};
    }
    return builder.finish(root, body);
}

void verify_loop_intrinsics(const decompiler_entity_key_t& entity_value,
                            const type_graph_t& types)
{
    const decompiler_render_evidence_t evidence;
    const auto memset_source = make_loop_ast(entity_value, types, false, "c03-quality-loop-memset");
    require(validate_typed_pseudocode_ast(memset_source).valid(),
        "loop_memset fixture is not a valid typed AST");
    require_deterministic_transforms(memset_source, types, evidence);
    auto memset_transformed = transform_checked(memset_source, types, evidence);
    require(memset_transformed.result.metrics.loop_intrinsics_rewritten == 1,
        "loop_memset was not rewritten exactly once");
    const auto memset_rendered = render_checked(memset_transformed.ast, types, &evidence);
    require(memset_rendered.text.find("memset(dst, 0, n)") != std::string::npos,
        "loop_memset render lacks memset(dst, 0, n)");
    require(memset_rendered.text.find("for (") == std::string::npos,
        "loop_memset render retained the loop");

    const auto memcpy_source = make_loop_ast(entity_value, types, true, "c03-quality-loop-memcpy");
    require_deterministic_transforms(memcpy_source, types, evidence);
    auto memcpy_transformed = transform_checked(memcpy_source, types, evidence);
    require(memcpy_transformed.result.metrics.loop_intrinsics_rewritten == 1,
        "loop_memcpy was not rewritten exactly once");
    const auto memcpy_rendered = render_checked(memcpy_transformed.ast, types, &evidence);
    require(memcpy_rendered.text.find("memcpy(dst, src, n * 4)") != std::string::npos,
        "loop_memcpy render lacks memcpy(dst, src, n * 4)");

    const auto aida_skeleton = skeleton_of(memset_rendered.text);
    const skeleton_t printc_reference{0, 2, 0, 0};
    require(aida_skeleton.goto_count <= printc_reference.goto_count &&
            aida_skeleton.statement_count >= 1 && aida_skeleton.statement_count <= 3 &&
            aida_skeleton.switch_count == printc_reference.switch_count,
        "loop_memset AiDA skeleton exceeded the PrintC reference skeleton");

    pseudocode_baseline_capture_request_t baseline;
    baseline.provider = pseudocode_baseline_provider_t::aida_current;
    baseline.provider_build_hash = stable_serialization_hash("c03-quality-provider-build");
    baseline.fixture_set_hash = stable_serialization_hash("c03-quality-fixture-set");
    baseline.fixture_id = "native/loop_memset_fixture";
    baseline.rendered_text = memset_rendered.text;
    const auto baseline_capture = capture_pseudocode_readability_baseline(baseline);
    require(baseline_capture.succeeded() && baseline_capture.capture.has_value(),
        "loop_memset baseline capture failed");
    require(baseline_capture.capture->rendered_text_hash == stable_serialization_hash(memset_rendered.text),
        "loop_memset baseline hash pin drifted from the AiDA render");
    const auto baseline_second = capture_pseudocode_readability_baseline(baseline);
    require(baseline_second.succeeded() &&
            baseline_second.capture->capture_hash == baseline_capture.capture->capture_hash,
        "loop_memset baseline capture is not deterministic");
}

void verify_bit_idioms(const decompiler_entity_key_t& entity_value,
                       const type_graph_t& types)
{
    ast_builder_t builder(entity_value, types, "c03-quality-rotate-bswap");
    const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
        fixture_graph_t::uint32, {}, "rotate_bswap_fixture", entity_value);
    const auto decl_x = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::uint32, {}, "x", entity_value);
    const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::uint32, {}, {}, entity_value);
    const auto rotate_statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::uint32, {}, {}, entity_value);
    const auto rotate_assign = builder.add(typed_pseudocode_ast_node_kind_t::assignment_expression,
        fixture_graph_t::uint32, {}, "=", entity_value);
    const auto rotate_target = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, "x", entity_value);
    const auto rotate_or = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::uint32, {}, "|", entity_value);
    const auto rotate_shl = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::uint32, {}, "<<", entity_value);
    const auto rotate_x_left = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, "x", entity_value);
    const auto rotate_k = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::uint32, {}, "8", entity_value);
    const auto rotate_shr = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::uint32, {}, ">>", entity_value);
    const auto rotate_x_right = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, "x", entity_value);
    const auto rotate_wk = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::uint32, {}, "24", entity_value);
    const auto bswap_statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::uint32, {}, {}, entity_value);
    const auto bswap_assign = builder.add(typed_pseudocode_ast_node_kind_t::assignment_expression,
        fixture_graph_t::uint32, {}, "=", entity_value);
    const auto bswap_target = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, "x", entity_value);
    const auto or3 = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::uint32, {}, "|", entity_value);
    const auto or2 = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::uint32, {}, "|", entity_value);
    const auto or1 = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::uint32, {}, "|", entity_value);
    std::uint64_t term_ids[4]{};
    const auto make_term = [&builder, &entity_value](const bool shifted_mask,
                                                     const char* mask,
                                                     const char* shift) {
        std::vector<std::uint64_t> mask_children;
        if (shifted_mask) {
            const auto shr = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
                fixture_graph_t::uint32, {}, ">>", entity_value);
            const auto x = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
                fixture_graph_t::uint32, {}, "x", entity_value);
            const auto amount = builder.add(typed_pseudocode_ast_node_kind_t::literal,
                fixture_graph_t::uint32, {}, shift, entity_value);
            builder.ast.nodes[shr - 1].child_ids = {x, amount};
            mask_children.push_back(shr);
        } else {
            const auto x = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
                fixture_graph_t::uint32, {}, "x", entity_value);
            mask_children.push_back(x);
        }
        const auto mask_node = builder.add(typed_pseudocode_ast_node_kind_t::literal,
            fixture_graph_t::uint32, {}, mask, entity_value);
        const auto and_node = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
            fixture_graph_t::uint32, {}, "&", entity_value);
        builder.ast.nodes[and_node - 1].child_ids = {mask_children[0], mask_node};
        if (!shifted_mask) {
            const auto shl = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
                fixture_graph_t::uint32, {}, "<<", entity_value);
            const auto amount = builder.add(typed_pseudocode_ast_node_kind_t::literal,
                fixture_graph_t::uint32, {}, shift, entity_value);
            builder.ast.nodes[shl - 1].child_ids = {and_node, amount};
            return shl;
        }
        return and_node;
    };
    term_ids[0] = make_term(false, "255", "24");
    term_ids[1] = make_term(false, "65280", "8");
    term_ids[2] = make_term(true, "65280", "8");
    term_ids[3] = make_term(true, "255", "24");
    const auto return_statement = builder.add(typed_pseudocode_ast_node_kind_t::return_statement,
        fixture_graph_t::uint32, {}, {}, entity_value);
    const auto return_x = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, "x", entity_value);
    auto& ast = builder.ast;
    ast.nodes[root - 1].child_ids = {decl_x, body};
    ast.nodes[body - 1].child_ids = {rotate_statement, bswap_statement, return_statement};
    ast.nodes[return_statement - 1].child_ids = {return_x};
    ast.nodes[rotate_statement - 1].child_ids = {rotate_assign};
    ast.nodes[rotate_assign - 1].child_ids = {rotate_target, rotate_or};
    ast.nodes[rotate_or - 1].child_ids = {rotate_shl, rotate_shr};
    ast.nodes[rotate_shl - 1].child_ids = {rotate_x_left, rotate_k};
    ast.nodes[rotate_shr - 1].child_ids = {rotate_x_right, rotate_wk};
    ast.nodes[bswap_statement - 1].child_ids = {bswap_assign};
    ast.nodes[bswap_assign - 1].child_ids = {bswap_target, or3};
    ast.nodes[or3 - 1].child_ids = {or2, term_ids[3]};
    ast.nodes[or2 - 1].child_ids = {or1, term_ids[2]};
    ast.nodes[or1 - 1].child_ids = {term_ids[0], term_ids[1]};
    const auto source = builder.finish(root, body);
    require(validate_typed_pseudocode_ast(source).valid(),
        "rotate_bswap fixture is not a valid typed AST");

    const decompiler_render_evidence_t evidence;
    require_deterministic_transforms(source, types, evidence);
    auto transformed = transform_checked(source, types, evidence);
    require(transformed.result.metrics.bit_operation_idioms_rewritten == 2,
        "rotate_bswap did not rewrite exactly two idioms");
    const auto rendered = render_checked(transformed.ast, types, &evidence);
    require(rendered.text.find("_rotl(x, 8)") != std::string::npos,
        "rotate_bswap render lacks _rotl(x, 8)");
    require(rendered.text.find("_byteswap_ulong(x)") != std::string::npos,
        "rotate_bswap render lacks _byteswap_ulong(x)");
}

void verify_magic_division(const decompiler_entity_key_t& entity_value,
                           const type_graph_t& types)
{
    static constexpr struct {
        std::uint32_t divisor;
        std::uint32_t multiplier;
        std::uint8_t shift;
    } k_rows[] = {
        {3, 0xAAAAAAABU, 33}, {5, 0xCCCCCCCDU, 34}, {6, 0xAAAAAAABU, 34},
        {9, 0x38E38E39U, 33}, {10, 0xCCCCCCCDU, 35}, {11, 0xBA2E8BA3U, 35},
        {12, 0xAAAAAAABU, 35}, {13, 0x4EC4EC4FU, 34}, {15, 0x88888889U, 35},
        {100, 0x51EB851FU, 37}, {1000, 0x10624DD3U, 38},
    };
    const decompiler_render_evidence_t evidence;
    for (const auto& row : k_rows) {
        ast_builder_t builder(entity_value, types, "c03-quality-magic-div");
        const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
            fixture_graph_t::uint32, {}, "magic_div_fixture", entity_value);
        const auto decl_x = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
            fixture_graph_t::uint32, {}, "x", entity_value);
        const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
            fixture_graph_t::uint32, {}, {}, entity_value);
        const auto ret = builder.add(typed_pseudocode_ast_node_kind_t::return_statement,
            fixture_graph_t::uint32, {}, {}, entity_value);
        const auto shr = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
            fixture_graph_t::uint64, {}, ">>", entity_value);
        const auto mul = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
            fixture_graph_t::uint64, {}, "*", entity_value);
        const auto x = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
            fixture_graph_t::uint32, {}, "x", entity_value);
        const auto magic = builder.add(typed_pseudocode_ast_node_kind_t::literal,
            fixture_graph_t::uint64, {}, std::to_string(row.multiplier), entity_value);
        const auto shift = builder.add(typed_pseudocode_ast_node_kind_t::literal,
            fixture_graph_t::uint32, {}, std::to_string(row.shift), entity_value);
        auto& ast = builder.ast;
        ast.nodes[root - 1].child_ids = {decl_x, body};
        ast.nodes[body - 1].child_ids = {ret};
        ast.nodes[ret - 1].child_ids = {shr};
        ast.nodes[shr - 1].child_ids = {mul, shift};
        ast.nodes[mul - 1].child_ids = {x, magic};
        const auto source = builder.finish(root, body);
        require_deterministic_transforms(source, types, evidence);
        auto transformed = transform_checked(source, types, evidence);
        require(transformed.result.metrics.magic_divisions_recognized == 1,
            "magic_div row did not rewrite exactly once");
        const auto rendered = render_checked(transformed.ast, types, &evidence);
        const std::string expected = "x / " + std::to_string(row.divisor);
        require(rendered.text.find(expected) != std::string::npos,
            "magic_div render lacks the recovered division");
    }
}

void verify_switch_case_naming(const decompiler_entity_key_t& entity_value,
                               const type_graph_t& types)
{
    const auto hir_value = [&entity_value](const std::uint64_t id, const hir_node_kind_t kind,
            std::string stable, std::vector<std::uint64_t> operands, const std::uint64_t type_id) {
        hir_value_t result;
        result.id = id;
        result.kind = kind;
        result.type_id = type_id;
        result.operand_ids = std::move(operands);
        result.stable_value = std::move(stable);
        result.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::hir);
        result.confidence = 100;
        result.provenance = decompiler_fact_provenance_t::provider_semantics;
        return result;
    };
    const auto hir_variable = [&entity_value](const std::uint64_t id, const std::string& name) {
        hir_variable_t result;
        result.id = id;
        result.stable_name = name;
        result.type_id = fixture_graph_t::uint32;
        result.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::hir);
        result.confidence = 100;
        result.provenance = decompiler_fact_provenance_t::debug_metadata;
        return result;
    };
    hir_block_t header;
    header.id = 1;
    header.successor_ids = {2, 3, 4};
    header.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::hir);
    header.values = {
        hir_value(1, hir_node_kind_t::reference, "sel", {}, fixture_graph_t::uint32),
        hir_value(2, hir_node_kind_t::switch_branch, "case.2=2;case.5=3;default=4", {1},
            fixture_graph_t::uint32)};
    const auto make_return_block = [&](const std::uint64_t block_id, const std::uint64_t value_id,
            const char* literal_text) {
        hir_block_t block;
        block.id = block_id;
        block.predecessor_ids = {1};
        block.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::hir);
        block.values = {
            hir_value(value_id, hir_node_kind_t::literal, literal_text, {}, fixture_graph_t::uint32),
            hir_value(value_id + 1, hir_node_kind_t::return_value, {}, {value_id},
                fixture_graph_t::uint32)};
        return block;
    };
    hir_function_t hir;
    hir.entity = entity_value;
    hir.provider_ir_hash = stable_serialization_hash("c03-quality-switch-hir");
    hir.type_graph_revision = types.revision;
    hir.return_type_id = fixture_graph_t::uint32;
    hir.parameters.push_back(hir_variable(1, "sel"));
    hir.blocks.push_back(std::move(header));
    hir.blocks.push_back(make_return_block(2, 3, "10"));
    hir.blocks.push_back(make_return_block(3, 5, "20"));
    hir.blocks.push_back(make_return_block(4, 7, "30"));
    auto ast_build = build_typed_ast(hir, types);
    require(ast_build.succeeded() && ast_build.ast.has_value(),
        "switch_win32_error AST build failed");
    const auto rendered = render_checked(*ast_build.ast, types);
    require(rendered.text.find("case ERROR_FILE_NOT_FOUND:") != std::string::npos &&
            rendered.text.find("case ERROR_ACCESS_DENIED:") != std::string::npos,
        "switch_win32_error render lacks named win32 error cases");
    const auto aida_skeleton = skeleton_of(rendered.text);
    const skeleton_t printc_reference{0, 5, 1, 3};
    require(aida_skeleton.goto_count <= printc_reference.goto_count &&
            aida_skeleton.switch_count == printc_reference.switch_count &&
            aida_skeleton.return_count == printc_reference.return_count &&
            aida_skeleton.statement_count >= 3 && aida_skeleton.statement_count <= 8,
        "switch_win32_error AiDA skeleton exceeded the PrintC reference skeleton");
}

typed_pseudocode_ast_v2_t make_big_ast(const decompiler_entity_key_t& entity_value,
                                       const type_graph_t& types,
                                       const std::size_t target_nodes)
{
    ast_builder_t builder(entity_value, types, "c03-quality-big-function");
    const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
        fixture_graph_t::int32, {}, "big_function_fixture", entity_value);
    const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    builder.ast.nodes[root - 1].child_ids = {body};
    std::vector<std::uint64_t> statements;
    std::string previous;
    std::size_t chain_index = 0;
    bool first_iteration = true;
    while (builder.ast.nodes.size() + (first_iteration ? 4 : 6) <= target_nodes - 2) {
        ++chain_index;
        const std::string alive_name = "local_" + std::to_string(chain_index);
        const auto declaration = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
            fixture_graph_t::uint32, {}, alive_name, entity_value);
        std::uint64_t initializer = 0;
        if (previous.empty()) {
            initializer = builder.add(typed_pseudocode_ast_node_kind_t::literal,
                fixture_graph_t::uint32, {}, "1", entity_value);
        } else {
            initializer = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
                fixture_graph_t::uint32, {}, "+", entity_value);
            const auto prior = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
                fixture_graph_t::uint32, {}, previous, entity_value);
            const auto one = builder.add(typed_pseudocode_ast_node_kind_t::literal,
                fixture_graph_t::uint32, {}, "1", entity_value);
            builder.ast.nodes[initializer - 1].child_ids = {prior, one};
        }
        builder.ast.nodes[declaration - 1].child_ids = {initializer};
        statements.push_back(declaration);
        previous = alive_name;
        const auto dead_declaration = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
            fixture_graph_t::uint32, {}, "dead_" + std::to_string(chain_index), entity_value);
        const auto dead_literal = builder.add(typed_pseudocode_ast_node_kind_t::literal,
            fixture_graph_t::uint32, {}, std::to_string(chain_index), entity_value);
        builder.ast.nodes[dead_declaration - 1].child_ids = {dead_literal};
        statements.push_back(dead_declaration);
        first_iteration = false;
    }
    while (builder.ast.nodes.size() + 2 <= target_nodes - 2) {
        ++chain_index;
        const auto dead_declaration = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
            fixture_graph_t::uint32, {}, "dead_" + std::to_string(chain_index), entity_value);
        const auto dead_literal = builder.add(typed_pseudocode_ast_node_kind_t::literal,
            fixture_graph_t::uint32, {}, std::to_string(chain_index), entity_value);
        builder.ast.nodes[dead_declaration - 1].child_ids = {dead_literal};
        statements.push_back(dead_declaration);
    }
    const auto ret = builder.add(typed_pseudocode_ast_node_kind_t::return_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto final_identifier = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::uint32, {}, previous, entity_value);
    builder.ast.nodes[ret - 1].child_ids = {final_identifier};
    statements.push_back(ret);
    builder.ast.nodes[body - 1].child_ids = std::move(statements);
    auto ast = builder.finish(root, body);
    require(ast.nodes.size() == target_nodes,
        "big_function generator missed its exact node target");
    return ast;
}

void verify_transform_capacity(const decompiler_entity_key_t& entity_value,
                               const type_graph_t& types)
{
    const auto source = make_big_ast(entity_value, types, 100000);
    require(validate_typed_pseudocode_ast(source).valid(),
        "big_function_100k fixture is not a valid typed AST");
    const decompiler_render_evidence_t evidence;
    auto first_ast = source;
    const auto begin = std::chrono::steady_clock::now();
    const auto result = apply_readability_transforms(first_ast, types, {}, evidence);
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    require(elapsed_ms < 2000,
        "big_function_100k transforms exceeded the 2 second acceptance bound");
    require(std::none_of(result.diagnostics.begin(), result.diagnostics.end(),
            [](const decompiler_diagnostic_t& diagnostic) {
                return diagnostic.localization_key == "readability.node_limit_exceeded";
            }),
        "big_function_100k emitted node_limit_exceeded after the cap lift");
    require(result.metrics.variables_renamed > 0 &&
            result.metrics.temporaries_inlined > 0 &&
            result.metrics.dead_stores_eliminated > 0,
        "big_function_100k did not engage renames, inlining, and dead-store elimination");

    auto second_ast = source;
    const auto second = apply_readability_transforms(second_ast, types, {}, evidence);
    require(stable_serialization_hash(first_ast) == stable_serialization_hash(second_ast),
        "big_function_100k transforms are not byte-identical across two runs");
}

void verify_work_budget(const decompiler_entity_key_t& entity_value,
                        const type_graph_t& types)
{
    const auto source = make_big_ast(entity_value, types, 100000);
    const decompiler_render_evidence_t evidence;
    readability_transform_settings_t starved = to_rt_settings({});
    starved.max_transform_work_units = 65536;
    auto starved_ast = source;
    const auto starved_result = apply_readability_transforms(starved_ast, types, starved, evidence);
    require(std::any_of(starved_result.diagnostics.begin(), starved_result.diagnostics.end(),
            [](const decompiler_diagnostic_t& diagnostic) {
                return diagnostic.localization_key == "readability.work_budget_exceeded";
            }),
        "starved budget fixture did not emit readability.work_budget_exceeded");
    require(validate_typed_pseudocode_ast(starved_ast).valid(),
        "starved budget fixture left the AST invalid");

    readability_transform_settings_t partial = to_rt_settings({});
    partial.max_transform_work_units = 450000;
    auto partial_ast = source;
    const auto partial_result = apply_readability_transforms(partial_ast, types, partial, evidence);
    require(std::any_of(partial_result.diagnostics.begin(), partial_result.diagnostics.end(),
            [](const decompiler_diagnostic_t& diagnostic) {
                return diagnostic.localization_key == "readability.work_budget_exceeded";
            }),
        "partial budget fixture did not emit readability.work_budget_exceeded");
    require(partial_result.metrics.variables_renamed > 0,
        "partial budget fixture did not keep the completed rename pass output");
    require(validate_typed_pseudocode_ast(partial_ast).valid(),
        "partial budget fixture left the AST invalid");
}

void verify_sidecar_codec()
{
    namespace sidecar_ns = native_worker::snapshot_sidecar;
    sidecar_ns::sidecar_t sidecar;
    sidecar.is_64bit = true;
    sidecar_ns::name_record_t data_name;
    data_name.rva = 0x1000;
    data_name.kind = sidecar_ns::name_kind_t::data;
    data_name.name = "g_Config";
    sidecar.names.push_back(data_name);
    sidecar_ns::name_record_t function_name;
    function_name.rva = 0x2000;
    function_name.kind = sidecar_ns::name_kind_t::function;
    function_name.name = "fixture_entry";
    sidecar.names.push_back(function_name);
    sidecar_ns::import_record_t import;
    import.iat_rva = 0x3000;
    import.thunk_rva = 0x3100;
    import.module = "kernel32.dll";
    import.name = "ReadFile";
    sidecar.imports.push_back(import);
    sidecar.noreturn.push_back(0x2200);
    sidecar_ns::prototype_record_t prototype;
    prototype.rva = 0x3100;
    prototype.confidence = 90;
    prototype.name = "ReadFile";
    prototype.prototype = "int __stdcall ReadFile(void *handle, void *buffer, unsigned int bytes_to_read, unsigned int *bytes_read, void *overlapped)";
    sidecar.prototypes.push_back(prototype);
    sidecar_ns::string_record_t narrow;
    narrow.rva = 0x4000;
    narrow.confidence = 100;
    narrow.original_byte_length = 12;
    narrow.content = "Hello, AiDA";
    sidecar.strings.push_back(narrow);
    sidecar_ns::string_record_t wide;
    wide.rva = 0x4100;
    wide.flags = sidecar_ns::k_string_flag_is_wide | sidecar_ns::k_string_flag_truncated;
    wide.confidence = 80;
    wide.original_byte_length = 4096;
    wide.content = "Wide content";
    sidecar.strings.push_back(wide);
    sidecar_ns::global_scalar_record_t scalar;
    scalar.rva = 0x4200;
    scalar.size_log2 = 2;
    scalar.value = 42;
    sidecar.global_scalars.push_back(scalar);
    sidecar_ns::member_record_t member;
    member.object_type_canonical = "struct_a";
    member.byte_offset = 8;
    member.field_name = "c";
    member.confidence = 95;
    sidecar.members.push_back(member);
    sidecar_ns::member_record_t wildcard_member;
    wildcard_member.byte_offset = 16;
    wildcard_member.field_name = "wildcard_field";
    wildcard_member.selector_hint = "field_0x10";
    wildcard_member.confidence = 60;
    sidecar.members.push_back(wildcard_member);
    sidecar_ns::vtable_record_t vtable;
    vtable.vtable_rva = 0x5000;
    vtable.slot_index = 1;
    vtable.method_name = "OnEvent";
    vtable.confidence = 100;
    sidecar.vtables.push_back(vtable);
    sidecar_ns::comment_record_t comment;
    comment.rva = 0x2000;
    comment.flags = sidecar_ns::k_comment_flag_before_statement;
    comment.text = "entry comment";
    sidecar.comments.push_back(comment);
    sidecar_ns::comment_record_t trailing_comment;
    trailing_comment.rva = 0x2010;
    trailing_comment.text = "trailing comment";
    sidecar.comments.push_back(trailing_comment);
    for (std::uint32_t index = 0; index < 32; ++index)
        sidecar.feedback_digest[index] = static_cast<std::uint8_t>(index * 7U);

    const auto encoded = sidecar_ns::encode(sidecar);
    require(!encoded.empty(), "sidecar v2 encode failed");
    const auto decoded = sidecar_ns::decode(encoded.data(), encoded.size());
    require(decoded.has_value(), "sidecar v2 decode failed");
    require(decoded->is_64bit && decoded->names.size() == 2 && decoded->imports.size() == 1 &&
            decoded->noreturn.size() == 1 && decoded->prototypes.size() == 1,
        "sidecar v2 round-trip lost v1 sections");
    require(decoded->strings.size() == 2 && decoded->global_scalars.size() == 1 &&
            decoded->members.size() == 2 && decoded->vtables.size() == 1 &&
            decoded->comments.size() == 2,
        "sidecar v2 round-trip lost v2 sections");
    require(decoded->strings[0].rva == narrow.rva && decoded->strings[0].content == narrow.content &&
            !decoded->strings[0].is_wide() && !decoded->strings[0].truncated() &&
            decoded->strings[0].confidence == narrow.confidence &&
            decoded->strings[0].original_byte_length == narrow.original_byte_length,
        "sidecar v2 narrow string round-trip drifted");
    require(decoded->strings[1].is_wide() && decoded->strings[1].truncated() &&
            decoded->strings[1].original_byte_length == 4096 &&
            decoded->strings[1].content == "Wide content",
        "sidecar v2 wide string round-trip lost flags");
    require(decoded->global_scalars[0].rva == scalar.rva &&
            decoded->global_scalars[0].size_log2 == 2 && decoded->global_scalars[0].value == 42,
        "sidecar v2 scalar round-trip drifted");
    require(decoded->members[0].object_type_canonical == "struct_a" &&
            decoded->members[0].byte_offset == 8 && decoded->members[0].field_name == "c" &&
            decoded->members[1].object_type_canonical.empty() &&
            decoded->members[1].selector_hint == "field_0x10",
        "sidecar v2 member round-trip drifted");
    require(decoded->vtables[0].vtable_rva == vtable.vtable_rva &&
            decoded->vtables[0].slot_index == 1 && decoded->vtables[0].method_name == "OnEvent",
        "sidecar v2 vtable round-trip drifted");
    require(decoded->comments[0].rva == 0x2000 && decoded->comments[0].before_statement() &&
            decoded->comments[0].text == "entry comment" &&
            decoded->comments[1].rva == 0x2010 && !decoded->comments[1].before_statement(),
        "sidecar v2 comment round-trip drifted");
    require(std::memcmp(decoded->feedback_digest, sidecar.feedback_digest, 32) == 0,
        "sidecar v2 feedback digest round-trip drifted");

    std::string v1_blob;
    sidecar_ns::append_u32(v1_blob, sidecar_ns::k_magic);
    sidecar_ns::append_u32(v1_blob, sidecar_ns::k_version);
    sidecar_ns::append_u32(v1_blob, sidecar_ns::k_flag_is_64bit);
    sidecar_ns::append_u32(v1_blob, 0U);
    sidecar_ns::append_u32(v1_blob, 1U);
    sidecar_ns::append_u32(v1_blob, 0U);
    sidecar_ns::append_u32(v1_blob, 0U);
    sidecar_ns::append_u32(v1_blob, 0U);
    char digest_bytes[32]{};
    sidecar_ns::append_bytes(v1_blob, std::string_view(digest_bytes, sizeof(digest_bytes)));
    sidecar_ns::append_u64(v1_blob, 0x2100ULL);
    sidecar_ns::append_u8(v1_blob, static_cast<std::uint8_t>(sidecar_ns::name_kind_t::data));
    sidecar_ns::append_u8(v1_blob, 0U);
    sidecar_ns::append_u16(v1_blob, 0U);
    sidecar_ns::append_u32(v1_blob, 8U);
    sidecar_ns::append_bytes(v1_blob, "g_Legacy");
    sidecar_ns::append_u64(v1_blob,
        sidecar_ns::fnv1a64(v1_blob.data(), v1_blob.size(), 14695981039346656037ULL));
    const auto v1_decoded = sidecar_ns::decode(v1_blob.data(), v1_blob.size());
    require(v1_decoded.has_value(), "sidecar v1 blob rejected by dual-version decode");
    require(v1_decoded->names.size() == 1 && v1_decoded->names[0].name == "g_Legacy" &&
            v1_decoded->names[0].kind == sidecar_ns::name_kind_t::data,
        "sidecar v1 name section did not decode");
    require(v1_decoded->strings.empty() && v1_decoded->global_scalars.empty() &&
            v1_decoded->members.empty() && v1_decoded->vtables.empty() &&
            v1_decoded->comments.empty(),
        "sidecar v1 decode produced phantom v2 sections");
    const auto v1_reencoded = sidecar_ns::encode(*v1_decoded);
    require(!v1_reencoded.empty(), "sidecar v1 decode result did not re-encode as v2");
    const auto v1_roundtrip = sidecar_ns::decode(v1_reencoded.data(), v1_reencoded.size());
    require(v1_roundtrip.has_value() && v1_roundtrip->names.size() == 1 &&
            v1_roundtrip->names[0].name == "g_Legacy",
        "sidecar v1 to v2 repack round-trip failed");

    sidecar_ns::sidecar_t bounded;
    bounded.strings.reserve(sidecar_ns::k_max_string_records);
    for (std::uint32_t index = 0; index < sidecar_ns::k_max_string_records; ++index) {
        sidecar_ns::string_record_t record;
        record.rva = 0x4000 + index * 16ULL;
        record.confidence = 100;
        record.original_byte_length = 2;
        record.content = "s" + std::to_string(index % 10);
        bounded.strings.push_back(std::move(record));
    }
    const auto bounded_encoded = sidecar_ns::encode(bounded);
    require(!bounded_encoded.empty(), "sidecar v2 encode rejected the 65536-record bound");
    const auto bounded_decoded = sidecar_ns::decode(bounded_encoded.data(), bounded_encoded.size());
    require(bounded_decoded.has_value() &&
            bounded_decoded->strings.size() == sidecar_ns::k_max_string_records &&
            bounded_decoded->strings.front().content == "s0" &&
            bounded_decoded->strings.back().rva == 0x4000 + (sidecar_ns::k_max_string_records - 1) * 16ULL,
        "sidecar v2 65536-record round-trip drifted");
    sidecar_ns::string_record_t overflow_record;
    overflow_record.rva = 0xFF0000;
    overflow_record.content = "x";
    bounded.strings.push_back(std::move(overflow_record));
    require(sidecar_ns::encode(bounded).empty(),
        "sidecar v2 encode accepted one record beyond the 65536 bound");

    sidecar_ns::sidecar_t truncated_probe;
    sidecar_ns::string_record_t truncated_string;
    truncated_string.rva = 0x5000;
    truncated_string.flags = sidecar_ns::k_string_flag_truncated;
    truncated_string.confidence = 100;
    truncated_string.original_byte_length = 9000;
    truncated_string.content.assign(sidecar_ns::k_max_string_content_bytes, 'q');
    truncated_probe.strings.push_back(truncated_string);
    const auto truncated_encoded = sidecar_ns::encode(truncated_probe);
    const auto truncated_decoded = sidecar_ns::decode(truncated_encoded.data(), truncated_encoded.size());
    require(truncated_decoded.has_value() &&
            truncated_decoded->strings.front().truncated() &&
            truncated_decoded->strings.front().original_byte_length == 9000 &&
            truncated_decoded->strings.front().content.size() == sidecar_ns::k_max_string_content_bytes,
        "sidecar v2 truncation flag or content bound round-trip drifted");
}

void verify_sidecar_evidence_mapping()
{
    namespace sidecar_ns = native_worker::snapshot_sidecar;
    constexpr std::uint64_t image_base = 0x140000000ULL;
    sidecar_ns::sidecar_t sidecar;
    sidecar_ns::name_record_t data_name;
    data_name.rva = 0x1000;
    data_name.kind = sidecar_ns::name_kind_t::data;
    data_name.name = "g_Config";
    sidecar.names.push_back(data_name);
    sidecar_ns::name_record_t function_name;
    function_name.rva = 0x2000;
    function_name.kind = sidecar_ns::name_kind_t::function;
    function_name.name = "fixture_entry";
    sidecar.names.push_back(function_name);
    sidecar_ns::name_record_t vtable_name;
    vtable_name.rva = 0x5000;
    vtable_name.kind = sidecar_ns::name_kind_t::data;
    vtable_name.name = "Widget::vftable";
    sidecar.names.push_back(vtable_name);
    sidecar_ns::string_record_t narrow;
    narrow.rva = 0x4000;
    narrow.confidence = 100;
    narrow.original_byte_length = 12;
    narrow.content = "Hello, AiDA";
    sidecar.strings.push_back(narrow);
    sidecar_ns::global_scalar_record_t scalar;
    scalar.rva = 0x4200;
    scalar.size_log2 = 2;
    scalar.value = 42;
    sidecar.global_scalars.push_back(scalar);
    sidecar_ns::member_record_t member;
    member.object_type_canonical = "struct_a";
    member.byte_offset = 8;
    member.field_name = "c";
    member.confidence = 95;
    sidecar.members.push_back(member);
    sidecar_ns::vtable_record_t vtable;
    vtable.vtable_rva = 0x5000;
    vtable.slot_index = 1;
    vtable.method_name = "OnEvent";
    vtable.confidence = 100;
    sidecar.vtables.push_back(vtable);
    sidecar_ns::comment_record_t comment;
    comment.rva = 0x2000;
    comment.flags = sidecar_ns::k_comment_flag_before_statement;
    comment.text = "entry comment";
    sidecar.comments.push_back(comment);
    const auto encoded = sidecar_ns::encode(sidecar);
    require(!encoded.empty(), "sidecar evidence fixture encode failed");

    const auto evidence = build_render_evidence_from_sidecar(
        encoded.data(), encoded.size(), image_base);
    require(evidence != nullptr, "sidecar v2 evidence mapping returned null");
    require(validate_decompiler_render_evidence(*evidence).valid(),
        "sidecar v2 evidence mapping failed validation");
    const auto has_symbol = [&evidence](const std::string& unresolved, const std::string& resolved) {
        return std::any_of(evidence->symbols.begin(), evidence->symbols.end(),
            [&](const decompiler_symbol_evidence_t& symbol) {
                return symbol.unresolved_text == unresolved && symbol.resolved_name == resolved;
            });
    };
    require(has_symbol("DAT_140001000", "g_Config"),
        "data-named sidecar record did not map to the DAT_ symbol channel");
    require(has_symbol("sub_140002000", "fixture_entry"),
        "function sidecar record did not map to the sub_ symbol channel");
    require(evidence->strings.size() == 1 &&
            evidence->strings.front().absolute_address == image_base + 0x4000 &&
            evidence->strings.front().utf8_content == "Hello, AiDA",
        "sidecar string section did not map to absolute-address string evidence");
    require(evidence->global_scalars.size() == 1 &&
            evidence->global_scalars.front().absolute_address == image_base + 0x4200 &&
            evidence->global_scalars.front().value == 42 &&
            evidence->global_scalars.front().size_log2 == 2,
        "sidecar scalar section did not map to scalar evidence");
    require(evidence->members.size() == 1 &&
            evidence->members.front().object_type_canonical == "struct_a" &&
            evidence->members.front().byte_offset == 8 &&
            evidence->members.front().field_name == "c",
        "sidecar member section did not map to member evidence");
    require(evidence->vtable_slots.size() == 1 &&
            evidence->vtable_slots.front().vtable_selector == "Widget::vftable" &&
            evidence->vtable_slots.front().slot_index == 1 &&
            evidence->vtable_slots.front().method_name == "OnEvent" &&
            evidence->vtable_slots.front().vtable_rva == image_base + 0x5000,
        "sidecar vtable section did not map to vtable evidence with a named selector");
    require(evidence->user_comments.size() == 1 &&
            evidence->user_comments.front().rva == image_base + 0x2000 &&
            evidence->user_comments.front().before_statement &&
            evidence->user_comments.front().comment_text == "entry comment" &&
            evidence->user_comments.front().anchor_text.empty(),
        "sidecar comment section did not map to address-anchored comment evidence");
    require(std::all_of(evidence->symbols.begin(), evidence->symbols.end(),
            [](const decompiler_symbol_evidence_t& symbol) { return symbol.confidence <= 100; }),
        "sidecar evidence symbol confidence exceeded the validator bound");
}

void verify_typelib_overlay()
{
    decompiler_render_evidence_t evidence;
    build_render_evidence_typelib_overlay(evidence);
    require(!evidence.members.empty(),
        "typelib overlay produced no member evidence");
    const auto point_x = std::any_of(evidence.members.begin(), evidence.members.end(),
        [](const decompiler_member_evidence_t& entry) {
            return entry.object_type_canonical == "POINT" && entry.byte_offset == 0 &&
                   entry.field_name == "x";
        });
    require(point_x, "typelib overlay lacks the POINT.x member");
    const auto critical_section = std::any_of(evidence.members.begin(), evidence.members.end(),
        [](const decompiler_member_evidence_t& entry) {
            return entry.object_type_canonical == "RTL_CRITICAL_SECTION" &&
                   entry.byte_offset == 8 && entry.field_name == "LockCount";
        });
    require(critical_section, "typelib overlay lacks the RTL_CRITICAL_SECTION.LockCount member");
    require(validate_decompiler_render_evidence(evidence).valid(),
        "typelib overlay evidence failed validation");

    decompiler_render_evidence_t merged;
    decompiler_member_evidence_t sidecar_winner;
    sidecar_winner.object_type_canonical = "POINT";
    sidecar_winner.byte_offset = 0;
    sidecar_winner.field_name = "recovered_x";
    sidecar_winner.confidence = 100;
    merged.members.push_back(sidecar_winner);
    build_render_evidence_typelib_overlay(merged);
    const auto point_entries = std::count_if(merged.members.begin(), merged.members.end(),
        [](const decompiler_member_evidence_t& entry) {
            return entry.object_type_canonical == "POINT" && entry.byte_offset == 0;
        });
    require(point_entries == 1 &&
            std::any_of(merged.members.begin(), merged.members.end(),
                [](const decompiler_member_evidence_t& entry) {
                    return entry.object_type_canonical == "POINT" && entry.byte_offset == 0 &&
                           entry.field_name == "recovered_x";
                }),
        "typelib overlay did not prefer the sidecar member on a canonical/offset collision");
}

class quality_fake_source_t final
    : public aida::workbench::pseudocode_document::pseudocode_source_adapter_t {
public:
    std::uint64_t current_generation() const noexcept override
    {
        return generation_;
    }

    bool generation_current(const std::uint64_t generation) const noexcept override
    {
        return generation == generation_;
    }

    aida::workbench::workbench_error_t request_decompilation(
        const aida::workbench::pseudocode_document::pseudocode_request_t& request,
        const std::uint64_t job_id) override
    {
        if (request.workspace_generation != generation_ || job_id == 0)
            return {aida::workbench::workbench_error_code_t::revision_mismatch,
                    request.workspace_generation};
        job_id_ = job_id;
        active_ = true;
        return {};
    }

    aida::workbench::workbench_error_t cancel_decompilation(const std::uint64_t job_id) override
    {
        if (job_id == job_id_)
            active_ = false;
        return {};
    }

    bool poll_result(const std::uint64_t job_id, decompiler_document_t& output) override
    {
        if (job_id != job_id_ || !pending_)
            return false;
        output = std::move(*pending_);
        pending_.reset();
        active_ = false;
        return true;
    }

    bool poll_failure(std::uint64_t, std::vector<decompiler_diagnostic_t>&) override
    {
        return false;
    }

    bool job_active(const std::uint64_t job_id) const noexcept override
    {
        return active_ && job_id == job_id_;
    }

    decompiler_profile_budget_t profile_budget(const decompiler_profile_id_t profile) const noexcept override
    {
        using namespace aida::workbench::pseudocode_document;
        decompiler_profile_budget_t result;
        result.profile = profile;
        result.max_wall_clock_ms = k_pseudocode_document_default_timeout_ms;
        result.max_cpu_ms = k_pseudocode_document_default_timeout_ms;
        result.max_memory_bytes = k_pseudocode_document_max_rendered_bytes;
        result.max_provider_ir_nodes = k_pseudocode_document_max_ast_nodes;
        result.max_hir_nodes = k_pseudocode_document_max_ast_nodes;
        result.max_ast_nodes = k_pseudocode_document_max_ast_nodes;
        return result;
    }

    aida::workbench::pseudocode_document::pseudocode_render_evidence_bundle_t render_evidence(
        const aida::workbench::pseudocode_document::pseudocode_request_t& request) const override
    {
        static_cast<void>(request);
        return bundle_;
    }

    void complete(decompiler_document_t document)
    {
        pending_ = std::move(document);
    }

    void set_bundle(const type_graph_t& types,
                    const decompiler_render_evidence_t& evidence)
    {
        bundle_.type_graph = std::make_shared<const type_graph_t>(types);
        bundle_.evidence = std::make_shared<const decompiler_render_evidence_t>(evidence);
    }

private:
    std::uint64_t generation_ = 31;
    std::uint64_t job_id_ = 0;
    bool active_ = false;
    std::optional<decompiler_document_t> pending_;
    aida::workbench::pseudocode_document::pseudocode_render_evidence_bundle_t bundle_;
};

typed_pseudocode_ast_v2_t make_rename_ast(const decompiler_entity_key_t& entity_value,
                                          const type_graph_t& types)
{
    ast_builder_t builder(entity_value, types, "c03-quality-rename");
    const auto root = builder.add(typed_pseudocode_ast_node_kind_t::function_definition,
        fixture_graph_t::int32, {}, "rename_fixture", entity_value);
    const auto body = builder.add(typed_pseudocode_ast_node_kind_t::compound_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto declaration = builder.add(typed_pseudocode_ast_node_kind_t::declaration,
        fixture_graph_t::int32, {}, "local_4", entity_value);
    const auto one = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::int32, {}, "1", entity_value);
    const auto statement = builder.add(typed_pseudocode_ast_node_kind_t::expression_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto assignment = builder.add(typed_pseudocode_ast_node_kind_t::assignment_expression,
        fixture_graph_t::int32, {}, "=", entity_value);
    const auto target = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "local_4", entity_value);
    const auto add = builder.add(typed_pseudocode_ast_node_kind_t::binary_expression,
        fixture_graph_t::int32, {}, "+", entity_value);
    const auto use = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "local_4", entity_value);
    const auto two = builder.add(typed_pseudocode_ast_node_kind_t::literal,
        fixture_graph_t::int32, {}, "2", entity_value);
    const auto ret = builder.add(typed_pseudocode_ast_node_kind_t::return_statement,
        fixture_graph_t::int32, {}, {}, entity_value);
    const auto final_use = builder.add(typed_pseudocode_ast_node_kind_t::identifier,
        fixture_graph_t::int32, {}, "local_4", entity_value);
    auto& ast = builder.ast;
    ast.nodes[root - 1].child_ids = {body};
    ast.nodes[body - 1].child_ids = {declaration, statement, ret};
    ast.nodes[declaration - 1].child_ids = {one};
    ast.nodes[statement - 1].child_ids = {assignment};
    ast.nodes[assignment - 1].child_ids = {target, add};
    ast.nodes[add - 1].child_ids = {use, two};
    ast.nodes[ret - 1].child_ids = {final_use};
    return builder.finish(root, body);
}

void verify_local_rename(const decompiler_entity_key_t& entity_value,
                         const type_graph_t& types)
{
    namespace model = aida::workbench::pseudocode_document;
    const decompiler_render_evidence_t evidence;
    const auto source_ast = make_rename_ast(entity_value, types);
    const auto canonical_render = render_checked(source_ast, types, &evidence);
    require(canonical_render.text.find("local_4") != std::string::npos,
        "rename fixture canonical render lost local_4");

    auto rename_work_ast = source_ast;
    const auto direct = apply_pseudocode_local_rename(
        rename_work_ast, types, "local_4", "counter");
    require(direct.applied && direct.nodes_renamed == 4,
        "direct AST rename did not rewrite all four uses");
    require(validate_typed_pseudocode_ast(rename_work_ast).valid(),
        "direct AST rename left the AST invalid");
    const auto keyword = apply_pseudocode_local_rename(
        rename_work_ast, types, "counter", "int");
    require(!keyword.applied && !keyword.diagnostics.empty(),
        "rename accepted a C keyword as the new name");
    auto collision_ast = source_ast;
    const auto collision = apply_pseudocode_local_rename(
        collision_ast, types, "local_4", "rename_fixture");
    require(!collision.applied && !collision.diagnostics.empty(),
        "rename accepted a colliding function name");
    const auto function_name = apply_pseudocode_local_rename(
        collision_ast, types, "rename_fixture", "other_name");
    require(!function_name.applied && !function_name.diagnostics.empty(),
        "rename accepted the function name as a rename source");

    quality_fake_source_t source;
    source.set_bundle(types, evidence);
    model::pseudocode_document_model_t doc_model(source);
    model::pseudocode_request_t request;
    request.entity = entity_value;
    request.profile = decompiler_profile_id_t::balanced;
    request.workspace_generation = 31;
    request.timeout_ms = model::k_pseudocode_document_default_timeout_ms;
    require(doc_model.request(request).ok() && doc_model.cached_document(),
        "rename fixture model request failed");
    const auto job_id = doc_model.cached_document()->job_id;
    source.complete(canonical_render.document);
    require(doc_model.poll(job_id).ok() &&
            doc_model.cache_state() == model::pseudocode_cache_state_t::cached,
        "rename fixture model did not cache the canonical document");
    std::uint64_t renamed = 0;
    const auto applied = doc_model.apply_local_rename("local_4", "counter", renamed);
    require(applied.ok() && renamed != 0,
        "model-level local rename failed");
    require(doc_model.cached_document()->job_id == job_id,
        "model-level local rename forced a pipeline re-entry (job id changed)");
    model::pseudocode_page_t page;
    require(doc_model.page({0, model::k_pseudocode_document_max_page_lines}, page).ok(),
        "model-level renamed document did not page");
    std::string renamed_text;
    for (const auto& line : page.lines)
        renamed_text += line.text + "\n";
    require(renamed_text.find("counter") != std::string::npos &&
            renamed_text.find("local_4") == std::string::npos,
        "model-level renamed document lacks the new name at every use");
    const auto keyword_model = doc_model.apply_local_rename("counter", "int", renamed);
    require(!keyword_model.ok(),
        "model-level rename accepted a keyword");
    const auto absent_model = doc_model.apply_local_rename("nonexistent_local", "other", renamed);
    require(!absent_model.ok(),
        "model-level rename accepted an absent identifier");

    quality_fake_source_t reloaded_source;
    reloaded_source.set_bundle(types, evidence);
    model::pseudocode_document_model_t reloaded_model(reloaded_source);
    require(reloaded_model.request(request).ok() && reloaded_model.cached_document(),
        "rename reload fixture model request failed");
    const auto reload_job_id = reloaded_model.cached_document()->job_id;
    reloaded_source.complete(canonical_render.document);
    require(reloaded_model.poll(reload_job_id).ok() &&
            reloaded_model.cache_state() == model::pseudocode_cache_state_t::cached,
        "rename reload fixture did not cache the canonical document");
    std::uint64_t reloaded_renamed = 0;
    require(reloaded_model.apply_local_rename("local_4", "counter", reloaded_renamed).ok() &&
            reloaded_renamed != 0,
        "rename map did not survive the simulated view reload");
    model::pseudocode_page_t reloaded_page;
    require(reloaded_model.page({0, model::k_pseudocode_document_max_page_lines}, reloaded_page).ok(),
        "reloaded renamed document did not page");
    std::string reloaded_text;
    for (const auto& line : reloaded_page.lines)
        reloaded_text += line.text + "\n";
    require(reloaded_text == renamed_text,
        "reloaded rename render diverged from the live rename render");
}

void run_pseudocode_quality_differential_harness()
{
    const auto entity_value = entity();
    const auto graph = fixture_graph(entity_value);
    require(validate_type_graph(graph.graph).valid(), "quality fixture type graph is invalid");

    verify_sidecar_codec();
    verify_sidecar_evidence_mapping();
    verify_typelib_overlay();
    verify_string_inline(entity_value, graph.graph);
    verify_scalar_and_comment_channels(entity_value, graph.graph);
    verify_member_chain(entity_value, graph.graph);
    verify_array_member(entity_value, graph.graph);
    verify_thiscall_this(entity_value, graph.graph);
    verify_union_selection(entity_value, graph.graph);
    verify_cast_noise(entity_value, graph.graph);
    verify_loop_intrinsics(entity_value, graph.graph);
    verify_bit_idioms(entity_value, graph.graph);
    verify_magic_division(entity_value, graph.graph);
    verify_switch_case_naming(entity_value, graph.graph);
    verify_transform_capacity(entity_value, graph.graph);
    verify_work_budget(entity_value, graph.graph);
    verify_local_rename(entity_value, graph.graph);
}

}

}

int main()
{
    try {
        aida::analysis::c03_test::run_pseudocode_quality_differential_harness();
        std::cout << "pseudocode_quality_differential_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
