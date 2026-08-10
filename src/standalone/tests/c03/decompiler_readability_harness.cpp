#include "decompiler_readability_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/pseudocode_readability.hpp"
#include "../../src/core/analysis/decompiler/pseudocode_renderer.hpp"
#include "../../src/core/analysis/decompiler/source_reconstructor.hpp"
#include "../../src/core/analysis/decompiler/typed_ast.hpp"
#include "../../src/core/analysis/source_reconstructor.hpp"
#include "../../src/core/workbench/adapters/pseudocode_document.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
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
    identity.function_id = 707;
    identity.entry = address(0x2000);
    identity.end = address(0x2040);
    identity.function_bytes_hash = stable_serialization_hash("c03-readability-function");
    identity.canonical_symbol = "readability_fixture";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::native_function;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.identity = std::move(identity);
    return result;
}

source_coordinate_t coordinate(
    const decompiler_entity_key_t& entity_value,
    const decompiler_coordinate_layer_t layer)
{
    source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = 23;
    result.entity = entity_value;
    result.address_range = decompiler_address_range_t{address(0x2000), address(0x2004)};
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
    integer.provenance = decompiler_fact_provenance_t::provider_semantics;
    type_graph_t result;
    result.entity = entity_value;
    result.revision = 29;
    result.nodes.push_back(std::move(integer));
    return result;
}

typed_pseudocode_ast_node_t node(
    const std::uint64_t id,
    const typed_pseudocode_ast_node_kind_t kind,
    std::vector<std::uint64_t> children,
    std::string text,
    const decompiler_entity_key_t& entity_value)
{
    typed_pseudocode_ast_node_t result;
    result.id = id;
    result.kind = kind;
    result.type_id = 1;
    result.child_ids = std::move(children);
    result.stable_text = std::move(text);
    result.coordinate = coordinate(entity_value, decompiler_coordinate_layer_t::typed_ast);
    result.confidence = 100;
    result.provenance = decompiler_fact_provenance_t::semantic_proof;
    return result;
}

typed_pseudocode_ast_v2_t ast(
    const decompiler_entity_key_t& entity_value,
    const type_graph_t& types,
    const bool proven_body)
{
    typed_pseudocode_ast_v2_t result;
    result.entity = entity_value;
    result.hir_hash = stable_serialization_hash(proven_body
        ? "c03-readability-proven-hir" : "c03-readability-empty-hir");
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes.push_back(node(1, typed_pseudocode_ast_node_kind_t::function_definition,
        {2}, "readability_fixture", entity_value));
    result.nodes.push_back(node(2, typed_pseudocode_ast_node_kind_t::compound_statement,
        proven_body ? std::vector<std::uint64_t>{3} : std::vector<std::uint64_t>{}, {}, entity_value));
    if (proven_body) {
        result.nodes.push_back(node(3, typed_pseudocode_ast_node_kind_t::return_statement,
            {4}, {}, entity_value));
        result.nodes.push_back(node(4, typed_pseudocode_ast_node_kind_t::literal,
            {}, "7", entity_value));
    }
    return result;
}

decompiler_document_t render(
    const typed_pseudocode_ast_v2_t& ast_value,
    const type_graph_t& types)
{
    pseudocode_renderer_request_t request;
    request.profile = decompiler_profile_id_t::balanced;
    request.settings = pseudocode_renderer_style_settings(
        pseudocode_renderer_style_profile_t::balanced);
    auto rendered = render_pseudocode(ast_value, types, request);
    require(rendered.succeeded() && rendered.document.has_value(),
        "readability fixture renderer rejected a valid typed AST");
    return std::move(*rendered.document);
}

decompiler_diagnostic_t retained_diagnostic()
{
    decompiler_diagnostic_t result;
    result.severity = decompiler_diagnostic_severity_t::warning;
    result.code = decompiler_diagnostic_code_t::unresolved_symbol;
    result.localization_key = "c03.readability.retained_diagnostic";
    result.localization_arguments = {"fixture_symbol"};
    result.confidence = 91;
    result.ordinal = 1;
    return result;
}

class fake_pseudocode_source_t final
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
        if (request.workspace_generation != generation_ || job_id == 0) {
            return {aida::workbench::workbench_error_code_t::revision_mismatch,
                    request.workspace_generation};
        }
        job_id_ = job_id;
        active_ = true;
        pending_.reset();
        return {};
    }

    aida::workbench::workbench_error_t cancel_decompilation(
        const std::uint64_t job_id) override
    {
        if (job_id == job_id_)
            active_ = false;
        return {};
    }

    bool poll_result(
        const std::uint64_t job_id,
        decompiler_document_t& output) override
    {
        if (job_id != job_id_ || !pending_)
            return false;
        output = std::move(*pending_);
        pending_.reset();
        return true;
    }

    bool poll_failure(
        std::uint64_t,
        std::vector<decompiler_diagnostic_t>&) override
    {
        return false;
    }

    bool job_active(const std::uint64_t job_id) const noexcept override
    {
        return active_ && job_id == job_id_;
    }

    decompiler_profile_budget_t profile_budget(
        const decompiler_profile_id_t profile) const noexcept override
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
        if (profile == decompiler_profile_id_t::thorough) {
            result.max_semantic_queries = 1;
            result.semantic_proofs_enabled = true;
        }
        return result;
    }

    void complete(decompiler_document_t document)
    {
        pending_ = std::move(document);
        active_ = false;
    }

    void set_generation(const std::uint64_t generation) noexcept
    {
        generation_ = generation;
    }

private:
    std::uint64_t generation_ = 23;
    std::uint64_t job_id_ = 0;
    bool active_ = false;
    std::optional<decompiler_document_t> pending_;
};

void verify_null_and_fabricated_rejection(
    const decompiler_document_t& valid_document,
    const typed_pseudocode_ast_v2_t& empty_ast,
    const decompiler_document_t& empty_document)
{
    require(!adapt_decompiler_document_for_legacy(
        static_cast<const decompiler_document_t*>(nullptr)).succeeded(),
        "legacy adapter accepted a null document");
    require(!analyze_pseudocode_readability(
        static_cast<const typed_pseudocode_ast_v2_t*>(nullptr), &valid_document).succeeded(),
        "readability analysis accepted a null AST");
    require(!analyze_pseudocode_readability(
        &empty_ast, &empty_document).succeeded(),
        "readability analysis accepted a fabricated empty body");
    const auto adapted = adapt_decompiler_document_for_legacy(empty_document);
    require(!adapted.succeeded(), "legacy adapter accepted a fabricated empty body");
    require(std::any_of(adapted.diagnostics.begin(), adapted.diagnostics.end(),
        [](const decompiler_diagnostic_t& diagnostic) {
            return diagnostic.localization_key == "decompiler.legacy_adapter.fabricated_body";
        }), "legacy adapter omitted the fabricated-body diagnostic");
}

void verify_diagnostic_and_mapping_preservation(
    const typed_pseudocode_ast_v2_t& valid_ast,
    decompiler_document_t document)
{
    document.diagnostics.push_back(retained_diagnostic());
    const auto adapted = adapt_decompiler_document_for_legacy(document);
    require(adapted.succeeded() && adapted.view.has_value(),
        "legacy adapter rejected the diagnostic-preservation fixture");
    require(adapted.view->diagnostics.size() == 1 &&
            adapted.view->diagnostics.front().localization_key ==
                "c03.readability.retained_diagnostic",
        "legacy adapter dropped document diagnostics");
    require(hash_decompiler_source_maps(adapted.view->source_maps) ==
            hash_decompiler_source_maps(document.source_maps),
        "legacy adapter changed complete source mappings");

    const auto readability = analyze_pseudocode_readability(valid_ast, document);
    require(readability.succeeded() && readability.report.has_value(),
        "readability analysis rejected the diagnostic-preservation fixture");
    require(readability.report->diagnostics.size() == 1 &&
            readability.report->diagnostics.front().localization_key ==
                "c03.readability.retained_diagnostic",
        "readability report dropped document diagnostics");

    auto unmapped = document;
    unmapped.source_maps.pop_back();
    require(!adapt_decompiler_document_for_legacy(unmapped).succeeded(),
        "legacy adapter accepted source-map loss");
    require(!analyze_pseudocode_readability(valid_ast, unmapped).succeeded(),
        "readability analysis accepted source-map loss");
}

void verify_bounded_deterministic_view(const decompiler_document_t& document)
{
    require(!document.tokens.empty(), "bounded-view fixture has no document tokens");
    legacy_document_adapter_limits_t limits;
    limits.max_text_bytes = document.tokens.front().range.end;
    limits.max_tokens = 1;
    limits.max_source_maps = 1;
    const auto first = adapt_decompiler_document_for_legacy(document, limits);
    const auto second = adapt_decompiler_document_for_legacy(document, limits);
    require(first.succeeded() && second.succeeded(),
        "legacy adapter rejected a bounded deterministic view");
    require(first.view->status == legacy_document_view_status_t::bounded_prefix &&
            first.view->pseudocode.size() <= limits.max_text_bytes &&
            first.view->source_maps.size() <= limits.max_source_maps,
        "legacy adapter exceeded bounded-view limits");
    require(first.view->view_hash == second.view->view_hash &&
            first.view->pseudocode == second.view->pseudocode &&
            hash_decompiler_source_maps(first.view->source_maps) ==
                hash_decompiler_source_maps(second.view->source_maps),
        "legacy adapter produced a nondeterministic bounded view");
}

typed_pseudocode_ast_node_t golden_node(
    const std::uint64_t id,
    const typed_pseudocode_ast_node_kind_t kind,
    const std::uint64_t type_id,
    std::vector<std::uint64_t> children,
    std::string text,
    const decompiler_entity_key_t& entity_value)
{
    auto result = node(id, kind, std::move(children), std::move(text), entity_value);
    result.type_id = type_id;
    return result;
}

type_graph_t golden_type_graph(const decompiler_entity_key_t& entity_value)
{
    const auto make_type = [](const std::uint64_t id, const decompiler_type_kind_t kind,
                              const std::string& name, const std::uint32_t size,
                              const std::uint32_t alignment, const bool is_signed) {
        decompiler_type_node_t result;
        result.id = id;
        result.kind = kind;
        result.canonical_name = name;
        result.display_name = name;
        result.byte_size = size;
        result.alignment = alignment;
        result.is_signed = is_signed;
        result.confidence = 100;
        result.provenance = decompiler_fact_provenance_t::provider_semantics;
        return result;
    };
    type_graph_t result;
    result.entity = entity_value;
    result.revision = 31;
    result.nodes.push_back(make_type(1, decompiler_type_kind_t::unsigned_integer, "DWORD", 4, 4, false));
    result.nodes.push_back(make_type(2, decompiler_type_kind_t::unsigned_integer, "SIZE_T", 8, 8, false));
    result.nodes.push_back(make_type(3, decompiler_type_kind_t::pointer, "HANDLE", 8, 8, false));
    result.nodes.push_back(make_type(4, decompiler_type_kind_t::signed_integer, "BOOL", 4, 4, true));
    return result;
}

typed_pseudocode_ast_v2_t golden_ast(
    const decompiler_entity_key_t& entity_value,
    const type_graph_t& types)
{
    typed_pseudocode_ast_v2_t result;
    result.entity = entity_value;
    result.hir_hash = stable_serialization_hash("c03-readability-golden-hir");
    result.type_graph_hash = stable_serialization_hash(types);
    result.root_node_id = 1;
    result.body_node_id = 2;
    result.nodes.push_back(golden_node(1, typed_pseudocode_ast_node_kind_t::function_definition,
        0, {2}, "readability_golden_fixture", entity_value));
    result.nodes.push_back(golden_node(2, typed_pseudocode_ast_node_kind_t::compound_statement,
        0, {3, 5, 7, 13, 17}, {}, entity_value));
    result.nodes.push_back(golden_node(3, typed_pseudocode_ast_node_kind_t::declaration,
        1, {4}, "local_4", entity_value));
    result.nodes.push_back(golden_node(4, typed_pseudocode_ast_node_kind_t::identifier,
        1, {}, "global_count", entity_value));
    result.nodes.push_back(golden_node(5, typed_pseudocode_ast_node_kind_t::declaration,
        2, {6}, "local_8", entity_value));
    result.nodes.push_back(golden_node(6, typed_pseudocode_ast_node_kind_t::identifier,
        2, {}, "local_4", entity_value));
    result.nodes.push_back(golden_node(7, typed_pseudocode_ast_node_kind_t::declaration,
        3, {8}, "local_12", entity_value));
    result.nodes.push_back(golden_node(8, typed_pseudocode_ast_node_kind_t::binary_expression,
        1, {9, 10}, "&", entity_value));
    result.nodes.push_back(golden_node(9, typed_pseudocode_ast_node_kind_t::identifier,
        1, {}, "local_4", entity_value));
    result.nodes.push_back(golden_node(10, typed_pseudocode_ast_node_kind_t::binary_expression,
        1, {11, 12}, "+", entity_value));
    result.nodes.push_back(golden_node(11, typed_pseudocode_ast_node_kind_t::literal,
        1, {}, "2", entity_value));
    result.nodes.push_back(golden_node(12, typed_pseudocode_ast_node_kind_t::literal,
        1, {}, "3", entity_value));
    result.nodes.push_back(golden_node(13, typed_pseudocode_ast_node_kind_t::declaration,
        4, {14}, "local_16", entity_value));
    result.nodes.push_back(golden_node(14, typed_pseudocode_ast_node_kind_t::binary_expression,
        4, {15, 16}, "+", entity_value));
    result.nodes.push_back(golden_node(15, typed_pseudocode_ast_node_kind_t::identifier,
        4, {}, "local_8", entity_value));
    result.nodes.push_back(golden_node(16, typed_pseudocode_ast_node_kind_t::literal,
        4, {}, "0", entity_value));
    result.nodes.push_back(golden_node(17, typed_pseudocode_ast_node_kind_t::return_statement,
        0, {18}, {}, entity_value));
    result.nodes.push_back(golden_node(18, typed_pseudocode_ast_node_kind_t::identifier,
        3, {}, "local_12", entity_value));
    return result;
}

bool same_transform_metrics(const readability_transform_metrics_t& left,
                            const readability_transform_metrics_t& right)
{
    return left.variables_renamed == right.variables_renamed &&
        left.loop_counters_named == right.loop_counters_named &&
        left.api_call_names_applied == right.api_call_names_applied &&
        left.type_based_names_applied == right.type_based_names_applied &&
        left.string_reference_names_applied == right.string_reference_names_applied &&
        left.constants_folded == right.constants_folded &&
        left.identities_simplified == right.identities_simplified &&
        left.casts_simplified == right.casts_simplified &&
        left.double_negations_simplified == right.double_negations_simplified &&
        left.comparisons_normalized == right.comparisons_normalized &&
        left.compound_assignments_marked == right.compound_assignments_marked &&
        left.temporaries_inlined == right.temporaries_inlined &&
        left.copies_propagated == right.copies_propagated &&
        left.dead_stores_eliminated == right.dead_stores_eliminated &&
        left.nodes_removed == right.nodes_removed;
}

bool same_ast_nodes(const typed_pseudocode_ast_v2_t& left,
                    const typed_pseudocode_ast_v2_t& right)
{
    if (left.root_node_id != right.root_node_id || left.body_node_id != right.body_node_id ||
        left.nodes.size() != right.nodes.size())
        return false;
    for (std::size_t index = 0; index < left.nodes.size(); ++index) {
        const auto& a = left.nodes[index];
        const auto& b = right.nodes[index];
        if (a.id != b.id || a.kind != b.kind || a.type_id != b.type_id ||
            a.child_ids != b.child_ids || a.stable_text != b.stable_text)
            return false;
    }
    return true;
}

void verify_readability_golden_output(const decompiler_entity_key_t& entity_value)
{
    const auto types = golden_type_graph(entity_value);
    const auto source = golden_ast(entity_value, types);
    require(validate_typed_pseudocode_ast(source).valid(),
        "readability golden fixture is not a valid typed AST");

    auto first_ast = source;
    const auto first = apply_readability_transforms(first_ast, types, {});
    require(first.transformed && first.succeeded(),
        "readability golden fixture produced no transforms");
    auto second_ast = source;
    const auto second = apply_readability_transforms(second_ast, types, {});
    require(second.transformed && second.succeeded(),
        "readability golden second run produced no transforms");
    require(first.diagnostics.empty() && second.diagnostics.empty(),
        "readability golden transforms emitted diagnostics");
    require(same_transform_metrics(first.metrics, second.metrics) &&
            same_ast_nodes(first_ast, second_ast) &&
            stable_serialization_hash(first_ast) == stable_serialization_hash(second_ast),
        "readability golden transforms are not byte-identical across two runs");

    const auto& metrics = first.metrics;
    require(metrics.variables_renamed == 8 && metrics.type_based_names_applied == 4 &&
            metrics.loop_counters_named == 0 && metrics.api_call_names_applied == 0 &&
            metrics.string_reference_names_applied == 0,
        "readability golden renaming counters diverged");
    require(metrics.constants_folded == 1 && metrics.identities_simplified == 1 &&
            metrics.casts_simplified == 0 && metrics.double_negations_simplified == 0 &&
            metrics.comparisons_normalized == 0 && metrics.compound_assignments_marked == 0,
        "readability golden simplification counters diverged");
    require(metrics.temporaries_inlined == 2 && metrics.copies_propagated == 2 &&
            metrics.dead_stores_eliminated == 4 && metrics.nodes_removed == 12,
        "readability golden def-use counters diverged");

    require(first_ast.root_node_id == 1 && first_ast.body_node_id == 2 &&
            first_ast.nodes.size() == 6,
        "readability golden output shape diverged");
    const auto& nodes = first_ast.nodes;
    require(nodes[0].id == 1 &&
            nodes[0].kind == typed_pseudocode_ast_node_kind_t::function_definition &&
            nodes[0].child_ids == std::vector<std::uint64_t>{2} &&
            nodes[0].stable_text == "readability_golden_fixture",
        "readability golden function node diverged");
    require(nodes[1].id == 2 &&
            nodes[1].kind == typed_pseudocode_ast_node_kind_t::compound_statement &&
            nodes[1].child_ids == std::vector<std::uint64_t>{17},
        "readability golden body node diverged");
    require(nodes[2].id == 9 &&
            nodes[2].kind == typed_pseudocode_ast_node_kind_t::identifier &&
            nodes[2].stable_text == "global_count" && nodes[2].child_ids.empty(),
        "readability golden copy-propagated identifier diverged");
    require(nodes[3].id == 10 &&
            nodes[3].kind == typed_pseudocode_ast_node_kind_t::literal &&
            nodes[3].stable_text == "5" && nodes[3].child_ids.empty(),
        "readability golden folded literal diverged");
    require(nodes[4].id == 17 &&
            nodes[4].kind == typed_pseudocode_ast_node_kind_t::return_statement &&
            nodes[4].child_ids == std::vector<std::uint64_t>{18},
        "readability golden return node diverged");
    require(nodes[5].id == 18 &&
            nodes[5].kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
            nodes[5].stable_text == "&" &&
            nodes[5].child_ids == (std::vector<std::uint64_t>{9, 10}),
        "readability golden surviving expression diverged");
    require(std::none_of(nodes.begin(), nodes.end(), [](const typed_pseudocode_ast_node_t& value) {
            return value.stable_text == "local_4" || value.stable_text == "local_8" ||
                value.stable_text == "local_12" || value.stable_text == "local_16";
        }), "readability golden output retained generated identifier names");
    require(validate_typed_pseudocode_ast(first_ast).valid(),
        "readability golden output is not a valid typed AST");
}

void verify_new_pass_parity_on_golden(const decompiler_entity_key_t& entity_value)
{
    const auto types = golden_type_graph(entity_value);
    const auto source = golden_ast(entity_value, types);
    readability_transform_settings_t explicit_new_passes;
    explicit_new_passes.enable_string_literal_substitution = true;
    explicit_new_passes.enable_cast_idiom_folding = true;
    explicit_new_passes.enable_bit_operation_idioms = true;
    explicit_new_passes.enable_loop_intrinsic_idioms = true;
    explicit_new_passes.enable_magic_division_recognition = true;
    auto explicit_ast = source;
    const auto explicit_result = apply_readability_transforms(explicit_ast, types, explicit_new_passes);
    readability_transform_settings_t disabled_new_passes;
    disabled_new_passes.enable_string_literal_substitution = false;
    disabled_new_passes.enable_cast_idiom_folding = false;
    disabled_new_passes.enable_bit_operation_idioms = false;
    disabled_new_passes.enable_loop_intrinsic_idioms = false;
    disabled_new_passes.enable_magic_division_recognition = false;
    auto disabled_ast = source;
    const auto disabled_result = apply_readability_transforms(disabled_ast, types, disabled_new_passes);
    require(explicit_result.diagnostics.empty() && disabled_result.diagnostics.empty(),
        "new readability passes emitted diagnostics on the golden fixture");
    require(same_transform_metrics(explicit_result.metrics, disabled_result.metrics) &&
            explicit_result.metrics.string_literals_inlined == 0 &&
            explicit_result.metrics.cast_masks_folded == 0 &&
            explicit_result.metrics.bit_operation_idioms_rewritten == 0 &&
            explicit_result.metrics.loop_intrinsics_rewritten == 0 &&
            explicit_result.metrics.magic_divisions_recognized == 0 &&
            explicit_result.metrics.global_scalar_comments_injected == 0,
        "new readability passes changed golden metrics or fired without matching patterns");
    require(same_ast_nodes(explicit_ast, disabled_ast) &&
            stable_serialization_hash(explicit_ast) == stable_serialization_hash(disabled_ast),
        "new readability passes are not proven no-ops on the golden fixture");
    require(explicit_result.metrics.dead_stores_eliminated == 4 &&
            explicit_result.metrics.nodes_removed == 12,
        "linearized def-use passes changed golden dead-store or compaction counters");

    readability_transform_settings_t raised_cap = to_rt_settings({});
    require(raised_cap.max_transform_nodes == 250000 &&
            raised_cap.max_transform_work_units == 4000000,
        "readability settings clamp diverged from the 250k-node/4M-work defaults");
    readability_transform_settings_t clamped;
    clamped.max_transform_nodes = 1;
    clamped.max_transform_work_units = 1;
    const auto clamped_result = to_rt_settings(clamped);
    require(clamped_result.max_transform_nodes == 10000 &&
            clamped_result.max_transform_work_units == 65536,
        "readability settings clamp lost its floor bounds");
    clamped.max_transform_nodes = 10000000;
    clamped.max_transform_work_units = std::numeric_limits<std::size_t>::max();
    const auto clamped_ceiling = to_rt_settings(clamped);
    require(clamped_ceiling.max_transform_nodes == 500000 &&
            clamped_ceiling.max_transform_work_units == (std::size_t{1} << 26),
        "readability settings clamp lost its ceiling bounds");
}

void verify_baseline_capture(
    const typed_pseudocode_ast_v2_t& valid_ast,
    const decompiler_document_t& document)
{
    pseudocode_baseline_capture_request_t baseline;
    baseline.provider = pseudocode_baseline_provider_t::ghidra_printc;
    baseline.provider_build_hash = stable_serialization_hash("c03-readability-provider");
    baseline.fixture_set_hash = stable_serialization_hash("c03-readability-fixture-set");
    baseline.fixture_id = "native/readability_fixture";
    baseline.rendered_text = document.rendered_text;
    baseline.diagnostics = document.diagnostics;
    const auto first = capture_pseudocode_readability_baseline(baseline);
    const auto second = capture_pseudocode_readability_baseline(baseline);
    require(first.succeeded() && second.succeeded() &&
            first.capture->capture_hash == second.capture->capture_hash,
        "readability baseline capture is not deterministic");

    auto invalid = baseline;
    invalid.rendered_text.clear();
    require(!capture_pseudocode_readability_baseline(invalid).succeeded(),
        "readability baseline accepted empty rendered text");

    pseudocode_readability_request_t request;
    request.baseline = baseline;
    const auto report = analyze_pseudocode_readability(valid_ast, document, request);
    require(report.succeeded() && report.report->baseline.has_value() &&
            report.report->baseline->capture_hash == first.capture->capture_hash,
        "readability report did not preserve baseline capture");
}

void verify_pseudocode_document_delivery(decompiler_document_t document)
{
    namespace model = aida::workbench::pseudocode_document;
    document.diagnostics.push_back(retained_diagnostic());
    model::pseudocode_request_t request;
    request.entity = document.entity;
    request.profile = document.profile;
    request.workspace_generation = 23;
    request.timeout_ms = model::k_pseudocode_document_default_timeout_ms;

    fake_pseudocode_source_t source;
    model::pseudocode_document_model_t document_model(source);
    require(document_model.request(request).ok() && document_model.cached_document(),
        "pseudocode document model rejected a typed request");
    const auto job_id = document_model.cached_document()->job_id;
    source.complete(document);
    require(document_model.poll(job_id).ok() &&
            document_model.cache_state() == model::pseudocode_cache_state_t::cached,
        "pseudocode document model rejected a current typed worker result");
    model::pseudocode_page_t page;
    require(document_model.page({0, model::k_pseudocode_document_max_page_lines}, page).ok() &&
            page.tokens.size() == document.tokens.size() &&
            page.source_maps.size() >= document.source_maps.size() &&
            page.diagnostics.size() == document.diagnostics.size() &&
            page.diagnostics.front().localization_key ==
                "c03.readability.retained_diagnostic",
        "pseudocode document page dropped tokens, source maps, or diagnostics");

    fake_pseudocode_source_t stale_source;
    model::pseudocode_document_model_t stale_model(stale_source);
    require(stale_model.request(request).ok() && stale_model.cached_document(),
        "pseudocode stale-result fixture request failed");
    const auto stale_job_id = stale_model.cached_document()->job_id;
    stale_source.set_generation(24);
    stale_source.complete(document);
    const auto stale_error = stale_model.poll(stale_job_id);
    const auto stale_diagnostics = stale_model.diagnostics();
    model::pseudocode_page_t stale_page;
    const auto stale_page_error = stale_model.page({0, 1}, stale_page);
    require(stale_error.code == model::pseudocode_error_code_t::stale_result &&
            stale_model.cache_state() == model::pseudocode_cache_state_t::stale &&
            !stale_diagnostics.empty() &&
            stale_diagnostics.front().localization_key ==
                "decompiler.worker.stale_result" &&
            stale_page_error.code == model::pseudocode_error_code_t::stale_result &&
            !stale_page.diagnostics.empty(),
        "pseudocode document model exposed or hid a stale worker result");

    auto oversized = document;
    oversized.rendered_text.clear();
    for (std::uint32_t line = 0; line < model::k_pseudocode_document_max_lines; ++line)
        oversized.rendered_text += "x\n";
    oversized.rendered_text += 'x';
    fake_pseudocode_source_t bounded_source;
    model::pseudocode_document_model_t bounded_model(bounded_source);
    require(bounded_model.request(request).ok() && bounded_model.cached_document(),
        "pseudocode line-limit fixture request failed");
    const auto bounded_job_id = bounded_model.cached_document()->job_id;
    bounded_source.complete(std::move(oversized));
    require(bounded_model.poll(bounded_job_id).code ==
            model::pseudocode_error_code_t::resource_exhausted &&
            bounded_model.cache_state() == model::pseudocode_cache_state_t::failed,
        "pseudocode document model accepted unbounded line metadata");
}

void verify_reconstructor_gate(
    const decompiler_document_t& valid_document,
    const decompiler_document_t& empty_document)
{
    source_reconstructor::function_info_t function;
    function.name = "sub_2000";
    std::vector<decompiler_diagnostic_t> diagnostics;
    auto diagnostic_document = valid_document;
    diagnostic_document.diagnostics.push_back(retained_diagnostic());
    require(source_reconstructor::accept_decompiler_document(
        function, diagnostic_document, "Readable::Fixture", diagnostics),
        "source reconstructor rejected a complete typed document");
    require(function.decompiled && !function.pseudocode.empty() &&
            !function.source_maps.empty() && function.name == "Readable__Fixture" &&
            function.diagnostics.size() == 1 && diagnostics.size() == 1 &&
            function.diagnostics.front().localization_key ==
                "c03.readability.retained_diagnostic" &&
            diagnostics.front().localization_key ==
                "c03.readability.retained_diagnostic",
        "source reconstructor did not preserve the accepted document view");

    diagnostics.clear();
    require(!source_reconstructor::accept_decompiler_document(
        function, empty_document, "fabricated", diagnostics),
        "source reconstructor accepted a fabricated body");
    require(!function.decompiled && function.pseudocode.empty() &&
            function.source_maps.empty() && !diagnostics.empty(),
        "source reconstructor retained fabricated success state");
}

void verify_typed_reconstructor(
    const decompiler_document_t& valid_document,
    const decompiler_document_t& empty_document)
{
    auto diagnostic_document = valid_document;
    diagnostic_document.diagnostics.push_back(retained_diagnostic());
    source_reconstruction_request_t request;
    source_reconstruction_input_t input;
    input.document = &diagnostic_document;
    input.relative_path = "src/readability_fixture.cpp";
    request.inputs.push_back(std::move(input));
    const auto reconstructed = reconstruct_source_documents(request);
    require(reconstructed.succeeded() && reconstructed.output.has_value() &&
            reconstructed.output->artifacts.size() == 1 &&
            reconstructed.output->artifacts.front().content ==
                diagnostic_document.rendered_text &&
            reconstructed.output->artifacts.front().source_maps.size() ==
                diagnostic_document.source_maps.size() &&
            reconstructed.output->artifacts.front().diagnostics.size() == 1 &&
            reconstructed.output->diagnostics.size() == 1,
        "typed source reconstruction dropped document evidence");

    request.inputs.front().document = &empty_document;
    require(!reconstruct_source_documents(request).succeeded(),
        "typed source reconstruction accepted a fabricated document");
}

type_graph_t quality_type_graph(const decompiler_entity_key_t& entity_value)
{
    const auto make_type = [](const std::uint64_t id, const decompiler_type_kind_t kind,
                              const std::string& name, const std::uint32_t size,
                              const std::uint32_t alignment, const bool is_signed) {
        decompiler_type_node_t result;
        result.id = id;
        result.kind = kind;
        result.canonical_name = name;
        result.display_name = name;
        result.byte_size = size;
        result.alignment = alignment;
        result.is_signed = is_signed;
        result.confidence = 100;
        result.provenance = decompiler_fact_provenance_t::provider_semantics;
        return result;
    };
    const auto make_edge = [](const std::uint64_t source, const std::uint64_t target,
                              const decompiler_type_edge_kind_t kind, const std::string& name,
                              const std::uint32_t ordinal) {
        decompiler_type_edge_t result;
        result.source_type_id = source;
        result.target_type_id = target;
        result.kind = kind;
        result.stable_name = name;
        result.ordinal = ordinal;
        result.confidence = 100;
        result.provenance = decompiler_fact_provenance_t::provider_semantics;
        return result;
    };
    type_graph_t result;
    result.entity = entity_value;
    result.revision = 43;
    result.nodes = {
        make_type(1, decompiler_type_kind_t::signed_integer, "int", 4, 4, true),
        make_type(2, decompiler_type_kind_t::boolean, "bool", 1, 1, false),
        make_type(3, decompiler_type_kind_t::pointer, "int*", 8, 8, false),
        make_type(4, decompiler_type_kind_t::unsigned_integer, "DWORD", 4, 4, false),
        make_type(5, decompiler_type_kind_t::unsigned_integer, "QWORD", 8, 8, false),
        make_type(6, decompiler_type_kind_t::signed_integer, "char", 1, 1, true),
        make_type(7, decompiler_type_kind_t::pointer, "char*", 8, 8, false),
        make_type(8, decompiler_type_kind_t::structure, "Config", 16, 8, false),
        make_type(9, decompiler_type_kind_t::pointer, "Config*", 8, 8, false),
        make_type(10, decompiler_type_kind_t::array, "int[16]", 64, 4, false),
        make_type(11, decompiler_type_kind_t::signed_integer, "long long", 8, 8, true)};
    result.edges = {
        make_edge(3, 1, decompiler_type_edge_kind_t::pointee, "pointee", 1),
        make_edge(7, 6, decompiler_type_edge_kind_t::pointee, "pointee", 2),
        make_edge(9, 8, decompiler_type_edge_kind_t::pointee, "pointee", 3),
        make_edge(10, 1, decompiler_type_edge_kind_t::element, "element", 4)};
    return result;
}

struct quality_ast_builder_t {
    const decompiler_entity_key_t& entity_value;
    std::vector<typed_pseudocode_ast_node_t> nodes;
    std::uint64_t next_id = 3;

    std::uint64_t add(const typed_pseudocode_ast_node_kind_t kind, const std::uint64_t type_id,
                      std::vector<std::uint64_t> children, std::string text) {
        const auto id = next_id++;
        nodes.push_back(golden_node(id, kind, type_id, std::move(children), std::move(text), entity_value));
        return id;
    }

    std::uint64_t declaration(const std::uint64_t type_id, const std::string& name) {
        return add(typed_pseudocode_ast_node_kind_t::declaration, type_id, {}, name);
    }

    std::uint64_t identifier(const std::uint64_t type_id, const std::string& name) {
        return add(typed_pseudocode_ast_node_kind_t::identifier, type_id, {}, name);
    }

    std::uint64_t literal(const std::uint64_t type_id, const std::string& text) {
        return add(typed_pseudocode_ast_node_kind_t::literal, type_id, {}, text);
    }

    std::uint64_t binary(const std::uint64_t type_id, const std::string& op,
                         const std::uint64_t left, const std::uint64_t right) {
        return add(typed_pseudocode_ast_node_kind_t::binary_expression, type_id, {left, right}, op);
    }

    std::uint64_t unary(const std::uint64_t type_id, const std::string& op,
                        const std::uint64_t operand) {
        return add(typed_pseudocode_ast_node_kind_t::unary_expression, type_id, {operand}, op);
    }

    std::uint64_t assign(const std::uint64_t type_id, const std::uint64_t target,
                         const std::uint64_t value) {
        return add(typed_pseudocode_ast_node_kind_t::assignment_expression, type_id,
            {target, value}, "=");
    }

    std::uint64_t expression_statement(const std::uint64_t type_id, const std::uint64_t expression) {
        return add(typed_pseudocode_ast_node_kind_t::expression_statement, type_id, {expression}, {});
    }

    std::uint64_t call(const std::uint64_t type_id, const std::uint64_t callee,
                       std::vector<std::uint64_t> arguments) {
        std::vector<std::uint64_t> children{callee};
        children.insert(children.end(), arguments.begin(), arguments.end());
        return add(typed_pseudocode_ast_node_kind_t::call_expression, type_id, std::move(children), {});
    }

    std::uint64_t return_statement(const std::uint64_t type_id, const std::uint64_t expression) {
        return add(typed_pseudocode_ast_node_kind_t::return_statement, type_id, {expression}, {});
    }

    std::uint64_t compound(const std::uint64_t type_id, std::vector<std::uint64_t> children) {
        return add(typed_pseudocode_ast_node_kind_t::compound_statement, type_id,
            std::move(children), {});
    }

    std::uint64_t if_statement(const std::uint64_t type_id, const std::uint64_t condition,
                               const std::uint64_t then_body, const std::uint64_t else_body) {
        const auto else_clause = add(typed_pseudocode_ast_node_kind_t::else_clause, type_id,
            {else_body}, {});
        return add(typed_pseudocode_ast_node_kind_t::if_statement, type_id,
            {condition, then_body, else_clause}, {});
    }

    typed_pseudocode_ast_v2_t finish(const type_graph_t& types, std::string name,
                                     std::vector<std::uint64_t> body_children, const char* hir_seed) {
        typed_pseudocode_ast_v2_t result;
        result.entity = entity_value;
        result.hir_hash = stable_serialization_hash(hir_seed);
        result.type_graph_hash = stable_serialization_hash(types);
        result.root_node_id = 1;
        result.body_node_id = 2;
        std::vector<typed_pseudocode_ast_node_t> ordered;
        ordered.push_back(golden_node(1, typed_pseudocode_ast_node_kind_t::function_definition,
            1, {2}, std::move(name), entity_value));
        ordered.push_back(golden_node(2, typed_pseudocode_ast_node_kind_t::compound_statement,
            1, std::move(body_children), {}, entity_value));
        ordered.insert(ordered.end(), nodes.begin(), nodes.end());
        result.nodes = std::move(ordered);
        return result;
    }
};

std::size_t count_kind(const typed_pseudocode_ast_v2_t& ast,
                       const typed_pseudocode_ast_node_kind_t kind)
{
    return static_cast<std::size_t>(std::count_if(ast.nodes.begin(), ast.nodes.end(),
        [kind](const typed_pseudocode_ast_node_t& value) { return value.kind == kind; }));
}

const typed_pseudocode_ast_node_t* find_node(const typed_pseudocode_ast_v2_t& ast,
                                             const std::uint64_t id)
{
    const auto found = std::find_if(ast.nodes.begin(), ast.nodes.end(),
        [id](const typed_pseudocode_ast_node_t& value) { return value.id == id; });
    return found == ast.nodes.end() ? nullptr : &*found;
}

const typed_pseudocode_ast_node_t* parent_of(const typed_pseudocode_ast_v2_t& ast,
                                             const std::uint64_t id)
{
    const auto found = std::find_if(ast.nodes.begin(), ast.nodes.end(),
        [id](const typed_pseudocode_ast_node_t& value) {
            return std::find(value.child_ids.begin(), value.child_ids.end(), id) != value.child_ids.end();
        });
    return found == ast.nodes.end() ? nullptr : &*found;
}

void require_quality_determinism(
    const typed_pseudocode_ast_v2_t& source,
    const type_graph_t& types,
    const readability_transform_settings_t& settings,
    const decompiler_render_evidence_t* evidence,
    const std::vector<rt_semantic_fact_view_t>& facts,
    const std::vector<typed_ast_branch_bridge_entry_t>& bridge,
    readability_transform_result_t& first_result,
    typed_pseudocode_ast_v2_t& first_ast)
{
    static const decompiler_render_evidence_t k_empty_evidence{};
    first_ast = source;
    first_result = apply_readability_transforms(first_ast, types, settings,
        evidence != nullptr ? *evidence : k_empty_evidence, facts, bridge);
    typed_pseudocode_ast_v2_t second_ast = source;
    const auto second_result = apply_readability_transforms(second_ast, types, settings,
        evidence != nullptr ? *evidence : k_empty_evidence, facts, bridge);
    require(first_result.diagnostics.empty() && second_result.diagnostics.empty(),
        "quality fixture transforms emitted diagnostics");
    require(same_ast_nodes(first_ast, second_ast) &&
            stable_serialization_hash(first_ast) == stable_serialization_hash(second_ast),
        "quality fixture transforms are not byte-identical across two runs");
    require(validate_typed_pseudocode_ast(first_ast).valid(),
        "quality fixture transformed output is not a valid typed AST");
}

std::uint64_t add_nested_conditional(quality_ast_builder_t& builder)
{
    return builder.add(typed_pseudocode_ast_node_kind_t::conditional_expression, 1,
        {builder.identifier(2, "c2"), builder.identifier(1, "y"), builder.identifier(1, "z")}, "?:");
}

void verify_ternary_formation_fixtures(const decompiler_entity_key_t& entity_value)
{
    const auto types = quality_type_graph(entity_value);
    const std::vector<typed_ast_branch_bridge_entry_t> no_bridge;
    const std::vector<rt_semantic_fact_view_t> no_facts;
    readability_transform_result_t result;
    typed_pseudocode_ast_v2_t ast;

    const auto assign_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto ok = builder.declaration(2, "ok");
        const auto r = builder.declaration(1, "r");
        const auto base = builder.declaration(1, "base");
        const auto off = builder.declaration(1, "off");
        const auto then_body = builder.compound(1, {
            builder.expression_statement(1, builder.assign(1,
                builder.identifier(1, "r"),
                builder.binary(1, "+", builder.identifier(1, "base"), builder.identifier(1, "off"))))});
        const auto else_body = builder.compound(1, {
            builder.expression_statement(1, builder.assign(1,
                builder.identifier(1, "r"), builder.literal(1, "0")))});
        const auto if_node = builder.if_statement(1, builder.identifier(2, "ok"), then_body, else_body);
        const auto ret = builder.return_statement(1, builder.identifier(1, "r"));
        return builder.finish(types, "ternary_assign_fixture", {ok, r, base, off, if_node, ret},
            "c03-quality-ternary-assign");
    }();
    require(validate_typed_pseudocode_ast(assign_source).valid(),
        "ternary assign fixture is not a valid typed AST");
    require_quality_determinism(assign_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.ternaries_formed == 1, "ternary assign form was not formed");
    require(count_kind(ast, typed_pseudocode_ast_node_kind_t::conditional_expression) == 1 &&
            count_kind(ast, typed_pseudocode_ast_node_kind_t::if_statement) == 0,
        "ternary assign form left an if or wrong conditional count");
    {
        const auto* conditional = nullptr;
        for (const auto& value : ast.nodes) {
            if (value.kind == typed_pseudocode_ast_node_kind_t::conditional_expression)
                conditional = &value;
        }
        require(conditional != nullptr && conditional->child_ids.size() == 3,
            "ternary assign conditional has wrong shape");
        const auto* condition = find_node(ast, conditional->child_ids[0]);
        const auto* then_arm = find_node(ast, conditional->child_ids[1]);
        const auto* else_arm = find_node(ast, conditional->child_ids[2]);
        require(condition != nullptr && condition->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                then_arm != nullptr && then_arm->kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
                else_arm != nullptr && else_arm->kind == typed_pseudocode_ast_node_kind_t::literal &&
                else_arm->stable_text == "0",
            "ternary assign conditional arms diverged");
        const auto* assignment = parent_of(ast, conditional->id);
        require(assignment != nullptr &&
                assignment->kind == typed_pseudocode_ast_node_kind_t::assignment_expression &&
                assignment->child_ids.size() == 2 && assignment->child_ids[1] == conditional->id,
            "ternary assign conditional is not the assignment right-hand side");
    }

    const auto return_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto p = builder.declaration(3, "p");
        const auto then_body = builder.compound(1, {
            builder.return_statement(1, builder.unary(1, "*", builder.identifier(3, "p")))});
        const auto else_body = builder.compound(1, {
            builder.return_statement(1, builder.unary(1, "-", builder.literal(1, "1")))});
        const auto if_node = builder.if_statement(1, builder.identifier(3, "p"), then_body, else_body);
        return builder.finish(types, "ternary_return_fixture", {p, if_node},
            "c03-quality-ternary-return");
    }();
    require_quality_determinism(return_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.ternaries_formed == 1, "ternary return form was not formed");
    require(count_kind(ast, typed_pseudocode_ast_node_kind_t::if_statement) == 0,
        "ternary return form left an if statement");
    {
        const typed_pseudocode_ast_node_t* ret = nullptr;
        for (const auto& value : ast.nodes) {
            if (value.kind == typed_pseudocode_ast_node_kind_t::return_statement)
                ret = &value;
        }
        require(ret != nullptr && ret->child_ids.size() == 1,
            "ternary return form lost the return statement");
        const auto* conditional = find_node(ast, ret->child_ids[0]);
        require(conditional != nullptr &&
                conditional->kind == typed_pseudocode_ast_node_kind_t::conditional_expression &&
                conditional->child_ids.size() == 3,
            "ternary return conditional is not the return expression");
    }

    const auto min_max_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto v4 = builder.declaration(1, "v4");
        const auto v7 = builder.declaration(1, "v7");
        const auto r = builder.declaration(1, "r");
        const auto then_body = builder.compound(1, {
            builder.expression_statement(1, builder.assign(1,
                builder.identifier(1, "r"), builder.identifier(1, "v4")))});
        const auto else_body = builder.compound(1, {
            builder.expression_statement(1, builder.assign(1,
                builder.identifier(1, "r"), builder.identifier(1, "v7")))});
        const auto if_node = builder.if_statement(1,
            builder.binary(2, "<", builder.identifier(1, "v4"), builder.identifier(1, "v7")),
            then_body, else_body);
        const auto ret = builder.return_statement(1, builder.identifier(1, "r"));
        return builder.finish(types, "min_max_precedence_fixture", {v4, v7, r, if_node, ret},
            "c03-quality-min-max-precedence");
    }();
    require_quality_determinism(min_max_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.min_max_idioms_rewritten == 1 && result.metrics.ternaries_formed == 0,
        "min/max idiom did not take precedence over ternary formation");
    require(count_kind(ast, typed_pseudocode_ast_node_kind_t::conditional_expression) == 0,
        "min/max precedence fixture produced a conditional expression");
    {
        const auto* call = nullptr;
        for (const auto& value : ast.nodes) {
            if (value.kind == typed_pseudocode_ast_node_kind_t::call_expression)
                call = &value;
        }
        require(call != nullptr && !call->child_ids.empty(),
            "min/max precedence fixture lost the min call");
        const auto* callee = find_node(ast, call->child_ids[0]);
        require(callee != nullptr && callee->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                callee->stable_text == "min",
            "min/max precedence fixture did not emit a min call");
    }

    const auto side_effect_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto r = builder.declaration(1, "r");
        const auto a = builder.declaration(1, "a");
        const auto b = builder.declaration(1, "b");
        const auto then_body = builder.compound(1, {
            builder.expression_statement(1, builder.assign(1,
                builder.identifier(1, "r"), builder.identifier(1, "a")))});
        const auto else_body = builder.compound(1, {
            builder.expression_statement(1, builder.assign(1,
                builder.identifier(1, "r"), builder.identifier(1, "b")))});
        const auto if_node = builder.if_statement(1,
            builder.call(1, builder.identifier(1, "f"), {}), then_body, else_body);
        const auto ret = builder.return_statement(1, builder.identifier(1, "r"));
        return builder.finish(types, "ternary_side_effect_fixture", {r, a, b, if_node, ret},
            "c03-quality-ternary-side-effect");
    }();
    require_quality_determinism(side_effect_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.ternaries_formed == 0 &&
            count_kind(ast, typed_pseudocode_ast_node_kind_t::if_statement) == 1 &&
            count_kind(ast, typed_pseudocode_ast_node_kind_t::conditional_expression) == 0,
        "ternary formation accepted a side-effect condition");

    const auto nested_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto c1 = builder.declaration(2, "c1");
        const auto c2 = builder.declaration(2, "c2");
        const auto r = builder.declaration(1, "r");
        const auto x = builder.declaration(1, "x");
        const auto y = builder.declaration(1, "y");
        const auto z = builder.declaration(1, "z");
        const auto inner = add_nested_conditional(builder);
        const auto then_body = builder.compound(1, {
            builder.expression_statement(1, builder.assign(1,
                builder.identifier(1, "r"), builder.identifier(1, "x")))});
        const auto else_body = builder.compound(1, {
            builder.expression_statement(1, builder.assign(1,
                builder.identifier(1, "r"), inner))});
        const auto if_node = builder.if_statement(1, builder.identifier(2, "c1"), then_body, else_body);
        const auto ret = builder.return_statement(1, builder.identifier(1, "r"));
        return builder.finish(types, "ternary_nested_fixture", {c1, c2, r, x, y, z, if_node, ret},
            "c03-quality-ternary-nested");
    }();
    require_quality_determinism(nested_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.ternaries_formed == 0 &&
            count_kind(ast, typed_pseudocode_ast_node_kind_t::if_statement) == 1 &&
            count_kind(ast, typed_pseudocode_ast_node_kind_t::conditional_expression) == 1,
        "ternary formation rewrote a nested ternary arm");

    const auto mismatch_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto ok = builder.declaration(2, "ok");
        const auto r = builder.declaration(1, "r");
        const auto a = builder.declaration(1, "a");
        const auto p = builder.declaration(3, "p");
        const auto then_body = builder.compound(1, {
            builder.expression_statement(1, builder.assign(1,
                builder.identifier(1, "r"), builder.identifier(1, "a")))});
        const auto else_body = builder.compound(1, {
            builder.expression_statement(1, builder.assign(1,
                builder.identifier(1, "r"), builder.identifier(3, "p")))});
        const auto if_node = builder.if_statement(1, builder.identifier(2, "ok"), then_body, else_body);
        const auto ret = builder.return_statement(1, builder.identifier(1, "r"));
        return builder.finish(types, "ternary_type_mismatch_fixture", {ok, r, a, p, if_node, ret},
            "c03-quality-ternary-type-mismatch");
    }();
    require_quality_determinism(mismatch_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.ternaries_formed == 0 &&
            count_kind(ast, typed_pseudocode_ast_node_kind_t::if_statement) == 1 &&
            count_kind(ast, typed_pseudocode_ast_node_kind_t::conditional_expression) == 0,
        "ternary formation accepted a type-mismatched diamond");
}

void verify_array_index_recognition_fixtures(const decompiler_entity_key_t& entity_value)
{
    const auto types = quality_type_graph(entity_value);
    const std::vector<typed_ast_branch_bridge_entry_t> no_bridge;
    const std::vector<rt_semantic_fact_view_t> no_facts;
    readability_transform_result_t result;
    typed_pseudocode_ast_v2_t ast;
    const auto count_indexes = [&]() {
        return count_kind(ast, typed_pseudocode_ast_node_kind_t::index_expression);
    };

    const auto scaled_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto v9 = builder.declaration(3, "v9");
        const auto i = builder.declaration(1, "i");
        const auto deref = builder.unary(1, "*",
            builder.binary(3, "+", builder.identifier(3, "v9"),
                builder.binary(1, "*", builder.identifier(1, "i"), builder.literal(1, "4"))));
        const auto store = builder.expression_statement(1, builder.assign(1, deref, builder.literal(1, "0")));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "array_scaled_fixture", {v9, i, store, ret},
            "c03-quality-array-scaled");
    }();
    require_quality_determinism(scaled_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.array_indexes_formed == 1 && count_indexes() == 1,
        "array scaled fixture did not form an index expression");
    {
        const typed_pseudocode_ast_node_t* index = nullptr;
        for (const auto& value : ast.nodes) {
            if (value.kind == typed_pseudocode_ast_node_kind_t::index_expression)
                index = &value;
        }
        require(index != nullptr && index->child_ids.size() == 2,
            "array scaled index expression has wrong shape");
        const auto* base = find_node(ast, index->child_ids[0]);
        const auto* subscript = find_node(ast, index->child_ids[1]);
        require(base != nullptr && base->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                base->stable_text == "v9" &&
                subscript != nullptr && subscript->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                subscript->stable_text == "i",
            "array scaled index base or subscript diverged");
        const auto* store_root = parent_of(ast, index->id);
        require(store_root != nullptr &&
                store_root->kind == typed_pseudocode_ast_node_kind_t::assignment_expression,
            "array scaled index is not the store target");
    }

    const auto byte_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto buf = builder.declaration(7, "buf");
        const auto i = builder.declaration(1, "i");
        const auto v5 = builder.declaration(6, "v5");
        const auto deref = builder.unary(6, "*",
            builder.binary(7, "+", builder.identifier(7, "buf"), builder.identifier(1, "i")));
        const auto store = builder.expression_statement(1, builder.assign(6,
            builder.identifier(6, "v5"), deref));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "array_byte_fixture", {buf, i, v5, store, ret},
            "c03-quality-array-byte");
    }();
    require_quality_determinism(byte_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.array_indexes_formed == 1 && count_indexes() == 1,
        "array byte fixture did not form an index expression");

    const auto displaced_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto ctx = builder.declaration(9, "ctx");
        const auto idx = builder.declaration(1, "idx");
        const auto deref = builder.unary(8, "*",
            builder.binary(9, "+",
                builder.binary(9, "+", builder.identifier(9, "ctx"),
                    builder.binary(1, "*", builder.identifier(1, "idx"), builder.literal(1, "8"))),
                builder.literal(1, "16")));
        const auto store = builder.expression_statement(8, builder.assign(8, deref,
            builder.identifier(8, "field")));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "array_displaced_fixture", {ctx, idx, store, ret},
            "c03-quality-array-displaced");
    }();
    require_quality_determinism(displaced_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.array_indexes_formed == 1 && count_indexes() == 1,
        "array displaced fixture did not form an index expression");
    {
        const typed_pseudocode_ast_node_t* index = nullptr;
        for (const auto& value : ast.nodes) {
            if (value.kind == typed_pseudocode_ast_node_kind_t::index_expression)
                index = &value;
        }
        require(index != nullptr && index->child_ids.size() == 2,
            "array displaced index expression has wrong shape");
        const auto* subscript = find_node(ast, index->child_ids[1]);
        require(subscript != nullptr &&
                subscript->kind == typed_pseudocode_ast_node_kind_t::binary_expression &&
                subscript->stable_text == "+" && subscript->child_ids.size() == 2,
            "array displaced subscript is not the folded displacement sum");
        const auto* displacement = find_node(ast, subscript->child_ids[1]);
        require(displacement != nullptr &&
                displacement->kind == typed_pseudocode_ast_node_kind_t::literal &&
                displacement->stable_text == "2",
            "array displaced subscript constant diverged");
    }

    const auto stack_array_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto arr = builder.declaration(10, "arr");
        const auto i = builder.declaration(1, "i");
        const auto deref = builder.unary(1, "*",
            builder.binary(10, "+", builder.identifier(10, "arr"),
                builder.binary(1, "*", builder.identifier(1, "i"), builder.literal(1, "4"))));
        const auto store = builder.expression_statement(1, builder.assign(1, deref, builder.literal(1, "0")));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "array_stack_fixture", {arr, i, store, ret},
            "c03-quality-array-stack");
    }();
    require_quality_determinism(stack_array_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.array_indexes_formed == 1 && count_indexes() == 1,
        "array stack fixture did not form an index expression over the array binding");

    const auto zero_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto arr = builder.declaration(10, "arr");
        const auto v = builder.declaration(1, "v");
        const auto store = builder.expression_statement(1, builder.assign(1,
            builder.identifier(1, "v"), builder.unary(1, "*", builder.identifier(10, "arr"))));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "array_zero_fixture", {arr, v, store, ret},
            "c03-quality-array-zero");
    }();
    require_quality_determinism(zero_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.array_indexes_formed == 1 && count_indexes() == 1,
        "array zero fixture did not form an index expression at subscript zero");

    const auto call_subtree_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto i = builder.declaration(1, "i");
        const auto deref = builder.unary(1, "*",
            builder.binary(3, "+", builder.call(3, builder.identifier(3, "base_of"), {}),
                builder.binary(1, "*", builder.identifier(1, "i"), builder.literal(1, "4"))));
        const auto store = builder.expression_statement(1, builder.assign(1, deref, builder.literal(1, "0")));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "array_volatile_fixture", {i, store, ret},
            "c03-quality-array-volatile");
    }();
    require_quality_determinism(call_subtree_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.array_indexes_formed == 0 && count_indexes() == 0,
        "array recognition rewrote a volatile-risk call subtree");

    const auto wrong_scale_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto v9 = builder.declaration(3, "v9");
        const auto i = builder.declaration(1, "i");
        const auto deref = builder.unary(1, "*",
            builder.binary(3, "+", builder.identifier(3, "v9"),
                builder.binary(1, "*", builder.identifier(1, "i"), builder.literal(1, "8"))));
        const auto store = builder.expression_statement(1, builder.assign(1, deref, builder.literal(1, "0")));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "array_wrong_scale_fixture", {v9, i, store, ret},
            "c03-quality-array-wrong-scale");
    }();
    require_quality_determinism(wrong_scale_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.array_indexes_formed == 0 && count_indexes() == 0,
        "array recognition accepted an unprovable element scale");

    const auto width_mismatch_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto v9 = builder.declaration(3, "v9");
        const auto i = builder.declaration(1, "i");
        const auto deref = builder.unary(1, "*",
            builder.binary(3, "+", builder.identifier(3, "v9"),
                builder.binary(1, "*", builder.identifier(1, "i"), builder.literal(1, "4"))));
        const auto store = builder.expression_statement(5, builder.assign(5, deref,
            builder.identifier(5, "wide")));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "array_width_mismatch_fixture", {v9, i, store, ret},
            "c03-quality-array-width-mismatch");
    }();
    require_quality_determinism(width_mismatch_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.array_indexes_formed == 0 && count_indexes() == 0,
        "array recognition accepted a store-width mismatch");
}

void verify_method_call_restructuring_fixtures(const decompiler_entity_key_t& entity_value)
{
    const auto types = quality_type_graph(entity_value);
    const std::vector<typed_ast_branch_bridge_entry_t> no_bridge;
    const std::vector<rt_semantic_fact_view_t> no_facts;
    readability_transform_result_t result;
    typed_pseudocode_ast_v2_t ast;
    decompiler_render_evidence_t evidence;
    decompiler_prototype_evidence_t prototype;
    prototype.api_name = "Config::Load";
    prototype.return_type_display = "int";
    prototype.argument_names = {"this", "path"};
    prototype.argument_type_displays = {"Config*", "char*"};
    prototype.calling_convention = "__thiscall";
    prototype.class_qualifier = "Config";
    prototype.confidence = 100;
    evidence.prototypes.push_back(std::move(prototype));

    const auto rewrite_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto v1 = builder.declaration(9, "v1");
        const auto call_stmt = builder.expression_statement(1, builder.call(1,
            builder.identifier(1, "Config::Load"),
            {builder.identifier(9, "v1"), builder.literal(7, "\"app.ini\"")}));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "method_call_fixture", {v1, call_stmt, ret},
            "c03-quality-method-call");
    }();
    require_quality_determinism(rewrite_source, types, {}, &evidence, no_facts, no_bridge, result, ast);
    require(result.metrics.method_calls_restructured == 1,
        "method-call restructuring did not rewrite the qualified direct call");
    {
        const typed_pseudocode_ast_node_t* call = nullptr;
        for (const auto& value : ast.nodes) {
            if (value.kind == typed_pseudocode_ast_node_kind_t::call_expression)
                call = &value;
        }
        require(call != nullptr && call->child_ids.size() == 2,
            "method-call rewrite did not remove the object argument");
        const auto* callee = find_node(ast, call->child_ids[0]);
        require(callee != nullptr &&
                callee->kind == typed_pseudocode_ast_node_kind_t::member_expression &&
                callee->stable_text == "Load" && callee->child_ids.size() == 1,
            "method-call rewrite did not emit the member callee");
        const auto* object = find_node(ast, callee->child_ids[0]);
        require(object != nullptr && object->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                object->stable_text == "v1",
            "method-call rewrite lost the receiver object");
        const auto* argument = find_node(ast, call->child_ids[1]);
        require(argument != nullptr && argument->kind == typed_pseudocode_ast_node_kind_t::literal,
            "method-call rewrite dropped the surviving argument");
    }

    const auto side_effect_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto call_stmt = builder.expression_statement(1, builder.call(1,
            builder.identifier(1, "Config::Load"),
            {builder.call(9, builder.identifier(9, "make_config"), {}),
             builder.literal(7, "\"app.ini\"")}));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "method_call_side_effect_fixture", {call_stmt, ret},
            "c03-quality-method-call-side-effect");
    }();
    require_quality_determinism(side_effect_source, types, {}, &evidence, no_facts, no_bridge, result, ast);
    require(result.metrics.method_calls_restructured == 0,
        "method-call restructuring accepted a side-effect receiver");
}

void verify_semantic_fact_elimination_fixtures(const decompiler_entity_key_t& entity_value)
{
    const auto types = quality_type_graph(entity_value);
    readability_transform_result_t result;
    typed_pseudocode_ast_v2_t ast;
    const auto dead_branch_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto condition = builder.identifier(2, "c");
        const auto then_body = builder.compound(1, {
            builder.expression_statement(1, builder.call(1, builder.identifier(1, "Handle"), {}))});
        const auto else_body = builder.compound(1, {
            builder.expression_statement(1, builder.call(1, builder.identifier(1, "Fallthrough"), {}))});
        const auto if_node = builder.add(typed_pseudocode_ast_node_kind_t::if_statement, 1,
            {condition, then_body,
             builder.add(typed_pseudocode_ast_node_kind_t::else_clause, 1, {else_body}, {})}, {});
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        auto ast_value = builder.finish(types, "semantic_dead_branch_fixture",
            {if_node, ret}, "c03-quality-semantic-dead-branch");
        return std::make_tuple(std::move(ast_value), if_node, condition);
    };
    const auto fact_view = [](const std::string& key, const std::uint8_t confidence) {
        rt_semantic_fact_view_t view;
        view.refinement_key = key;
        view.confidence = confidence;
        return view;
    };
    const auto bridge_entry = [](const std::uint64_t value_id, const std::uint64_t statement,
                                 const std::uint64_t condition, const bool inverted) {
        typed_ast_branch_bridge_entry_t entry;
        entry.hir_value_id = value_id;
        entry.statement_node_id = statement;
        entry.condition_node_id = condition;
        entry.polarity_inverted = inverted;
        return entry;
    };
    const auto require_single_call = [&](const char* surviving, const char* eliminated) {
        require(count_kind(ast, typed_pseudocode_ast_node_kind_t::if_statement) == 0,
            "semantic elimination left the if statement");
        bool surviving_present = false;
        bool eliminated_present = false;
        bool comment_present = false;
        for (const auto& value : ast.nodes) {
            if (value.kind == typed_pseudocode_ast_node_kind_t::identifier &&
                value.stable_text == surviving)
                surviving_present = true;
            if (value.kind == typed_pseudocode_ast_node_kind_t::identifier &&
                value.stable_text == eliminated)
                eliminated_present = true;
            if (value.kind == typed_pseudocode_ast_node_kind_t::comment_statement &&
                value.stable_text ==
                    "proven dead branch eliminated (semantic_proof: branch_cond_eq0.v123)")
                comment_present = true;
        }
        require(surviving_present && !eliminated_present && comment_present,
            "semantic elimination did not splice the surviving arm with its proof comment");
    };

    {
        const auto [source, if_node, condition] = dead_branch_source();
        const std::vector<rt_semantic_fact_view_t> facts{fact_view("branch_cond_eq0.v123", 100)};
        const std::vector<typed_ast_branch_bridge_entry_t> bridge{
            bridge_entry(123, if_node, condition, false)};
        require_quality_determinism(source, types, {}, nullptr, facts, bridge, result, ast);
        require(result.metrics.dead_branches_eliminated == 1 &&
                result.metrics.semantic_facts_applied == 1,
            "semantic elimination did not eliminate the proved-dead then arm");
        require_single_call("Fallthrough", "Handle");
    }
    {
        const auto [source, if_node, condition] = dead_branch_source();
        const std::vector<rt_semantic_fact_view_t> facts{fact_view("branch_cond_eq0.v123", 100)};
        const std::vector<typed_ast_branch_bridge_entry_t> bridge{
            bridge_entry(123, if_node, condition, true)};
        require_quality_determinism(source, types, {}, nullptr, facts, bridge, result, ast);
        require(result.metrics.dead_branches_eliminated == 1 &&
                result.metrics.semantic_facts_applied == 1,
            "semantic elimination did not eliminate the proved-dead else arm");
        require_single_call("Handle", "Fallthrough");
    }
    {
        const auto [source, if_node, condition] = dead_branch_source();
        (void)if_node;
        (void)condition;
        const std::vector<rt_semantic_fact_view_t> facts{fact_view("branch_cond_eq0.v123", 100)};
        const std::vector<typed_ast_branch_bridge_entry_t> no_bridge;
        require_quality_determinism(source, types, {}, nullptr, facts, no_bridge, result, ast);
        require(result.metrics.dead_branches_eliminated == 0 &&
                count_kind(ast, typed_pseudocode_ast_node_kind_t::if_statement) == 1,
            "semantic elimination rewrote a branch without a bridge entry");
    }
    {
        const auto [source, if_node, condition] = dead_branch_source();
        const std::vector<rt_semantic_fact_view_t> facts{fact_view("branch_cond_eq0.v123", 50)};
        const std::vector<typed_ast_branch_bridge_entry_t> bridge{
            bridge_entry(123, if_node, condition, false)};
        require_quality_determinism(source, types, {}, nullptr, facts, bridge, result, ast);
        require(result.metrics.dead_branches_eliminated == 0 &&
                count_kind(ast, typed_pseudocode_ast_node_kind_t::if_statement) == 1,
            "semantic elimination rewrote a branch on a sub-100-confidence fact");
    }
    {
        quality_ast_builder_t builder{entity_value};
        const auto condition = builder.call(2, builder.identifier(2, "evaluate"), {});
        const auto then_body = builder.compound(1, {
            builder.expression_statement(1, builder.call(1, builder.identifier(1, "Handle"), {}))});
        const auto else_body = builder.compound(1, {
            builder.expression_statement(1, builder.call(1, builder.identifier(1, "Fallthrough"), {}))});
        const auto if_node = builder.add(typed_pseudocode_ast_node_kind_t::if_statement, 1,
            {condition, then_body,
             builder.add(typed_pseudocode_ast_node_kind_t::else_clause, 1, {else_body}, {})}, {});
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        auto source = builder.finish(types, "semantic_side_effect_fixture",
            {if_node, ret}, "c03-quality-semantic-side-effect");
        const std::vector<rt_semantic_fact_view_t> facts{fact_view("branch_cond_eq0.v123", 100)};
        const std::vector<typed_ast_branch_bridge_entry_t> bridge{
            bridge_entry(123, if_node, condition, false)};
        require_quality_determinism(source, types, {}, nullptr, facts, bridge, result, ast);
        require(result.metrics.dead_branches_eliminated == 0 &&
                count_kind(ast, typed_pseudocode_ast_node_kind_t::if_statement) == 1,
            "semantic elimination rewrote a side-effect condition");
    }
}

void verify_constant_folding_hardening_fixtures(const decompiler_entity_key_t& entity_value)
{
    const auto types = quality_type_graph(entity_value);
    const std::vector<typed_ast_branch_bridge_entry_t> no_bridge;
    const std::vector<rt_semantic_fact_view_t> no_facts;
    readability_transform_result_t result;
    typed_pseudocode_ast_v2_t ast;
    const auto fold_source = [&](const std::uint64_t type, const std::string& op,
                                 const std::string& left, const std::string& right,
                                 const char* name, const char* seed) {
        quality_ast_builder_t builder{entity_value};
        const auto r = builder.declaration(type, "r");
        const auto store = builder.expression_statement(type, builder.assign(type,
            builder.identifier(type, "r"),
            builder.binary(type, op, builder.literal(type, left), builder.literal(type, right))));
        const auto ret = builder.return_statement(type, builder.identifier(type, "r"));
        return builder.finish(types, name, {r, store, ret}, seed);
    };
    const auto folded_literal = [&]() -> const typed_pseudocode_ast_node_t* {
        for (const auto& value : ast.nodes) {
            if (value.kind == typed_pseudocode_ast_node_kind_t::literal &&
                value.stable_text != "4611686018427387904" && value.stable_text != "4" &&
                value.stable_text != "3u" && value.stable_text != "5u" &&
                value.stable_text != "-9223372036854775808" && value.stable_text != "-1" &&
                value.stable_text != "2" && value.stable_text != "3" &&
                value.stable_text != "5" && value.stable_text != "9" &&
                value.stable_text != "6" && value.stable_text != "7")
                return &value;
        }
        return nullptr;
    };

    ast = fold_source(11, "*", "4611686018427387904", "4",
        "fold_overflow_fixture", "c03-quality-fold-overflow");
    require_quality_determinism(ast, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.constants_folded == 0 && result.metrics.overflow_guards_hit >= 1 &&
            count_kind(ast, typed_pseudocode_ast_node_kind_t::binary_expression) == 1,
        "overflow-checked multiply folded an overflowing signed product");

    ast = fold_source(4, "*", "3u", "5u",
        "fold_unsigned_fixture", "c03-quality-fold-unsigned");
    require_quality_determinism(ast, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.unsigned_folds == 1,
        "unsigned multiply was not folded through the unsigned path");
    {
        const auto* folded = folded_literal();
        require(folded != nullptr && folded->stable_text == "15u",
            "unsigned multiply fold lost the unsigned suffix");
    }

    ast = fold_source(11, "/", "-9223372036854775808", "-1",
        "fold_min_div_fixture", "c03-quality-fold-min-div");
    require_quality_determinism(ast, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.constants_folded == 0 &&
            count_kind(ast, typed_pseudocode_ast_node_kind_t::binary_expression) == 1,
        "division folding accepted INT64_MIN divided by -1");

    ast = fold_source(2, "<", "2", "3",
        "fold_relational_fixture", "c03-quality-fold-relational");
    require_quality_determinism(ast, types, {}, nullptr, no_facts, no_bridge, result, ast);
    {
        const auto* folded = folded_literal();
        require(folded != nullptr && folded->stable_text == "1" && folded->type_id == 2,
            "relational folding did not produce a boolean true literal");
    }

    ast = fold_source(2, ">=", "5", "9",
        "fold_relational_false_fixture", "c03-quality-fold-relational-false");
    require_quality_determinism(ast, types, {}, nullptr, no_facts, no_bridge, result, ast);
    {
        const auto* folded = folded_literal();
        require(folded != nullptr && folded->stable_text == "0" && folded->type_id == 2,
            "relational folding did not produce a boolean false literal");
    }

    ast = fold_source(1, "+", "6", "7",
        "fold_signed_suffix_fixture", "c03-quality-fold-signed-suffix");
    require_quality_determinism(ast, types, {}, nullptr, no_facts, no_bridge, result, ast);
    {
        const auto* folded = folded_literal();
        require(folded != nullptr && folded->stable_text == "42",
            "signed fold did not preserve the plain literal spelling");
    }
}

void verify_cast_agreement_insertion_fixtures(const decompiler_entity_key_t& entity_value)
{
    const auto types = quality_type_graph(entity_value);
    const std::vector<typed_ast_branch_bridge_entry_t> no_bridge;
    const std::vector<rt_semantic_fact_view_t> no_facts;
    readability_transform_result_t result;
    typed_pseudocode_ast_v2_t ast;
    readability_transform_settings_t audit;
    audit.enable_cast_agreement_insertion = true;
    const auto count_casts = [&]() {
        return count_kind(ast, typed_pseudocode_ast_node_kind_t::cast_expression);
    };

    const auto widening_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto v7 = builder.declaration(5, "v7");
        const auto v4 = builder.declaration(4, "v4");
        const auto v5 = builder.declaration(5, "v5");
        const auto store = builder.expression_statement(5, builder.assign(5,
            builder.identifier(5, "v7"),
            builder.binary(5, "+", builder.identifier(4, "v4"), builder.identifier(5, "v5"))));
        const auto ret = builder.return_statement(5, builder.identifier(5, "v7"));
        return builder.finish(types, "cast_widening_fixture", {v7, v4, v5, store, ret},
            "c03-quality-cast-widening");
    }();
    require_quality_determinism(widening_source, types, audit, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.casts_inserted == 1 && count_casts() == 1,
        "cast agreement insertion did not insert the widening cast");
    {
        const typed_pseudocode_ast_node_t* cast = nullptr;
        for (const auto& value : ast.nodes) {
            if (value.kind == typed_pseudocode_ast_node_kind_t::cast_expression)
                cast = &value;
        }
        require(cast != nullptr && cast->type_id == 5 && cast->child_ids.size() == 1,
            "cast agreement insertion produced a wrong widening cast");
        const auto* operand = find_node(ast, cast->child_ids[0]);
        require(operand != nullptr && operand->kind == typed_pseudocode_ast_node_kind_t::identifier &&
                operand->stable_text == "v4",
            "cast agreement insertion wrapped the wrong operand");
    }
    require_quality_determinism(widening_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.casts_inserted == 0 && count_casts() == 0,
        "cast agreement insertion fired without the audit flag");

    const auto narrowing_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto v = builder.declaration(4, "v");
        const auto a = builder.declaration(5, "a");
        const auto b = builder.declaration(4, "b");
        const auto store = builder.expression_statement(4, builder.assign(4,
            builder.identifier(4, "v"),
            builder.binary(4, "+", builder.identifier(5, "a"), builder.identifier(4, "b"))));
        const auto ret = builder.return_statement(4, builder.identifier(4, "v"));
        return builder.finish(types, "cast_narrowing_fixture", {v, a, b, store, ret},
            "c03-quality-cast-narrowing");
    }();
    require_quality_determinism(narrowing_source, types, audit, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.casts_inserted == 0 && count_casts() == 0,
        "cast agreement insertion inserted a narrowing cast");

    const auto literal_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto v = builder.declaration(5, "v");
        const auto w = builder.declaration(5, "w");
        const auto store = builder.expression_statement(5, builder.assign(5,
            builder.identifier(5, "v"),
            builder.binary(5, "+", builder.literal(4, "3"), builder.identifier(5, "w"))));
        const auto ret = builder.return_statement(5, builder.identifier(5, "v"));
        return builder.finish(types, "cast_literal_fixture", {v, w, store, ret},
            "c03-quality-cast-literal");
    }();
    require_quality_determinism(literal_source, types, audit, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.casts_inserted == 0 && count_casts() == 0,
        "cast agreement insertion wrapped a literal operand");
}

void verify_vararg_format_comment_fixtures(const decompiler_entity_key_t& entity_value)
{
    const auto types = quality_type_graph(entity_value);
    const std::vector<typed_ast_branch_bridge_entry_t> no_bridge;
    const std::vector<rt_semantic_fact_view_t> no_facts;
    readability_transform_result_t result;
    typed_pseudocode_ast_v2_t ast;
    decompiler_render_evidence_t evidence;
    decompiler_prototype_evidence_t prototype;
    prototype.api_name = "printf";
    prototype.return_type_display = "int";
    prototype.argument_names = {"format"};
    prototype.argument_type_displays = {"const char*"};
    prototype.is_variadic = true;
    prototype.calling_convention = "__cdecl";
    prototype.confidence = 100;
    evidence.prototypes.push_back(std::move(prototype));
    const auto vararg_source = [&](const std::string& format,
                                   std::vector<std::pair<std::uint64_t, std::string>> arguments,
                                   const char* name, const char* seed) {
        quality_ast_builder_t builder{entity_value};
        std::vector<std::uint64_t> call_arguments{builder.literal(7, format)};
        std::vector<std::uint64_t> declarations;
        for (auto& argument : arguments) {
            declarations.push_back(builder.declaration(argument.first, argument.second));
            call_arguments.push_back(builder.identifier(argument.first, argument.second));
        }
        const auto call_stmt = builder.expression_statement(1, builder.call(1,
            builder.identifier(1, "printf"), std::move(call_arguments)));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        declarations.push_back(call_stmt);
        declarations.push_back(ret);
        return builder.finish(types, name, std::move(declarations), seed);
    };
    const auto comments = [&]() {
        std::vector<std::string> texts;
        for (const auto& value : ast.nodes) {
            if (value.kind == typed_pseudocode_ast_node_kind_t::comment_statement)
                texts.push_back(value.stable_text);
        }
        return texts;
    };

    ast = vararg_source("\"x=%d y=%s\"", {{1, "x"}}, "vararg_mismatch_fixture",
        "c03-quality-vararg-mismatch");
    require_quality_determinism(ast, types, {}, &evidence, no_facts, no_bridge, result, ast);
    require(result.metrics.vararg_format_comments_injected == 1,
        "vararg format analysis did not comment on the mismatching printf call");
    {
        const auto texts = comments();
        require(texts.size() == 1 &&
                texts.front().find("printf-family: format specifies 2 args, 1 supplied") !=
                    std::string::npos &&
                texts.front().find("MISMATCH") != std::string::npos,
            "vararg mismatch comment text diverged");
    }

    ast = vararg_source("\"100%%\"", {}, "vararg_escaped_fixture", "c03-quality-vararg-escaped");
    require_quality_determinism(ast, types, {}, &evidence, no_facts, no_bridge, result, ast);
    require(result.metrics.vararg_format_comments_injected == 1,
        "vararg format analysis did not comment on the escaped-percent printf call");
    {
        const auto texts = comments();
        require(texts.size() == 1 &&
                texts.front().find("printf-family: format specifies 0 args, 0 supplied") !=
                    std::string::npos &&
                texts.front().find("MISMATCH") == std::string::npos,
            "vararg escaped-percent comment text diverged");
    }

    ast = vararg_source("\"%*d\"", {{1, "width"}, {1, "x"}}, "vararg_width_fixture",
        "c03-quality-vararg-width");
    require_quality_determinism(ast, types, {}, &evidence, no_facts, no_bridge, result, ast);
    require(result.metrics.vararg_format_comments_injected == 1,
        "vararg format analysis did not comment on the star-width printf call");
    {
        const auto texts = comments();
        require(texts.size() == 1 &&
                texts.front().find("printf-family: format specifies 2 args, 2 supplied") !=
                    std::string::npos &&
                texts.front().find("MISMATCH") == std::string::npos,
            "vararg star-width comment text diverged");
    }

    std::string oversized_format(4100, 'x');
    oversized_format = "\"" + oversized_format + "\"";
    ast = vararg_source(oversized_format, {{1, "x"}}, "vararg_cap_fixture",
        "c03-quality-vararg-cap");
    require_quality_determinism(ast, types, {}, &evidence, no_facts, no_bridge, result, ast);
    require(result.metrics.vararg_format_comments_injected == 0 && comments().empty(),
        "vararg format analysis exceeded its format literal cap");
}

void verify_declaration_relocation_parity(const decompiler_entity_key_t& entity_value)
{
    const auto types = quality_type_graph(entity_value);
    const std::vector<typed_ast_branch_bridge_entry_t> no_bridge;
    const std::vector<rt_semantic_fact_view_t> no_facts;
    readability_transform_result_t result;
    typed_pseudocode_ast_v2_t ast;

    const auto adjacent_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto foo = builder.expression_statement(1, builder.call(1,
            builder.identifier(1, "foo"), {}));
        const auto alpha = builder.declaration(1, "alpha");
        const auto beta = builder.declaration(1, "beta");
        const auto use_alpha = builder.expression_statement(1, builder.call(1,
            builder.identifier(1, "f"), {builder.identifier(1, "alpha")}));
        const auto use_beta = builder.expression_statement(1, builder.call(1,
            builder.identifier(1, "g"), {builder.identifier(1, "beta")}));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "relocation_adjacent_fixture",
            {foo, alpha, beta, use_alpha, use_beta, ret}, "c03-quality-relocation-adjacent");
    }();
    require_quality_determinism(adjacent_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.declarations_relocated == 2,
        "declaration relocation did not move both declarations adjacent to first use");
    {
        const auto* body = find_node(ast, ast.body_node_id);
        require(body != nullptr && body->child_ids.size() == 6,
            "relocation adjacent fixture changed the body shape");
        const auto child_kind = [&](const std::size_t index) {
            const auto* value = find_node(ast, body->child_ids[index]);
            return value != nullptr ? value->kind : typed_pseudocode_ast_node_kind_t::unknown_expression;
        };
        require(child_kind(0) == typed_pseudocode_ast_node_kind_t::expression_statement &&
                child_kind(1) == typed_pseudocode_ast_node_kind_t::declaration &&
                child_kind(2) == typed_pseudocode_ast_node_kind_t::expression_statement &&
                child_kind(3) == typed_pseudocode_ast_node_kind_t::declaration &&
                child_kind(4) == typed_pseudocode_ast_node_kind_t::expression_statement &&
                child_kind(5) == typed_pseudocode_ast_node_kind_t::return_statement,
            "relocation adjacent fixture produced a different child order");
        const auto* first_decl = find_node(ast, body->child_ids[1]);
        const auto* first_use = find_node(ast, body->child_ids[2]);
        const auto* second_decl = find_node(ast, body->child_ids[3]);
        const auto* second_use = find_node(ast, body->child_ids[4]);
        const auto uses_name = [&](const typed_pseudocode_ast_node_t* statement,
                                   const std::string& name) {
            bool found = false;
            for (const auto& value : ast.nodes) {
                if (value.kind == typed_pseudocode_ast_node_kind_t::identifier &&
                    value.stable_text == name) {
                    const auto* owner = parent_of(ast, value.id);
                    while (owner != nullptr) {
                        if (owner->id == statement->id)
                            found = true;
                        owner = parent_of(ast, owner->id);
                    }
                }
            }
            return found;
        };
        require(first_decl != nullptr && first_use != nullptr && second_decl != nullptr &&
                second_use != nullptr && !first_decl->stable_text.empty() &&
                !second_decl->stable_text.empty() &&
                first_decl->stable_text != second_decl->stable_text &&
                uses_name(first_use, first_decl->stable_text) &&
                !uses_name(first_use, second_decl->stable_text) &&
                uses_name(second_use, second_decl->stable_text) &&
                !uses_name(second_use, first_decl->stable_text),
            "relocation adjacent fixture did not bind each declaration to its own first use");
    }

    const auto merged_source = [&]() {
        quality_ast_builder_t builder{entity_value};
        const auto m = builder.declaration(1, "m");
        const auto foo = builder.expression_statement(1, builder.call(1,
            builder.identifier(1, "foo"), {}));
        const auto assign_m = builder.expression_statement(1, builder.assign(1,
            builder.identifier(1, "m"),
            builder.call(1, builder.identifier(1, "q"), {})));
        const auto use_m = builder.expression_statement(1, builder.call(1,
            builder.identifier(1, "h"), {builder.identifier(1, "m")}));
        const auto ret = builder.return_statement(1, builder.literal(1, "0"));
        return builder.finish(types, "relocation_merged_fixture",
            {m, foo, assign_m, use_m, ret}, "c03-quality-relocation-merged");
    }();
    require_quality_determinism(merged_source, types, {}, nullptr, no_facts, no_bridge, result, ast);
    require(result.metrics.declarations_relocated == 1,
        "declaration relocation did not merge the declaration into the first assignment");
    {
        const auto* body = find_node(ast, ast.body_node_id);
        require(body != nullptr && body->child_ids.size() == 4,
            "relocation merged fixture changed the body shape");
        const auto* decl = find_node(ast, body->child_ids[1]);
        require(decl != nullptr && decl->kind == typed_pseudocode_ast_node_kind_t::declaration &&
                decl->stable_text == "m" && decl->child_ids.size() == 1,
            "relocation merged fixture lost the initialized declaration");
        const auto* initializer = find_node(ast, decl->child_ids[0]);
        require(initializer != nullptr &&
                initializer->kind == typed_pseudocode_ast_node_kind_t::call_expression,
            "relocation merged fixture did not keep the assignment expression as the initializer");
    }
}

void verify_advisory_metric_fixtures(const decompiler_entity_key_t& entity_value)
{
    const auto types = quality_type_graph(entity_value);
    const std::vector<typed_ast_branch_bridge_entry_t> no_bridge;
    const std::vector<rt_semantic_fact_view_t> no_facts;
    readability_transform_result_t result;
    typed_pseudocode_ast_v2_t ast;
    pseudocode_renderer_request_t render_request;
    render_request.profile = decompiler_profile_id_t::balanced;
    render_request.settings = pseudocode_renderer_style_settings(
        pseudocode_renderer_style_profile_t::balanced);
    const auto analyze_transformed = [&](const typed_pseudocode_ast_v2_t& source,
                                         const char* message) {
        ast = source;
        result = apply_readability_transforms(ast, types, {}, decompiler_render_evidence_t{},
            no_facts, no_bridge);
        require(result.diagnostics.empty(), message);
        const auto rendered = render_pseudocode(ast, types, render_request);
        require(rendered.succeeded() && rendered.document.has_value(), message);
        const auto analyzed = analyze_pseudocode_readability(ast, *rendered.document);
        require(analyzed.succeeded() && analyzed.report.has_value(), message);
        return *analyzed.report;
    };

    quality_ast_builder_t ternary_builder{entity_value};
    const auto ok = ternary_builder.declaration(2, "ok");
    const auto r = ternary_builder.declaration(1, "r");
    const auto a = ternary_builder.declaration(1, "a");
    const auto b = ternary_builder.declaration(1, "b");
    const auto then_body = ternary_builder.compound(1, {
        ternary_builder.expression_statement(1, ternary_builder.assign(1,
            ternary_builder.identifier(1, "r"), ternary_builder.identifier(1, "a")))});
    const auto else_body = ternary_builder.compound(1, {
        ternary_builder.expression_statement(1, ternary_builder.assign(1,
            ternary_builder.identifier(1, "r"), ternary_builder.identifier(1, "b")))});
    const auto if_node = ternary_builder.if_statement(1,
        ternary_builder.identifier(2, "ok"), then_body, else_body);
    const auto ret = ternary_builder.return_statement(1, ternary_builder.identifier(1, "r"));
    const auto ternary_source = ternary_builder.finish(types, "advisory_ternary_fixture",
        {ok, r, a, b, if_node, ret}, "c03-quality-advisory-ternary");
    {
        const auto report = analyze_transformed(ternary_source,
            "advisory ternary fixture did not analyze");
        require(report.metrics.ternary_count == 1,
            "advisory analysis did not count the ternary expression");
    }

    quality_ast_builder_t array_builder{entity_value};
    const auto v9 = array_builder.declaration(3, "v9");
    const auto i = array_builder.declaration(1, "i");
    const auto store = array_builder.expression_statement(1, array_builder.assign(1,
        array_builder.unary(1, "*",
            array_builder.binary(3, "+", array_builder.identifier(3, "v9"),
                array_builder.binary(1, "*", array_builder.identifier(1, "i"),
                    array_builder.literal(1, "4")))),
        array_builder.literal(1, "0")));
    const auto array_ret = array_builder.return_statement(1, array_builder.literal(1, "0"));
    const auto array_source = array_builder.finish(types, "advisory_array_fixture",
        {v9, i, store, array_ret}, "c03-quality-advisory-array");
    {
        const auto report = analyze_transformed(array_source,
            "advisory array fixture did not analyze");
        require(report.metrics.array_index_count == 1,
            "advisory analysis did not count the array index expression");
    }

    quality_ast_builder_t method_builder{entity_value};
    const auto obj = method_builder.declaration(9, "obj");
    const auto member = method_builder.add(typed_pseudocode_ast_node_kind_t::member_expression,
        1, {method_builder.identifier(9, "obj")}, "Load");
    const auto call_stmt = method_builder.expression_statement(1, method_builder.call(1,
        member, {method_builder.literal(7, "\"app.ini\"")}));
    const auto method_ret = method_builder.return_statement(1, method_builder.literal(1, "0"));
    const auto method_source = method_builder.finish(types, "advisory_method_fixture",
        {obj, call_stmt, method_ret}, "c03-quality-advisory-method");
    {
        const auto report = analyze_transformed(method_source,
            "advisory method fixture did not analyze");
        require(report.metrics.method_call_count == 1,
            "advisory analysis did not count the member-shaped call");
    }
}

}

void run_decompiler_readability_harness()
{
    const auto entity_value = entity();
    const auto types = type_graph(entity_value);
    require(validate_decompiler_entity_key(entity_value).valid(),
        "readability entity fixture is invalid");
    require(validate_type_graph(types).valid(), "readability type graph fixture is invalid");

    const auto valid_ast = ast(entity_value, types, true);
    const auto empty_ast = ast(entity_value, types, false);
    require(validate_typed_pseudocode_ast(valid_ast).valid(),
        "readability typed AST fixture is invalid");
    auto valid_document = render(valid_ast, types);
    auto empty_document = valid_document;
    empty_document.ast = empty_ast;
    empty_document.ast_hash = stable_serialization_hash(empty_ast);
    require(!typed_ast_has_proven_function_body(empty_ast),
        "fabricated-body fixture unexpectedly contains a proven body");

    verify_null_and_fabricated_rejection(valid_document, empty_ast, empty_document);
    verify_diagnostic_and_mapping_preservation(valid_ast, valid_document);
    verify_bounded_deterministic_view(valid_document);
    verify_readability_golden_output(entity_value);
    verify_new_pass_parity_on_golden(entity_value);
    verify_baseline_capture(valid_ast, valid_document);
    verify_pseudocode_document_delivery(valid_document);
    verify_reconstructor_gate(valid_document, empty_document);
    verify_typed_reconstructor(valid_document, empty_document);
    verify_ternary_formation_fixtures(entity_value);
    verify_array_index_recognition_fixtures(entity_value);
    verify_method_call_restructuring_fixtures(entity_value);
    verify_semantic_fact_elimination_fixtures(entity_value);
    verify_constant_folding_hardening_fixtures(entity_value);
    verify_cast_agreement_insertion_fixtures(entity_value);
    verify_vararg_format_comment_fixtures(entity_value);
    verify_declaration_relocation_parity(entity_value);
    verify_advisory_metric_fixtures(entity_value);
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_decompiler_readability_harness();
        std::cout << "decompiler_readability_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
