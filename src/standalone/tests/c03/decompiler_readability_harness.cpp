#include "decompiler_readability_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/pseudocode_readability.hpp"
#include "../../src/core/analysis/decompiler/pseudocode_renderer_v2.hpp"
#include "../../src/core/analysis/decompiler/source_reconstructor.hpp"
#include "../../src/core/analysis/source_reconstructor.hpp"
#include "../../src/core/workbench/adapters/pseudocode_document.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
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
    pseudocode_renderer_v2_request_t request;
    request.profile = decompiler_profile_id_t::balanced;
    request.settings = pseudocode_renderer_v2_style_settings(
        pseudocode_renderer_v2_style_profile_t::balanced);
    auto rendered = render_pseudocode_v2(ast_value, types, request);
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
    verify_baseline_capture(valid_ast, valid_document);
    verify_pseudocode_document_delivery(valid_document);
    verify_reconstructor_gate(valid_document, empty_document);
    verify_typed_reconstructor(valid_document, empty_document);
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
