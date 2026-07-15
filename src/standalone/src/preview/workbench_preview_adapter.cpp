#include "workbench_preview_adapter.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../core/analysis/workspace/analysis_workspace.hpp"

#include <algorithm>
#include <utility>

namespace aida::preview {
namespace {

workbench::workbench_error_t error(workbench::workbench_error_code_t code,
                                   std::uint64_t subject = 0) {
    return {code, subject};
}

analysis::sha256_digest_t digest(std::uint8_t seed) {
    analysis::sha256_digest_t value;
    for (std::size_t index = 0; index < value.bytes.size(); ++index)
        value.bytes[index] = static_cast<std::uint8_t>(seed + index * 7U);
    return value;
}

analysis::source_coordinate_t coordinate(
    const analysis::decompiler_entity_key_t& entity,
    analysis::decompiler_coordinate_layer_t layer,
    std::uint64_t generation, std::uint64_t begin, std::uint64_t end,
    std::optional<analysis::decompiler_token_range_t> document = {}) {
    analysis::source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = generation;
    result.entity = entity;
    result.address_range = analysis::decompiler_address_range_t{
        {analysis::address_space_id_t::relative_virtual, begin,
         analysis::architecture_id_t::x86_64,
         analysis::architecture_mode_t::x86_64},
        {analysis::address_space_id_t::relative_virtual, end,
         analysis::architecture_id_t::x86_64,
         analysis::architecture_mode_t::x86_64}};
    result.document_range = document;
    return result;
}

analysis::decompiler_document_t document_for(
    const workbench::pseudocode_document::pseudocode_request_t& request) {
    analysis::decompiler_document_t document;
    document.entity = request.entity;
    document.profile = request.profile;
    document.renderer.style_id = "aida-blue";
    document.renderer.indentation_spaces = 4;
    document.rendered_text =
        "bool analyze_image(const image_t* image)\n"
        "{\n"
        "    if (image == nullptr || !validate_header(image))\n"
        "        return false;\n"
        "\n"
        "    const auto sections = enumerate_sections(image);\n"
        "    for (const auto& section : sections)\n"
        "        classify_region(section);\n"
        "\n"
        "    publish_analysis(image, sections);\n"
        "    return true;\n"
        "}";
    const auto* native = std::get_if<analysis::native_decompiler_entity_identity_t>(
        &request.entity.identity);
    const auto begin = native ? native->entry.value : 0x1000;
    const auto end = native ? native->end.value : 0x101E;
    document.ast.entity = request.entity;
    document.ast.hir_hash = digest(0x41);
    document.ast.type_graph_hash = digest(0x83);
    document.ast.root_node_id = 1;
    document.ast.body_node_id = 2;
    analysis::typed_pseudocode_ast_node_t root;
    root.id = 1;
    root.kind = analysis::typed_pseudocode_ast_node_kind_t::function_definition;
    root.type_id = 1;
    root.child_ids = {2};
    root.stable_text = "analyze_image";
    root.coordinate = coordinate(request.entity,
        analysis::decompiler_coordinate_layer_t::typed_ast,
        request.workspace_generation, begin, end);
    root.confidence = 98;
    root.provenance = analysis::decompiler_fact_provenance_t::provider_semantics;
    analysis::typed_pseudocode_ast_node_t body;
    body.id = 2;
    body.kind = analysis::typed_pseudocode_ast_node_kind_t::compound_statement;
    body.type_id = 1;
    body.child_ids = {3};
    body.stable_text = "body";
    body.coordinate = root.coordinate;
    body.confidence = 97;
    body.provenance = analysis::decompiler_fact_provenance_t::provider_semantics;
    analysis::typed_pseudocode_ast_node_t statement;
    statement.id = 3;
    statement.kind = analysis::typed_pseudocode_ast_node_kind_t::return_statement;
    statement.type_id = 1;
    statement.stable_text = "return true";
    statement.coordinate = root.coordinate;
    statement.confidence = 96;
    statement.provenance = analysis::decompiler_fact_provenance_t::provider_semantics;
    document.ast.nodes = {std::move(root), std::move(body),
                          std::move(statement)};
    document.type_graph_hash = document.ast.type_graph_hash;
    document.ast_hash = analysis::stable_serialization_hash(document.ast);
    analysis::decompiler_document_token_t token;
    token.kind = analysis::decompiler_document_token_kind_t::unknown;
    token.range = {0, static_cast<std::uint32_t>(document.rendered_text.size())};
    token.ast_node_id = 1;
    document.tokens.push_back(token);
    analysis::decompiler_document_source_map_t source_map;
    source_map.document_range = token.range;
    source_map.coordinates.push_back(coordinate(
        request.entity, analysis::decompiler_coordinate_layer_t::document,
        request.workspace_generation, begin, end, token.range));
    document.source_maps.push_back(std::move(source_map));
    return document;
}

}

synchronous_pseudocode_source_adapter_t::synchronous_pseudocode_source_adapter_t(
    std::shared_ptr<analysis::analysis_workspace_t> workspace)
    : workspace_(std::move(workspace)) {}

std::uint64_t synchronous_pseudocode_source_adapter_t::current_generation()
    const noexcept {
    return workspace_ ? workspace_->generation() : 0;
}

bool synchronous_pseudocode_source_adapter_t::generation_current(
    std::uint64_t generation) const noexcept {
    return workspace_ && generation != 0 && workspace_->generation() == generation;
}

workbench::workbench_error_t
synchronous_pseudocode_source_adapter_t::resolve_request(
    std::uint64_t function_address,
    analysis::decompiler_profile_id_t profile,
    std::uint64_t timeout_ms,
    workbench::pseudocode_document::pseudocode_request_t& output) const {
    output = {};
    const auto publication = workspace_ ? workspace_->analysis_publication() : nullptr;
    if (!publication || !publication->snapshot || timeout_ms == 0)
        return error(workbench::workbench_error_code_t::adapter_rejected,
                     function_address);
    const auto found = std::find_if(
        publication->snapshot->functions.begin(),
        publication->snapshot->functions.end(),
        [&](const auto& function) {
            return function.start.value == function_address;
        });
    if (found == publication->snapshot->functions.end())
        return error(workbench::workbench_error_code_t::invalid_document,
                     function_address);
    analysis::native_decompiler_entity_identity_t identity;
    identity.function_id = found->id;
    identity.entry = found->start;
    identity.end = found->end;
    identity.function_bytes_hash = digest(
        static_cast<std::uint8_t>(found->start.value & 0xFFU));
    const auto symbol = found->symbol_id
        ? std::find_if(publication->snapshot->symbols.begin(),
              publication->snapshot->symbols.end(), [&](const auto& candidate) {
                  return candidate.id == *found->symbol_id;
              })
        : publication->snapshot->symbols.end();
    identity.canonical_symbol = symbol == publication->snapshot->symbols.end()
        ? "sub_" + std::to_string(found->start.value) : symbol->name;
    output.entity.kind = analysis::decompiler_entity_kind_t::native_function;
    output.entity.format = workspace_->identity().format();
    output.entity.architecture = workspace_->identity().architecture();
    output.entity.mode = workspace_->identity().architecture_mode();
    output.entity.endian = workspace_->identity().endian();
    output.entity.identity = std::move(identity);
    output.profile = profile;
    output.workspace_generation = publication->generation;
    output.timeout_ms = (std::min)(timeout_ms,
                                  profile_budget(profile).max_wall_clock_ms);
    return {};
}

workbench::workbench_error_t
synchronous_pseudocode_source_adapter_t::request_decompilation(
    const workbench::pseudocode_document::pseudocode_request_t& request,
    std::uint64_t job_id) {
    if (job_id == 0 || !generation_current(request.workspace_generation))
        return error(workbench::workbench_error_code_t::revision_mismatch,
                     request.workspace_generation);
    auto document = document_for(request);
    if (!analysis::validate_decompiler_document(document).valid())
        return error(workbench::workbench_error_code_t::adapter_rejected, job_id);
    std::lock_guard lock(mutex_);
    if (!completed_.emplace(job_id, std::move(document)).second)
        return error(workbench::workbench_error_code_t::duplicate_identifier,
                     job_id);
    return {};
}

workbench::workbench_error_t
synchronous_pseudocode_source_adapter_t::cancel_decompilation(
    std::uint64_t job_id) {
    std::lock_guard lock(mutex_);
    completed_.erase(job_id);
    return {};
}

bool synchronous_pseudocode_source_adapter_t::poll_result(
    std::uint64_t job_id, analysis::decompiler_document_t& output) {
    std::lock_guard lock(mutex_);
    const auto found = completed_.find(job_id);
    if (found == completed_.end())
        return false;
    output = std::move(found->second);
    completed_.erase(found);
    return true;
}

bool synchronous_pseudocode_source_adapter_t::poll_failure(
    std::uint64_t job_id,
    std::vector<analysis::decompiler_diagnostic_t>& output) {
    static_cast<void>(job_id);
    output.clear();
    return false;
}

bool synchronous_pseudocode_source_adapter_t::job_active(
    std::uint64_t job_id) const noexcept {
    try {
        std::lock_guard lock(mutex_);
        static_cast<void>(job_id);
        return false;
    } catch (...) {
        return false;
    }
}

analysis::decompiler_profile_budget_t
synchronous_pseudocode_source_adapter_t::profile_budget(
    analysis::decompiler_profile_id_t profile) const noexcept {
    analysis::decompiler_profile_budget_t budget;
    budget.profile = profile;
    budget.max_wall_clock_ms = profile == analysis::decompiler_profile_id_t::fast
        ? 1500 : profile == analysis::decompiler_profile_id_t::balanced
            ? 5000 : 12000;
    budget.max_cpu_ms = budget.max_wall_clock_ms;
    budget.max_memory_bytes = 64ULL * 1024ULL * 1024ULL;
    budget.max_provider_ir_nodes = 100000;
    budget.max_hir_nodes = 100000;
    budget.max_ast_nodes = 100000;
    budget.max_semantic_queries = 64;
    budget.semantic_proofs_enabled =
        profile == analysis::decompiler_profile_id_t::thorough;
    return budget;
}

}

#endif
