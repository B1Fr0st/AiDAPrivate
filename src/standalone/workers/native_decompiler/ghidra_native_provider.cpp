#include "ghidra_native_provider.hpp"

#include "../../src/core/analysis/decompiler/providers/ghidra_ir_adapter.hpp"
#include "../../src/core/analysis/decompiler/pseudocode_renderer_v2.hpp"
#include "../../src/core/analysis/decompiler/typed_ast_v2.hpp"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis::native_worker::ghidra_native_provider {
namespace {

decompiler_diagnostic_t failure(const decompiler_diagnostic_code_t code, std::string key)
{
    decompiler_diagnostic_t result;
    result.severity = decompiler_diagnostic_severity_t::error;
    result.code = code;
    result.localization_key = std::move(key);
    result.confidence = 100;
    result.ordinal = 1;
    return result;
}

bool same_provider(const decompiler_provider_identity_t& left, const decompiler_provider_identity_t& right)
{
    return left.provider == right.provider && left.provider_name == right.provider_name &&
        left.provider_version == right.provider_version && left.provider_binary_hash == right.provider_binary_hash &&
        left.worker_build_id == right.worker_build_id && left.worker_build_hash == right.worker_build_hash;
}

bool same_language(const decompiler_language_identity_t& left, const decompiler_language_identity_t& right)
{
    return left.language_id == right.language_id && left.language_version == right.language_version &&
        left.compiler_spec_id == right.compiler_spec_id && left.language_spec_hash == right.language_spec_hash &&
        left.architecture == right.architecture && left.mode == right.mode && left.endian == right.endian;
}

std::optional<std::string> snapshot_bytes(const runtime::startup_t& startup)
{
    if (startup.snapshot_size == 0 || startup.snapshot_size > 32U * 1024U * 1024U)
        return std::nullopt;
    void* view = MapViewOfFile(startup.snapshot_handle, FILE_MAP_READ, 0, 0, startup.snapshot_size);
    if (!view)
        return std::nullopt;
    std::optional<std::string> result;
    try {
        result.emplace(static_cast<const char*>(view), startup.snapshot_size);
    } catch (...) {
    }
    UnmapViewOfFile(view);
    return result;
}

}

result_t produce(const runtime::startup_t& startup, const decompiler_worker_job_request_t& job)
{
    result_t result;
    const auto bytes = snapshot_bytes(startup);
    if (!bytes) {
        result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::resource_limit,
            "decompiler.native_worker.typed_snapshot_unavailable"));
        return result;
    }
    std::vector<decompiler_diagnostic_t> decode_diagnostics;
    const auto artifacts = ghidra_ir_adapter::deserialize_artifacts(*bytes, decode_diagnostics);
    if (!artifacts) {
        result.diagnostics = std::move(decode_diagnostics);
        if (result.diagnostics.empty())
            result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::unsupported_provider,
                "decompiler.native_worker.typed_artifact_required"));
        return result;
    }
    if (!(artifacts->provider_ir.entity == job.cache_key.entity) ||
        !(artifacts->hir.entity == job.cache_key.entity) ||
        !(artifacts->type_graph.entity == job.cache_key.entity) ||
        !same_provider(artifacts->provider_ir.provider, job.cache_key.provider) ||
        !same_language(artifacts->provider_ir.language, job.cache_key.language) ||
        artifacts->type_graph.revision != job.cache_key.type_graph_revision ||
        artifacts->hir.type_graph_revision != job.cache_key.type_graph_revision) {
        result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.native_worker.typed_artifact_binding"));
        return result;
    }
    typed_ast_v2_build_request_t ast_request;
    ast_request.limits.max_hir_values = job.profile.max_hir_nodes;
    ast_request.limits.max_ast_nodes = job.profile.max_ast_nodes;
    const auto ast = build_typed_ast_v2(artifacts->hir, artifacts->type_graph, ast_request);
    if (!ast.succeeded()) {
        result.diagnostics = ast.diagnostics;
        if (result.diagnostics.empty())
            result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::malformed_ast,
                "decompiler.native_worker.typed_ast"));
        return result;
    }
    pseudocode_renderer_v2_request_t render_request;
    render_request.profile = job.profile.profile;
    render_request.settings = job.cache_key.renderer;
    render_request.limits.max_ast_nodes = job.profile.max_ast_nodes;
    const auto rendered = render_pseudocode_v2(*ast.ast, artifacts->type_graph, render_request);
    if (!rendered.succeeded()) {
        result.diagnostics = rendered.diagnostics;
        if (result.diagnostics.empty())
            result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::malformed_document,
                "decompiler.native_worker.typed_render"));
        return result;
    }
    result.document = std::move(*rendered.document);
    if (!(result.document->entity == job.cache_key.entity) ||
        !(result.document->ast.entity == job.cache_key.entity) ||
        result.document->type_graph_hash != stable_serialization_hash(artifacts->type_graph)) {
        result.document.reset();
        result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.native_worker.typed_document_binding"));
        return result;
    }
    result.document->diagnostics.insert(result.document->diagnostics.end(), artifacts->provider_ir.diagnostics.begin(),
        artifacts->provider_ir.diagnostics.end());
    result.document->diagnostics.insert(result.document->diagnostics.end(), artifacts->hir.diagnostics.begin(),
        artifacts->hir.diagnostics.end());
    result.document->diagnostics.insert(result.document->diagnostics.end(), artifacts->type_graph.diagnostics.begin(),
        artifacts->type_graph.diagnostics.end());
    for (std::uint32_t index = 0; index < result.document->diagnostics.size(); ++index)
        result.document->diagnostics[index].ordinal = index + 1U;
    if (!validate_decompiler_document(*result.document).valid()) {
        result.document.reset();
        result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::malformed_document,
            "decompiler.native_worker.document_validation"));
    }
    return result;
}

}
