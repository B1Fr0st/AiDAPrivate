#include "ghidra_native_provider.hpp"

#include "../../src/core/analysis/decompiler/native_worker_host.hpp"
#include "../../src/core/analysis/decompiler/providers/dalvik_ssa.hpp"
#include "../../src/core/analysis/decompiler/providers/ghidra_ir_adapter.hpp"
#include "../../src/core/analysis/decompiler/providers/jvm_ssa.hpp"
#include "../../src/core/analysis/decompiler/pseudocode_readability.hpp"
#include "../../src/core/analysis/decompiler/pseudocode_renderer_v2.hpp"
#include "../../src/core/analysis/decompiler/typed_ast_v2.hpp"
#include "../../src/core/disasm/ghidra_decompiler.hpp"

#include <windows.h>

#include "../../src/core/disasm/ghidra_adapters/aida_ghidra_preamble.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis::native_worker::ghidra_native_provider {
namespace {

struct provider_output_t {
    provider_ir_t provider_ir;
    hir_function_t hir;
    type_graph_t type_graph;
    std::string serialized;
    std::optional<std::string> printc_evidence;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct arch_session_cache_t {
    std::deque<std::unique_ptr<ghidra_decompiler::arch_session_entry_t>> entries;
    std::uint64_t hits = 0;
    std::uint64_t misses = 0;
    std::uint64_t evictions = 0;
    bool disabled = false;
};

constexpr std::size_t k_arch_session_cache_capacity = 2;

std::unique_ptr<arch_session_cache_t> g_arch_session_cache;

arch_session_cache_t& arch_session_cache()
{
    if (!g_arch_session_cache) {
        g_arch_session_cache = std::make_unique<arch_session_cache_t>();
        const std::string kill_switch =
            ghidra_decompiler::detail::read_env_var("AIDA_DECOMPILER_NO_ARCH_REUSE");
        if (!kill_switch.empty() && kill_switch != "0") {
            g_arch_session_cache->disabled = true;
            diag::log_tagged_fmt("dec",
                "arch_pool_disabled reason=env_kill_switch value=%s", kill_switch.c_str());
        }
    }
    return *g_arch_session_cache;
}

ghidra_decompiler::arch_session_entry_t* arch_session_acquire(
    arch_session_cache_t& cache,
    ghidra_decompiler::arch_pool_key_t key,
    std::vector<native_provider_snapshot_range_t>& source_ranges,
    std::uint64_t image_base,
    std::uint64_t image_size,
    bool keep_fixateglobals,
    std::string& error_text)
{
    for (auto it = cache.entries.begin(); it != cache.entries.end(); ++it) {
        if ((*it)->key.matches(key)) {
            auto hit = std::move(*it);
            cache.entries.erase(it);
            cache.entries.push_front(std::move(hit));
            ++cache.hits;
            auto* entry = cache.entries.front().get();
            diag::log_tagged_fmt("dec",
                "arch_pool_hit hits=%llu misses=%llu jobs_completed=%llu sleigh=%s",
                static_cast<unsigned long long>(cache.hits),
                static_cast<unsigned long long>(cache.misses),
                static_cast<unsigned long long>(entry->jobs_completed),
                entry->key.language_id.c_str());
            return entry;
        }
    }
    ++cache.misses;
    const std::string sleigh = key.language_id;
    std::vector<aida_ghidra::region_t> regions;
    regions.reserve(source_ranges.size());
    for (auto& source : source_ranges) {
        aida_ghidra::region_t region;
        region.start_va = image_base + source.relative_virtual_address;
        region.data = std::move(source.bytes);
        regions.push_back(std::move(region));
    }
    auto created = ghidra_decompiler::make_arch_session_entry(
        std::move(regions), image_base, image_size, std::move(key), keep_fixateglobals);
    if (!created.ok) {
        error_text = std::move(created.error_text);
        diag::log_tagged_fmt("dec",
            "arch_pool_init_failed misses=%llu sleigh=%s",
            static_cast<unsigned long long>(cache.misses), sleigh.c_str());
        return nullptr;
    }
    diag::log_tagged_fmt("dec",
        "arch_pool_miss arch_init_ms=%.2f hits=%llu misses=%llu sleigh=%s",
        created.entry->arch_init_ms,
        static_cast<unsigned long long>(cache.hits),
        static_cast<unsigned long long>(cache.misses),
        sleigh.c_str());
    cache.entries.push_front(std::move(created.entry));
    while (cache.entries.size() > k_arch_session_cache_capacity) {
        const std::uint64_t evicted_jobs = cache.entries.back()->jobs_completed;
        cache.entries.pop_back();
        ++cache.evictions;
        diag::log_tagged_fmt("dec",
            "arch_pool_evict evictions=%llu evicted_jobs_completed=%llu",
            static_cast<unsigned long long>(cache.evictions),
            static_cast<unsigned long long>(evicted_jobs));
    }
    return cache.entries.front().get();
}

decompiler_diagnostic_t failure(const decompiler_diagnostic_code_t code, std::string key,
    std::string detail = {})
{
    decompiler_diagnostic_t result;
    result.severity = decompiler_diagnostic_severity_t::error;
    result.code = code;
    result.localization_key = std::move(key);
    result.confidence = 100;
    result.ordinal = 1;
    if (!detail.empty()) {
        constexpr std::size_t detail_limit = 4096;
        if (detail.size() > detail_limit)
            detail.resize(detail_limit);
        result.localization_arguments.push_back(std::move(detail));
    }
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
    if (startup.snapshot_size == 0 || startup.snapshot_size > 256U * 1024U * 1024U)
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

bool checked_entry_address(
    const native_decompiler_entity_identity_t& identity,
    const std::uint64_t image_base,
    const std::size_t image_size,
    std::uint64_t& entry) noexcept
{
    switch (identity.entry.space) {
    case address_space_id_t::relative_virtual:
        if (identity.entry.value > (std::numeric_limits<std::uint64_t>::max)() - image_base)
            return false;
        entry = image_base + identity.entry.value;
        break;
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        entry = identity.entry.value;
        break;
    default:
        return false;
    }
    return entry >= image_base && entry - image_base < image_size;
}

std::optional<provider_output_t> execute_native(
    const std::string& payload,
    const decompiler_worker_job_request_t& job,
    std::atomic<bool>* shared_cancel,
    std::vector<decompiler_diagnostic_t>& diagnostics)
{
    auto snapshot = deserialize_native_provider_snapshot(payload, diagnostics);
    const auto* identity = std::get_if<native_decompiler_entity_identity_t>(&job.cache_key.entity.identity);
    if (!snapshot || !identity || job.cache_key.entity.kind != decompiler_entity_kind_t::native_function)
        return std::nullopt;
    std::uint64_t entry = 0;
    if (!checked_entry_address(*identity, snapshot->image_base,
            static_cast<std::size_t>(snapshot->image_size), entry)) {
        diagnostics.push_back(failure(decompiler_diagnostic_code_t::invalid_contract,
            "decompiler.native_worker.entry_binding"));
        return std::nullopt;
    }
    ghidra_ir_adapter::capture_request_t capture;
    capture.provider = job.cache_key.provider;
    capture.language = job.cache_key.language;
    capture.entity = job.cache_key.entity;
    capture.workspace_generation = job.cache_key.workspace_generation;
    capture.type_graph_revision = job.cache_key.type_graph_revision;
    std::atomic<bool> local_cancel{false};
    std::atomic<bool>* const cancelled = shared_cancel ? shared_cancel : &local_cancel;
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(job.profile.max_wall_clock_ms);
    ghidra_decompiler::ghidra_decompile_result_limits_t limits;
    limits.max_result_bytes = (std::min<std::uint64_t>)(
        limits.max_result_bytes, job.profile.max_memory_bytes);
    limits.capture_printc_evidence = job.request_printc_evidence;
    limits.keep_fixateglobals = job.profile.profile == decompiler_profile_id_t::thorough;
    ghidra_decompiler::ghidra_result_t output;
    bool executed = false;
    auto& cache = arch_session_cache();
    if (!cache.disabled) {
        ghidra_decompiler::arch_pool_key_t key;
        key.language_id = job.cache_key.language.language_id;
        key.compiler_spec_id = job.cache_key.language.compiler_spec_id;
        key.architecture_mode = job.cache_key.language.mode;
        key.endian = job.cache_key.language.endian;
        key.snapshot_hash = job.snapshot_hash;
        key.keep_fixateglobals = limits.keep_fixateglobals;
        std::string pool_error;
        if (auto* pooled = arch_session_acquire(cache, std::move(key), snapshot->ranges,
                snapshot->image_base, snapshot->image_size, limits.keep_fixateglobals, pool_error)) {
            output = ghidra_decompiler::decompile_isolated_regions_reusing(
                *pooled, entry, cancelled, deadline, limits, capture);
        } else {
            output.function_addr = entry;
            output.is_error = true;
            output.error_text = std::move(pool_error);
        }
        executed = true;
    }
    if (!executed) {
        std::vector<aida_ghidra::region_t> regions;
        regions.reserve(snapshot->ranges.size());
        for (auto& source : snapshot->ranges) {
            aida_ghidra::region_t region;
            region.start_va = snapshot->image_base + source.relative_virtual_address;
            region.data = std::move(source.bytes);
            regions.push_back(std::move(region));
        }
        output = ghidra_decompiler::decompile_isolated_regions(
            std::move(regions), snapshot->image_base, snapshot->image_size, entry,
            job.cache_key.language.language_id, job.cache_key.language.mode,
            cancelled, deadline, limits, capture);
    }
    if (output.is_error || !output.typed_artifacts) {
        diagnostics.insert(diagnostics.end(), output.typed_diagnostics.begin(), output.typed_diagnostics.end());
        if (!output.error_text.empty())
            diagnostics.push_back(failure(decompiler_diagnostic_code_t::provider_failure,
                "decompiler.native_worker.provider_failed", output.error_text));
        else if (diagnostics.empty())
            diagnostics.push_back(failure(decompiler_diagnostic_code_t::provider_failure,
                "decompiler.native_worker.provider_failed"));
        return std::nullopt;
    }
    if (job.request_printc_evidence &&
        (!output.printc_evidence || output.printc_evidence->empty() ||
         output.printc_evidence->size() > k_decompiler_worker_printc_evidence_max_bytes)) {
        diagnostics.push_back(failure(decompiler_diagnostic_code_t::provider_failure,
            "decompiler.native_worker.printc_evidence_required"));
        return std::nullopt;
    }
    provider_output_t result;
    result.provider_ir = output.typed_artifacts->provider_ir;
    result.hir = output.typed_artifacts->hir;
    result.type_graph = output.typed_artifacts->type_graph;
    result.diagnostics = output.typed_diagnostics;
    result.serialized = ghidra_ir_adapter::serialize_artifacts(*output.typed_artifacts);
    result.printc_evidence = output.printc_evidence;
    if (result.serialized.empty()) {
        diagnostics.push_back(failure(decompiler_diagnostic_code_t::malformed_serialization,
            "decompiler.native_worker.provider_serialize"));
        return std::nullopt;
    }
    return result;
}

std::optional<provider_output_t> execute_jvm(
    const std::string& payload,
    std::vector<decompiler_diagnostic_t>& diagnostics)
{
    auto input = jvm_ssa::deserialize_jvm_method_input(payload, diagnostics);
    if (!input)
        return std::nullopt;
    auto output = jvm_ssa::decompile_method(*input);
    diagnostics = output.diagnostics;
    if (!output.succeeded() || !output.provider_ir || !output.hir || !output.type_graph)
        return std::nullopt;
    provider_output_t result;
    result.provider_ir = std::move(*output.provider_ir);
    result.hir = std::move(*output.hir);
    result.type_graph = std::move(*output.type_graph);
    result.diagnostics = diagnostics;
    jvm_ssa::jvm_ssa_result_t serialized;
    serialized.provider_ir = result.provider_ir;
    serialized.hir = result.hir;
    serialized.type_graph = result.type_graph;
    result.serialized = jvm_ssa::serialize_jvm_ssa_result(serialized);
    if (result.serialized.empty())
        return std::nullopt;
    return result;
}

std::optional<provider_output_t> execute_dalvik(
    const std::string& payload,
    std::vector<decompiler_diagnostic_t>& diagnostics)
{
    auto capture = dalvik_ssa::deserialize_capture(payload, diagnostics);
    if (!capture)
        return std::nullopt;
    auto output = dalvik_ssa::normalize(*capture);
    diagnostics = output.diagnostics;
    if (!output.succeeded() || !output.artifacts)
        return std::nullopt;
    provider_output_t result;
    result.provider_ir = output.artifacts->provider_ir;
    result.hir = output.artifacts->hir;
    result.type_graph = output.artifacts->type_graph;
    result.diagnostics = diagnostics;
    result.serialized = dalvik_ssa::serialize_artifacts(*output.artifacts);
    if (result.serialized.empty())
        return std::nullopt;
    return result;
}

bool validate_output(const provider_output_t& output, const decompiler_worker_job_request_t& job)
{
    return !output.serialized.empty() && validate_provider_ir(output.provider_ir).valid() &&
        validate_hir_function(output.hir).valid() && validate_type_graph(output.type_graph).valid() &&
        output.provider_ir.entity == job.cache_key.entity && output.hir.entity == job.cache_key.entity &&
        output.type_graph.entity == job.cache_key.entity &&
        same_provider(output.provider_ir.provider, job.cache_key.provider) &&
        same_language(output.provider_ir.language, job.cache_key.language) &&
        output.hir.provider_ir_hash == stable_serialization_hash(output.provider_ir) &&
        output.hir.type_graph_revision == job.cache_key.type_graph_revision &&
        output.type_graph.revision == job.cache_key.type_graph_revision && output.hir.return_type_id != 0;
}

}

result_t produce(const runtime::startup_t& startup, const decompiler_worker_job_request_t& job,
    std::atomic<bool>* shared_cancel)
{
    result_t result;
    if (job.request_printc_evidence &&
        job.cache_key.provider.provider != decompiler_provider_id_t::ghidra_native) {
        result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::worker_protocol_failure,
            "decompiler.isolated_worker.printc_provider"));
        return result;
    }
    const auto bytes = snapshot_bytes(startup);
    if (!bytes) {
        result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::resource_limit,
            "decompiler.isolated_worker.snapshot_unavailable"));
        return result;
    }
    std::optional<provider_output_t> output;
    switch (job.cache_key.provider.provider) {
    case decompiler_provider_id_t::ghidra_native:
        output = execute_native(*bytes, job, shared_cancel, result.diagnostics);
        break;
    case decompiler_provider_id_t::jvm_ssa:
        output = execute_jvm(*bytes, result.diagnostics);
        break;
    case decompiler_provider_id_t::dalvik_ssa:
        output = execute_dalvik(*bytes, result.diagnostics);
        break;
    case decompiler_provider_id_t::ilspy_cli:
        break;
    }
    if (!output || !validate_output(*output, job)) {
        if (result.diagnostics.empty())
            result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::worker_protocol_failure,
                "decompiler.isolated_worker.provider_output_binding"));
        return result;
    }
    typed_ast_v2_build_request_t ast_request;
    ast_request.limits.max_hir_values = static_cast<std::size_t>((std::min<std::uint64_t>)(
        job.profile.max_hir_nodes, (std::numeric_limits<std::size_t>::max)()));
    ast_request.limits.max_ast_nodes = static_cast<std::size_t>((std::min<std::uint64_t>)(
        job.profile.max_ast_nodes, (std::numeric_limits<std::size_t>::max)()));
    auto ast = build_typed_ast_v2(output->hir, output->type_graph, ast_request);
    if (!ast.succeeded() || !ast.ast) {
        result.diagnostics = ast.diagnostics;
        if (result.diagnostics.empty())
            result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::malformed_ast,
                "decompiler.isolated_worker.typed_ast"));
        return result;
    }
    std::vector<decompiler_diagnostic_t> readability_diagnostics;
    if (output->hir.entity.kind == decompiler_entity_kind_t::native_function &&
        readability_transforms_enabled(job.cache_key.renderer.readability)) {
        auto readability_result = apply_readability_transforms(
            *ast.ast, output->type_graph, to_rt_settings(job.cache_key.renderer.readability));
        readability_diagnostics = std::move(readability_result.diagnostics);
        if (readability_result.succeeded()) {
            diag::log_tagged_fmt("dec", "readability_transforms applied renamed=%u folded=%u simplified=%u inlined=%u dead_stores=%u",
                static_cast<unsigned int>(readability_result.metrics.variables_renamed),
                static_cast<unsigned int>(readability_result.metrics.constants_folded),
                static_cast<unsigned int>(readability_result.metrics.identities_simplified),
                static_cast<unsigned int>(readability_result.metrics.temporaries_inlined),
                static_cast<unsigned int>(readability_result.metrics.dead_stores_eliminated));
        } else {
            diag::log_tagged_fmt("dec", "readability_transforms status=warning_no_transform continuing_with_unmodified_ast");
        }
    }
    pseudocode_renderer_v2_request_t render_request;
    render_request.profile = job.profile.profile;
    render_request.settings = job.cache_key.renderer;
    render_request.limits.max_ast_nodes = ast_request.limits.max_ast_nodes;
    const auto rendered = render_pseudocode_v2(*ast.ast, output->type_graph, render_request);
    if (!rendered.succeeded() || !rendered.document) {
        result.diagnostics = rendered.diagnostics;
        if (result.diagnostics.empty())
            result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::malformed_document,
                "decompiler.isolated_worker.typed_render"));
        return result;
    }
    result.document = std::move(*rendered.document);
    result.provider_artifacts = std::move(output->serialized);
    result.printc_evidence = std::move(output->printc_evidence);
    result.document->diagnostics.insert(result.document->diagnostics.end(),
        output->provider_ir.diagnostics.begin(), output->provider_ir.diagnostics.end());
    result.document->diagnostics.insert(result.document->diagnostics.end(),
        output->hir.diagnostics.begin(), output->hir.diagnostics.end());
    result.document->diagnostics.insert(result.document->diagnostics.end(),
        output->type_graph.diagnostics.begin(), output->type_graph.diagnostics.end());
    result.document->diagnostics.insert(result.document->diagnostics.end(),
        readability_diagnostics.begin(), readability_diagnostics.end());
    for (std::uint32_t index = 0; index < result.document->diagnostics.size(); ++index)
        result.document->diagnostics[index].ordinal = index + 1U;
    if (!validate_decompiler_document(*result.document).valid()) {
        result.document.reset();
        result.provider_artifacts.clear();
        result.diagnostics.push_back(failure(decompiler_diagnostic_code_t::malformed_document,
            "decompiler.isolated_worker.document_validation"));
    }
    return result;
}

}
