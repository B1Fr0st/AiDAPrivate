#include "decompiler_ui_integration.hpp"

#include "decompiler_contracts.hpp"
#include "pseudocode_renderer_v2.hpp"
#include "typed_ast_v2.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace aida::analysis {
namespace {

struct ui_state_t final {
    std::shared_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<decompiler_pipeline_service_t> service;
    decompiler_ui_integration_config_t config;
    mutable std::mutex metrics_mutex;
    decompiler_ui_integration_metrics_t metrics;
    std::atomic<std::uint64_t> request_counter{0};
};

decompiler_entity_key_t build_entity_key(
    const decompiler_ui_request_t& request,
    const analysis_workspace_t& workspace) {
    decompiler_entity_key_t key;
    key.schema_version = k_decompiler_contract_schema_version;
    key.kind = decompiler_entity_kind_t::native_function;
    const auto& identity = workspace.identity();
    const auto normalized = workspace.normalized_image();
    if (normalized) {
        key.format = format_id_t::pe;
        key.architecture = normalized->architecture;
        key.mode = normalized->architecture_mode;
        key.endian = endian_t::little;
    } else {
        key.format = format_id_t::pe;
        key.architecture = architecture_id_t::x86_64;
        key.mode = architecture_mode_t::x86_64;
        key.endian = endian_t::little;
    }
    native_decompiler_entity_identity_t native_identity;
    native_identity.entry = address_t{address_space_id_t::relative_virtual,
        request.function_address, key.architecture, key.mode};
    native_identity.end = address_t{address_space_id_t::relative_virtual,
        request.function_end_address, key.architecture, key.mode};
    native_identity.canonical_symbol = request.function_symbol;
    key.identity = native_identity;
    return key;
}

decompiler_language_identity_t build_language_identity(
    const analysis_workspace_t& workspace) {
    decompiler_language_identity_t language;
    language.language_id = "c";
    const auto normalized = workspace.normalized_image();
    if (normalized) {
        language.architecture = normalized->architecture;
        language.mode = normalized->architecture_mode;
        language.endian = endian_t::little;
    } else {
        language.architecture = architecture_id_t::x86_64;
        language.mode = architecture_mode_t::x86_64;
        language.endian = endian_t::little;
    }
    return language;
}

decompiler_ui_diagnostic_t map_diagnostic(
    const decompiler_diagnostic_t& diag) {
    decompiler_ui_diagnostic_t ui_diag;
    ui_diag.severity = diag.severity;
    ui_diag.code = diag.code;
    ui_diag.confidence = diag.confidence;
    ui_diag.retryable = diag.retryable;
    if (!diag.localization_key.empty())
        ui_diag.message = diag.localization_key;
    else
        ui_diag.message = "decompiler_diagnostic";
    for (const auto& arg : diag.localization_arguments) {
        ui_diag.message += " ";
        ui_diag.message += arg;
    }
    return ui_diag;
}

decompiler_ui_source_mapping_t map_source_mapping(
    const decompiler_document_source_map_t& source_map,
    const decompiler_document_t& document) {
    decompiler_ui_source_mapping_t mapping;
    mapping.token_begin = source_map.document_range.begin;
    mapping.token_end = source_map.document_range.end;
    for (const auto& coord : source_map.coordinates) {
        if (coord.address_range) {
            mapping.address = coord.address_range->begin.value;
            break;
        }
        if (coord.instruction_range) {
            mapping.instruction_id = coord.instruction_range->first_instruction_id;
            break;
        }
        if (coord.source_origin) {
            mapping.source_path = coord.source_origin->source_path;
            mapping.source_line = coord.source_origin->first_line;
            mapping.source_column = coord.source_origin->first_column;
            break;
        }
    }
    return mapping;
}

bool result_has_null_ast(const decompiler_pipeline_result_t& result) noexcept {
    if (!result.rendered_stage)
        return true;
    const auto& document = *result.rendered_stage;
    if (!document.ast.root_node_id && document.ast.nodes.empty())
        return true;
    if (document.rendered_text.empty() && document.ast.nodes.empty())
        return true;
    return false;
}

bool result_has_guessed_body(const decompiler_pipeline_result_t& result) noexcept {
    if (!result.rendered_stage)
        return true;
    const auto& document = *result.rendered_stage;
    if (document.ast.root_node_id == 0)
        return true;
    bool has_function_def = false;
    for (const auto& node : document.ast.nodes) {
        if (node.kind == typed_pseudocode_ast_node_kind_t::function_definition) {
            has_function_def = true;
            break;
        }
    }
    return !has_function_def;
}

}

struct decompiler_ui_integration_t::impl_t {
    ui_state_t state;

    explicit impl_t(std::shared_ptr<analysis_workspace_t> ws,
                    std::shared_ptr<decompiler_pipeline_service_t> svc,
                    decompiler_ui_integration_config_t cfg)
        : state(std::move(ws), std::move(svc), std::move(cfg)) {}

    void increment_metric(
        std::uint64_t decompiler_ui_integration_metrics_t::*field) noexcept {
        std::lock_guard<std::mutex> lock(state.metrics_mutex);
        state.metrics.*field += 1;
    }
};

decompiler_ui_integration_t::decompiler_ui_integration_t(
    std::unique_ptr<impl_t> impl)
    : impl_(std::move(impl)) {}

decompiler_ui_integration_t::~decompiler_ui_integration_t() = default;

workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>
decompiler_ui_integration_t::create(
    std::shared_ptr<analysis_workspace_t> workspace,
    std::shared_ptr<decompiler_pipeline_service_t> service,
    decompiler_ui_integration_config_t config) {
    if (!workspace) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "decompiler UI integration requires a workspace",
                "decompiler_ui_integration"));
    }
    if (!service) {
        return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                "decompiler UI integration requires a pipeline service",
                "decompiler_ui_integration"));
    }
    auto impl = std::make_unique<impl_t>(workspace, service, config);
    return workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>::success(
        std::shared_ptr<decompiler_ui_integration_t>(
            new decompiler_ui_integration_t(std::move(impl))));
}

decompiler_pipeline_invocation_t
decompiler_ui_integration_t::map_invocation_source(
    decompiler_ui_invocation_source_t source) noexcept {
    switch (source) {
    case decompiler_ui_invocation_source_t::keyboard_f5:
    case decompiler_ui_invocation_source_t::keyboard_shift_f5:
    case decompiler_ui_invocation_source_t::context_menu:
        return decompiler_pipeline_invocation_t::explicit_ui;
    case decompiler_ui_invocation_source_t::mcp_request:
        return decompiler_pipeline_invocation_t::explicit_mcp;
    case decompiler_ui_invocation_source_t::api_call:
        return decompiler_pipeline_invocation_t::explicit_api;
    case decompiler_ui_invocation_source_t::baseline_hook:
        return decompiler_pipeline_invocation_t::baseline_analysis;
    default:
        return decompiler_pipeline_invocation_t::unspecified;
    }
}

decompiler_pipeline_request_t
decompiler_ui_integration_t::build_pipeline_request(
    const decompiler_ui_request_t& request,
    const analysis_workspace_t& workspace) {
    decompiler_pipeline_request_t pipeline_request;
    pipeline_request.invocation = map_invocation_source(request.source);
    pipeline_request.cache_mode = request.cache_mode;
    pipeline_request.workspace_id = workspace.identity().binary_id().to_hex();
    pipeline_request.workspace_generation = workspace.generation();
    pipeline_request.analysis_revision = workspace.analysis_revision();
    pipeline_request.entity = build_entity_key(request, workspace);
    pipeline_request.language = build_language_identity(workspace);
    pipeline_request.profile = request.profile;
    pipeline_request.deadline = request.deadline;
    if (request.require_complete_source_map)
        pipeline_request.renderer = decompiler_renderer_settings_t{};
    return pipeline_request;
}

decompiler_ui_result_t
decompiler_ui_integration_t::map_pipeline_result(
    const decompiler_pipeline_result_t& result) {
    decompiler_ui_result_t ui_result;
    ui_result.status = result.status;
    ui_result.elapsed_ms = result.elapsed_wall_clock_ms;
    ui_result.cache_hit_stage = result.cache_hit_stage;
    if (result.rendered_stage) {
        const auto& document = *result.rendered_stage;
        ui_result.rendered_text = document.rendered_text;
        if (document.ast.nodes.empty() && document.rendered_text.empty())
            ui_result.status = decompiler_pipeline_status_t::normalization_failed;
        for (const auto& source_map : document.source_maps) {
            ui_result.source_mappings.push_back(
                map_source_mapping(source_map, document));
        }
    }
    for (const auto& diag : result.diagnostics) {
        ui_result.diagnostics.push_back(map_diagnostic(diag));
    }
    return ui_result;
}

workspace_result_t<decompiler_ui_result_t>
decompiler_ui_integration_t::decompile(
    const decompiler_ui_request_t& request,
    const cancellation_token_t& cancel) {
    if (!impl_ || !impl_->state.workspace || !impl_->state.service) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "decompiler UI integration is not initialized",
                "decompile"));
    }
    if (request.function_address == 0) {
        return workspace_result_t<decompiler_ui_result_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "decompiler UI request requires a non-zero function address",
                "decompile"));
    }
    impl_->state.request_counter.fetch_add(1, std::memory_order_acq_rel);
    impl_->increment_metric(&decompiler_ui_integration_metrics_t::total_requests);
    switch (request.source) {
    case decompiler_ui_invocation_source_t::keyboard_f5:
    case decompiler_ui_invocation_source_t::keyboard_shift_f5:
        impl_->increment_metric(&decompiler_ui_integration_metrics_t::f5_requests);
        break;
    case decompiler_ui_invocation_source_t::mcp_request:
        impl_->increment_metric(&decompiler_ui_integration_metrics_t::mcp_requests);
        break;
    case decompiler_ui_invocation_source_t::api_call:
        impl_->increment_metric(&decompiler_ui_integration_metrics_t::api_requests);
        break;
    default:
        break;
    }
    auto pipeline_request = build_pipeline_request(request, *impl_->state.workspace);
    auto pipeline_result = impl_->state.service->decompile(pipeline_request, cancel);
    if (pipeline_result.succeeded()) {
        if (impl_->state.config.reject_null_ast && result_has_null_ast(pipeline_result)) {
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::rejected_null_ast);
            decompiler_ui_result_t ui_result;
            ui_result.status = decompiler_pipeline_status_t::normalization_failed;
            ui_result.elapsed_ms = pipeline_result.elapsed_wall_clock_ms;
            decompiler_ui_diagnostic_t diag;
            diag.severity = decompiler_diagnostic_severity_t::error;
            diag.code = decompiler_diagnostic_code_t::malformed_ast;
            diag.message = "decompiler returned a null AST — rejected by integration policy";
            diag.retryable = true;
            ui_result.diagnostics.push_back(std::move(diag));
            return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
        }
        if (impl_->state.config.reject_guessed_body && result_has_guessed_body(pipeline_result)) {
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::rejected_guessed_body);
            decompiler_ui_result_t ui_result;
            ui_result.status = decompiler_pipeline_status_t::normalization_failed;
            ui_result.elapsed_ms = pipeline_result.elapsed_wall_clock_ms;
            decompiler_ui_diagnostic_t diag;
            diag.severity = decompiler_diagnostic_severity_t::error;
            diag.code = decompiler_diagnostic_code_t::malformed_ast;
            diag.message = "decompiler returned a guessed body without a function definition node — rejected by integration policy";
            diag.retryable = true;
            ui_result.diagnostics.push_back(std::move(diag));
            return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
        }
        impl_->increment_metric(&decompiler_ui_integration_metrics_t::completed);
        if (pipeline_result.cache_hit_stage)
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::cache_hits);
    } else {
        switch (pipeline_result.status) {
        case decompiler_pipeline_status_t::provider_failed:
        case decompiler_pipeline_status_t::provider_crashed:
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::provider_failures);
            break;
        case decompiler_pipeline_status_t::deadline_exceeded:
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::deadline_exceeded);
            break;
        case decompiler_pipeline_status_t::cancelled:
            impl_->increment_metric(&decompiler_ui_integration_metrics_t::cancelled);
            break;
        default:
            break;
        }
    }
    auto ui_result = map_pipeline_result(pipeline_result);
    return workspace_result_t<decompiler_ui_result_t>::success(std::move(ui_result));
}

workspace_result_t<void>
decompiler_ui_integration_t::invalidate_workspace() {
    if (!impl_ || !impl_->state.workspace || !impl_->state.service) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "decompiler UI integration is not initialized",
                "invalidate_workspace"));
    }
    return impl_->state.service->invalidate_workspace(
        impl_->state.workspace->identity().binary_id().to_hex(),
        impl_->state.workspace->generation());
}

decompiler_ui_integration_metrics_t
decompiler_ui_integration_t::metrics() const noexcept {
    if (!impl_)
        return {};
    std::lock_guard<std::mutex> lock(impl_->state.metrics_mutex);
    return impl_->state.metrics;
}

std::shared_ptr<decompiler_pipeline_service_t>
decompiler_ui_integration_t::service() const noexcept {
    if (!impl_)
        return nullptr;
    return impl_->state.service;
}

std::shared_ptr<analysis_workspace_t>
decompiler_ui_integration_t::workspace() const noexcept {
    if (!impl_)
        return nullptr;
    return impl_->state.workspace;
}

}
