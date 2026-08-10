#pragma once

#include "decompiler_service.hpp"
#include "managed_entity_binding.hpp"
#include "../workspace/analysis_workspace.hpp"
#include "../workspace/workspace_types.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

enum class decompiler_ui_invocation_source_t : std::uint8_t {
    keyboard_f5 = 0,
    keyboard_shift_f5 = 1,
    context_menu = 2,
    mcp_request = 3,
    api_call = 4,
    baseline_hook = 5
};

struct decompiler_ui_request_t {
    decompiler_ui_invocation_source_t source = decompiler_ui_invocation_source_t::keyboard_f5;
    std::uint64_t function_address = 0;
    std::uint64_t function_end_address = 0;
    std::string function_symbol;
    decompiler_language_identity_t language;
    sha256_digest_t worker_protocol_hash;
    std::uint64_t metadata_revision = 0;
    std::uint64_t type_graph_revision = 0;
    std::vector<decompiler_dependency_version_t> dependencies;
    decompiler_profile_id_t profile = decompiler_profile_id_t::balanced;
    decompiler_pipeline_cache_mode_t cache_mode = decompiler_pipeline_cache_mode_t::read_write;
    std::optional<decompiler_profile_budget_t> budget;
    std::optional<decompiler_renderer_settings_t> renderer;
    std::optional<std::string> provider_registration_id;
    std::shared_ptr<const decompiler_provider_context_t> provider_context;
    decompiler_provider_context_factory_t provider_context_factory;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    bool require_complete_source_map = true;
};

struct decompiler_ui_source_mapping_t {
    std::uint64_t token_begin = 0;
    std::uint64_t token_end = 0;
    std::uint64_t instruction_id = 0;
    std::uint64_t address = 0;
    std::optional<decompiler_address_range_t> address_range;
    std::optional<source_coordinate_t> coordinate;
    std::string source_path;
    std::uint32_t source_line = 0;
    std::uint32_t source_column = 0;
};

struct decompiler_ui_diagnostic_t {
    decompiler_diagnostic_severity_t severity = decompiler_diagnostic_severity_t::error;
    decompiler_diagnostic_code_t code = decompiler_diagnostic_code_t::invalid_contract;
    std::string localization_key;
    std::vector<std::string> localization_arguments;
    std::optional<source_coordinate_t> coordinate;
    std::string message;
    std::uint8_t confidence = 0;
    bool retryable = false;
};

struct decompiler_ui_result_t {
    decompiler_pipeline_status_t status = decompiler_pipeline_status_t::invalid_request;
    std::string function_symbol;
    std::string rendered_text;
    std::shared_ptr<const decompiler_provider_ir_cache_value_t> provider_stage;
    std::shared_ptr<const decompiler_normalized_cache_value_t> normalized_stage;
    std::shared_ptr<const decompiler_document_t> document;
    std::optional<decompiler_provider_descriptor_t> provider;
    std::optional<pseudocode_readability_report_t> readability;
    std::string language_id;
    std::uint64_t workspace_generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::vector<decompiler_ui_source_mapping_t> source_mappings;
    std::vector<decompiler_ui_diagnostic_t> diagnostics;
    std::uint64_t elapsed_ms = 0;
    std::optional<decompiler_cache_stage_t> cache_hit_stage;
    bool used_legacy_fallback = false;
    bool succeeded() const noexcept {
        return status == decompiler_pipeline_status_t::completed && document &&
               !rendered_text.empty();
    }
};

struct decompiler_ui_integration_config_t {
    decompiler_pipeline_service_config_t service_config = {};
    std::uint64_t max_function_bytes = 64ULL << 20;
    std::size_t max_function_chunks = 65536;
    bool reject_null_ast = true;
    bool reject_guessed_body = true;
    bool preserve_commands = true;
    bool preserve_shortcuts = true;
    bool preserve_source_mappings = true;
    bool preserve_diagnostics = true;
    bool legacy_fallback_enabled = true;
    std::size_t max_managed_capture_cache_entries = 16;
    std::uint64_t max_managed_capture_bytes = 64ULL << 20;
    readers::managed::managed_reader_limits_t managed_reader_limits = {};
};

struct decompiler_ui_integration_metrics_t {
    std::uint64_t total_requests = 0;
    std::uint64_t f5_requests = 0;
    std::uint64_t mcp_requests = 0;
    std::uint64_t api_requests = 0;
    std::uint64_t completed = 0;
    std::uint64_t rejected_null_ast = 0;
    std::uint64_t rejected_guessed_body = 0;
    std::uint64_t provider_failures = 0;
    std::uint64_t cache_hits = 0;
    std::uint64_t deadline_exceeded = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t entity_resolutions = 0;
    std::uint64_t entity_resolution_failures = 0;
    std::uint64_t managed_capture_cache_hits = 0;
    std::uint64_t native_identity_cache_hits = 0;
    std::uint64_t native_identity_cache_misses = 0;
};

workspace_result_t<decompiler_pipeline_request_t> make_native_pipeline_request(
    analysis_workspace_t& workspace,
    const std::shared_ptr<const analysis_publication_t>& publication,
    const function_record_t& function,
    decompiler_pipeline_invocation_t invocation,
    decompiler_pipeline_cache_mode_t cache_mode,
    decompiler_profile_id_t profile,
    const std::optional<decompiler_profile_budget_t>& budget = std::nullopt,
    const std::optional<std::chrono::steady_clock::time_point>& deadline = std::nullopt,
    const std::shared_ptr<const decompiler_provider_context_t>& provider_context = {},
    const cancellation_token_t& cancel = {});

class decompiler_ui_integration_t final {
public:
    static workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>
        create(std::shared_ptr<analysis_workspace_t> workspace,
               std::shared_ptr<decompiler_pipeline_service_t> service,
               decompiler_ui_integration_config_t config = {});
    static workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>
        create_production(std::shared_ptr<analysis_workspace_t> workspace,
                          std::filesystem::path runtime_root = {},
                          decompiler_ui_integration_config_t config = {});
    static workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>
        production_for_workspace(std::shared_ptr<analysis_workspace_t> workspace);
    static workspace_result_t<std::shared_ptr<decompiler_ui_integration_t>>
        find_production_for_workspace(
            const std::shared_ptr<analysis_workspace_t>& workspace);

    ~decompiler_ui_integration_t();
    decompiler_ui_integration_t(const decompiler_ui_integration_t&) = delete;
    decompiler_ui_integration_t& operator=(const decompiler_ui_integration_t&) = delete;

    workspace_result_t<decompiler_ui_result_t>
        decompile(const decompiler_ui_request_t& request,
                  const cancellation_token_t& cancel = {});
    workspace_result_t<decompiler_ui_result_t>
        decompile_native(std::uint64_t function_address,
                         decompiler_ui_invocation_source_t source =
                             decompiler_ui_invocation_source_t::keyboard_f5,
                         decompiler_profile_id_t profile = decompiler_profile_id_t::balanced,
                         decompiler_pipeline_cache_mode_t cache_mode =
                             decompiler_pipeline_cache_mode_t::read_write,
                          const cancellation_token_t& cancel = {});
    workspace_result_t<decompiler_ui_result_t>
        decompile_cli(std::shared_ptr<const managed_cli::request_t> request,
                      decompiler_ui_invocation_source_t source =
                          decompiler_ui_invocation_source_t::api_call,
                      decompiler_pipeline_cache_mode_t cache_mode =
                          decompiler_pipeline_cache_mode_t::read_write,
                      const cancellation_token_t& cancel = {});
    workspace_result_t<decompiler_ui_result_t>
        decompile_jvm(std::shared_ptr<const jvm_ssa::jvm_method_input_t> input,
                      decompiler_ui_invocation_source_t source =
                          decompiler_ui_invocation_source_t::api_call,
                      decompiler_profile_id_t profile = decompiler_profile_id_t::balanced,
                      decompiler_pipeline_cache_mode_t cache_mode =
                          decompiler_pipeline_cache_mode_t::read_write,
                      const cancellation_token_t& cancel = {});
    workspace_result_t<decompiler_ui_result_t>
        decompile_dalvik(std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t> capture,
                         decompiler_ui_invocation_source_t source =
                             decompiler_ui_invocation_source_t::api_call,
                         decompiler_profile_id_t profile = decompiler_profile_id_t::balanced,
                         decompiler_pipeline_cache_mode_t cache_mode =
                             decompiler_pipeline_cache_mode_t::read_write,
                         const cancellation_token_t& cancel = {});
    workspace_result_t<generation_bound_decompiler_entity_t>
        resolve_entity_at(const decompiler_entity_locator_t& locator,
                          const cancellation_token_t& cancel = {});
    workspace_result_t<decompiler_ui_result_t>
        decompile_entity(
            const generation_bound_decompiler_entity_t& binding,
            decompiler_ui_invocation_source_t source =
                decompiler_ui_invocation_source_t::api_call,
            decompiler_profile_id_t profile = decompiler_profile_id_t::balanced,
            decompiler_pipeline_cache_mode_t cache_mode =
                decompiler_pipeline_cache_mode_t::read_write,
            const cancellation_token_t& cancel = {});

    workspace_result_t<void> invalidate_workspace();

    decompiler_ui_integration_metrics_t metrics() const noexcept;

    std::shared_ptr<decompiler_pipeline_service_t> service() const noexcept;
    std::shared_ptr<analysis_workspace_t> workspace() const noexcept;

    static decompiler_pipeline_invocation_t
        map_invocation_source(decompiler_ui_invocation_source_t source) noexcept;

    static workspace_result_t<decompiler_pipeline_request_t>
        build_pipeline_request(const decompiler_ui_request_t& request,
                               const analysis_workspace_t& workspace,
                               std::uint64_t max_function_bytes = 64ULL << 20,
                               std::size_t max_function_chunks = 65536,
                               const cancellation_token_t& cancel = {});

    static decompiler_ui_result_t
        map_pipeline_result(const decompiler_pipeline_result_t& result);

private:
    workspace_result_t<decompiler_ui_result_t>
        execute_pipeline(decompiler_pipeline_request_t request,
                         decompiler_ui_invocation_source_t source,
                         bool require_complete_source_map,
                         const cancellation_token_t& cancel);
    struct impl_t;
    explicit decompiler_ui_integration_t(std::unique_ptr<impl_t> impl);
    std::unique_ptr<impl_t> impl_;

    friend workspace_result_t<decompiler_pipeline_request_t> make_native_pipeline_request(
        analysis_workspace_t& workspace,
        const std::shared_ptr<const analysis_publication_t>& publication,
        const function_record_t& function,
        decompiler_pipeline_invocation_t invocation,
        decompiler_pipeline_cache_mode_t cache_mode,
        decompiler_profile_id_t profile,
        const std::optional<decompiler_profile_budget_t>& budget,
        const std::optional<std::chrono::steady_clock::time_point>& deadline,
        const std::shared_ptr<const decompiler_provider_context_t>& provider_context,
        const cancellation_token_t& cancel);
};

}
